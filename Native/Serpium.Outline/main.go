// Serpium's loopback adapter. Cryptography and the prefix format are provided by Outline SDK.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	ss "golang.getoutline.org/sdk/transport/shadowsocks"
)

type configuration struct {
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Method        string `json:"method"`
	Password      string `json:"password"`
	Prefix        []byte `json:"prefix"`
	LocalPassword string `json:"local_password"`
}

type bridge struct {
	config        configuration
	local, remote *ss.EncryptionKey
	listener      *net.TCPListener
	udp           *net.UDPConn
	context       context.Context
	cancel        context.CancelFunc
	workers       sync.WaitGroup
	slots         chan struct{}
	udpLock       sync.Mutex
	peers         map[string]*net.UDPConn
}

func start(parent context.Context, config configuration) (*bridge, error) {
	if config.Server == "" || len(config.Server) > 253 || config.Port < 1 || config.Port > 65535 || len(config.Password) == 0 || len(config.Password) > 2048 || len(config.LocalPassword) < 32 || len(config.LocalPassword) > 128 {
		return nil, errors.New("invalid configuration")
	}
	switch config.Method {
	case "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305":
	default:
		return nil, errors.New("unsupported method")
	}
	remote, err := ss.NewEncryptionKey(config.Method, config.Password)
	if err != nil {
		return nil, err
	}
	// Keep at least 128 random bits in every salt; prefixing never affects UDP here.
	if len(config.Prefix) == 0 || len(config.Prefix) > 16 || remote.SaltSize()-len(config.Prefix) < 16 {
		return nil, errors.New("invalid prefix length")
	}
	local, err := ss.NewEncryptionKey("chacha20-ietf-poly1305", config.LocalPassword)
	if err != nil {
		return nil, err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: listener.Addr().(*net.TCPAddr).Port})
	if err != nil {
		listener.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	b := &bridge{config: config, local: local, remote: remote, listener: listener, udp: udp, context: ctx, cancel: cancel, slots: make(chan struct{}, 256), peers: make(map[string]*net.UDPConn)}
	b.workers.Add(2)
	go b.acceptTCP()
	go b.acceptUDP()
	return b, nil
}

func (b *bridge) address() string { return b.listener.Addr().String() }
func (b *bridge) close() {
	b.cancel()
	b.listener.Close()
	b.udp.Close()
	b.udpLock.Lock()
	for _, peer := range b.peers {
		peer.Close()
	}
	b.udpLock.Unlock()
	b.workers.Wait()
}

func (b *bridge) acceptTCP() {
	defer b.workers.Done()
	for {
		client, err := b.listener.AcceptTCP()
		if err != nil {
			return
		}
		select {
		case b.slots <- struct{}{}:
			b.workers.Add(1)
			go func() { defer b.workers.Done(); defer func() { <-b.slots }(); b.relayTCP(client) }()
		default:
			client.Close()
		}
	}
}

func (b *bridge) relayTCP(client *net.TCPConn) {
	defer client.Close()
	stopClient := context.AfterFunc(b.context, func() { client.Close() })
	defer stopClient()
	client.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := ss.NewReader(client, b.local)
	// Authenticate the loopback client before making any server connection.
	first := make([]byte, 16384)
	defer clear(first)
	count, err := reader.Read(first)
	if err != nil || count == 0 {
		return
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(b.context, "tcp", net.JoinHostPort(b.config.Server, strconv.Itoa(b.config.Port)))
	if err != nil {
		return
	}
	remote := connection.(*net.TCPConn)
	defer remote.Close()
	stopRemote := context.AfterFunc(b.context, func() { remote.Close() })
	defer stopRemote()
	client.SetReadDeadline(time.Time{})
	writer := ss.NewWriter(remote, b.remote)
	writer.SetSaltGenerator(ss.NewPrefixSaltGenerator(b.config.Prefix))
	if _, err = writer.Write(first[:count]); err != nil {
		return
	}
	done := make(chan struct{})
	go func() { defer close(done); io.Copy(writer, reader); remote.CloseWrite() }()
	io.Copy(ss.NewWriter(client, b.local), ss.NewReader(remote, b.remote))
	client.CloseWrite()
	client.Close()
	remote.Close()
	<-done
}

func (b *bridge) acceptUDP() {
	defer b.workers.Done()
	buffer := make([]byte, 65535)
	plain := make([]byte, 65535)
	encrypted := make([]byte, 65535)
	defer clear(buffer)
	defer clear(plain)
	defer clear(encrypted)
	for {
		count, client, err := b.udp.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		payload, err := ss.Unpack(plain, buffer[:count], b.local)
		if err != nil {
			continue
		}
		packet, err := ss.Pack(encrypted, payload, b.remote)
		if err != nil {
			continue
		}
		b.udpLock.Lock()
		peer := b.peers[client.String()]
		full := len(b.peers) >= 256
		b.udpLock.Unlock()
		if peer == nil {
			if full {
				continue
			}
			connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(b.context, "udp", net.JoinHostPort(b.config.Server, strconv.Itoa(b.config.Port)))
			if err != nil {
				continue
			}
			peer = connection.(*net.UDPConn)
			b.udpLock.Lock()
			b.peers[client.String()] = peer
			b.udpLock.Unlock()
			b.workers.Add(1)
			go b.receiveUDP(client, peer)
		}
		peer.SetWriteDeadline(time.Now().Add(5 * time.Second))
		peer.Write(packet)
	}
}

func (b *bridge) receiveUDP(client *net.UDPAddr, peer *net.UDPConn) {
	defer b.workers.Done()
	defer peer.Close()
	stop := context.AfterFunc(b.context, func() { peer.Close() })
	defer stop()
	defer func() {
		b.udpLock.Lock()
		if b.peers[client.String()] == peer {
			delete(b.peers, client.String())
		}
		b.udpLock.Unlock()
	}()
	buffer := make([]byte, 65535)
	plain := make([]byte, 65535)
	encrypted := make([]byte, 65535)
	defer clear(buffer)
	defer clear(plain)
	defer clear(encrypted)
	for {
		peer.SetReadDeadline(time.Now().Add(2 * time.Minute))
		count, err := peer.Read(buffer)
		if err != nil {
			return
		}
		payload, err := ss.Unpack(plain, buffer[:count], b.remote)
		if err != nil {
			continue
		}
		packet, err := ss.Pack(encrypted, payload, b.local)
		if err != nil {
			continue
		}
		b.udp.WriteToUDP(packet, client)
	}
}

func run() error {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("Serpium.Outline 1; Outline SDK v0.1.0")
		return nil
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024), 16384)
	if !scanner.Scan() {
		return errors.New("configuration missing")
	}
	var config configuration
	if err := json.Unmarshal(scanner.Bytes(), &config); err != nil {
		return errors.New("configuration invalid")
	}
	b, err := start(context.Background(), config)
	if err != nil {
		return errors.New("transport unavailable")
	}
	defer b.close()
	if err = json.NewEncoder(os.Stdout).Encode(map[string]int{"port": b.listener.Addr().(*net.TCPAddr).Port}); err != nil {
		return err
	}
	// The parent keeps stdin open. EOF closes all connections even after a parent crash.
	for scanner.Scan() {
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "OUTLINE_TRANSPORT_FAILED")
		os.Exit(1)
	}
}
