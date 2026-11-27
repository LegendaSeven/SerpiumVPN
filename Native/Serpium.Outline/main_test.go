package main

import (
	"bytes"
	"context"
	ss "golang.getoutline.org/sdk/transport/shadowsocks"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var testPrefix = []byte{0x16, 0x03, 0x01, 0x00, 0xa8, 0x01, 0x01}

func testConfig(port int) configuration {
	return configuration{Server: "127.0.0.1", Port: port, Method: "chacha20-ietf-poly1305", Password: "synthetic-outline-fixture", Prefix: testPrefix, LocalPassword: strings.Repeat("L", 64)}
}

func TestPrefixTCP(t *testing.T) {
	remote, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	config := testConfig(remote.Addr().(*net.TCPAddr).Port)
	b, err := start(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	salts := make(chan []byte, 2)
	failures := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			connection, err := remote.AcceptTCP()
			if err != nil {
				failures <- err
				return
			}
			func() {
				defer connection.Close()
				connection.SetDeadline(time.Now().Add(5 * time.Second))
				salt := make([]byte, b.remote.SaltSize())
				if _, err := io.ReadFull(connection, salt); err != nil {
					failures <- err
					return
				}
				salts <- salt
				reader := ss.NewReader(io.MultiReader(bytes.NewReader(salt), connection), b.remote)
				data := make([]byte, 5)
				_, err = io.ReadFull(reader, data)
				if err != nil {
					failures <- err
					return
				}
				_, err = ss.NewWriter(connection, b.remote).Write(data)
				failures <- err
			}()
		}
	}()
	for i := 0; i < 2; i++ {
		connection, err := net.Dial("tcp", b.address())
		if err != nil {
			t.Fatal(err)
		}
		connection.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err = ss.NewWriter(connection, b.local).Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 5)
		if _, err = io.ReadFull(ss.NewReader(connection, b.local), reply); err != nil {
			t.Fatal(err)
		}
		connection.Close()
		if string(reply) != "hello" {
			t.Fatal("incorrect TCP round trip")
		}
		if err = <-failures; err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-salts, <-salts
	if !bytes.HasPrefix(first, testPrefix) || !bytes.HasPrefix(second, testPrefix) {
		t.Fatal("prefix not emitted byte-for-byte")
	}
	if bytes.Equal(first, second) {
		t.Fatal("salt randomness lost")
	}
}

func TestUDPUnprefixed(t *testing.T) {
	remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	b, err := start(context.Background(), testConfig(remote.LocalAddr().(*net.UDPAddr).Port))
	if err != nil {
		t.Fatal(err)
	}
	defer b.close()
	failures := make(chan error, 1)
	go func() {
		remote.SetDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 65535)
		n, client, err := remote.ReadFromUDP(buffer)
		if err != nil {
			failures <- err
			return
		}
		if bytes.HasPrefix(buffer[:n], testPrefix) {
			failures <- io.ErrNoProgress
			return
		}
		plain, err := ss.Unpack(nil, buffer[:n], b.remote)
		if err != nil {
			failures <- err
			return
		}
		response, err := ss.Pack(make([]byte, 65535), plain, b.remote)
		if err == nil {
			_, err = remote.WriteToUDP(response, client)
		}
		failures <- err
	}()
	connection, err := net.Dial("udp", b.address())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(5 * time.Second))
	packet, err := ss.Pack(make([]byte, 65535), []byte("udp-fixture"), b.local)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Write(packet); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	n, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := ss.Unpack(nil, buffer[:n], b.local)
	if err != nil || string(plain) != "udp-fixture" {
		t.Fatal("incorrect UDP round trip", err)
	}
	if err = <-failures; err != nil {
		t.Fatal(err)
	}
}

func TestBoundsAndShutdown(t *testing.T) {
	for _, c := range []configuration{
		{Server: "127.0.0.1", Port: 443, Method: "chacha20-ietf-poly1305", Password: "test", Prefix: make([]byte, 17), LocalPassword: strings.Repeat("x", 64)},
		{Server: "127.0.0.1", Port: 443, Method: "aes-128-gcm", Password: "test", Prefix: []byte{1}, LocalPassword: strings.Repeat("x", 64)},
		{Server: "127.0.0.1", Port: 443, Method: "chacha20-ietf-poly1305", Password: "test", Prefix: testPrefix, LocalPassword: "short"},
	} {
		if b, err := start(context.Background(), c); err == nil {
			b.close()
			t.Fatal("unsafe config accepted")
		}
	}
	b, err := start(context.Background(), testConfig(443))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", b.address())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	done := make(chan struct{})
	go func() { b.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown left blocked connections")
	}
}
