package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

const version = "0.5.1-mvp6.2.1-headless-client-build-hotfix"

var loginURLPattern = regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9]+`)

type upResult struct {
	status *ipnstate.Status
	err    error
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	command := strings.ToLower(os.Args[1])
	fs := flag.NewFlagSet(command, flag.ExitOnError)
	hostname := fs.String("hostname", "serpium-gateway", "tsnet hostname")
	stateDir := fs.String("state-dir", defaultStateDir(), "tsnet state directory")
	port := fs.Int("port", 28443, "virtual gateway listen port")
	target := fs.String("target", "127.0.0.1:28443", "local TCP forwarding target")
	controlURL := fs.String("control-url", envOrDefault("SERPIUM_CONTROL_URL", ""), "Headscale coordination URL")
	authKey := fs.String("auth-key", envOrDefault("SERPIUM_AUTH_KEY", ""), "one-time Headscale enrollment key")
	listen := fs.String("listen", "127.0.0.1:0", "local client bridge listen address")
	remote := fs.String("remote", "", "remote tailnet target host:port")
	_ = fs.Parse(os.Args[2:])

	switch command {
	case "version":
		fmt.Println("SerpiumNet", version)
	case "login", "status":
		if err := runLogin(*hostname, *stateDir, *controlURL, *authKey); err != nil {
			fatal(err)
		}
	case "node", "run":
		if err := runNode(*hostname, *stateDir, *controlURL, *authKey); err != nil {
			fatal(err)
		}
	case "gateway":
		if err := runGateway(*hostname, *stateDir, *port, *target, *controlURL, *authKey); err != nil {
			fatal(err)
		}
	case "client", "bridge":
		if err := runClientBridge(*hostname, *stateDir, *listen, *remote, *controlURL, *authKey); err != nil {
			fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func printControlMode(controlURL, authKey string) {
	if strings.TrimSpace(controlURL) == "" {
		fmt.Println("CONTROL_MODE=missing")
	} else {
		fmt.Println("CONTROL_URL=" + strings.TrimSpace(controlURL))
	}
	if strings.TrimSpace(authKey) != "" {
		fmt.Println("AUTH_KEY=provided")
	} else {
		fmt.Println("AUTH_KEY=not-provided")
	}
}

func defaultStateDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		base = "."
	}
	return filepath.Join(base, "SerpiumVPN", "SerpiumNet")
}

func hasPersistentState(stateDir string) bool {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return false
	}
	return len(entries) > 0
}

func validateHeadlessEnrollment(stateDir, controlURL, authKey string) error {
	if strings.TrimSpace(controlURL) == "" {
		return errors.New("Headscale control URL is required; interactive Tailscale login is disabled")
	}
	if strings.TrimSpace(authKey) == "" && !hasPersistentState(stateDir) {
		return errors.New("Headscale enrollment key or persistent client state is required; browser login is disabled")
	}
	return nil
}

func newServer(hostname, stateDir, controlURL, authKey string) (*tsnet.Server, <-chan string) {
	_ = os.MkdirAll(stateDir, 0o700)
	authURL := make(chan string, 1)
	var once sync.Once

	server := &tsnet.Server{
		Hostname:   hostname,
		Dir:        stateDir,
		ControlURL: strings.TrimSpace(controlURL),
		AuthKey:    strings.TrimSpace(authKey),
		Logf: func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			if url := loginURLPattern.FindString(line); url != "" {
				once.Do(func() { authURL <- url })
				line = strings.ReplaceAll(line, url, "<interactive-login-url-blocked>")
			}
			fmt.Fprintln(os.Stderr, "[tsnet] "+line)
		},
	}

	return server, authURL
}

func upHeadless(ctx context.Context, server *tsnet.Server, authURL <-chan string) (*ipnstate.Status, error) {
	upCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	result := make(chan upResult, 1)
	go func() {
		status, err := server.Up(upCtx)
		result <- upResult{status: status, err: err}
	}()

	select {
	case r := <-result:
		return r.status, r.err
	case <-authURL:
		cancel()
		return nil, errors.New("interactive browser authorization was requested and blocked; provide a Headscale key or valid persistent state")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func runLogin(hostname, stateDir, controlURL, authKey string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := validateHeadlessEnrollment(stateDir, controlURL, authKey); err != nil {
		return err
	}

	printControlMode(controlURL, authKey)
	server, authURL := newServer(hostname, stateDir, controlURL, authKey)
	defer server.Close()

	status, err := upHeadless(ctx, server, authURL)
	if err != nil {
		return fmt.Errorf("authorization/connection failed: %w", err)
	}
	fmt.Println("LOGIN_OK")
	printIPs(status.TailscaleIPs, "TAILSCALE_IP")
	return nil
}

func runNode(hostname, stateDir, controlURL, authKey string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := validateHeadlessEnrollment(stateDir, controlURL, authKey); err != nil {
		return err
	}

	printControlMode(controlURL, authKey)
	server, authURL := newServer(hostname, stateDir, controlURL, authKey)
	defer server.Close()

	status, err := upHeadless(ctx, server, authURL)
	if err != nil {
		return fmt.Errorf("authorization/connection failed: %w", err)
	}

	fmt.Println("NODE_ONLINE")
	printIPs(status.TailscaleIPs, "TAILSCALE_IP")
	fmt.Println("STATE_DIR=" + stateDir)

	<-ctx.Done()
	fmt.Println("NODE_STOPPING")
	return nil
}

func runGateway(hostname, stateDir string, port int, target, controlURL, authKey string) error {
	if port < 1 || port > 65535 {
		return errors.New("port must be in range 1..65535")
	}
	if err := validateHeadlessEnrollment(stateDir, controlURL, authKey); err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	printControlMode(controlURL, authKey)
	server, authURL := newServer(hostname, stateDir, controlURL, authKey)
	defer server.Close()

	status, err := upHeadless(ctx, server, authURL)
	if err != nil {
		return fmt.Errorf("authorization/connection failed: %w", err)
	}
	fmt.Println("LOGIN_OK")
	printIPs(status.TailscaleIPs, "TAILSCALE_IP")

	listener, err := server.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("tsnet listen failed: %w", err)
	}
	defer listener.Close()

	fmt.Printf("GATEWAY_READY=%d\n", port)
	fmt.Printf("FORWARD_TARGET=%s\n", target)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "accept error:", err)
			time.Sleep(250 * time.Millisecond)
			continue
		}
		go proxyConnection(conn, target)
	}
}

func runClientBridge(hostname, stateDir, listenAddr, remote, controlURL, authKey string) error {
	if err := validateHeadlessEnrollment(stateDir, controlURL, authKey); err != nil {
		return err
	}
	if strings.TrimSpace(remote) == "" {
		return errors.New("remote tailnet target is required")
	}
	if _, _, err := net.SplitHostPort(remote); err != nil {
		return fmt.Errorf("invalid remote target %q: %w", remote, err)
	}
	if _, _, err := net.SplitHostPort(listenAddr); err != nil {
		return fmt.Errorf("invalid local listen address %q: %w", listenAddr, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	printControlMode(controlURL, authKey)
	server, authURL := newServer(hostname, stateDir, controlURL, authKey)
	defer server.Close()

	status, err := upHeadless(ctx, server, authURL)
	if err != nil {
		return fmt.Errorf("authorization/connection failed: %w", err)
	}
	fmt.Println("CLIENT_ONLINE")
	printIPs(status.TailscaleIPs, "CLIENT_IP")

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("local bridge listen failed: %w", err)
	}
	defer listener.Close()

	fmt.Println("CLIENT_BRIDGE_READY=" + listener.Addr().String())
	fmt.Println("REMOTE_TARGET=" + remote)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		localConn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			fmt.Fprintln(os.Stderr, "local accept error:", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go proxyTailnetConnection(ctx, server, localConn, remote)
	}
}

func proxyTailnetConnection(ctx context.Context, server *tsnet.Server, local net.Conn, remote string) {
	defer local.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	tailnetConn, err := server.Dial(dialCtx, "tcp", remote)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailnet dial error:", err)
		return
	}
	defer tailnetConn.Close()

	copyBoth(local, tailnetConn)
}

func proxyConnection(in net.Conn, target string) {
	defer in.Close()
	out, err := net.DialTimeout("tcp", target, 8*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "forward dial error:", err)
		return
	}
	defer out.Close()
	copyBoth(in, out)
}

func copyBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(b, bufio.NewReader(a)); done <- struct{}{} }()
	go func() { _, _ = io.Copy(a, bufio.NewReader(b)); done <- struct{}{} }()
	<-done
}

func printIPs(ips []netip.Addr, prefix string) {
	for _, ip := range ips {
		if ip.Is4() {
			fmt.Println(prefix + "=" + ip.String())
			return
		}
	}
	if len(ips) > 0 {
		fmt.Println(prefix + "=" + ips[0].String())
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ERROR:", err)
	os.Exit(1)
}

func usage() {
	fmt.Println("SerpiumNet", version)
	fmt.Println("Commands: login, status, node, gateway, client, version")
	fmt.Println("Headless mode requires --control-url and either --auth-key or persistent state.")
}
