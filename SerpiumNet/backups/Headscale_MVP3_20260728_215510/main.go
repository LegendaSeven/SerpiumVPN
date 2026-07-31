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

    "tailscale.com/tsnet"
)

const version = "0.2.0-mvp2"

var loginURLPattern = regexp.MustCompile(`https://login\.tailscale\.com/a/[A-Za-z0-9]+`)

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
    _ = fs.Parse(os.Args[2:])

    switch command {
    case "version":
        fmt.Println("SerpiumNet", version)
    case "login", "status":
        if err := runLogin(*hostname, *stateDir); err != nil {
            fatal(err)
        }
    case "gateway":
        if err := runGateway(*hostname, *stateDir, *port, *target); err != nil {
            fatal(err)
        }
    default:
        usage()
        os.Exit(2)
    }
}

func defaultStateDir() string {
    base, err := os.UserConfigDir()
    if err != nil || base == "" {
        base = "."
    }
    return filepath.Join(base, "SerpiumVPN", "SerpiumNet")
}

func newServer(hostname, stateDir string) *tsnet.Server {
    _ = os.MkdirAll(stateDir, 0o700)
    var once sync.Once
    return &tsnet.Server{
        Hostname: hostname,
        Dir:      stateDir,
        Logf: func(format string, args ...any) {
            line := fmt.Sprintf(format, args...)
            if url := loginURLPattern.FindString(line); url != "" {
                once.Do(func() { fmt.Println("LOGIN_URL=" + url) })
            }
            fmt.Fprintln(os.Stderr, "[tsnet] "+line)
        },
    }
}

func runLogin(hostname, stateDir string) error {
    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    server := newServer(hostname, stateDir)
    defer server.Close()

    status, err := server.Up(ctx)
    if err != nil {
        return fmt.Errorf("authorization/connection failed: %w", err)
    }
    fmt.Println("LOGIN_OK")
    printIPs(status.TailscaleIPs)
    return nil
}

func runGateway(hostname, stateDir string, port int, target string) error {
    if port < 1 || port > 65535 {
        return errors.New("port must be in range 1..65535")
    }

    ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
    defer cancel()

    server := newServer(hostname, stateDir)
    defer server.Close()

    status, err := server.Up(ctx)
    if err != nil {
        return fmt.Errorf("authorization/connection failed: %w", err)
    }
    fmt.Println("LOGIN_OK")
    printIPs(status.TailscaleIPs)

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

func proxyConnection(in net.Conn, target string) {
    defer in.Close()
    out, err := net.DialTimeout("tcp", target, 8*time.Second)
    if err != nil {
        fmt.Fprintln(os.Stderr, "forward dial error:", err)
        return
    }
    defer out.Close()

    done := make(chan struct{}, 2)
    go func() { _, _ = io.Copy(out, bufio.NewReader(in)); done <- struct{}{} }()
    go func() { _, _ = io.Copy(in, bufio.NewReader(out)); done <- struct{}{} }()
    <-done
}

func printIPs(ips []netip.Addr) {
    for _, ip := range ips {
        if ip.Is4() {
            fmt.Println("TAILSCALE_IP=" + ip.String())
            return
        }
    }
    if len(ips) > 0 {
        fmt.Println("TAILSCALE_IP=" + ips[0].String())
    }
}

func fatal(err error) {
    fmt.Fprintln(os.Stderr, "ERROR:", err)
    os.Exit(1)
}

func usage() {
    fmt.Println("SerpiumNet", version)
    fmt.Println("Commands: login, status, gateway, version")
}
