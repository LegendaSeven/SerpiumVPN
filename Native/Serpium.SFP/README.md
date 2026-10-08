# Serpium Flow Platform — SFP Bridge v1

SFP Bridge v1 is the first data-plane stage on top of SFP Core.

For TCP:

```text
application connect()
        |
        v
SFP policy lookup
        |
        +-- DIRECT -> unchanged Windows connection
        |
        `-- VPN
              |
              v
       ALE_CONNECT_REDIRECT
              |
              v
       127.0.0.1:SFP Bridge
              |
              v
       local SOCKS5 Relay endpoint
              |
              v
             VPN
```

The bridge gets the original destination from WFP redirect context and copies
WFP redirect records from the accepted connection onto the new proxy socket.

Loop protection is explicit:
- SFP Bridge PID is bypassed;
- Relay backend PIDs supplied to the bridge are bypassed;
- loopback destinations are never redirected.

This is important for `defaultRoute=VPN`: the Relay must never feed its own
outbound socket back into SFP.

Bridge v1 is fail-open. If the bridge is not armed or a redirect cannot be
prepared, the kernel does not intentionally block the connection.

## TCP only

Bridge v1 redirects TCP only. UDP/QUIC is intentionally a separate phase.

## Bridge command

```text
Serpium.SFP.Bridge.exe <socks-port> [relay-pid ...]
```

Example:

```text
Serpium.SFP.Bridge.exe 2080 1234 5678
```

`2080` is the local no-auth SOCKS5 endpoint exposed by the active Relay
backend. The following PIDs are backend processes that must bypass redirect.

This patch only writes/builds source. It does not install or start the kernel
driver and does not touch BCD, TESTSIGNING, Hyper-V, old Serpium.Flow, or old
Serpium.Wfp trees.
