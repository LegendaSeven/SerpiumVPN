# SFP Bridge v1 architecture

```text
Serpium UI / policy owner
        |
        | REPLACE_POLICY generation N
        v
Serpium.SFP.Kernel
        |
        +-- DIRECT --------------------------> Windows TCP/IP
        |
        `-- VPN
             |
             | ALE_CONNECT_REDIRECT V4/V6
             v
      Serpium.SFP.Bridge.exe
             |
             | query redirect context + records
             | set redirect records on new socket
             v
      local Relay SOCKS5 endpoint
             |
             v
            VPN
```

Hard cutover stays independent:

```text
policy N -> N+1
ABORT_STALE(app, N+1)
        |
        v
old flow closes
        |
        v
application reconnects
        |
        v
new connect receives N+1 route immediately
```

No Clash API polling is used.
