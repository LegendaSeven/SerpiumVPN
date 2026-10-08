# Clean-room architecture

```text
SerpiumVPN.exe
    |
    | policy commands (P2)
    v
Serpium.Wfp.Service / client
    |
    | IOCTL + blocking event stream
    v
\\.\SerpiumWfp
    |
    v
Serpium.Wfp.Driver.sys
    |
    +-- ALE_AUTH_CONNECT_V4/V6
    |      immediate connection-attempt event
    |
    +-- ALE_FLOW_ESTABLISHED_V4/V6
    |      create FLOW_CONTEXT
    |      event: OPEN
    |
    +-- flowDeleteFn
           event: CLOSE
```

No sing-box telemetry is used for status.

The kernel is the source of truth for:

- process/application identity;
- active flow lifetime;
- TCP/UDP protocol;
- local/remote tuple;
- later: policy generation;
- later: DIRECT/VPN decision.

The product UI will aggregate active flow contexts per routing card:

```text
Edge
  active VPN:    12
  active DIRECT: 0
  pending:       0
  generation:    37
```

P1 intentionally stops before route enforcement.
