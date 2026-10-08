# Serpium Flow — WFP-4A Guarded TCP Route Core

WFP-4A is the first route-enforcement increment after the completed WFP-3A
policy transport. It preserves the bounded AppRule and FlowTable ABI while
adding actual TCP connect redirection to a local transparent bridge.

## Route semantics

- no rules: Full Tunnel intent; ordinary new TCP flows choose VPN;
- one or more rules: matching rules choose their configured VPN/DIRECT route;
- unmatched new flows in Split Tunnel choose DIRECT;
- loopback traffic, the bridge process, and declared Relay backend PIDs always
  bypass redirection;
- one live, leased bridge owns route configuration; another PID cannot replace
  it until disarm or lease expiry;
- existing TCP flows are not modified or terminated in WFP-4A.

## Guarded enforcement

Redirect enforcement is disarmed after driver start. The bridge must create V4
and V6 loopback listeners, prove that a local no-auth SOCKS5 endpoint is ready,
and renew a 5-second kernel lease. The driver permits the original connection
without redirection when configuration is absent, invalid, expired, or cannot
be applied. It never blocks, pends, absorbs, or injects traffic.

The bridge command is explicit and foreground-only in this increment:

```text
Serpium.Flow.Service.exe bridge <local-socks5-port> <backend-pid> [backend-pid ...]
```

It queries the WFP redirect context and records from each accepted socket,
passes the records to its outbound socket, performs a SOCKS5 CONNECT to the
original IPv4/IPv6 destination, and relays bytes unchanged. Ctrl+C disarms the
route before the bridge exits. A separate emergency command is also present:

```text
Serpium.Flow.Service.exe disarm-route
```

Emergency disarm revokes the active bridge PID, so its next lease renewal is
rejected instead of silently re-arming the route.

WFP-4A accepts only a SOCKS5 listener on `127.0.0.1` with no authentication.
The backend PID list is mandatory and lease renewal stops if any listed process
dies or the SOCKS5 health check fails.

## Explicit exclusions

- no UDP, QUIC, ICMP, DNS interception, or packet injection;
- no kill switch or fail-closed policy;
- no forced abort of pre-existing TCP flows;
- no automatic Serpium Relay manager or WPF UI integration;
- no signing, installation, TESTSIGNING, or runtime action in the source patch.

Automatic Relay lifecycle wiring and selective old-flow termination belong to
later WFP-4 increments. UDP/QUIC remains a separate stage.

## Build

Run the direct x64 Release build after applying the patch:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\Program\Serpium\SerpiumVPN\Native\Serpium.Flow\scripts\build_wfp1.ps1" -VisualStudioRoot "D:\Program\Visual Studio\18" -Configuration Release
```

Expected terminal marker and result archive:

```text
SERPIUM_WFP4A_ROUTE_CORE_BUILD_PASS
Serpium_WFP4A_RouteCoreBuild_Result_YYYYMMDD_HHMMSS.zip
```

The build uses the direct MSVC/WDK toolchain, compiles `service.cpp` and
`bridge.cpp` separately, links `Fwpuclnt.lib` and `Ws2_32.lib`, runs Inf2Cat,
and records the guarded redirect contract in `BUILD_MANIFEST.json`. It does not
sign, install, load, arm, or exercise the driver.
