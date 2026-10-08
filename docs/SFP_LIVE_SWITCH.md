# SFP live application switching

The simple home screen uses a user-mode SFP controller with the existing sing-box
TUN engine. The product does not include a separate native kernel backend.

## Switching sequence

1. Persist the application's new choice in the existing encrypted routing registry.
2. Atomically replace the shared local application rule-set, including a fresh
   activation challenge. Unselected applications use the direct final route;
   an empty selection never becomes full tunnel.
3. Ask the authenticated loopback engine API to resolve the challenge. This proves
   that the running engine loaded the particular rule-set revision. A fixed delay,
   a successful file write, and an empty connection list are not acknowledgements.
4. Query active connections and close only exact executable paths belonging to
   the changed application that still use the wrong route for their destination. TCP and UDP are
   handled together; DNS-port flows are not silently excluded. Extended Windows
   path prefixes and case differences are normalized, without matching basenames.
5. Confirm that the old-route connections disappeared and that the engine process
   is still the same. Then update the toggle and show the short confirmation.

The controller uses individual connection deletion, never the global delete-all
endpoint. Concurrently closed connections are harmless. Unavailable snapshots,
HTTP failures and unconfirmed activation cause an error, rather than success.
Switches are serialized by the existing UI operation guard.

The route compiler and cleanup share `SfpDirectRouteExceptions`: destinations in
`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` and `127.0.0.0/8` remain direct
regardless of the application's toggle. Their existing direct TCP/UDP connections
are preserved. A connection to those destinations still using a proxy (or an
unknown route) is closed. Cleanup checks the numeric `destinationIP` reported by
the engine; a host name, source address, missing or malformed destination does not
grant a direct exception. No new IPv6, link-local, CGNAT or fake-IP exceptions are
introduced by this change.

On failure, the UI restores the old saved choice and applies it through the same
live path. If recovery also fails, the existing transport cleanup runs and the UI
reports a failure. Normal application switching never restarts the engine.

## Activation challenge

Each revision includes a random 128-bit name below `sfp.invalid`. Matching this
name through the same rule-set returns an internal `NOERROR`; an older revision
returns an internal `NXDOMAIN`. Both answers are synthesized by sing-box and
cache lookup is disabled for this reserved suffix. The challenge is queried only
through the authenticated loopback API; it does not contact an external resolver
or the VPN server. The controller verifies the returned question and internal
response source. No VPN key is stored in the rule-set.

Activation is bounded to four seconds, connection draining to five. A healthy
engine typically finishes much sooner. A partial or malformed response is never
treated as a positive acknowledgement. This requires sing-box DNS predefined
actions (available since 1.12); the bundled 1.13.15 was verified.

## Verification and limits

The automated local integration harness uses the installed native sing-box and
separate Windows client processes. One scenario preserves the native direct
outbound and verifies persistent loopback TCP/UDP connections across both toggle
changes. A second scenario mixes local and synthetic internet destinations for the
same application, using two local SOCKS echo servers as the direct and VPN
transports. Only old internet flows close; local flows and another application's
flows survive. It also checks newly discovered applications and the all-off policy.
Both scenarios preserve the production LAN rules. Only in the harness, a SOCKS
inbound replaces TUN and physical adapter auto-binding is disabled. Destination
boundary and malformed metadata checks cover the cleanup decision separately.
No system routes or user VPN credentials are changed by the harness.

The native direct scenario reproduced the original defect before the fix: enabling
the toggle closed both local TCP and UDP connections. The same scenario must
preserve both connections after the fix.

These checks establish engine policy activation and flow closure, not end-to-end
behavior with every TUN application or a real VPN server. Existing TCP connections
cannot move between external addresses intact. They are closed, and each application
decides when to reconnect; a download, game or call may briefly pause. This is not
a packet-atomic kernel transaction and not a zero-latency guarantee.

References:
- https://sing-box.sagernet.org/configuration/dns/rule_action/
- https://sing-box.sagernet.org/configuration/rule-set/
