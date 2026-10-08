# Serpium WFP CleanRoom — P1

This is a new WFP implementation. It does **not** reuse the old
`Native\Serpium.Flow` driver/service logic.

The old tree is left untouched.

## P1 goal

Build the first trustworthy primitive: event-driven application flow
monitoring in the kernel, without sing-box/Clash polling and without a timer.

Kernel layers:

- `ALE_AUTH_CONNECT_V4`
- `ALE_AUTH_CONNECT_V6`
- `ALE_FLOW_ESTABLISHED_V4`
- `ALE_FLOW_ESTABLISHED_V6`

Event stream:

- `CONNECT` — outbound connection attempt
- `OPEN` — actual ALE flow established
- `CLOSE` — WFP flow-delete callback

For TCP, `OPEN` happens after the handshake. For UDP/non-TCP, ALE flow
establishment follows authorization immediately.

## No polling

`Serpium.Wfp.Monitor.exe stream` performs a blocking `ReadFile()` on
`\\.\SerpiumWfp`.

The KMDF driver keeps pending read requests in a manual queue and completes
one immediately when a WFP event arrives. If the monitor is temporarily not
reading, a bounded kernel ring stores the latest 2048 events.

This means there is no 500 ms/160 ms application polling loop.

## Safety

P1 is observe-only:

- no BLOCK
- no redirect
- no packet injection
- no route mutation
- no old-flow termination
- no driver install in the patch
- no TESTSIGNING/BCD/Hyper-V changes

## Planned next phases

### P2 — kernel policy engine

`app-id -> DIRECT/VPN`, atomic generation replace.

The `AUTH_CONNECT` event will carry the route decision and policy generation.
UI receives the decision immediately from the same event that made it.

### P3 — WFP route adapter

For VPN decisions, connect redirect goes to a Serpium local bridge/back-end.
DIRECT remains native.

### P4 — hard cutover

Existing flows stay pinned by default. Optional hard cutover will explicitly
terminate only stale flows for the selected application after a policy
generation change.

This is separate because Windows cannot transparently teleport an established
TCP stream to another upstream path.

## Build

`build_wfpng.ps1` uses direct `cl.exe + link.exe` and the installed WDK/KMDF.
It does not depend on `WindowsKernelModeDriver10.0` Visual Studio integration.

P1 does not install the driver.
