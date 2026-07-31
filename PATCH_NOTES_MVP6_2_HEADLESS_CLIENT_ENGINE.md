# SerpiumVPN MVP6.2 — Headless Client Engine

## Goal

Remove the right-side dependency on the installed Windows Tailscale client.
The Relay client now reaches a Headscale/tailnet gateway through an embedded
SerpiumNet `tsnet` userspace bridge, then points Xray at that local bridge.

## New connection chain

```text
Relay client button
    ↓
SerpiumNet.exe client (embedded tsnet)
    ↓ Headscale / persistent state / one-time key
local TCP bridge 127.0.0.1:<dynamic-port>
    ↓
Xray client
    ↓
SOCKS5 127.0.0.1:10808
```

No `tailscale.exe`, Windows Tailscale service, GUI window, browser login or OS
route to `100.64.0.0/10` is required.

## Enrollment files

Client state is separate from the gateway state:

```text
%APPDATA%\SerpiumVPN\SerpiumNet\Client\
```

For a first registration, place the one-time Headscale key here:

```text
%APPDATA%\SerpiumVPN\SerpiumNet\headscale-client-auth.key
```

The key file is deleted after the bridge reaches the ready state. Later starts
reuse the persistent client state.

The Headscale URL is read from:

```text
%APPDATA%\SerpiumVPN\SerpiumNet\client-control-url.txt
```

For the current same-PC test, the fallback remains:

```text
http://127.0.0.1:8080
```

For another device, this file must contain a Headscale URL reachable from that
device. A coordinator bound only to `127.0.0.1` cannot register remote clients.

## Safety

- Interactive Tailscale/browser login is blocked in the Go binary.
- A fresh client without state and without a Headscale key fails with a clear
  error instead of opening a browser.
- The one-time key is passed through `ProcessStartInfo.ArgumentList` and is not
  written to Serpium logs.
- The local bridge uses an OS-selected loopback port.
- Relay gateway probing transparently checks the local bridge because tsnet
  userspace mode intentionally creates no Windows route to the tailnet range.
- Disconnect stops both Xray and the SerpiumNet bridge and removes PID metadata.

## Current scope

MVP6.2 proves the fully headless client on the same machine or against an already
reachable Headscale endpoint. Automatic remote Headscale URL publication and
pre-auth-key issuance inside the relay key belong to the next coordinator/key
provisioning stage.
