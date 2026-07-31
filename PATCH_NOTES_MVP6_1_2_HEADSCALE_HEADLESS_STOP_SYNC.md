# MVP6.1.2 — Headscale Headless + Stop Synchronization

## Why this patch exists

MVP6.1.1 accidentally restored the public Tailscale browser-login flow. That
contradicted the Serpium design: Headscale should enroll a fresh node with a
one-time key and all later starts should reuse the persistent node state.

The previous Stop command did terminate `SerpiumNet.exe`, but the UI could keep
showing `SerpiumNet: connecting` because the Start and Stop handlers completed in
a race.

## Changes

- SerpiumNet Engine version: `0.4.3`.
- Default coordinator: `http://127.0.0.1:8080`.
- Supports coordinator override through:
  - `SERPIUM_CONTROL_URL`, or
  - `%APPDATA%\SerpiumVPN\SerpiumNet\headscale-control-url.txt`.
- Reuses `%APPDATA%\SerpiumVPN\SerpiumNet\tailscaled.state` after enrollment.
- For a fresh node, reads a one-time key from:
  - `SERPIUM_AUTH_KEY`, or
  - `%APPDATA%\SerpiumVPN\SerpiumNet\headscale-auth.key`.
- Deletes `headscale-auth.key` after successful enrollment/readiness.
- Never logs the auth key.
- Rejects `CONTROL_MODE=tailscale-default`.
- Treats any `login.tailscale.com` URL as an error; no browser or auth window is opened.
- Stop kills the complete process tree, waits for exit, and logs
  `ProcessVerifiedExited=true`.
- `SerpiumNetManager.StopAsync()` waits for the concurrent startup task to unwind,
  reducing the stale `connecting` status race.

## First registration

If `tailscaled.state` does not exist, create the key file before starting Relay:

```powershell
$dir="$env:APPDATA\SerpiumVPN\SerpiumNet"; New-Item -ItemType Directory -Path $dir -Force | Out-Null; Set-Content -LiteralPath "$dir\headscale-auth.key" -Value "PASTE_ONE_TIME_HEADSCALE_KEY_HERE" -NoNewline
```

The key file should disappear automatically after `GATEWAY_READY`.

## Existing registration

If `tailscaled.state` already contains the registered Headscale node, no new key
is needed. The state is preserved when Stop is pressed.

## Expected log

```text
Gateway process started. ... ControlURL=http://127.0.0.1:8080; Enrollment=persistent-state.
stdout: CONTROL_URL=http://127.0.0.1:8080
stdout: AUTH_KEY=not-provided
stdout: TAILSCALE_IP=...
stdout: GATEWAY_READY=...
Gateway ready. ...
Gateway stopped. ProcessVerifiedExited=true
```

On a fresh enrollment, `Enrollment=one-time-key` and then:

```text
One-time Headscale auth-key file deleted after successful enrollment.
```

## Deliberately unchanged

- Relay key format.
- Xray gateway/client logic.
- Persistent Headscale registration state.
- MainWindow layout.
