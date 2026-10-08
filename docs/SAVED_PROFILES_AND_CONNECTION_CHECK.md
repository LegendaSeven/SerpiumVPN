# Saved profiles and connection feedback

The simple home screen lists existing encrypted vault profiles above the key
field. Selection uses stable vault IDs and safe labels, never the saved key.
The selected ID is remembered across launches. Missing/deleted IDs do not fall
back silently to a different saved profile.

Selecting a profile clears a competing typed key. Typing a new key switches the
selector to “Новый профиль”. Selection alone does not connect. A structurally
valid new key is saved in the existing DPAPI vault and selected before connection
testing; if network testing fails, it remains available for retry or deletion.
Importing the same key keeps the vault's existing duplicate detection.

Deletion has an inline confirmation tied to the selected ID. Cancellation or a
selection change cancels that confirmation. The connected profile is protected:
disconnect before selecting another profile or deleting it. Deletion removes the
profile through the existing vault API, clears its selection, and leaves other
profiles untouched.

## Connection state

The button shows “Проверка ключа…” and then “Проверка соединения…”. The existing
engine startup checks the selected VPN outbound using the authenticated loopback
controller. The UI shows “Соединение активно” only after that check succeeds and
the requested saved profile is actually running. A started process or a reachable
local API is insufficient. No additional direct internet fallback was added.

The original connection exception now reaches the simple home screen after
cleanup, rather than being replaced by a generic “connection not confirmed”.
Known failures have fixed, user-safe messages: malformed/unsupported keys, rejected
authentication, DNS, refused connections, unavailable networks, secure handshake,
timeout, local checking service, missing engine, and administrator requirements.
Probe error response bodies are bounded and used only for classification; raw
server text, addresses and credentials are not displayed. The local controller's
401 is a checking-service failure, not evidence of a rejected VPN key.

A timeout cannot prove that a key expired. When the controller does not report
the underlying cause, the UI states that VPN internet access was not confirmed
and that the precise reason is unavailable. The error stays below the button,
with retry enabled; at small window sizes it scrolls into view. Both themes use
the same states and controls.

## Stopping a connection attempt

During key import and connection testing the main button remains available as
“Стоп”. The progress description stays above it. Stop cancels the attempt's own
token, changes the button to “Остановка…”, and blocks another start until the
owning operation has unwound and completed cleanup. Active connections still
use “Отключить”; profile deletion and live routing changes do not expose Stop.

The token reaches profile import, vault reads, configuration checks and both
engine startup paths. Cancellation cannot report
a late successful connection. Cleanup runs independently of the canceled token.
Saved profiles remain available; cancellation is not recorded as an invalid key.
Key decoding and DPAPI/ACL work run off the UI thread to keep Stop responsive.

Version and configuration-check subprocesses are terminated and awaited on
cancellation, including cancellation while writing configuration to stdin.
24 focused checks cover pending network-request cancellation, blocked version,
configuration and stdin processes, absence of leftover test children, a successful
retry, and Stop/Stopping/Disconnect states in both themes. No real VPN credentials
or system routes were used in these checks.

## Profile verification

53 automated checks cover profile selection, key precedence, deletion confirmation,
selection persistence, progress/success/failure states, safe error propagation,
malformed responses and both rendered themes. An isolated installed sing-box
process with a deliberately unavailable loopback proxy confirms that starting the
engine cannot pass the connection test. Tests use no real user keys, no TUN, and
do not modify system routing. Real VPN-server connectivity requires a valid key
and was not exercised by this harness.
