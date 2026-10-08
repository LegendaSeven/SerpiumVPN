# HTTPS subscription import

The simple home screen accepts a direct key, a Base64/Base64URL envelope (up to
two layers), a newline-separated subscription or an HTTPS subscription URL.
The URL is loaded when the user presses Connect. Every node is structurally
validated before import; malformed or unsupported nodes are not silently skipped.
VLESS, VMess, Trojan, AVO and Hysteria2 (`hysteria2://` / `hy2://`) are recognized.

All nodes are saved individually to the existing DPAPI CurrentUser vault. Exact
duplicates update an existing profile. The first node in subscription order is
selected for the normal connection check. Other imported nodes remain available
in Saved profiles, including when the selected server fails its connection check.
Successful download/import alone never means Connected.

The URL and response are kept in memory. Only the existing fingerprint is stored
for each source key, not the original key or URL. A saved profile uses its imported
settings; subscriptions are not refreshed in the background. Paste the URL again
to fetch current nodes. Changed keys can create new entries, and old entries can
be removed using the existing delete action. Stop cancels downloading/importing;
profiles saved just before cancellation remain available.

Downloads use validated HTTPS, no system proxy, cookies, referrer or authorization
headers, a twenty-second deadline, at most three redirects and a 128 KiB limit on
the decompressed response. Redirects to HTTP or embedded user credentials are
rejected. HTML, empty responses and invalid UTF-8 are rejected. HTTP, expiration,
size and timeout failures produce fixed messages without the URL/token. At most
100 distinct nodes are accepted; the existing vault capacity still applies.

VLESS XHTTP `extra` is parsed as a bounded JSON object, survives vault serialization
and is passed to Xray without dropping nested values. Hysteria2 is converted to a
native sing-box outbound and then uses the existing application routing compiler.
Its single-port URI supports authentication, SNI, explicit insecure flag and
salamander obfuscation. Unknown URI parameters (including unsupported pinning/ECH)
are rejected instead of ignored. Multi-port/realm forms are not supported here.

The bundled Xray is updated from 1.8.9 to official release 26.3.27 because 1.8.9
rejects the new XHTTP configuration. Asset provenance and SHA-256 are recorded in
`bin_files/relay/xray.version.json`. The download archive is checked against the
digest published by the official GitHub release before its binary is used.

Verification covers HTTP errors, redirects, cancellation, response limits,
malformed/mixed subscriptions, duplicate nodes, TLS/obfuscation, XHTTP JSON and
encrypted-vault round trips. Configurations from the user's seven-node subscription
are checked through stdin by the installed engines without saving plaintext
configuration files. The test does not start TUN, change system routes or establish
a live VPN session; the application's normal connection probe remains required.

Format references:
- [Hysteria2 URI](https://v2.hysteria.network/docs/developers/URI-Scheme/)
- [sing-box Hysteria2 outbound](https://sing-box.sagernet.org/configuration/outbound/hysteria2/)
- [Xray XHTTP](https://xtls.github.io/config/transports/splithttp.html)
- [Official Xray 26.3.27 release](https://github.com/XTLS/Xray-core/releases/tag/v26.3.27)
