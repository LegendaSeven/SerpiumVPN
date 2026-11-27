# Serpium Outline prefix adapter

Build on Windows x64 with Go 1.25+ using `./build.ps1`. Go modules are pinned in
`go.mod`/`go.sum`; the release ships `bin_files/relay/Serpium.Outline.exe` and the
dependency licenses. This adapter is updated with Serpium itself.

The executable reads one bounded JSON line from stdin, binds an ephemeral TCP/UDP
port on 127.0.0.1, and writes one JSON readiness message containing the port. The
parent keeps stdin open; EOF shuts down listeners and all connections. Secrets are
never command-line arguments, log output, or configuration files.

Local Shadowsocks uses a fresh random credential. After authenticating a local
connection, the adapter forwards decrypted Shadowsocks frames to the fixed remote
server using the official Outline SDK. TCP uses its prefix salt generator; UDP
uses random salts without a prefix. The local and remote credentials differ.

The URI prefix is decoded by Serpium using Outline's UTF-8-to-Latin-1 convention.
At most 16 prefix bytes are accepted, retaining at least 16 random salt bytes. AES
128 therefore has no prefix mode; AES-192 allows up to 8 bytes, and AES-256/ChaCha20
allow up to 16. Unsupported formats are rejected instead of stripping parameters.

`go test ./...` checks the TCP bytes/random salt tail, UDP relay, configuration
bounds and shutdown. `Tests/Outline` additionally verifies interoperability with
the bundled sing-box, encrypted profile storage, selection and the import UI.

References:
- https://developer.getoutline.org/vpn/advanced/prefixing/
- https://github.com/OutlineFoundation/outline-sdk/tree/v0.1.0
