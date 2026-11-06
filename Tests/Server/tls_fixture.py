"""Loopback-only TLS 1.3/X25519 endpoint for REALITY integration checks."""
import socketserver
import ssl
import sys

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.set_alpn_protocols(["h2"])
context.set_ecdh_curve("X25519")
context.load_cert_chain(sys.argv[2], sys.argv[3])


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(10)
            with context.wrap_socket(self.request, server_side=True) as secured:
                secured.recv(4096)
        except (OSError, ssl.SSLError):
            pass


class Server(socketserver.ThreadingTCPServer):
    daemon_threads = True


with Server(("127.0.0.1", int(sys.argv[1])), Handler) as server:
    server.serve_forever()
