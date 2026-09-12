#!/usr/bin/env python3
"""Minimal HTTP test server for the AJOS x86-64 test64 harness.

python3 -m http.server is avoided on purpose: HTTPServer.server_bind()
calls socket.getfqdn(host) which can block for a long time on reverse
DNS for 0.0.0.0 / LAN addresses, hanging the test fixture."""
import socket, sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8130
body = b'<html><body>AJOS64-HTTP-TEST-PAGE</body></html>\n'
resp = (b'HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n'
        b'Content-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body)

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', port))
s.listen(5)
print('listening on', port, flush=True)
while True:
    c, a = s.accept()
    try:
        c.recv(4096)
        c.sendall(resp)
    finally:
        c.close()
