# HTTPS (TLS 1.2 server) - AJOS

Implemented 2026-09-04. The kernel now serves the same web stack over TLS on
port 443 alongside plain HTTP on port 80.

## What was added

- **TLS 1.2 server** (`src/tls.c`, server block at end of file):
  cipher suite `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (0xC02F) with x25519.
  Reuses the browser client's primitives (X25519, AES-128-GCM, SHA-256 PRF,
  transcript hash, GHASH) but keeps a separate session state so an HTTPS
  connection and a browser (client) session never clobber each other.
- **Certificate** (`include/tls_cert.h`): self-signed X.509v3, CN=AJOS,
  serial 0x414A4F53, validity 2026-01-01..2036-01-01, basicConstraints
  CA:TRUE (critical), SAN DNS:ajos.local + DNS:localhost,
  sha256WithRSAEncryption. Generated on the host from the exact RSA-2048
  host key embedded in `src/crypto.c` (get_default_rsa_key), so SSH and
  HTTPS share one identity. Regenerate with the same method: extract
  n_init/d_init from crypto.c, build DER, sign with d, verify with e=65537.
- **Runtime signing** (`src/crypto.c: tls_rsa_sign_sha256`): PKCS#1 v1.5
  SHA-256 signature with the embedded host key (Montgomery modexp path).
  Signs the ServerKeyExchange every handshake - this is what proves the
  server holds the private key; the cert just carries the public half.
- **HTTP integration** (`src/http.c`, `src/tcp.c`): second listener PCB on
  443 (`HTTPS_PORT`); RX on 443 drives the handshake state machine
  (`tls_server_input`); once established, decrypted requests dispatch to
  `http_handle_connection` and every response byte goes through the TLS
  record layer (`tls_server_write`) instead of raw TCP.
- **Keepalive** (`run_aj.sh`): host forward 9443 -> guest 443 added to
  `start` and `serve`.

## Behavior / semantics

- Handshake is a synchronous state machine driven from the TCP RX path
  (same context the port-80 HTTP parser already runs in). No sleeping.
- Stale-state recovery: a plaintext ClientHello arriving in any state
  (mid-handshake or after a finished session) resets the session and
  restarts the handshake on that connection. Without this, the first
  completed HTTPS session poisoned all later ones.
- Server flight (SH+Cert+SKE+SHD) goes out as ONE plaintext record; the
  server ChangeCipherSpec is sent before the encrypted Finished (required:
  the client switches its receive epoch on CCS, not on its own CCS).
- Uses the same transcript rules as the client: hash up to (not including)
  own Finished; client Finished enters the transcript before server
  Finished is computed.

## Verified (host, via QEMU slirp)

- `curl -sk https://127.0.0.1:9443/` -> 200 buildwithAJ page (3809 B).
- 4+ sequential HTTPS connections all 200 (state reset works).
- /app/buildwithaj, /app/store, POST /auth (302 -> /success) over TLS.
- `openssl s_client`: TLSv1.2, cert chain parses, SKE signature accepted
  by LibreSSL (bad sigs abort the handshake - so the RSA sign path works).
- Plain HTTP (80) and SSH (22) unaffected.

## Limitations

- TLS 1.2 only; single cipher suite; no session resumption/tickets.
- One TLS server session state (last connection wins on overlap).
- Cert is self-signed; clients need `-k` / trust-store import. The browser
  client already runs in `-k` mode.
- Server logs ([TLS-SRV] ...) may not reach the serial console during the
  FAT mkdir debug spam; functionality is unaffected.
