#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// SHA-512
void sha512(const uint8_t *data, size_t len, uint8_t *digest);

// SSH Exchange Hash
int ssh_compute_exchange_hash(
    const uint8_t *v_c, size_t v_c_len, const uint8_t *v_s, size_t v_s_len,
    const uint8_t *i_c, size_t i_c_len, const uint8_t *i_s, size_t i_s_len,
    const uint8_t *k_s, size_t k_s_len, uint32_t min, uint32_t preferred,
    uint32_t max, const uint8_t *p, size_t p_len, const uint8_t *g,
    size_t g_len, const uint8_t *e, size_t e_len, const uint8_t *f,
    size_t f_len, const uint8_t *k, size_t k_len, uint8_t *hash_out);

// SSH Signature Encoding
int ssh_encode_signature(const uint8_t *signature, size_t sig_len,
                         const char *algorithm, uint8_t *output, size_t *output_len);

// RSA Signing (for SSH host key)
// Computes exchange hash, signs it, and encodes for SSH
int ssh_sign_exchange_hash(const uint8_t *v_c, size_t v_c_len,
                           const uint8_t *v_s, size_t v_s_len,
                           const uint8_t *i_c, size_t i_c_len,
                           const uint8_t *i_s, size_t i_s_len,
                           const uint8_t *k_s, size_t k_s_len, uint32_t min,
                           uint32_t n, uint32_t max, const uint8_t *p,
                           size_t p_len, const uint8_t *g, size_t g_len,
                           const uint8_t *e, size_t e_len, const uint8_t *f,
                           size_t f_len, const uint8_t *k, size_t k_len,
                           const char *signature_algorithm,
                           uint8_t *signature_out, size_t *signature_out_len);

// Modular Exponentiation (for DH)
// result = base^exp % mod
// Modular Exponentiation (for DH)
// result = base^exp % mod
// Inputs must be RSA_KEY_SIZE (256 bytes) big-endian
void bigint_mod_exp(const uint8_t *base, const uint8_t *exp, const uint8_t *mod,
                    uint8_t *result);

// Montgomery modular exponentiation with caller-provided R^2 mod mod (R=2^2048).
// Inputs/outputs are 256-byte big-endian.
void mont_modexp_be256_custom_r2(const uint8_t *base_be, const uint8_t *exp_be,
                                 const uint8_t *mod_be, const uint8_t *r2_be,
                                 uint8_t *out_be);

// Get RSA public key blob in SSH wire format
int ssh_get_rsa_public_key_blob(uint8_t *output, size_t output_len);

// SSH transport key derivation (RFC 4253). recv_mac_key/send_mac_key may be NULL (32 bytes each).
void ssh_derive_transport_keys(const uint8_t *exchange_hash,
                                const uint8_t *k_mpint, uint16_t k_mpint_len,
                                uint8_t *recv_iv, uint8_t *recv_key,
                                uint8_t *send_iv, uint8_t *send_key,
                                uint8_t *recv_mac_key, uint8_t *send_mac_key);
// Same but K is value-only (no 4-byte length prefix). For compatibility with some clients.
void ssh_derive_transport_keys_k_value_only(const uint8_t *exchange_hash,
                                             const uint8_t *k_value, uint16_t k_value_len,
                                             uint8_t *recv_iv, uint8_t *recv_key,
                                             uint8_t *send_iv, uint8_t *send_key,
                                             uint8_t *recv_mac_key, uint8_t *send_mac_key);

// KDF known-answer test (run at SSH init to verify RFC 4253 KDF).
void ssh_kdf_selftest(void);
// DH known-answer test: 6^15 mod 23 = 8 (verifies bigint_mod_exp for SSH K).
void ssh_dh_selftest(void);
// AES-128 one-block NIST vector (verifies AES used for SSH transport).
void ssh_aes128_selftest(void);
// HMAC-SHA256 RFC 4231 test vector (verifies MAC used after NEWKEYS).
void ssh_hmac_sha256_selftest(void);

// HMAC-SHA256 for SSH MAC: key 32 bytes, output 32 bytes.
void ssh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg,
                     size_t msg_len, uint8_t *out);
// HMAC-SHA256 over two contiguous regions: HMAC(key, msg1||msg2).
void ssh_hmac_sha256_two(const uint8_t *key, size_t key_len,
                         const uint8_t *msg1, size_t msg1_len,
                         const uint8_t *msg2, size_t msg2_len, uint8_t *out);

// AES-128-CTR: crypt len bytes in-place. key and ctr are 16 bytes; ctr is updated.
void aes128_ctr_crypt(uint8_t *key, uint8_t *ctr, uint8_t *data, int len);
// One block of keystream for debug: out = AES_Encrypt(key, ctr). ctr unchanged.
void aes128_ctr_keystream_block(const uint8_t *key, const uint8_t *ctr, uint8_t *out);

#endif // CRYPTO_H

/* TLS crypto primitives (src/tls.c) */
void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32],
                       const uint8_t point[32]);
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);
void aes128gcm_encrypt(const uint8_t *key, const uint8_t iv[12],
                       const uint8_t *aad, uint32_t aad_len, uint8_t *data,
                       uint32_t len, uint8_t tag[16]);
int tls_selftest(void);

/* TLS 1.2 client (src/tls.c) */
struct tcp_pcb;
int tls_handshake(struct tcp_pcb *pcb, const char *host);
int tls_established(void);
int tls_write(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len);
int tls_read(struct tcp_pcb *pcb, uint8_t *out, uint32_t *len);

/* Max decrypted application-data bytes tls_read() will accumulate for a
 * caller (src/tls.c enforces this internally; callers like src/browser.c
 * size their own receive buffer to match). Shared here so the two never
 * drift apart — they used to be independent hardcoded 8192s in each file,
 * which silently capped every page at 8KB regardless of how big a buffer
 * browser.c thought it had. Some real pages (WordPress themes that inline
 * all their CSS into <head>) run 100-200KB before any visible text, so
 * this needs real headroom, not just "big enough for a paragraph". */
#define TLS_APP_DATA_CAP 393216

/* TLS 1.2 server (src/tls.c) - HTTPS listener on port 443. */
struct tcp_pcb;
void tls_server_reset(void);
void tls_server_input(struct tcp_pcb *pcb);
int tls_server_write(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len);

/* PKCS#1 v1.5 SHA-256 signature with the host RSA key (src/crypto.c).
 * Signs the embedded SSH host key's private exponent over a 32-byte
 * digest; sig_out receives the 256-byte big-endian signature.
 * Returns 256 on success, 0 on failure. Used by the TLS server for the
 * ServerKeyExchange signature (ECDHE_RSA key exchange). */
int tls_rsa_sign_sha256(const uint8_t *hash, uint8_t *sig_out);
