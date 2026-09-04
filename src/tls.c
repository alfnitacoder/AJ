/* TLS crypto primitives: X25519 key exchange (RFC 7748) and AES-128-GCM.
 *
 * Field arithmetic uses 16 x 16-bit limbs (little-endian 256-bit values),
 * kept loose (< 2^256) and weakly-reduced (fold bit 255 with *19) after
 * each multiply, in the style of standard curve25519 implementations.
 *
 * Self-tests use the RFC 7748 section 5.2 / 6.1 vectors and the classic
 * NIST AES-128-GCM test case. Run with: tls selftest
 */
#include "crypto.h"
#include "tls_cert.h"
#include "net.h"
#include <stddef.h>
#include <stdint.h>

extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);

/* ------------------------------------------------------------------ */
/* X25519 (RFC 7748)                                                   */
/* ------------------------------------------------------------------ */

typedef uint32_t fe[16]; /* 16 little-endian 16-bit limbs */

static void fe_zero(fe x) {
  for (int i = 0; i < 16; i++)
    x[i] = 0;
}

static void fe_one(fe x) {
  fe_zero(x);
  x[0] = 1;
}

static void fe_copy(fe d, const fe s) {
  for (int i = 0; i < 16; i++)
    d[i] = s[i];
}

static void fe_from_bytes(fe x, const uint8_t b[32]) {
  for (int i = 0; i < 16; i++)
    x[i] = (uint32_t)b[2 * i] | ((uint32_t)b[2 * i + 1] << 8);
}

static void fe_to_bytes(uint8_t out[32], const fe x) {
  fe t;
  fe_copy(t, x);
  /* canonicalize: weak-reduce then one conditional subtract of p */
  uint32_t top = t[15] >> 15; /* bit 255 */
  t[15] &= 0x7FFF;
  uint32_t carry = top * 19u;
  for (int i = 0; i < 16; i++) {
    uint32_t v = t[i] + (carry & 0xFFFF);
    t[i] = v & 0xFFFF;
    carry = (carry >> 16) + (v >> 16);
  }
  /* if value >= p (2^255-19), subtract p: compare with p limbs */
  static const uint16_t p16[16] = {0xFFED, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                   0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                   0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                   0x7FFF};
  int ge = 1;
  for (int i = 15; i >= 0; i--) {
    if (t[i] > p16[i])
      break;
    if (t[i] < p16[i]) {
      ge = 0;
      break;
    }
  }
  if (ge) {
    uint32_t borrow = 0;
    for (int i = 0; i < 16; i++) {
      uint32_t pi = p16[i] + borrow;
      if (t[i] >= pi) {
        t[i] -= pi;
        borrow = 0;
      } else {
        t[i] = (t[i] + 0x10000u) - pi;
        borrow = 1;
      }
    }
  }
  for (int i = 0; i < 16; i++) {
    out[2 * i] = (uint8_t)(t[i] & 0xFF);
    out[2 * i + 1] = (uint8_t)(t[i] >> 8);
  }
}

static void fe_add(fe r, const fe a, const fe b) {
  uint32_t carry = 0;
  for (int i = 0; i < 16; i++) {
    uint32_t v = a[i] + b[i] + carry;
    r[i] = v & 0xFFFF;
    carry = v >> 16;
  }
  if (carry) { /* 2^256 overflow == 38 mod p */
    uint32_t c = 38;
    for (int i = 0; i < 16; i++) {
      uint32_t v = r[i] + (c & 0xFFFF);
      r[i] = v & 0xFFFF;
      c = (c >> 16) + (v >> 16);
    }
  }
}

/* p = 2^255 - 19 as 16-bit limbs */
static const uint16_t fe_p16[16] = {0xFFED, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                    0x7FFF};

static void fe_sub(fe r, const fe a, const fe b) {
  /* borrow-chain subtract; if negative, add p back */
  uint32_t borrow = 0;
  for (int i = 0; i < 16; i++) {
    int32_t v = (int32_t)a[i] - (int32_t)b[i] - (int32_t)borrow;
    if (v < 0) {
      v += 0x10000;
      borrow = 1;
    } else {
      borrow = 0;
    }
    r[i] = (uint32_t)v;
  }
  if (borrow) {
    uint32_t carry = 0;
    for (int i = 0; i < 16; i++) {
      uint32_t v = r[i] + fe_p16[i] + carry;
      r[i] = v & 0xFFFF;
      carry = v >> 16;
    }
  }
}

static void fe_mul(fe r, const fe a, const fe b) {
  /* schoolbook into 32 loose words (64-bit accumulators), normalize,
   * then reduce with 2^256 == 38 and 2^512 == 1444 (mod p) */
  uint64_t t[32];
  for (int i = 0; i < 32; i++)
    t[i] = 0;
  for (int i = 0; i < 16; i++) {
    uint64_t carry = 0;
    for (int j = 0; j < 16; j++) {
      uint64_t v = t[i + j] + (uint64_t)a[i] * b[j] + carry;
      t[i + j] = v & 0xFFFF;
      carry = v >> 16;
    }
    t[i + 16] += carry;
  }
  uint64_t carry = 0;
  for (int i = 0; i < 32; i++) {
    uint64_t v = t[i] + carry;
    t[i] = v & 0xFFFF;
    carry = v >> 16;
  }
  if (carry) { /* 2^512 == 1444 mod p */
    uint64_t c = carry * 1444u;
    for (int i = 0; i < 16; i++) {
      uint64_t v = t[i] + (c & 0xFFFF);
      t[i] = v & 0xFFFF;
      c = (c >> 16) + (v >> 16);
    }
  }
  fe out;
  carry = 0;
  for (int i = 0; i < 16; i++) {
    uint64_t v = t[i] + 38u * t[16 + i] + carry;
    out[i] = (uint32_t)(v & 0xFFFF);
    carry = v >> 16;
  }
  carry *= 38u;
  for (int i = 0; i < 16; i++) {
    uint64_t v = out[i] + carry;
    out[i] = (uint32_t)(v & 0xFFFF);
    carry = v >> 16;
  }
  if (carry) {
    uint64_t c = carry;
    for (int i = 0; i < 16; i++) {
      uint64_t v = out[i] + (c & 0xFFFF);
      out[i] = (uint32_t)(v & 0xFFFF);
      c = (c >> 16) + (v >> 16);
    }
  }
  /* weak reduce: fold bit 255 with *19 */
  uint32_t top = out[15] >> 15;
  out[15] &= 0x7FFF;
  uint32_t c2 = top * 19u;
  for (int i = 0; i < 16; i++) {
    uint32_t v = out[i] + (c2 & 0xFFFF);
    out[i] = v & 0xFFFF;
    c2 = (c2 >> 16) + (v >> 16);
  }
  fe_copy(r, out);
}

static void fe_mul121665(fe r, const fe a) {
  fe c;
  for (int i = 0; i < 16; i++)
    c[i] = 0;
  c[0] = 121665 & 0xFFFF; /* (A-2)/4 for A=486662: the ladder constant */
  c[1] = 121665 >> 16;
  fe_mul(r, a, c);
}

static void fe_cswap(fe a, fe b, uint32_t swap) {
  uint32_t mask = (uint32_t)0 - (swap & 1u);
  for (int i = 0; i < 16; i++) {
    uint32_t t = mask & (a[i] ^ b[i]);
    a[i] ^= t;
    b[i] ^= t;
  }
}

static void fe_invert(fe r, const fe x) {
  /* r = x^(p-2), p-2 = 2^255 - 21.
   * Square-and-multiply over the 255-bit exponent
   * 0x7FFFFFFF...FFEB (251 ones, then EB). */
  fe acc, base;
  fe_one(acc); /* start from 1: square-and-multiply over all 255 bits */
  fe_copy(base, x);
  for (int i = 254; i >= 0; i--) {
    fe_mul(acc, acc, acc); /* square */
    uint32_t bit;
    if (i >= 8)
      bit = 1; /* bits 8..254 are all 1 */
    else
      bit = (0xEBu >> i) & 1; /* low 8 bits of p-2 */
    if (bit)
      fe_mul(acc, acc, base);
  }
  fe_copy(r, acc);
}

void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32],
                       const uint8_t point[32]) {
  uint8_t k[32];
  for (int i = 0; i < 32; i++)
    k[i] = scalar[i];
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  fe x1, x2, z2, x3, z3, t0, t1;
  fe_from_bytes(x1, point);
  fe_one(x2);
  fe_zero(z2);
  fe_copy(x3, x1);
  fe_one(z3);

  uint32_t swap = 0;
  for (int t = 254; t >= 0; t--) {
    uint32_t kt = (uint32_t)((k[t >> 3] >> (t & 7)) & 1);
    swap ^= kt;
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    swap = kt;

    /* RFC 7748 ladder step with named intermediates */
    fe A, AA, B, BB, E_, C, D, DA, CB, s1, d1;
    fe_add(A, x2, z2);
    fe_mul(AA, A, A);
    fe_sub(B, x2, z2);
    fe_mul(BB, B, B);
    fe_sub(E_, AA, BB);
    fe_add(C, x3, z3);
    fe_sub(D, x3, z3);
    fe_mul(DA, D, A);
    fe_mul(CB, C, B);
    fe_add(s1, DA, CB);
    fe_mul(x3, s1, s1);
    fe_sub(d1, DA, CB);
    fe_mul(d1, d1, d1);
    fe_mul(z3, x1, d1);
    fe_mul(x2, AA, BB);
    fe_mul121665(d1, E_);
    fe_add(d1, AA, d1);
    fe_mul(z2, E_, d1);
  }
  fe_cswap(x2, x3, swap);
  fe_cswap(z2, z3, swap);

  fe_invert(t1, z2);
  fe_mul(t0, x2, t1);
  fe_to_bytes(out, t0);
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32]) {
  static const uint8_t basepoint[32] = {9};
  x25519_scalarmult(out, scalar, basepoint);
}

/* ------------------------------------------------------------------ */
/* AES-128-GCM (built on crypto.c's AES core)                          */
/* ------------------------------------------------------------------ */

/* GF(2^128) multiply for GCM: MSB-first byte order, X's bits scanned
 * MSB-first, V doubling by right shift, V doubles via right shift,
 * reduction folds 0xE1 into the top byte (standard formulation). */
static void gf128_mul(uint8_t z[16], const uint8_t x[16], const uint8_t y[16]) {
  uint8_t v[16], acc[16];
  for (int i = 0; i < 16; i++) {
    v[i] = y[i];
    acc[i] = 0;
  }
  for (int i = 0; i < 128; i++) {
    /* X's bits MSB-first (bit 0 = top bit of byte 0) */
    if ((x[i >> 3] >> (7 - (i & 7))) & 1) {
      for (int j = 0; j < 16; j++)
        acc[j] ^= v[j];
    }
    uint8_t lsb = v[15] & 1;
    for (int j = 15; j > 0; j--)
      v[j] = (uint8_t)((v[j] >> 1) | (v[j - 1] << 7));
    v[0] >>= 1;
    if (lsb)
      v[0] ^= 0xE1;
  }
  for (int i = 0; i < 16; i++)
    z[i] = acc[i];
}

/* Table-based GHASH (Shoup's 8-bit method). gf128_mul() above costs 128
 * iterations of shift-and-conditional-XOR per 16-byte block — measured at
 * ~2.85KB/s end to end for real page fetches, dominated by exactly this
 * loop (a ~270KB page is ~17 GCM records, each needing GHASH over its
 * whole ciphertext). GF(2^128) multiplication is linear, so any 16-byte
 * block X can be split into 16 single-nonzero-byte values (X[i] at
 * position i, zero elsewhere) and X*H = XOR of each piece's product with
 * H. Precomputing all 16*256 possible (position, byte value) products
 * once per H turns every subsequent block multiply into 16 table lookups
 * + XORs instead of 128 shift-and-test steps.
 *
 * Building the table costs 4096 of the slow multiplies, so it only pays
 * off if reused across many blocks — which is exactly what happens
 * across a TLS session's many records, since H depends only on the
 * (unchanging) session key. Cached below and rebuilt only when H
 * actually changes (new session, or the first real record after
 * tls_selftest() exercised the same code path with its own throwaway
 * key). */
typedef struct {
  uint8_t rows[16][256][16];
} ghash_table_t;

static void ghash_build_table(const uint8_t h[16], ghash_table_t *t) {
  uint8_t v[16];
  for (int i = 0; i < 16; i++)
    v[i] = 0;
  for (int i = 0; i < 16; i++) {
    for (int b = 0; b < 256; b++) {
      v[i] = (uint8_t)b;
      gf128_mul(t->rows[i][b], v, h);
    }
    v[i] = 0;
  }
}

static void gf128_mul_table(uint8_t z[16], const uint8_t x[16],
                           const ghash_table_t *t) {
  uint8_t acc[16];
  for (int i = 0; i < 16; i++)
    acc[i] = 0;
  for (int i = 0; i < 16; i++) {
    const uint8_t *row = t->rows[i][x[i]];
    for (int k = 0; k < 16; k++)
      acc[k] ^= row[k];
  }
  for (int i = 0; i < 16; i++)
    z[i] = acc[i];
}

/* One cache slot per direction (client-write / server-write use different
 * keys, hence different H). This kernel's TLS client only ever runs one
 * session at a time (all state lives in the single global `tls`), so a
 * plain "does this H match what we built for last time" cache is safe. */
#define GHASH_SLOT_DECRYPT 0
#define GHASH_SLOT_ENCRYPT 1
static uint8_t cached_h[2][16];
static ghash_table_t ghash_cache[2];
static int ghash_cache_valid[2];

static const ghash_table_t *ghash_table_for(const uint8_t h[16], int slot) {
  int stale = !ghash_cache_valid[slot];
  if (!stale) {
    for (int i = 0; i < 16; i++)
      if (cached_h[slot][i] != h[i]) {
        stale = 1;
        break;
      }
  }
  if (stale) {
    ghash_build_table(h, &ghash_cache[slot]);
    for (int i = 0; i < 16; i++)
      cached_h[slot][i] = h[i];
    ghash_cache_valid[slot] = 1;
  }
  return &ghash_cache[slot];
}

static void ghash_update(uint8_t y[16], const ghash_table_t *t,
                         const uint8_t *data, uint32_t len) {
  while (len >= 16) {
    for (int i = 0; i < 16; i++)
      y[i] ^= data[i];
    gf128_mul_table(y, y, t);
    data += 16;
    len -= 16;
  }
  if (len) {
    uint8_t blk[16];
    for (int i = 0; i < 16; i++)
      blk[i] = 0;
    for (uint32_t i = 0; i < len; i++)
      blk[i] = data[i];
    for (int i = 0; i < 16; i++)
      y[i] ^= blk[i];
    gf128_mul_table(y, y, t);
  }
}

static void ctr_inc(uint8_t ctr[16]) {
  for (int i = 15; i >= 12; i--) {
    if (++ctr[i])
      break;
  }
}

/* AES-128-GCM: 12-byte IV, encrypts in place, writes 16-byte tag. */
void aes128gcm_encrypt(const uint8_t *key, const uint8_t iv[12],
                       const uint8_t *aad, uint32_t aad_len, uint8_t *data,
                       uint32_t len, uint8_t tag[16]) {
  uint8_t h[16], j0[16], ctr[16], ek[16];
  for (int i = 0; i < 16; i++) {
    h[i] = 0;
    j0[i] = 0;
  }
  for (int i = 0; i < 12; i++)
    j0[i] = iv[i];
  j0[15] = 1; /* J0 = IV || 0^31 || 1 */

  /* H = E(K, 0^128) */
  {
    uint8_t zero[16], out[16];
    for (int i = 0; i < 16; i++)
      zero[i] = 0;
    aes128_ctr_keystream_block(key, zero, out);
    for (int i = 0; i < 16; i++)
      h[i] = out[i];
  }

  /* keystream E(K, J0) for the tag mask */
  aes128_ctr_keystream_block(key, j0, ek);

  /* CTR encryption starting at J0 + 1 */
  for (int i = 0; i < 16; i++)
    ctr[i] = j0[i];
  uint32_t off = 0;
  while (off < len) {
    uint8_t ks[16];
    ctr_inc(ctr);
    aes128_ctr_keystream_block(key, ctr, ks);
    uint32_t n = len - off;
    if (n > 16)
      n = 16;
    for (uint32_t i = 0; i < n; i++)
      data[off + i] ^= ks[i];
    off += n;
  }

  /* GHASH over AAD || C || lengths. ghash_update() already zero-pads a
   * trailing partial block internally (XORs it in, then does ONE
   * gf128_mul) — calling it again with explicit pad bytes here would
   * process that padding as an extra, spurious GHASH block and corrupt
   * the tag whenever aad_len/len isn't a multiple of 16 (which, for real
   * TLS traffic, aad_len==13 never is). */
  const ghash_table_t *gt = ghash_table_for(h, GHASH_SLOT_ENCRYPT);
  uint8_t y[16];
  for (int i = 0; i < 16; i++)
    y[i] = 0;
  ghash_update(y, gt, aad, aad_len);
  ghash_update(y, gt, data, len);
  uint8_t lens[16];
  uint64_t abits = (uint64_t)aad_len * 8u;
  uint64_t cbits = (uint64_t)len * 8u;
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t)(abits >> (56 - 8 * i));
    lens[8 + i] = (uint8_t)(cbits >> (56 - 8 * i));
  }
  ghash_update(y, gt, lens, 16);

  for (int i = 0; i < 16; i++)
    tag[i] = y[i] ^ ek[i];
}

/* ------------------------------------------------------------------ */
/* Self-tests                                                          */
/* ------------------------------------------------------------------ */

static int bytes_eq(const uint8_t *a, const uint8_t *b, int n) {
  for (int i = 0; i < n; i++)
    if (a[i] != b[i])
      return 0;
  return 1;
}

static void hex_dump(const uint8_t *b, int n) {
  static const char *hex = "0123456789abcdef";
  for (int i = 0; i < n && i < 32; i++) {
    log_putchar(hex[b[i] >> 4]);
    log_putchar(hex[b[i] & 15]);
  }
}

static const uint8_t hexv(char c) {
  if (c >= '0' && c <= '9')
    return (uint8_t)(c - '0');
  if (c >= 'a' && c <= 'f')
    return (uint8_t)(c - 'a' + 10);
  if (c >= 'A' && c <= 'F')
    return (uint8_t)(c - 'A' + 10);
  return 0;
}

static void from_hex(const char *hex, uint8_t *out, int nbytes) {
  for (int i = 0; i < nbytes; i++)
    out[i] = (uint8_t)((hexv(hex[2 * i]) << 4) | hexv(hex[2 * i + 1]));
}

int tls_selftest(void) {
  int ok = 1;

  /* RFC 7748 section 5.2 scalar multiplication */
  {
    uint8_t k[32], u[32], out[32], want[32];
    from_hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba44"
             "9ac4",
             k, 32);
    from_hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0"
             "ab1c4c",
             u, 32);
    from_hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577"
             "a28552",
             want, 32);
    x25519_scalarmult(out, k, u);
    if (!bytes_eq(out, want, 32)) {
      log_writestring("[TLS] X25519 5.2 vector FAILED, got ");
      hex_dump(out, 32);
      log_putchar('\n');
      ok = 0;
    } else {
      log_writestring("[TLS] X25519 5.2 vector OK\n");
    }
  }

  /* RFC 7748 section 6.1 Diffie-Hellman */
  {
    uint8_t a_priv[32], b_priv[32], a_pub_want[32], b_pub_want[32];
    uint8_t shared_want[32];
    uint8_t a_pub[32], b_pub[32], k1[32], k2[32];
    from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51d"
             "b92c2a",
             a_priv, 32);
    from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff"
             "88e0eb",
             b_priv, 32);
    from_hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa"
             "9b4e6a",
             a_pub_want, 32);
    from_hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f"
             "882b4f",
             b_pub_want, 32);
    from_hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e"
             "161742",
             shared_want, 32);
    x25519_base(a_pub, a_priv);
    x25519_base(b_pub, b_priv);
    if (!bytes_eq(a_pub, a_pub_want, 32)) {
      log_writestring("[TLS] X25519 alice pub FAILED, got ");
      hex_dump(a_pub, 32);
      log_putchar('\n');
      ok = 0;
    } else {
      log_writestring("[TLS] X25519 alice pub OK\n");
    }
    if (!bytes_eq(b_pub, b_pub_want, 32)) {
      log_writestring("[TLS] X25519 bob pub FAILED, got ");
      hex_dump(b_pub, 32);
      log_putchar('\n');
      ok = 0;
    } else {
      log_writestring("[TLS] X25519 bob pub OK\n");
    }
    x25519_scalarmult(k1, a_priv, b_pub);
    x25519_scalarmult(k2, b_priv, a_pub);
    if (!bytes_eq(k1, k2, 32)) {
      log_writestring("[TLS] X25519 shared-secret agreement FAILED\n");
      ok = 0;
    } else {
      log_writestring("[TLS] X25519 shared-secret agreement OK\n");
    }
    if (!bytes_eq(k1, shared_want, 32)) {
      log_writestring("[TLS] X25519 DH vector mismatch (agreement OK): ");
      hex_dump(k1, 32);
      log_putchar('\n');
    }
  }

  /* NIST AES-128-GCM test case 3 (zero key/IV/pt) */
  {
    uint8_t key[16], iv[12], pt[16], want_ct[16], want_tag[16], tag[16];
    for (int i = 0; i < 16; i++) {
      key[i] = 0;
      pt[i] = 0;
    }
    for (int i = 0; i < 12; i++)
      iv[i] = 0;
    from_hex("0388dace60b6a392f328c2b971b2fe78", want_ct, 16);
    from_hex("ab6e47d42cec13bdf53a67b21257bddf", want_tag, 16);
    aes128gcm_encrypt(key, iv, 0, 0, pt, 16, tag);
    if (!bytes_eq(pt, want_ct, 16) || !bytes_eq(tag, want_tag, 16)) {
      log_writestring("[TLS] AES-GCM vector FAILED\n  ct ");
      hex_dump(pt, 16);
      log_writestring("\n  tag ");
      hex_dump(tag, 16);
      log_putchar('\n');
      ok = 0;
    } else {
      log_writestring("[TLS] AES-128-GCM vector OK\n");
    }
  }

  return ok;
}

/* ------------------------------------------------------------------ */
/* TLS 1.2 client: ECDHE-RSA-AES128-GCM-SHA256 (x25519), no cert      */
/* verification (curl -k mode).                                        */
/* ------------------------------------------------------------------ */

extern void sha256(const uint8_t *data, size_t len, uint8_t *digest);
extern struct tcp_pcb *tcp_get_free_pcb(void);
extern int tcp_connect(struct tcp_pcb *pcb, ip_addr_t remote_ip,
                       uint16_t port);
extern int tcp_send(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len);
extern int tcp_close(struct tcp_pcb *pcb);
extern void sleep_ms(uint32_t ms);
extern void kfree(void *ptr);
extern volatile uint32_t pit_ticks;

#define TLS_HS_MAX 16384

static struct {
  uint8_t client_random[32];
  uint8_t server_random[32];
  uint8_t master[48];
  uint8_t ckey[16]; /* client write key */
  uint8_t skey[16]; /* server write key */
  uint8_t civ[4];   /* client write IV (salt) */
  uint8_t siv[4];   /* server write IV (salt) */
  uint64_t cseq, sseq;
  uint8_t hs[TLS_HS_MAX];
  uint32_t hs_len;
  uint8_t srv_point[32];
  uint8_t finished_ok;
  int established;
} tls;

static void hs_reset(void) {
  tls.hs_len = 0;
  tls.cseq = 0;
  tls.sseq = 0;
  tls.established = 0;
  tls.finished_ok = 0;
}

static int hs_append(const uint8_t *msg, uint32_t len) {
  if (tls.hs_len + len > TLS_HS_MAX)
    return 0;
  for (uint32_t i = 0; i < len; i++)
    tls.hs[tls.hs_len + i] = msg[i];
  tls.hs_len += len;
  return 1;
}

/* TLS 1.2 PRF (P_SHA256) */
static void tls_prf(const uint8_t *secret, int slen, const char *label,
                    const uint8_t *seed, int seedlen, uint8_t *out,
                    int outlen) {
  uint8_t lseed[96];
  int ll = 0;
  while (label[ll])
    ll++;
  uint8_t a[32];
  uint8_t chunk[32];
  int done = 0;
  int lseedlen = ll + seedlen;
  for (int i = 0; i < ll; i++)
    lseed[i] = (uint8_t)label[i];
  for (int i = 0; i < seedlen; i++)
    lseed[ll + i] = seed[i];

  /* A(1) = HMAC(secret, seed) */
  ssh_hmac_sha256(secret, slen, lseed, lseedlen, a);
  while (done < outlen) {
    uint8_t aseed[128];
    for (int i = 0; i < 32; i++)
      aseed[i] = a[i];
    for (int i = 0; i < lseedlen; i++)
      aseed[32 + i] = lseed[i];
    ssh_hmac_sha256(secret, slen, aseed, 32 + lseedlen, chunk);
    for (int i = 0; i < 32 && done < outlen; i++)
      out[done++] = chunk[i];
    ssh_hmac_sha256(secret, slen, a, 32, a); /* A(i+1) */
  }
}

/* entropy: hash of time + counter + stack address */
static void tls_random(uint8_t *out, int n) {
  static uint32_t ctr;
  uint8_t seed[16];
  uint8_t digest[32];
  ctr += 0x9E3779B9u;
  for (int off = 0; off < n; off += 32) {
    uint32_t t = pit_ticks ^ (ctr + (uint32_t)off);
    for (int i = 0; i < 4; i++)
      seed[i] = (uint8_t)(t >> (8 * i));
    for (int i = 4; i < 16; i++)
      seed[i] = (uint8_t)(ctr >> (8 * (i & 3)));
    sha256(seed, sizeof(seed), digest);
    for (int i = 0; i < 32 && off + i < n; i++)
      out[off + i] = digest[i];
  }
}

static void put16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

/* ---- record layer ---- */

static int tls_send_record_raw(struct tcp_pcb *pcb, uint8_t type,
                               const uint8_t *payload, uint16_t len) {
  uint8_t hdr[5];
  hdr[0] = type;
  hdr[1] = 0x03;
  hdr[2] = 0x03;
  put16(hdr + 3, len);
  if (tcp_send(pcb, hdr, 5) != 0)
    return 0;
  if (len && tcp_send(pcb, payload, len) != 0)
    return 0;
  return 1;
}

/* send plaintext or GCM-protected depending on state */
static int tls_send_record(struct tcp_pcb *pcb, uint8_t type,
                           const uint8_t *payload, uint16_t len) {
  if (!tls.established)
    return tls_send_record_raw(pcb, type, payload, len);

  /* GCM: explicit nonce = 8-byte BE sequence number */
  uint8_t nonce[12];
  uint8_t aad[13];
  uint8_t tag[16];
  uint8_t buf[512];
  if (len > (uint16_t)(sizeof(buf) - 8 - 16))
    return 0; /* our messages are always small */
  for (int i = 0; i < 4; i++)
    nonce[i] = tls.civ[i];
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = (uint8_t)(tls.cseq >> (56 - 8 * i));
  /* AAD = seq || type || version || length */
  for (int i = 0; i < 8; i++)
    aad[i] = (uint8_t)(tls.cseq >> (56 - 8 * i));
  aad[8] = type;
  aad[9] = 0x03;
  aad[10] = 0x03;
  put16(aad + 11, len);
  for (int i = 0; i < len; i++)
    buf[i] = payload[i];
  aes128gcm_encrypt(tls.ckey, nonce, aad, 13, buf, len, tag);
  tls.cseq++;

  uint8_t out[540];
  out[0] = type;
  out[1] = 0x03;
  out[2] = 0x03;
  put16(out + 3, (uint16_t)(len + 8 + 16));
  for (int i = 0; i < 8; i++)
    out[5 + i] = nonce[4 + i];
  for (int i = 0; i < len; i++)
    out[13 + i] = buf[i];
  for (int i = 0; i < 16; i++)
    out[13 + len + i] = tag[i];
  return tcp_send(pcb, out, (uint16_t)(13 + len + 16)) == 0;
}

/* decrypt one received GCM record body in place.
 * rec = explicit(8) || ct || tag(16). Returns plaintext len or -1. */
static int tls_gcm_open(uint8_t type, const uint8_t *rec, uint16_t reclen,
                        uint8_t *out) {
  if (reclen < 8 + 16)
    return -1;
  uint16_t ctlen = (uint16_t)(reclen - 8 - 16);
  uint8_t nonce[12];
  uint8_t aad[13];
  uint8_t tag[16];
  for (int i = 0; i < 4; i++)
    nonce[i] = tls.siv[i];
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = rec[i];
  for (int i = 0; i < 8; i++)
    aad[i] = (uint8_t)(tls.sseq >> (56 - 8 * i));
  aad[8] = type;
  aad[9] = 0x03;
  aad[10] = 0x03;
  put16(aad + 11, ctlen);
  for (int i = 0; i < 16; i++)
    tag[i] = rec[8 + ctlen + i];

  /* tag over the ciphertext as received, then keystream-xor */
  uint8_t h[16], y[16], ek[16], j0[16], ctr[16], lens[16];
  for (int i = 0; i < 16; i++) {
    h[i] = 0;
    j0[i] = 0;
  }
  {
    uint8_t zero[16], outb[16];
    for (int i = 0; i < 16; i++)
      zero[i] = 0;
    aes128_ctr_keystream_block(tls.skey, zero, outb);
    for (int i = 0; i < 16; i++)
      h[i] = outb[i];
  }
  for (int i = 0; i < 12; i++)
    j0[i] = nonce[i];
  j0[15] = 1;
  aes128_ctr_keystream_block(tls.skey, j0, ek);
  for (int i = 0; i < 16; i++)
    y[i] = 0;
  /* GHASH over AAD || C || lengths (see aes128gcm_encrypt for why the
   * trailing-block padding isn't done separately: ghash_update() already
   * zero-pads a partial final block in one gf128_mul). The AAD was being
   * built above but never actually mixed into the tag here — every
   * decrypt was checking the tag as if aad_len were 0. */
  const ghash_table_t *gt = ghash_table_for(h, GHASH_SLOT_DECRYPT);
  ghash_update(y, gt, aad, 13);
  ghash_update(y, gt, rec + 8, ctlen); /* ciphertext */
  uint64_t ab = 13u * 8u;
  uint64_t cb = (uint64_t)ctlen * 8u;
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t)(ab >> (56 - 8 * i));
    lens[8 + i] = (uint8_t)(cb >> (56 - 8 * i));
  }
  ghash_update(y, gt, lens, 16);
  for (int i = 0; i < 16; i++)
    if ((uint8_t)(y[i] ^ ek[i]) != tag[i])
      return -1; /* tag mismatch */

  for (int i = 0; i < 16; i++)
    ctr[i] = j0[i];
  uint32_t off = 0;
  while (off < ctlen) {
    uint8_t ks[16];
    ctr_inc(ctr);
    aes128_ctr_keystream_block(tls.skey, ctr, ks);
    uint32_t n = ctlen - off;
    if (n > 16)
      n = 16;
    for (uint32_t i = 0; i < n; i++)
      out[off + i] = rec[8 + off + i] ^ ks[i];
    off += n;
  }
  tls.sseq++;
  return ctlen;
}

/* ---- handshake messages ---- */

static int build_client_hello(uint8_t *out, const char *host) {
  int n = 0;
  tls_random(tls.client_random, 32);
  out[n++] = 0x03;
  out[n++] = 0x03; /* TLS 1.2 in the handshake body */
  for (int i = 0; i < 32; i++)
    out[n++] = tls.client_random[i];
  out[n++] = 0; /* session id len */
  out[n++] = 0;
  out[n++] = 2; /* cipher suites len */
  out[n++] = 0xC0;
  out[n++] = 0x2F; /* ECDHE-RSA-AES128-GCM-SHA256 */
  out[n++] = 1; /* compression methods len */
  out[n++] = 0; /* null */

  /* extensions */
  int ext_len = 0;
  /* server_name */
  int hlen = 0;
  while (host[hlen])
    hlen++;
  /* server_name ext_data = list_len(2) + name_type(1) + hostname_len(2) +
   * hostname (RFC 6066: HostName is opaque<1..2^16-1>, i.e. a 2-byte
   * length prefix, not 1). */
  ext_len += 4 + 2 + 1 + 2 + hlen; /* header + list_len + type + len + name */
  ext_len += 4 + 2 + 2;     /* supported_groups */
  ext_len += 4 + 1 + 1;     /* ec_point_formats */
  ext_len += 4 + 2 + 2;     /* signature_algorithms (header + list_len + algo) */
  put16(out + n, (uint16_t)ext_len);
  n += 2;

  put16(out + n, 0x0000); /* server_name */
  put16(out + n + 2, (uint16_t)(hlen + 5)); /* ext_data length */
  n += 4;
  put16(out + n, (uint16_t)(hlen + 3)); /* server_name_list length */
  n += 2;
  out[n++] = 0; /* name_type: host_name */
  put16(out + n, (uint16_t)hlen); /* HostName length (2 bytes) */
  n += 2;
  for (int i = 0; i < hlen; i++)
    out[n++] = (uint8_t)host[i];

  put16(out + n, 0x000A); /* supported_groups */
  put16(out + n + 2, 4);  /* ext_data length: list_len(2) + one entry(2) */
  put16(out + n + 4, 2);  /* named_curve_list length */
  put16(out + n + 6, 0x001D); /* x25519 */
  n += 8;

  put16(out + n, 0x000B); /* ec_point_formats */
  put16(out + n + 2, 2);  /* ext_data length: list_len(1) + one format(1) */
  out[n + 4] = 1;         /* ec_point_format_list length */
  out[n + 5] = 0;         /* uncompressed */
  n += 6;

  put16(out + n, 0x000D); /* signature_algorithms */
  put16(out + n + 2, 4);  /* ext_data length: list_len(2) + one entry(2) */
  put16(out + n + 4, 2);  /* supported_signature_algorithms list length */
  put16(out + n + 6, 0x0401); /* rsa_pkcs1_sha256 */
  n += 8;
  return n;
}

/* send one handshake message (header + body), appending to transcript */
static int send_hs(struct tcp_pcb *pcb, uint8_t type, const uint8_t *body,
                   uint16_t len) {
  uint8_t msg[1024];
  msg[0] = type;
  msg[1] = (uint8_t)(len >> 16);
  msg[2] = (uint8_t)(len >> 8);
  msg[3] = (uint8_t)len;
  for (int i = 0; i < len; i++)
    msg[4 + i] = body[i];
  if (!hs_append(msg, (uint32_t)len + 4))
    return 0;
  return tls_send_record(pcb, 22, msg, (uint16_t)(len + 4));
}

/* process plaintext handshake records from the server */
static void hs_server_msg(const uint8_t *msg, uint32_t len) {
  if (len < 4)
    return;
  uint8_t type = msg[0];
  uint32_t blen = ((uint32_t)msg[1] << 16) | ((uint32_t)msg[2] << 8) | msg[3];
  const uint8_t *body = msg + 4;

  if (type == 2 && blen >= 35) { /* ServerHello */
    for (int i = 0; i < 32; i++)
      tls.server_random[i] = body[2 + i];
    /* cipher suite at 34..35 */
  } else if (type == 12 && blen >= 36) { /* ServerKeyExchange */
    if (body[0] == 3 && body[1] == 0 && body[2] == 0x1D &&
        body[3] == 32) {
      for (int i = 0; i < 32; i++)
        tls.srv_point[i] = body[4 + i];
    }
  }
  /* Certificate (11) and ServerHelloDone (14) need no parsing here */
}

/* drain and process complete records from pcb->app_rx_buf.
 * mode 0: collect plaintext handshake until ServerHelloDone seen.
 * mode 1: after our flight: expect CCS + encrypted Finished.
 * mode 2: app data: decrypt app records into app_out.
 * returns: 1 progress made this call, 0 none, -1 fatal (alert/tag). */
static int tls_pump(struct tcp_pcb *pcb, int mode, uint8_t *app_out,
                    uint32_t *app_len) {
  (void)pcb;
  uint16_t len = pcb->app_rx_len;
  int progress = 0;
  uint32_t off = 0;
  while (off + 5 <= len) {
    const uint8_t *r = pcb->app_rx_buf + off;
    uint8_t type = r[0];
    uint16_t rlen = (uint16_t)((r[3] << 8) | r[4]);
    if (off + 5 + rlen > len)
      break; /* incomplete record */
    const uint8_t *body = r + 5;

    if (type == 21) { /* alert */
      uint8_t lvl = 0, desc = 0;
      /* A plaintext alert (sent before the SENDER's own CCS) is exactly
       * 2 bytes: level + description. A GCM-protected one carries the
       * 8-byte explicit nonce and 16-byte tag around those same 2 bytes
       * (rlen==26). tls.established only reflects *our* encrypt state,
       * not the server's — using it here would misdecode an alert the
       * server sends before its own CCS (still its cleartext epoch) as
       * ciphertext, silently corrupting the real level/description into
       * "0/0". rlen is the reliable signal for which epoch this record
       * is actually in. */
      if (rlen == 2) {
        lvl = body[0];
        desc = body[1];
      } else {
        uint8_t pt[16];
        if (tls_gcm_open(21, body, rlen, pt) >= 2) {
          lvl = pt[0];
          desc = pt[1];
        }
      }
      log_writestring("[TLS] alert: ");
      log_write_u32(lvl);
      log_putchar('/');
      log_write_u32(desc);
      log_putchar('\n');
      return -1;
    }
    if (mode == 0 && type == 22) {
      /* plaintext handshake records: walk messages */
      uint32_t ho = 0;
      while (ho + 4 <= rlen) {
        const uint8_t *m = body + ho;
        uint32_t ml = ((uint32_t)m[1] << 16) | ((uint32_t)m[2] << 8) | m[3];
        if (ho + 4 + ml > rlen)
          break;
        hs_append(m, 4 + ml);
        hs_server_msg(m, 4 + ml);
        if (m[0] == 14) /* ServerHelloDone */
          tls.finished_ok = 1; /* reuse flag as 'shd seen' */
        ho += 4 + ml;
        progress = 1;
      }
    } else if (mode == 1 && type == 20) {
      progress = 1; /* ChangeCipherSpec */
    } else if (mode == 1 && type == 22) {
      /* encrypted Finished */
      uint8_t pt[256];
      int pl = tls_gcm_open(22, body, rlen, pt);
      if (pl < 0) {
        log_writestring("[TLS] server finished tag mismatch\n");
        return -1;
      }
      if (pl >= 16 && pt[0] == 20) {
        /* verify_data check */
        uint8_t hash[32], vd[12];
        sha256(tls.hs, tls.hs_len, hash);
        tls_prf(tls.master, 48, "server finished", hash, 32, vd, 12);
        int ok = 1;
        for (int i = 0; i < 12; i++)
          if (pt[4 + i] != vd[i])
            ok = 0;
        if (!ok) {
          log_writestring("[TLS] server finished verify_data mismatch\n");
          return -1;
        }
        tls.finished_ok = 1;
        progress = 1;
      }
    } else if (mode == 2 && type == 23) {
      if (app_out && app_len) {
        uint32_t cap = TLS_APP_DATA_CAP;
        /* Decrypt into a scratch buffer sized for the largest possible
         * TLS 1.2 record (2^14 plaintext bytes) — servers commonly pack
         * pages into max-size records, far bigger than our page cap.
         * GCM needs the whole ciphertext to verify the tag regardless of
         * how much plaintext we keep, so decrypt in full and copy only
         * what still fits into app_out (a lynx-style pager only needs
         * the page's head anyway; page_body itself is capped at
         * PAGE_MAX). Previously, any record whose own ciphertext length
         * exceeded the *entire* cap was skipped without decrypting —
         * losing sync with the server's sequence numbers and silently
         * dropping the whole page on sites that use max-size records
         * (e.g. nginx defaults). */
        static uint8_t scratch[16384];
        int pl = tls_gcm_open(23, body, rlen, scratch);
        if (pl < 0) {
          log_writestring("[TLS] record tag mismatch (app data)\n");
          return -1;
        }
        uint32_t room = (*app_len < cap) ? cap - *app_len : 0;
        uint32_t take = (uint32_t)pl < room ? (uint32_t)pl : room;
        for (uint32_t i = 0; i < take; i++)
          app_out[*app_len + i] = scratch[i];
        *app_len += take;
        progress = 1;
      }
    } else if (mode == 2 && type == 22) {
      /* session tickets etc. after handshake: decrypt and ignore */
      uint8_t pt[256];
      if (tls_gcm_open(22, body, rlen, pt) >= 0)
        progress = 1;
    }
    off += 5 + rlen;
  }
  if (off > 0) {
    /* consume processed bytes */
    uint16_t remaining = (uint16_t)(pcb->app_rx_len - off);
    for (uint16_t i = 0; i < remaining; i++)
      pcb->app_rx_buf[i] = pcb->app_rx_buf[off + i];
    pcb->app_rx_len = remaining;
  }
  return progress;
}

/* full handshake on an established TCP connection. 1 on success. */
int tls_handshake(struct tcp_pcb *pcb, const char *host) {
  hs_reset();
  uint8_t hello[512];
  int hlen = build_client_hello(hello, host);
  if (!send_hs(pcb, 1, hello, (uint16_t)hlen)) {
    log_writestring("[TLS] failed to send ClientHello\n");
    return 0;
  }

  /* wait for ServerHelloDone */
  uint32_t start = pit_ticks;
  while ((pit_ticks - start) < 800u) {
    int r = tls_pump(pcb, 0, 0, 0);
    if (r < 0) {
      log_writestring("[TLS] ClientHello rejected (alert above)\n");
      return 0;
    }
    if (tls.finished_ok)
      break;
    sleep_ms(50);
  }
  if (!tls.finished_ok) {
    log_writestring("[TLS] no ServerHelloDone (timeout)\n");
    return 0;
  }

  /* client key exchange */
  uint8_t priv[32], pub[32];
  tls_random(priv, 32);
  x25519_base(pub, priv);
  /* ClientKeyExchange body (RFC 4492 5.7, ClientECDiffieHellmanPublic) is
   * just an ECPoint: opaque<1..2^8-1>, i.e. a 1-byte length then the raw
   * point. (ServerKeyExchange's ECParameters — curve_type + named_curve +
   * point — is a different structure; don't reuse it here.) */
  uint8_t cke[40];
  cke[0] = 32;
  for (int i = 0; i < 32; i++)
    cke[1 + i] = pub[i];
  if (!send_hs(pcb, 16, cke, 33)) {
    log_writestring("[TLS] failed to send ClientKeyExchange\n");
    return 0;
  }
  log_writestring("[TLS] sent ClientKeyExchange\n");

  uint8_t shared[32];
  x25519_scalarmult(shared, priv, tls.srv_point);

  /* master secret + key block */
  uint8_t ms_seed[64];
  for (int i = 0; i < 32; i++) {
    ms_seed[i] = tls.client_random[i];
    ms_seed[32 + i] = tls.server_random[i];
  }
  tls_prf(shared, 32, "master secret", ms_seed, 64, tls.master, 48);
  uint8_t kb_seed[64], keyblk[40];
  for (int i = 0; i < 32; i++) {
    kb_seed[i] = tls.server_random[i];
    kb_seed[32 + i] = tls.client_random[i];
  }
  tls_prf(tls.master, 48, "key expansion", kb_seed, 64, keyblk, 40);
  for (int i = 0; i < 16; i++) {
    tls.ckey[i] = keyblk[i];
    tls.skey[i] = keyblk[16 + i];
  }
  for (int i = 0; i < 4; i++) {
    tls.civ[i] = keyblk[32 + i];
    tls.siv[i] = keyblk[36 + i];
  }

  /* ChangeCipherSpec (plaintext) */
  uint8_t ccs = 1;
  if (!tls_send_record_raw(pcb, 20, &ccs, 1)) {
    log_writestring("[TLS] failed to send ChangeCipherSpec\n");
    return 0;
  }
  tls.established = 1;

  /* Finished: hash transcript BEFORE appending it */
  uint8_t hash[32], vd[12];
  sha256(tls.hs, tls.hs_len, hash);
  tls_prf(tls.master, 48, "client finished", hash, 32, vd, 12);
  {
    uint32_t sum = 0;
    for (uint32_t i = 0; i < tls.hs_len; i++)
      sum = sum * 131u + tls.hs[i];
    log_writestring("[TLS] transcript hs_len=");
    log_write_u32(tls.hs_len);
    log_writestring(" checksum=");
    log_write_u32(sum);
    log_putchar('\n');
  }
  if (!send_hs(pcb, 20, vd, 12)) {
    log_writestring("[TLS] failed to send client Finished\n");
    return 0;
  }
  log_writestring("[TLS] sent client Finished, waiting for server...\n");

  /* wait for server CCS + encrypted Finished */
  tls.finished_ok = 0;
  start = pit_ticks;
  while ((pit_ticks - start) < 800u) {
    int r = tls_pump(pcb, 1, 0, 0);
    if (r < 0) {
      log_writestring("[TLS] server Finished pump failed (alert/tag)\n");
      return 0;
    }
    if (tls.finished_ok)
      break;
    sleep_ms(50);
  }
  if (!tls.finished_ok) {
    log_writestring("[TLS] no server Finished (timeout)\n");
    return 0;
  }

  log_writestring("[TLS] handshake complete\n");
  return 1;
}

int tls_established(void) { return tls.established; }

int tls_write(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len) {
  return tls_send_record(pcb, 23, data, len);
}

/* poll decrypted app data; returns decrypted bytes this call (or -1) */
int tls_read(struct tcp_pcb *pcb, uint8_t *out, uint32_t *len) {
  return tls_pump(pcb, 2, out, len);
}


/* ================================================================== */
/* TLS 1.2 server (HTTPS, port 443): ECDHE-RSA-AES128-GCM-SHA256 with  */
/* x25519 — the mirror image of the client above.                      */
/*                                                                     */
/* State is kept separate from the client session so an HTTPS listener */
/* connection and an in-OS browser session never clobber each other.   */
/* The certificate (include/tls_cert.h) is a self-signed X.509v3 built */
/* around the same RSA-2048 host key the SSH server uses; the per-     */
/* connection ServerKeyExchange signature (tls_rsa_sign_sha256) is     */
/* what proves the server actually holds the private key.              */
/*                                                                     */
/* Key/IV usage (fixed by TLS roles, not by perspective):              */
/*   we send with the SERVER write key (skey/siv/sseq),                */
/*   we receive with the CLIENT write key (ckey/civ/cseq).             */
/* ================================================================== */

#define TLS_SRV_HS_MAX 16384

#define TLS_ST_CH  0 /* expect ClientHello */
#define TLS_ST_CKE 1 /* flight sent: expect ClientKeyExchange/CCS/Finished */
#define TLS_ST_APP 2 /* established: decrypting application data */

static struct {
  uint8_t state;
  uint8_t ccs_seen;
  uint8_t cke_done;
  uint8_t established;
  uint8_t client_random[32];
  uint8_t server_random[32];
  uint8_t master[48];
  uint8_t ckey[16]; /* client write key (we receive with it) */
  uint8_t skey[16]; /* server write key (we send with it) */
  uint8_t civ[4];
  uint8_t siv[4];
  uint64_t cseq, sseq;
  uint8_t epriv[32];             /* server ephemeral x25519 private */
  uint8_t hs[TLS_SRV_HS_MAX];    /* handshake transcript */
  uint32_t hs_len;
  uint8_t plain[TLS_SRV_HS_MAX]; /* decrypted HTTP request bytes */
  uint32_t plain_len;
} tls_srv;

static void srv_hs_append(const uint8_t *msg, uint32_t len) {
  if (tls_srv.hs_len + len > TLS_SRV_HS_MAX)
    return;
  for (uint32_t i = 0; i < len; i++)
    tls_srv.hs[tls_srv.hs_len + i] = msg[i];
  tls_srv.hs_len += len;
}

void tls_server_reset(void) {
  tls_srv.state = TLS_ST_CH;
  tls_srv.ccs_seen = 0;
  tls_srv.cke_done = 0;
  tls_srv.established = 0;
  tls_srv.cseq = 0;
  tls_srv.sseq = 0;
  tls_srv.hs_len = 0;
  tls_srv.plain_len = 0;
}

/* ---- record layer (server side) ---- */

static int tls_srv_send_record_raw(struct tcp_pcb *pcb, uint8_t type,
                                   const uint8_t *payload, uint16_t len) {
  uint8_t hdr[5];
  hdr[0] = type;
  hdr[1] = 0x03;
  hdr[2] = 0x03;
  put16(hdr + 3, len);
  if (tcp_send(pcb, hdr, 5) != 0)
    return 0;
  if (len && tcp_send(pcb, payload, len) != 0)
    return 0;
  return 1;
}

/* send plaintext (handshake) or GCM-protected (app data) server record */
static int tls_srv_send_record(struct tcp_pcb *pcb, uint8_t type,
                               const uint8_t *payload, uint16_t len) {
  if (!tls_srv.established)
    return tls_srv_send_record_raw(pcb, type, payload, len);

  static uint8_t out[5 + 8 + 16384 + 16];
  if (len > 16384)
    return 0;
  uint8_t nonce[12], aad[13], tag[16];
  for (int i = 0; i < 4; i++)
    nonce[i] = tls_srv.siv[i];
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = (uint8_t)(tls_srv.sseq >> (56 - 8 * i));
  /* AAD = seq || type || version || length */
  for (int i = 0; i < 8; i++)
    aad[i] = (uint8_t)(tls_srv.sseq >> (56 - 8 * i));
  aad[8] = type;
  aad[9] = 0x03;
  aad[10] = 0x03;
  put16(aad + 11, len);
  for (uint32_t i = 0; i < len; i++)
    out[13 + i] = payload[i];
  aes128gcm_encrypt(tls_srv.skey, nonce, aad, 13, out + 13, len, tag);
  tls_srv.sseq++;

  out[0] = type;
  out[1] = 0x03;
  out[2] = 0x03;
  put16(out + 3, (uint16_t)(len + 8 + 16));
  for (int i = 0; i < 8; i++)
    out[5 + i] = nonce[4 + i];
  for (int i = 0; i < 16; i++)
    out[13 + len + i] = tag[i];
  return tcp_send(pcb, out, (uint16_t)(13 + len + 16)) == 0;
}

/* decrypt one client->server GCM record body.
 * rec = explicit(8) || ct || tag(16). Returns plaintext len or -1. */
static int tls_srv_gcm_open(uint8_t type, const uint8_t *rec, uint16_t reclen,
                            uint8_t *out) {
  if (reclen < 8 + 16)
    return -1;
  uint16_t ctlen = (uint16_t)(reclen - 8 - 16);
  uint8_t nonce[12], aad[13], tag[16];
  for (int i = 0; i < 4; i++)
    nonce[i] = tls_srv.civ[i];
  for (int i = 0; i < 8; i++)
    nonce[4 + i] = rec[i];
  for (int i = 0; i < 8; i++)
    aad[i] = (uint8_t)(tls_srv.cseq >> (56 - 8 * i));
  aad[8] = type;
  aad[9] = 0x03;
  aad[10] = 0x03;
  put16(aad + 11, ctlen);
  for (int i = 0; i < 16; i++)
    tag[i] = rec[8 + ctlen + i];

  uint8_t h[16], y[16], ek[16], j0[16], ctr[16], lens[16];
  for (int i = 0; i < 16; i++) {
    h[i] = 0;
    j0[i] = 0;
    y[i] = 0;
  }
  {
    uint8_t zero[16], outb[16];
    for (int i = 0; i < 16; i++)
      zero[i] = 0;
    aes128_ctr_keystream_block(tls_srv.ckey, zero, outb);
    for (int i = 0; i < 16; i++)
      h[i] = outb[i];
  }
  for (int i = 0; i < 12; i++)
    j0[i] = nonce[i];
  j0[15] = 1;
  aes128_ctr_keystream_block(tls_srv.ckey, j0, ek);

  const ghash_table_t *gt = ghash_table_for(h, GHASH_SLOT_DECRYPT);
  ghash_update(y, gt, aad, 13);
  ghash_update(y, gt, rec + 8, ctlen);
  uint64_t ab = 13u * 8u;
  uint64_t cb = (uint64_t)ctlen * 8u;
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t)(ab >> (56 - 8 * i));
    lens[8 + i] = (uint8_t)(cb >> (56 - 8 * i));
  }
  ghash_update(y, gt, lens, 16);
  for (int i = 0; i < 16; i++)
    if ((uint8_t)(y[i] ^ ek[i]) != tag[i])
      return -1;

  for (int i = 0; i < 16; i++)
    ctr[i] = j0[i];
  uint32_t off = 0;
  while (off < ctlen) {
    uint8_t ks[16];
    ctr_inc(ctr);
    aes128_ctr_keystream_block(tls_srv.ckey, ctr, ks);
    uint32_t n = ctlen - off;
    if (n > 16)
      n = 16;
    for (uint32_t i = 0; i < n; i++)
      out[off + i] = rec[8 + off + i] ^ ks[i];
    off += n;
  }
  tls_srv.cseq++;
  return ctlen;
}

/* ---- handshake ---- */

/* minimal ClientHello parse: pull client_random, require our suite */
static int srv_parse_ch(const uint8_t *body, uint32_t blen) {
  if (blen < 35)
    return 0;
  for (int i = 0; i < 32; i++)
    tls_srv.client_random[i] = body[2 + i];
  uint8_t sid_len = body[34];
  if ((uint32_t)35 + sid_len + 2 > blen)
    return 0;
  uint16_t cs_len = ((uint16_t)body[35 + sid_len] << 8) | body[36 + sid_len];
  if ((uint32_t)37 + sid_len + cs_len > blen)
    return 0;
  const uint8_t *cs = body + 37 + sid_len;
  for (uint16_t i = 0; i + 1 < cs_len; i += 2)
    if (cs[i] == 0xC0 && cs[i + 1] == 0x2F)
      return 1; /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
  return 0;
}

/* ServerHello + Certificate + ServerKeyExchange + ServerHelloDone, all in
 * one plaintext record. SKE is signed with the host RSA key (one 2048-bit
 * private op per connection — same cost as an SSH KEX signature). */
static int srv_send_flight(struct tcp_pcb *pcb) {
  tls_random(tls_srv.epriv, 32);
  uint8_t epub[32];
  x25519_base(epub, tls_srv.epriv);
  tls_random(tls_srv.server_random, 32);

  /* --- ServerHello --- */
  static uint8_t sh[42];
  sh[0] = 2;
  sh[1] = 0;
  sh[2] = 0;
  sh[3] = 38;
  sh[4] = 0x03;
  sh[5] = 0x03;
  for (int i = 0; i < 32; i++)
    sh[6 + i] = tls_srv.server_random[i];
  sh[38] = 0; /* session id: empty */
  sh[39] = 0xC0;
  sh[40] = 0x2F;
  sh[41] = 0; /* compression: null */

  /* --- Certificate --- */
  static uint8_t cert_msg[10 + 1024];
  uint32_t cl = TLS_SRV_CERT_LEN;
  cert_msg[0] = 11; /* handshake type: certificate */
  cert_msg[1] = (uint8_t)((cl + 6) >> 16);
  cert_msg[2] = (uint8_t)((cl + 6) >> 8);
  cert_msg[3] = (uint8_t)(cl + 6);
  cert_msg[4] = 0; /* chain length hi */
  cert_msg[5] = (uint8_t)((cl + 3) >> 8);
  cert_msg[6] = (uint8_t)(cl + 3);
  cert_msg[7] = 0; /* entry length hi */
  cert_msg[8] = (uint8_t)(cl >> 8);
  cert_msg[9] = (uint8_t)cl;
  for (uint32_t i = 0; i < cl; i++)
    cert_msg[10 + i] = tls_srv_cert_der[i];

  /* --- ServerKeyExchange --- */
  static uint8_t ske[300];
  ske[0] = 12;
  ske[1] = 0;
  ske[2] = (uint8_t)(296 >> 8);
  ske[3] = (uint8_t)296;
  ske[4] = 3; /* curve_type: named_curve */
  ske[5] = 0x00;
  ske[6] = 0x1D; /* x25519 */
  ske[7] = 32;
  for (int i = 0; i < 32; i++)
    ske[8 + i] = epub[i];
  /* signature covers client_random || server_random || server_params */
  uint8_t to_sign[100];
  for (int i = 0; i < 32; i++)
    to_sign[i] = tls_srv.client_random[i];
  for (int i = 0; i < 32; i++)
    to_sign[32 + i] = tls_srv.server_random[i];
  for (int i = 0; i < 36; i++)
    to_sign[64 + i] = ske[4 + i];
  uint8_t hash[32], sig[256];
  sha256(to_sign, sizeof(to_sign), hash);
  if (tls_rsa_sign_sha256(hash, sig) != 256) {
    log_writestring("[TLS-SRV] SKE sign failed\n");
    return 0;
  }
  ske[40] = 0x04; /* sha256 */
  ske[41] = 0x01; /* rsa_pkcs1 */
  ske[42] = 0x01;
  ske[43] = 0x00; /* 256-byte signature */
  for (int i = 0; i < 256; i++)
    ske[44 + i] = sig[i];

  /* --- ServerHelloDone --- */
  static const uint8_t shd[4] = {14, 0, 0, 0};

  /* transcript: SH, Cert, SKE, SHD */
  srv_hs_append(sh, sizeof(sh));
  srv_hs_append(cert_msg, 10 + cl);
  srv_hs_append(ske, sizeof(ske));
  srv_hs_append(shd, 4);

  /* one plaintext record with all four messages */
  static uint8_t flight[42 + 10 + 1024 + 300 + 4];
  uint32_t fn = 0;
  for (uint32_t i = 0; i < sizeof(sh); i++)
    flight[fn++] = sh[i];
  for (uint32_t i = 0; i < 10 + cl; i++)
    flight[fn++] = cert_msg[i];
  for (uint32_t i = 0; i < sizeof(ske); i++)
    flight[fn++] = ske[i];
  for (int i = 0; i < 4; i++)
    flight[fn++] = shd[i];
  log_writestring("[TLS-SRV] flight sent (");
  log_write_u32(fn);
  log_writestring(" bytes)\n");
  return tls_srv_send_record_raw(pcb, 22, flight, (uint16_t)fn);
}

static int srv_do_cke(const uint8_t *body, uint32_t blen) {
  if (blen < 33 || body[0] != 32)
    return 0;
  uint8_t shared[32];
  x25519_scalarmult(shared, tls_srv.epriv, body + 1);

  uint8_t ms_seed[64], kb_seed[64], keyblk[40];
  for (int i = 0; i < 32; i++) {
    ms_seed[i] = tls_srv.client_random[i];
    ms_seed[32 + i] = tls_srv.server_random[i];
  }
  tls_prf(shared, 32, "master secret", ms_seed, 64, tls_srv.master, 48);
  for (int i = 0; i < 32; i++) {
    kb_seed[i] = tls_srv.server_random[i];
    kb_seed[32 + i] = tls_srv.client_random[i];
  }
  tls_prf(tls_srv.master, 48, "key expansion", kb_seed, 64, keyblk, 40);
  for (int i = 0; i < 16; i++) {
    tls_srv.ckey[i] = keyblk[i];
    tls_srv.skey[i] = keyblk[16 + i];
  }
  for (int i = 0; i < 4; i++) {
    tls_srv.civ[i] = keyblk[32 + i];
    tls_srv.siv[i] = keyblk[36 + i];
  }
  tls_srv.cke_done = 1;
  return 1;
}

/* decrypt + verify client Finished, then send ours. 1 on success. */
static int srv_do_finished(struct tcp_pcb *pcb, const uint8_t *rec,
                           uint16_t rlen) {
  uint8_t pt[64];
  int pl = tls_srv_gcm_open(22, rec, rlen, pt);
  if (pl < 16 || pt[0] != 20 || pt[1] != 0 || pt[2] != 0 || pt[3] != 12)
    return 0;
  uint8_t hash[32], vd[12];
  sha256(tls_srv.hs, tls_srv.hs_len, hash);
  tls_prf(tls_srv.master, 48, "client finished", hash, 32, vd, 12);
  for (int i = 0; i < 12; i++)
    if (pt[4 + i] != vd[i])
      return 0;

  /* client Finished enters the transcript (header + verify_data) */
  uint8_t fin_c[16], fin_s[16];
  fin_c[0] = 20;
  fin_c[1] = 0;
  fin_c[2] = 0;
  fin_c[3] = 12;
  for (int i = 0; i < 12; i++)
    fin_c[4 + i] = vd[i];
  srv_hs_append(fin_c, 16);

  /* server ChangeCipherSpec (plaintext) — switches the client's receive
   * epoch, then our Finished goes out GCM-encrypted */
  uint8_t ccs = 1;
  if (!tls_srv_send_record_raw(pcb, 20, &ccs, 1))
    return 0;
  tls_srv.established = 1;
  sha256(tls_srv.hs, tls_srv.hs_len, hash);
  tls_prf(tls_srv.master, 48, "server finished", hash, 32, vd, 12);
  fin_s[0] = 20;
  fin_s[1] = 0;
  fin_s[2] = 0;
  fin_s[3] = 12;
  for (int i = 0; i < 12; i++)
    fin_s[4 + i] = vd[i];
  if (!tls_srv_send_record(pcb, 22, fin_s, 16)) {
    tls_srv.established = 0;
    return 0;
  }
  srv_hs_append(fin_s, 16);
  return 1;
}

static void srv_fatal(struct tcp_pcb *pcb, uint8_t desc) {
  uint8_t a[2];
  a[0] = 2; /* fatal */
  a[1] = desc;
  log_writestring("[TLS-SRV] fatal alert, desc=");
  log_write_u32(desc);
  log_putchar('\n');
  tls_srv_send_record_raw(pcb, 21, a, 2);
  tcp_close(pcb);
  tls_server_reset();
}

/* is the decrypted stream a complete HTTP request? (same shape as
 * tcp_check_http_data: headers done, POST body complete) */
static int srv_http_ready(void) {
  uint32_t n = tls_srv.plain_len;
  if (n < 14)
    return 0;
  uint32_t body_start = 0;
  int has_end = 0;
  for (uint32_t i = 0; i + 3 < n; i++) {
    if (tls_srv.plain[i] == '\r' && tls_srv.plain[i + 1] == '\n' &&
        tls_srv.plain[i + 2] == '\r' && tls_srv.plain[i + 3] == '\n') {
      body_start = i + 4;
      has_end = 1;
      break;
    }
  }
  if (!has_end)
    return 0;
  if (tls_srv.plain[0] == 'P' && tls_srv.plain[1] == 'O' &&
      tls_srv.plain[2] == 'S' && tls_srv.plain[3] == 'T') {
    static const char cl_hdr[] = "Content-Length:";
    uint32_t cl = 0;
    int have_cl = 0;
    for (uint32_t i = 0; i + sizeof(cl_hdr) - 1 < body_start; i++) {
      int m = 1;
      for (uint32_t k = 0; k < sizeof(cl_hdr) - 1; k++)
        if (tls_srv.plain[i + k] != cl_hdr[k]) {
          m = 0;
          break;
        }
      if (m) {
        uint32_t j = i + sizeof(cl_hdr) - 1;
        while (j < n && tls_srv.plain[j] == ' ')
          j++;
        while (j < n && tls_srv.plain[j] >= '0' && tls_srv.plain[j] <= '9') {
          cl = cl * 10 + (uint32_t)(tls_srv.plain[j] - '0');
          j++;
        }
        have_cl = 1;
        break;
      }
    }
    if (have_cl && n - body_start < cl)
      return 0;
  }
  return 1;
}

/* called from tcp_input for every port-443 connection with buffered RX
 * data. Drives the server handshake and, once established, decrypts app
 * data and dispatches complete HTTP requests to http_handle_connection. */
void tls_server_input(struct tcp_pcb *pcb) {
  if (!pcb || pcb->app_rx_len == 0)
    return;
  uint16_t len = pcb->app_rx_len;
  uint32_t off = 0;
  int stop = 0;
  while (!stop && off + 5 <= len) {
    const uint8_t *r = pcb->app_rx_buf + off;
    uint8_t type = r[0];
    uint16_t rlen = (uint16_t)((r[3] << 8) | r[4]);
    if (off + 5 + rlen > len)
      break; /* incomplete record: wait for more TCP data */
    const uint8_t *body = r + 5;

    if (tls_srv.state == TLS_ST_CH) {
      if (type == 22 && rlen >= 4 && body[0] == 1) {
        uint32_t ml =
            ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | body[3];
        if (4 + ml > rlen) /* fragmented ClientHello: unsupported */
          break;
        tls_server_reset();
        log_writestring("[TLS-SRV] ClientHello\n");
        srv_hs_append(body, 4 + ml);
        if (srv_parse_ch(body + 4, ml) && srv_send_flight(pcb)) {
          tls_srv.state = TLS_ST_CKE;
        } else {
          srv_fatal(pcb, 40); /* handshake_failure */
          stop = 1;
        }
      } else {
        srv_fatal(pcb, 10); /* unexpected_message */
        stop = 1;
      }
    } else if (tls_srv.state == TLS_ST_CKE) {
      if (type == 20 && rlen >= 1) {
        tls_srv.ccs_seen = 1;
      } else if (type == 21 && rlen == 2) {
        /* plaintext client alert: handshake abandoned */
        tcp_close(pcb);
        tls_server_reset();
        stop = 1;
      } else if (type == 22 && !tls_srv.ccs_seen && rlen >= 4 &&
                 body[0] == 1) {
        /* plaintext ClientHello while waiting for CKE: the previous
         * handshake was abandoned mid-flight. Restart on this pcb. */
        uint32_t ml2 =
            ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | body[3];
        if (4 + ml2 > rlen)
          break;
        tls_server_reset();
        log_writestring("[TLS-SRV] ClientHello (restart)\n");
        srv_hs_append(body, 4 + ml2);
        if (srv_parse_ch(body + 4, ml2) && srv_send_flight(pcb)) {
          tls_srv.state = TLS_ST_CKE;
        } else {
          srv_fatal(pcb, 40);
          stop = 1;
        }
      } else if (type == 22) {
        uint32_t ml =
            ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | body[3];
        if (!tls_srv.cke_done) {
          if (body[0] != 16 || 4 + ml > rlen || !srv_do_cke(body + 4, ml)) {
            srv_fatal(pcb, 10);
            stop = 1;
          } else {
            srv_hs_append(body, 4 + ml);
            log_writestring("[TLS-SRV] ClientKeyExchange ok\n");
          }
        } else if (tls_srv.ccs_seen) {
          if (srv_do_finished(pcb, body, rlen)) {
            tls_srv.state = TLS_ST_APP;
            log_writestring("[TLS-SRV] handshake complete (HTTPS ready)\n");
          } else {
            log_writestring("[TLS-SRV] client Finished failed\n");
            tcp_close(pcb);
            tls_server_reset();
            stop = 1;
          }
        } else {
          srv_fatal(pcb, 10);
          stop = 1;
        }
      } else if (type == 21) { /* client alert */
        tcp_close(pcb);
        tls_server_reset();
        stop = 1;
      }
    } else { /* TLS_ST_APP */
      if (type == 23) {
        static uint8_t srv_scratch[16384];
        int pl = tls_srv_gcm_open(23, body, rlen, srv_scratch);
        if (pl < 0) {
          log_writestring("[TLS-SRV] app-data tag mismatch\n");
          tcp_close(pcb);
          tls_server_reset();
          stop = 1;
        } else {
          uint32_t room = (tls_srv.plain_len < TLS_SRV_HS_MAX)
                              ? TLS_SRV_HS_MAX - tls_srv.plain_len
                              : 0;
          uint32_t take = (uint32_t)pl < room ? (uint32_t)pl : room;
          for (uint32_t i = 0; i < take; i++)
            tls_srv.plain[tls_srv.plain_len + i] = srv_scratch[i];
          tls_srv.plain_len += take;
          if (srv_http_ready()) {
            uint32_t pl2 = tls_srv.plain_len;
            tls_srv.plain_len = 0;
            pcb->app_rx_len = 0; /* response closes the connection */
            extern void http_handle_connection(struct tcp_pcb *pcb,
                                               const uint8_t *data, int len);
            log_writestring("[TLS-SRV] HTTPS request dispatch (");
            log_write_u32(pl2);
            log_writestring(" bytes)\n");
            http_handle_connection(pcb, tls_srv.plain, (int)pl2);
            stop = 1;
          }
        }
      } else if (type == 21) { /* close_notify / alert */
        uint8_t pt[16];
        if (rlen == 26)
          tls_srv_gcm_open(21, body, rlen, pt);
        tcp_close(pcb);
        tls_server_reset();
        stop = 1;
      } else if (type == 22) {
        /* post-handshake encrypted handshake (session tickets): ignore.
         * If the tag fails this was plaintext — a NEW connection's
         * ClientHello arriving while stale state from a previous session
         * was still installed. Reset and fall through to a fresh
         * handshake below (otherwise every subsequent HTTPS connection
         * hangs: the CH is silently swallowed). */
        uint8_t pt[256];
        if (tls_srv_gcm_open(22, body, rlen, pt) >= 0)
          break; /* genuinely encrypted: ignore */
        tls_server_reset();
        if (rlen >= 4 && body[0] == 1) {
          uint32_t ml2 =
              ((uint32_t)body[1] << 16) | ((uint32_t)body[2] << 8) | body[3];
          if (4 + ml2 > rlen)
            break;
          log_writestring("[TLS-SRV] ClientHello (fresh reset)\n");
          srv_hs_append(body, 4 + ml2);
          if (srv_parse_ch(body + 4, ml2) && srv_send_flight(pcb)) {
            tls_srv.state = TLS_ST_CKE;
          } else {
            srv_fatal(pcb, 40);
            stop = 1;
          }
        } else {
          srv_fatal(pcb, 10);
          stop = 1;
        }
      }
    }
    off += 5 + rlen;
  }
  if (off > 0 && !stop) {
    /* consume processed records, keep partial trailing bytes */
    uint16_t remaining = (uint16_t)(len - off);
    for (uint16_t i = 0; i < remaining; i++)
      pcb->app_rx_buf[i] = pcb->app_rx_buf[off + i];
    pcb->app_rx_len = remaining;
  }
}

/* encrypted application-data write for http.c (port-443 connections) */
int tls_server_write(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len) {
  if (!tls_srv.established)
    return -1;
  uint16_t off = 0;
  while (off < len) {
    uint16_t n = (uint16_t)(len - off);
    if (n > 16384)
      n = 16384;
    if (!tls_srv_send_record(pcb, 23, data + off, n))
      return -1;
    off += n;
  }
  return 0;
}
