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

static void ghash_update(uint8_t y[16], const uint8_t h[16], const uint8_t *data,
                         uint32_t len) {
  while (len >= 16) {
    for (int i = 0; i < 16; i++)
      y[i] ^= data[i];
    gf128_mul(y, y, h);
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
    gf128_mul(y, y, h);
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

  aes128_ctr_keystream_block(key, j0, h); /* H = E(K, 0^128) via zero j0? */
  /* careful: H must be E(K, 0^128); compute directly */
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

  /* GHASH over AAD || pad || C || pad || lengths */
  uint8_t y[16];
  for (int i = 0; i < 16; i++)
    y[i] = 0;
  ghash_update(y, h, aad, aad_len);
  /* zero-pad aad to 16 */
  if (aad_len % 16) {
    uint8_t pad[16];
    for (int i = 0; i < 16; i++)
      pad[i] = 0;
    ghash_update(y, h, pad, 16 - (aad_len % 16));
  }
  ghash_update(y, h, data, len);
  if (len % 16) {
    uint8_t pad[16];
    for (int i = 0; i < 16; i++)
      pad[i] = 0;
    ghash_update(y, h, pad, 16 - (len % 16));
  }
  uint8_t lens[16];
  uint64_t abits = (uint64_t)aad_len * 8u;
  uint64_t cbits = (uint64_t)len * 8u;
  for (int i = 0; i < 8; i++) {
    lens[i] = (uint8_t)(abits >> (56 - 8 * i));
    lens[8 + i] = (uint8_t)(cbits >> (56 - 8 * i));
  }
  ghash_update(y, h, lens, 16);

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
