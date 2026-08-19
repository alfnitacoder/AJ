/*
 * Host-side KDF known-answer test. Uses the same SHA-256 and KDF logic
 * as src/crypto.c so we can verify the KDF without booting the OS.
 * Build: gcc -o kdf_selftest tools/kdf_selftest_host.c && ./kdf_selftest
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static inline uint32_t rotr32(uint32_t x, int n) {
  return (x >> n) | (x << (32 - n));
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t *data) {
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h, t1, t2;

  for (int i = 0; i < 16; i++) {
    w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
           ((uint32_t)data[i * 4 + 2] << 8) | (uint32_t)data[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  for (int i = 0; i < 64; i++) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + sha256_k[i] + w[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667;
  ctx->state[1] = 0xbb67ae85;
  ctx->state[2] = 0x3c6ef372;
  ctx->state[3] = 0xa54ff53a;
  ctx->state[4] = 0x510e527f;
  ctx->state[5] = 0x9b05688c;
  ctx->state[6] = 0x1f83d9ab;
  ctx->state[7] = 0x5be0cd19;
  ctx->count = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = data[i];
    ctx->count++;
    if ((ctx->count % SHA256_BLOCK_SIZE) == 0) {
      sha256_transform(ctx, ctx->buffer);
    }
  }
}

static void sha256_final(sha256_ctx *ctx, uint8_t *digest) {
  uint64_t bit_len = ctx->count * 8;
  size_t index = ctx->count % SHA256_BLOCK_SIZE;
  int pad_len = (index < 56) ? (int)(56 - index) : (int)(120 - index);

  uint8_t padding[64];
  padding[0] = 0x80;
  for (int i = 1; i < pad_len; i++)
    padding[i] = 0;

  for (int i = 0; i < 8; i++)
    padding[pad_len + i] = (uint8_t)((bit_len >> (56 - i * 8)) & 0xFF);

  sha256_update(ctx, padding, (size_t)(pad_len + 8));

  for (int i = 0; i < 8; i++) {
    digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
    digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
    digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
    digest[i * 4 + 3] = ctx->state[i] & 0xFF;
  }
}

/* KDF one shot: out16 = first 16 bytes of SHA256(K||H||letter||H) */
static void ssh_kdf_one(const uint8_t *k_mpint, uint16_t k_mpint_len,
                        const uint8_t *h, uint8_t letter, uint8_t *out16) {
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_mpint, k_mpint_len);
  sha256_update(&ctx, h, 32);
  sha256_update(&ctx, &letter, 1);
  sha256_update(&ctx, h, 32);
  uint8_t digest[32];
  sha256_final(&ctx, digest);
  for (int i = 0; i < 16; i++)
    out16[i] = digest[i];
}

/* Known-answer: K = mpint(1) = 00 00 00 01 01, H = 32 zeros, letter 'A' */
static const uint8_t kdf_kat_k[] = {0x00, 0x00, 0x00, 0x01, 0x01};
static const uint8_t kdf_kat_h[32] = {0};
static const uint8_t kdf_kat_expected[16] = {
    0x6b, 0x1e, 0x7a, 0x45, 0x72, 0x4d, 0x96, 0xf6,
    0xe3, 0x47, 0xa1, 0xce, 0xa6, 0x61, 0xd8, 0xf9};

int main(void) {
  uint8_t out[16];
  ssh_kdf_one(kdf_kat_k, (uint16_t)sizeof(kdf_kat_k), kdf_kat_h, 'A', out);

  int ok = 1;
  for (int i = 0; i < 16; i++)
    if (out[i] != kdf_kat_expected[i])
      ok = 0;

  if (ok) {
    printf("[CRYPTO] SSH KDF selftest OK\n");
    return 0;
  }
  printf("[CRYPTO] SSH KDF selftest FAIL; got: ");
  for (int i = 0; i < 16; i++)
    printf("%02x%c", out[i], i < 15 ? ' ' : '\n');
  return 1;
}
