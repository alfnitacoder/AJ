#include "netdev.h"
// Minimal cryptographic functions for SSH host key signing
// Implements: SHA-512, RSA signing with PKCS#1 v1.5 padding

#include <stddef.h>
#include <stdint.h>

// String functions (simple implementations)
static int strncmp(const char *s1, const char *s2, size_t n)
{
  for (size_t i = 0; i < n; i++)
  {
    if (s1[i] != s2[i])
      return s1[i] - s2[i];
    if (s1[i] == '\0')
      return 0;
  }
  return 0;
}

static void *memcpy(void *dest, const void *src, size_t n)
{
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (size_t i = 0; i < n; i++)
    d[i] = s[i];
  return dest;
}

// External logging and memory
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_write_hex8(uint8_t v);
extern void log_putchar(char c);
extern void *kmalloc(uint32_t size);
extern void kfree(void *ptr);

// ============================================================================
// SHA-512 Implementation (RFC 6234)
// ============================================================================

#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

typedef struct
{
  uint64_t state[8];
  uint64_t count[2];
  uint8_t buffer[SHA512_BLOCK_SIZE];
} sha512_ctx;

// SHA-512 constants (first 64 bits of fractional parts of cube roots of primes)
static const uint64_t k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

// SHA-512 helpers (OpenBSD-style, known-good)
#define R64(b, x) ((x) >> (b))
#define S64(b, x) (((x) >> (b)) | ((x) << (64 - (b))))
#define Ch64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0_512(x) (S64(28, (x)) ^ S64(34, (x)) ^ S64(39, (x)))
#define Sigma1_512(x) (S64(14, (x)) ^ S64(18, (x)) ^ S64(41, (x)))
#define sigma0_512(x) (S64(1, (x)) ^ S64(8, (x)) ^ R64(7, (x)))
#define sigma1_512(x) (S64(19, (x)) ^ S64(61, (x)) ^ R64(6, (x)))

static uint64_t be64_load(const uint8_t *cp)
{
  return (uint64_t)cp[7] | ((uint64_t)cp[6] << 8) | ((uint64_t)cp[5] << 16) |
         ((uint64_t)cp[4] << 24) | ((uint64_t)cp[3] << 32) |
         ((uint64_t)cp[2] << 40) | ((uint64_t)cp[1] << 48) |
         ((uint64_t)cp[0] << 56);
}

static void be64_write(uint8_t *b, uint64_t v)
{
  b[0] = (v >> 56) & 0xFF;
  b[1] = (v >> 48) & 0xFF;
  b[2] = (v >> 40) & 0xFF;
  b[3] = (v >> 32) & 0xFF;
  b[4] = (v >> 24) & 0xFF;
  b[5] = (v >> 16) & 0xFF;
  b[6] = (v >> 8) & 0xFF;
  b[7] = v & 0xFF;
}

// SHA-512 initialization
static void sha512_init(sha512_ctx *ctx)
{
  ctx->state[0] = 0x6a09e667f3bcc908ULL;
  ctx->state[1] = 0xbb67ae8584caa73bULL;
  ctx->state[2] = 0x3c6ef372fe94f82bULL;
  ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->state[4] = 0x510e527fade682d1ULL;
  ctx->state[5] = 0x9b05688c2b3e6c1fULL;
  ctx->state[6] = 0x1f83d9abfb41bd6bULL;
  ctx->state[7] = 0x5be0cd19137e2179ULL;
  ctx->count[0] = 0;
  ctx->count[1] = 0;
}

// SHA-512 transform
static void sha512_transform(sha512_ctx *ctx, const uint8_t *data)
{
  uint64_t a, b, c, d, e, f, g, h;
  uint64_t T1, T2, s0, s1;
  uint64_t W[16];

  a = ctx->state[0];
  b = ctx->state[1];
  c = ctx->state[2];
  d = ctx->state[3];
  e = ctx->state[4];
  f = ctx->state[5];
  g = ctx->state[6];
  h = ctx->state[7];

  int j = 0;
  do
  {
    W[j] = be64_load(data);
    data += 8;
    T1 = h + Sigma1_512(e) + Ch64(e, f, g) + k[j] + W[j];
    T2 = Sigma0_512(a) + Maj64(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
    j++;
  } while (j < 16);

  do
  {
    s0 = sigma0_512(W[(j + 1) & 0x0F]);
    s1 = sigma1_512(W[(j + 14) & 0x0F]);
    T1 = h + Sigma1_512(e) + Ch64(e, f, g) + k[j] +
         (W[j & 0x0F] += s1 + W[(j + 9) & 0x0F] + s0);
    T2 = Sigma0_512(a) + Maj64(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + T1;
    d = c;
    c = b;
    b = a;
    a = T1 + T2;
    j++;
  } while (j < 80);

  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

// SHA-512 update
static void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len)
{
  if (len == 0)
    return;

  size_t used = (size_t)((ctx->count[0] >> 3) % SHA512_BLOCK_SIZE);

  uint64_t bit_len = ((uint64_t)len << 3);
  ctx->count[0] += bit_len;
  if (ctx->count[0] < bit_len)
    ctx->count[1]++;
  ctx->count[1] += ((uint64_t)len >> 61);

  if (used > 0)
  {
    size_t free = SHA512_BLOCK_SIZE - used;
    if (len >= free)
    {
      memcpy(&ctx->buffer[used], data, free);
      sha512_transform(ctx, ctx->buffer);
      data += free;
      len -= free;
      used = 0;
    }
    else
    {
      memcpy(&ctx->buffer[used], data, len);
      return;
    }
  }

  while (len >= SHA512_BLOCK_SIZE)
  {
    sha512_transform(ctx, data);
    data += SHA512_BLOCK_SIZE;
    len -= SHA512_BLOCK_SIZE;
  }

  if (len > 0)
    memcpy(ctx->buffer, data, len);
}

// SHA-512 finalize
static void sha512_final(sha512_ctx *ctx, uint8_t *digest)
{
  unsigned used = (unsigned)((ctx->count[0] >> 3) % SHA512_BLOCK_SIZE);

  if (used > 0)
  {
    ctx->buffer[used++] = 0x80;
    if (used <= 112)
    {
      for (unsigned i = used; i < 112; i++)
        ctx->buffer[i] = 0;
    }
    else
    {
      for (unsigned i = used; i < SHA512_BLOCK_SIZE; i++)
        ctx->buffer[i] = 0;
      sha512_transform(ctx, ctx->buffer);
      for (unsigned i = 0; i < 112; i++)
        ctx->buffer[i] = 0;
    }
  }
  else
  {
    for (unsigned i = 0; i < 112; i++)
      ctx->buffer[i] = 0;
    ctx->buffer[0] = 0x80;
  }

  // Append length (128-bit, big-endian): high then low
  be64_write(&ctx->buffer[112], ctx->count[1]);
  be64_write(&ctx->buffer[120], ctx->count[0]);

  sha512_transform(ctx, ctx->buffer);

  for (int i = 0; i < 8; i++)
    be64_write(digest + i * 8, ctx->state[i]);
}

// Public SHA-512 function
void sha512(const uint8_t *data, size_t len, uint8_t *digest)
{
  // One-time self-test to catch broken 64-bit SHA-512 on i386.
  // Vector: SHA-512("abc")
  static int did_selftest = 0;
  if (!did_selftest)
  {
    did_selftest = 1;
    static const uint8_t expect_abc[64] = {
        0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49,
        0xAE, 0x20, 0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2,
        0x0A, 0x9E, 0xEE, 0xE6, 0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A,
        0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA, 0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD,
        0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E, 0x2A, 0x9A, 0xC9, 0x4F,
        0xA5, 0x4C, 0xA4, 0x9F};

    sha512_ctx t;
    uint8_t got[64];
    sha512_init(&t);
    sha512_update(&t, (const uint8_t *)"abc", 3);
    sha512_final(&t, got);

    int ok = 1;
    for (int i = 0; i < 64; i++)
    {
      if (got[i] != expect_abc[i])
      {
        ok = 0;
        break;
      }
    }
    if (ok)
    {
      log_writestring("[CRYPTO] SHA-512 selftest OK\n");
    }
    else
    {
      log_writestring("[CRYPTO] SHA-512 selftest FAIL; got: ");
      for (int i = 0; i < 64; i++)
      {
        log_write_hex8(got[i]);
        if (i < 63)
          log_putchar(' ');
      }
      log_putchar('\n');
    }
  }

  sha512_ctx ctx;
  sha512_init(&ctx);
  sha512_update(&ctx, data, len);
  sha512_final(&ctx, digest);
}

// ============================================================================
// SHA-256 Implementation (for diffie-hellman-group-exchange-sha256)
// ============================================================================

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct
{
  uint32_t state[8];
  uint64_t count;
  uint8_t buffer[SHA256_BLOCK_SIZE];
} sha256_ctx;

// SHA-256 constants
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

// Right rotate
static inline uint32_t rotr32(uint32_t x, int n)
{
  return (x >> n) | (x << (32 - n));
}

// SHA-256 transform
static void sha256_transform(sha256_ctx *ctx, const uint8_t *data)
{
  uint32_t w[64];
  uint32_t a, b, c, d, e, f, g, h, t1, t2;

  // Load message schedule
  for (int i = 0; i < 16; i++)
  {
    w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
           ((uint32_t)data[i * 4 + 2] << 8) | (uint32_t)data[i * 4 + 3];
  }
  for (int i = 16; i < 64; i++)
  {
    uint32_t s0 =
        rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 =
        rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
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

  for (int i = 0; i < 64; i++)
  {
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

// SHA-256 init
static void sha256_init(sha256_ctx *ctx)
{
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

// SHA-256 update
static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
  uint32_t i;
  for (i = 0; i < len; i++)
  {
    ctx->buffer[ctx->count % SHA256_BLOCK_SIZE] = data[i];
    ctx->count++;
    if ((ctx->count % SHA256_BLOCK_SIZE) == 0)
    {
      sha256_transform(ctx, ctx->buffer);
    }
  }
}

// SHA-256 finalize (FIPS 180-4 padding). Must not use a single 64-byte stack
// buffer for pad+length: when (count % 64) == 63, pad_len becomes 57 and
// pad_len+8 > 64 → stack overflow in the naive layout (broke HMAC for some
// lengths and could corrupt exchange hashes / transport MAC keys).
static void sha256_final(sha256_ctx *ctx, uint8_t *digest)
{
  const uint64_t bit_len = ctx->count * 8ULL;

  uint8_t one = 0x80;
  sha256_update(ctx, &one, 1);
  while ((ctx->count % SHA256_BLOCK_SIZE) != 56)
  {
    uint8_t z = 0;
    sha256_update(ctx, &z, 1);
  }

  uint8_t lenbe[8];
  for (int i = 0; i < 8; i++)
    lenbe[i] = (uint8_t)((bit_len >> (56 - i * 8)) & 0xFF);
  sha256_update(ctx, lenbe, 8);

  for (int i = 0; i < 8; i++)
  {
    digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
    digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
    digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
    digest[i * 4 + 3] = ctx->state[i] & 0xFF;
  }
}

// Public SHA-256 function
void sha256(const uint8_t *data, size_t len, uint8_t *digest)
{
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, data, len);
  sha256_final(&ctx, digest);
}

// HMAC-SHA256 (RFC 2104): out must be 32 bytes. key_len can be any; key padded to 64 bytes.
void ssh_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg,
                     size_t msg_len, uint8_t *out)
{
  uint8_t k_pad[SHA256_BLOCK_SIZE]; // 64
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
  {
    uint8_t b = (i < key_len) ? key[i] : 0;
    k_pad[i] = b ^ 0x36;
  }
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
  sha256_update(&ctx, msg, msg_len);
  uint8_t inner[32];
  sha256_final(&ctx, inner);
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
  {
    uint8_t b = (i < key_len) ? key[i] : 0;
    k_pad[i] = b ^ 0x5c;
  }
  sha256_init(&ctx);
  sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, out);
}

void ssh_hmac_sha256_two(const uint8_t *key, size_t key_len,
                         const uint8_t *msg1, size_t msg1_len,
                         const uint8_t *msg2, size_t msg2_len, uint8_t *out)
{
  uint8_t k_pad[SHA256_BLOCK_SIZE];
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
  {
    uint8_t b = (i < key_len) ? key[i] : 0;
    k_pad[i] = b ^ 0x36;
  }
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
  sha256_update(&ctx, msg1, msg1_len);
  sha256_update(&ctx, msg2, msg2_len);
  uint8_t inner[32];
  sha256_final(&ctx, inner);
  for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
  {
    uint8_t b = (i < key_len) ? key[i] : 0;
    k_pad[i] = b ^ 0x5c;
  }
  sha256_init(&ctx);
  sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
  sha256_update(&ctx, inner, 32);
  sha256_final(&ctx, out);
}

/* RFC 4231 test case using HMAC-SHA-256 (count=2): verifies transport MAC. */
void ssh_hmac_sha256_selftest(void)
{
  uint8_t key[32];
  for (int i = 0; i < 32; i++)
    key[i] = (uint8_t)(i + 1);
  uint8_t data[50];
  for (int i = 0; i < 50; i++)
    data[i] = 0xdd;
  static const uint8_t exp[32] = {
      0xb3, 0xf5, 0x08, 0x7e, 0x55, 0x8c, 0xea, 0xe4, 0x2d, 0xfc, 0x08, 0x80,
      0x61, 0x61, 0x11, 0xe9, 0xbd, 0x7d, 0x31, 0xb8, 0x8d, 0x9e, 0xef, 0x57,
      0x32, 0xf7, 0x36, 0xe7, 0x2f, 0x9c, 0xe8, 0x43};
  uint8_t out[32];
  ssh_hmac_sha256(key, sizeof(key), data, sizeof(data), out);
  int ok = 1;
  for (int i = 0; i < 32; i++)
    if (out[i] != exp[i])
      ok = 0;
  if (ok)
    log_writestring("[CRYPTO] HMAC-SHA256 selftest OK\n");
  else
  {
    log_writestring("[CRYPTO] HMAC-SHA256 selftest FAIL\n");
  }
}

// ============================================================================
// RSA Implementation (Minimal - for 2048-bit keys)
// ============================================================================

// Big integer operations (simplified for 2048-bit RSA)
#define RSA_KEY_SIZE 256 // 2048 bits = 256 bytes

// RSA key structure
typedef struct
{
  uint8_t n[RSA_KEY_SIZE];     // Modulus
  uint8_t e[RSA_KEY_SIZE];     // Public exponent (usually 65537)
  uint8_t d[RSA_KEY_SIZE];     // Private exponent
  uint8_t p[RSA_KEY_SIZE / 2]; // Prime p
  uint8_t q[RSA_KEY_SIZE / 2]; // Prime q
} rsa_key;

// Big integer operations for 2048-bit RSA

// Add two 256-byte numbers (result = a + b)
static void bigint_add(const uint8_t *a, const uint8_t *b, uint8_t *result)
{
  uint16_t carry = 0;
  for (int i = RSA_KEY_SIZE - 1; i >= 0; i--)
  {
    uint16_t sum = (uint16_t)a[i] + (uint16_t)b[i] + carry;
    result[i] = sum & 0xFF;
    carry = sum >> 8;
  }
}

// Subtract two 256-byte numbers (result = a - b, assumes a >= b)
static void bigint_sub(const uint8_t *a, const uint8_t *b, uint8_t *result)
{
  uint16_t borrow = 0;
  for (int i = RSA_KEY_SIZE - 1; i >= 0; i--)
  {
    int16_t diff = (int16_t)a[i] - (int16_t)b[i] - borrow;
    if (diff < 0)
    {
      diff += 256;
      borrow = 1;
    }
    else
    {
      borrow = 0;
    }
    result[i] = diff & 0xFF;
  }
}

// Compare two 256-byte numbers (returns -1 if a < b, 0 if a == b, 1 if a > b)
// Numbers are stored BIG-ENDIAN (MSB at index 0, LSB at index RSA_KEY_SIZE-1)
// So we compare from MSB (index 0) to LSB (index RSA_KEY_SIZE-1)
static int bigint_cmp(const uint8_t *a, const uint8_t *b)
{
  // Compare from MSB to LSB (index 0 to RSA_KEY_SIZE-1)
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (a[i] < b[i])
      return -1;
    if (a[i] > b[i])
      return 1;
  }
  return 0;
}

// Check if bigint is zero
static int bigint_is_zero(const uint8_t *a)
{
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (a[i] != 0)
      return 0;
  }
  return 1;
}

// Left shift by 1 bit (multiply by 2)
// For big-endian: process from LSB (index 255) to MSB (index 0)
// Returns the bit shifted out from MSB (carry)
// Note: Even though representation is big-endian, we process LSB to MSB
// because carry propagates from LSB to MSB (like in bigint_add)
static int bigint_shl1(uint8_t *a)
{
  uint8_t carry = 0;
  int ret_carry = (a[0] >> 7) & 1; // MSB bit that will be shifted out
  // Process from LSB (index 255) to MSB (index 0) for carry propagation
  for (int i = RSA_KEY_SIZE - 1; i >= 0; i--)
  {
    uint16_t val = ((uint16_t)a[i] << 1) | carry;
    a[i] = val & 0xFF;
    carry = (val >> 8) & 1;
  }
  return ret_carry;
}

// Right shift by 1 bit (divide by 2)
// For big-endian: process from LSB (index 255) to MSB (index 0)
static void bigint_shr1(uint8_t *a)
{
  uint8_t carry = 0;
  for (int i = RSA_KEY_SIZE - 1; i >= 0; i--)
  {
    uint16_t val = ((uint16_t)a[i]) | ((uint16_t)carry << 8);
    carry = val & 1;
    a[i] = (val >> 1) & 0xFF;
  }
}

// Multiply two 256-byte numbers (result = a * b, result must be 512 bytes)
static void bigint_mul(const uint8_t *a, const uint8_t *b, uint8_t *result)
{
  // Initialize result to zero (512 bytes)
  for (int i = 0; i < RSA_KEY_SIZE * 2; i++)
  {
    result[i] = 0;
  }

  // Schoolbook multiplication
  // For big-endian: a[0] is MSB, a[255] is LSB
  // When multiplying a[i] * b[j], the product contributes to position (i+j+1)
  // in a 512-byte big-endian result (result[511] is the LSB).
  // We process from LSB (i=255) to MSB (i=0) for carry propagation.
  for (int i = RSA_KEY_SIZE - 1; i >= 0; i--)
  {
    uint16_t carry = 0;
    for (int j = RSA_KEY_SIZE - 1; j >= 0; j--)
    {
      int pos = i + j + 1;
      uint32_t prod =
          (uint32_t)a[i] * (uint32_t)b[j] + (uint32_t)result[pos] + carry;
      result[pos] = (uint8_t)(prod & 0xFF);
      carry = (uint16_t)(prod >> 8);
    }

    // Add carry to result[i], propagate if needed.
    int carry_pos = i;
    while (carry > 0 && carry_pos >= 0)
    {
      uint32_t sum = (uint32_t)result[carry_pos] + carry;
      result[carry_pos] = (uint8_t)(sum & 0xFF);
      carry = (uint16_t)(sum >> 8);
      carry_pos--;
    }
  }
}

// Modular reduction: result = a mod n (a is 512 bytes, n and result are 256
// bytes) Optimized: if high bytes are zero, use fast path
static void bigint_mod(const uint8_t *a, const uint8_t *n, uint8_t *result)
{
  // Check if high 256 bytes are all zero (common case for RSA)
  int high_zero = 1;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (a[i] != 0)
    {
      high_zero = 0;
      break;
    }
  }

  if (high_zero)
  {
    // Fast path: a < 2^2048, just copy low bytes and reduce
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      result[i] = a[RSA_KEY_SIZE + i];
    }

    // Reduce modulo n using repeated subtraction (only if needed)
    int cmp = bigint_cmp(result, n);
    if (cmp < 0)
    {
      // Already less than n, done
      return;
    }

    // Subtract n until result < n
    uint8_t temp[RSA_KEY_SIZE];
    int iterations = 0;
    while (cmp >= 0 && iterations < 1000)
    {
      bigint_sub(result, n, temp);
      for (int i = 0; i < RSA_KEY_SIZE; i++)
      {
        result[i] = temp[i];
      }
      iterations++;
      cmp = bigint_cmp(result, n);
    }
    if (iterations >= 1000)
    {
      log_writestring(
          "[CRYPTO] WARNING: bigint_mod fast path exceeded 1000 iterations!\n");
    }
    return;
  }

  // Slow path: high bytes are non-zero, use shift-and-subtract
  // But optimize: only process bits that matter
  // Use a 257-byte remainder to avoid losing the carry-out bit when shifting.
  // This is important for correctness when reducing a 4096-bit value mod a
  // near-2048-bit modulus.
  uint8_t rem_ext[RSA_KEY_SIZE + 1];
  for (int i = 0; i < RSA_KEY_SIZE + 1; i++)
  {
    rem_ext[i] = 0;
  }

  // Find the first non-zero byte to skip leading zeros
  int start_byte = 0;
  for (int i = 0; i < RSA_KEY_SIZE * 2; i++)
  {
    if (a[i] != 0)
    {
      start_byte = i;
      break;
    }
  }

  // Debug: Log slow path usage (disabled for performance - called thousands of times)
  // if (start_byte < RSA_KEY_SIZE)
  // {
  //   log_writestring("[CRYPTO] bigint_mod using slow path, start_byte=");
  //   log_write_u32(start_byte);
  //   log_putchar('\n');
  // }

  int bit_count = 0;
  int subtract_count = 0;
  // Process from first non-zero byte
  for (int i = start_byte; i < RSA_KEY_SIZE * 2; i++)
  {
    uint8_t byte = a[i];
    for (int bit = 7; bit >= 0; bit--)
    {
      bit_count++;
      // rem_ext = (rem_ext << 1) | next_bit_of_a
      uint8_t carry = 0;
      for (int j = RSA_KEY_SIZE; j >= 0; j--)
      {
        uint16_t v = ((uint16_t)rem_ext[j] << 1) | carry;
        rem_ext[j] = (uint8_t)(v & 0xFF);
        carry = (uint8_t)((v >> 8) & 1);
      }
      if ((byte >> bit) & 1)
      {
        rem_ext[RSA_KEY_SIZE] |= 1;
      }

      // If rem_ext >= n, subtract n (n is 256 bytes, aligned to rem_ext[1..256])
      int ge_n = 0;
      if (rem_ext[0] != 0)
      {
        ge_n = 1;
      }
      else
      {
        int cmp = 0; // -1: rem<n, 0: rem==n, 1: rem>n
        for (int j = 0; j < RSA_KEY_SIZE; j++)
        {
          uint8_t r = rem_ext[1 + j];
          uint8_t m = n[j];
          if (r < m)
          {
            cmp = -1;
            break;
          }
          if (r > m)
          {
            cmp = 1;
            break;
          }
        }
        ge_n = (cmp >= 0); // rem >= n (including equality)
      }

      if (ge_n)
      {
        uint16_t borrow = 0;
        for (int j = RSA_KEY_SIZE - 1; j >= 0; j--)
        {
          int16_t diff = (int16_t)rem_ext[1 + j] - (int16_t)n[j] - (int16_t)borrow;
          if (diff < 0)
          {
            diff += 256;
            borrow = 1;
          }
          else
          {
            borrow = 0;
          }
          rem_ext[1 + j] = (uint8_t)(diff & 0xFF);
        }
        // Propagate borrow into the extra MSB byte.
        if (borrow)
        {
          if (rem_ext[0] > 0)
            rem_ext[0]--;
          else
            rem_ext[0] = 0;
        }
        subtract_count++;
      }
    }
  }

  // Debug: Log slow path statistics (disabled for performance - called thousands of times)
  // if (start_byte < RSA_KEY_SIZE)
  // {
  //   log_writestring("[CRYPTO] bigint_mod slow path: processed ");
  //   log_write_u32(bit_count);
  //   log_writestring(" bits, subtracted ");
  //   log_write_u32(subtract_count);
  //   log_writestring(" times\n");
  // }

  // Copy remainder (low 256 bytes) out.
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    result[i] = rem_ext[1 + i];
  }

  // Defensive final reduction if needed.
  int final_cmp = bigint_cmp(result, n);
  int extra_subtract_count = 0;
  while (final_cmp >= 0 && extra_subtract_count < 10)
  {
    uint8_t temp[RSA_KEY_SIZE];
    bigint_sub(result, n, temp);
    for (int k = 0; k < RSA_KEY_SIZE; k++)
      result[k] = temp[k];
    extra_subtract_count++;
    final_cmp = bigint_cmp(result, n);
  }
}

// Modular multiplication: result = (a * b) mod n
static void bigint_mod_mul(const uint8_t *a, const uint8_t *b, const uint8_t *n,
                           uint8_t *result)
{
  // Special case: if both operands are 1, result is 1 mod n = 1
  // Check a and b separately
  int a_is_one = 1;
  for (int i = 0; i < RSA_KEY_SIZE - 1; i++)
  {
    if (a[i] != 0)
    {
      a_is_one = 0;
      break;
    }
  }
  if (a_is_one)
  {
    a_is_one = (a[RSA_KEY_SIZE - 1] == 1);
  }

  int b_is_one = 1;
  for (int i = 0; i < RSA_KEY_SIZE - 1; i++)
  {
    if (b[i] != 0)
    {
      b_is_one = 0;
      break;
    }
  }
  if (b_is_one)
  {
    b_is_one = (b[RSA_KEY_SIZE - 1] == 1);
  }

  if (a_is_one && b_is_one)
  {
    // Both are 1, so 1 * 1 mod n = 1
#ifdef AJOS_CRYPTO_DEBUG
    log_writestring("[CRYPTO] Special case: 1 * 1 mod n = 1\n");
#endif
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      result[i] = 0;
    }
    result[RSA_KEY_SIZE - 1] = 1;
    return;
  }

  // Special case: if a is 1, result should be b mod n
  if (a_is_one)
  {
#ifdef AJOS_CRYPTO_DEBUG
    log_writestring("[CRYPTO] Special case: 1 * b mod n = b mod n\n");
#endif
    // Compute b mod n
    uint8_t b_512[RSA_KEY_SIZE * 2];
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      b_512[i] = 0;
      b_512[RSA_KEY_SIZE + i] = b[i];
    }
    bigint_mod(b_512, n, result);
    return;
  }

  // Special case: if b is 1, result should be a mod n
  if (b_is_one)
  {
#ifdef AJOS_CRYPTO_DEBUG
    log_writestring("[CRYPTO] Special case: a * 1 mod n = a mod n\n");
#endif
    // Compute a mod n
    uint8_t a_512[RSA_KEY_SIZE * 2];
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      a_512[i] = 0;
      a_512[RSA_KEY_SIZE + i] = a[i];
    }
    bigint_mod(a_512, n, result);
    return;
  }

  uint8_t product[RSA_KEY_SIZE * 2];
  bigint_mul(a, b, product);

  // Check if product is 1 (for other cases that might produce 1)
  int product_is_one = 1;
  for (int i = 0; i < RSA_KEY_SIZE * 2 - 1; i++)
  {
    if (product[i] != 0)
    {
      product_is_one = 0;
      break;
    }
  }
  if (product_is_one && product[RSA_KEY_SIZE * 2 - 1] == 1)
  {
    // Product is 1, so result should be 1 mod n = 1
#ifdef AJOS_CRYPTO_DEBUG
    log_writestring("[CRYPTO] Product is 1, returning 1 mod n = 1\n");
#endif
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      result[i] = 0;
    }
    result[RSA_KEY_SIZE - 1] = 1;
    return; // Skip the expensive modular reduction
  }

  bigint_mod(product, n, result);

  // Debug: check if result became zero when product was 1
  if (product_is_one)
  {
    int result_is_zero = 1;
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      if (result[i] != 0)
      {
        result_is_zero = 0;
        break;
      }
    }
    if (result_is_zero)
    {
#ifdef AJOS_CRYPTO_DEBUG
      log_writestring(
          "[CRYPTO] ERROR: bigint_mod reduced 1 to 0! This is wrong!\n");
#endif
    }
  }
}

// Modular exponentiation: result = base^exp mod n
// Uses square-and-multiply algorithm
// Exposed for DH key exchange
void bigint_mod_exp(const uint8_t *base, const uint8_t *exp, const uint8_t *mod,
                    uint8_t *result)
{
  // Debug: Log the inputs (show last 16 bytes for small numbers)
  // DISABLED during boot to prevent excessive logging
  // Uncomment for debugging:
  /*
  log_writestring("[CRYPTO] bigint_mod_exp inputs:\n");
  log_writestring("[CRYPTO]   Base (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(base[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Exponent (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(exp[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Modulus (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(mod[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  */

  // Initialize result = 1
  // bigint operations use BIG-ENDIAN (MSB at index 0, LSB at index 255)
  // bigint_add/mul iterate from RSA_KEY_SIZE-1 down to 0, processing LSB to MSB
  // But the representation is big-endian: MSB at index 0, LSB at index 255
  // So 1 is stored as [0, 0, ..., 0, 1] where index 255 is LSB
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    result[i] = 0;
  }
  result[RSA_KEY_SIZE - 1] =
      1; // LSB is at index 255 (big-endian representation)

  // Reduce base modulo n first (important for correctness)
  // Create a 512-byte representation where base is at indices 256-511 (LSB side)
  // and zeros are at indices 0-255 (MSB side). This makes the number < 2^2048,
  // which allows bigint_mod to use the fast path.
  // NOTE: In big-endian, putting base at LSB side (256-511) with zeros at MSB (0-255)
  // represents the same value as the original 256-byte number, just in a 512-byte format.
  uint8_t *base_reduced = (uint8_t *)kmalloc(RSA_KEY_SIZE);
  if (!base_reduced)
  {
    log_writestring("[CRYPTO] ERROR: kmalloc failed in rsa_mod_exp\n");
    return;
  }

  // Create a 512-byte representation for reduction
  // Fast path in bigint_mod expects: a[0..255] = 0, a[256..511] = value
  uint8_t base_512[RSA_KEY_SIZE * 2];
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    base_512[i] = 0;                      // MSB bytes (0-255) = zeros (for fast path)
    base_512[RSA_KEY_SIZE + i] = base[i]; // LSB bytes (256-511) = base
  }

  // Debug: Show base before reduction (DISABLED during boot)
  /*
  log_writestring("[CRYPTO] Base before reduction (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(base[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  */

  bigint_mod(base_512, mod, base_reduced);

  // Debug: Show base after reduction (DISABLED during boot)
  /*
  log_writestring("[CRYPTO] Base after reduction (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(base_reduced[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  */

  // Verify base_reduced is not zero (sanity check)
  int base_zero = 1;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (base_reduced[i] != 0)
    {
      base_zero = 0;
      break;
    }
  }
  if (base_zero)
  {
    log_writestring("[CRYPTO] ERROR: Base reduced to zero modulo n!\n");
    log_writestring("[CRYPTO] This indicates base >= n or reduction error\n");
    kfree(base_reduced);
    return; // Can't proceed with zero base
  }

  // Standard left-to-right square-and-multiply.
  // Always square, then multiply when the current exponent bit is 1.
  // This is simpler (and less bug-prone) than skipping to the first 1-bit.
  int exp_all_zero = 1;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (exp[i] != 0)
    {
      exp_all_zero = 0;
      break;
    }
  }
  if (exp_all_zero)
  {
    kfree(base_reduced);
    return; // result already = 1
  }

  uint8_t temp[RSA_KEY_SIZE];
  for (int byte_idx = 0; byte_idx < RSA_KEY_SIZE; byte_idx++)
  {
    uint8_t exp_byte = exp[byte_idx];
    for (int bit_idx = 7; bit_idx >= 0; bit_idx--)
    {
      // result = result^2 mod n
      bigint_mod_mul(result, result, mod, temp);
      for (int i = 0; i < RSA_KEY_SIZE; i++)
        result[i] = temp[i];

      // If current bit is 1: result = result * base mod n
      if (exp_byte & (1 << bit_idx))
      {
        bigint_mod_mul(result, base_reduced, mod, temp);
        for (int i = 0; i < RSA_KEY_SIZE; i++)
          result[i] = temp[i];
      }
    }
  }

  // DISABLED during boot - too verbose
  // log_writestring("[CRYPTO] Exponentiation complete, operations=");
  // log_write_u32(op_count);
  // log_putchar('\n');

  // Debug: Show final result (DISABLED during boot)
  /*
  log_writestring("[CRYPTO] Final result (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO] Final result (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  */

  // Verify result < n (defensive check)
  int cmp_final = bigint_cmp(result, mod);
  if (cmp_final >= 0)
  {
    log_writestring("[CRYPTO] ERROR: Final result >= n! This should never happen!\n");
    log_writestring("[CRYPTO] result (first 16): ");
    for (int i = 0; i < 16; i++)
    {
      log_write_hex8(result[i]);
      log_putchar(' ');
    }
    log_writestring("\n[CRYPTO] mod (first 16): ");
    for (int i = 0; i < 16; i++)
    {
      log_write_hex8(mod[i]);
      log_putchar(' ');
    }
    log_putchar('\n');
  }

#ifdef AJOS_CRYPTO_DEBUG
  // Debug: Show final result
  log_writestring("[CRYPTO] Final result (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO] Final result (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  // Verify result < mod
  int final_cmp = bigint_cmp(result, mod);
  if (final_cmp >= 0)
  {
    log_writestring("[CRYPTO] ERROR: Final result >= mod! This is wrong!\n");
  }
  else
  {
    log_writestring("[CRYPTO] Final result < mod (correct)\n");
  }
#endif

  kfree(base_reduced);
}

// ---- Minimal Montgomery math for RSA-2048 (signing/verification) ----
// This is intentionally separate from the byte-based bigint reducer.
// Representation:
// - 2048-bit integers are 64 limbs of 32-bit, LITTLE-ENDIAN (limb 0 is least significant).
// - Inputs/outputs at the SSH boundary are 256-byte BIG-ENDIAN.
#define MONT_LIMBS 64

static void be256_to_le32(const uint8_t be[RSA_KEY_SIZE], uint32_t le[MONT_LIMBS])
{
  for (int i = 0; i < MONT_LIMBS; i++)
  {
    int off = RSA_KEY_SIZE - 4 - (i * 4);
    le[i] = ((uint32_t)be[off] << 24) | ((uint32_t)be[off + 1] << 16) |
            ((uint32_t)be[off + 2] << 8) | (uint32_t)be[off + 3];
  }
}

static void le32_to_be256(const uint32_t le[MONT_LIMBS], uint8_t be[RSA_KEY_SIZE])
{
  for (int i = 0; i < MONT_LIMBS; i++)
  {
    uint32_t w = le[i];
    int off = RSA_KEY_SIZE - 4 - (i * 4);
    be[off] = (uint8_t)((w >> 24) & 0xFF);
    be[off + 1] = (uint8_t)((w >> 16) & 0xFF);
    be[off + 2] = (uint8_t)((w >> 8) & 0xFF);
    be[off + 3] = (uint8_t)(w & 0xFF);
  }
}

static int le32_ge(const uint32_t a[MONT_LIMBS], const uint32_t b[MONT_LIMBS])
{
  for (int i = MONT_LIMBS - 1; i >= 0; i--)
  {
    if (a[i] > b[i])
      return 1;
    if (a[i] < b[i])
      return 0;
  }
  return 1; // equal
}

static void le32_sub(uint32_t a[MONT_LIMBS], const uint32_t b[MONT_LIMBS])
{
  uint64_t borrow = 0;
  for (int i = 0; i < MONT_LIMBS; i++)
  {
    uint64_t ai = (uint64_t)a[i];
    uint64_t bi = (uint64_t)b[i];
    uint64_t d = ai - bi - borrow;
    a[i] = (uint32_t)d;
    borrow = (d >> 63) & 1; // underflow => high bit set in unsigned wrap
  }
}

// Compute n0inv = -n^{-1} mod 2^32, where n is odd.
static uint32_t mont_n0inv32(uint32_t n0)
{
  // Newton-Raphson for inverse modulo 2^32.
  uint32_t x = 1;
  for (int i = 0; i < 5; i++)
  {
    uint64_t t = (uint64_t)x * (2u - (uint64_t)n0 * x);
    x = (uint32_t)t;
  }
  return (uint32_t)(0u - x);
}

typedef struct
{
  uint32_t n[MONT_LIMBS];
  uint32_t r2[MONT_LIMBS];
  uint32_t x[MONT_LIMBS];
  uint32_t one[MONT_LIMBS];
  uint32_t acc[MONT_LIMBS];
  uint32_t a[MONT_LIMBS];
  uint32_t tmp[MONT_LIMBS];
  uint32_t t[MONT_LIMBS + 1];
  uint32_t n0inv;
} mont2048_ctx;

// Montgomery multiplication: out = a*b*R^{-1} mod n, radix R = 2^(32*MONT_LIMBS)
// Uses ctx as scratch to avoid large stack frames (SSH RX path has limited stack).
static void mont_mul_2048(mont2048_ctx *ctx, const uint32_t a[MONT_LIMBS],
                          const uint32_t b[MONT_LIMBS], uint32_t out[MONT_LIMBS])
{
  uint32_t *t = ctx->t;
  const uint32_t *n = ctx->n;
  uint32_t n0inv = ctx->n0inv;

  for (int i = 0; i < MONT_LIMBS + 1; i++)
    t[i] = 0;

  for (int i = 0; i < MONT_LIMBS; i++)
  {
    // t += a * b[i]
    uint64_t carry = 0;
    uint32_t bi = b[i];
    for (int j = 0; j < MONT_LIMBS; j++)
    {
      uint64_t uv = (uint64_t)t[j] + (uint64_t)a[j] * (uint64_t)bi + carry;
      t[j] = (uint32_t)uv;
      carry = uv >> 32;
    }
    t[MONT_LIMBS] = (uint32_t)carry;

    // m = (t[0] * n0inv) mod 2^32
    uint32_t m = (uint32_t)((uint64_t)t[0] * (uint64_t)n0inv);

    // t += m * n
    carry = 0;
    for (int j = 0; j < MONT_LIMBS; j++)
    {
      uint64_t uv = (uint64_t)t[j] + (uint64_t)m * (uint64_t)n[j] + carry;
      t[j] = (uint32_t)uv;
      carry = uv >> 32;
    }
    uint64_t uvn = (uint64_t)t[MONT_LIMBS] + carry;
    t[MONT_LIMBS] = (uint32_t)uvn;
    uint32_t carry2 = (uint32_t)(uvn >> 32); // 0 or 1

    // t = t / 2^32 (shift one limb right)
    for (int j = 0; j < MONT_LIMBS; j++)
      t[j] = t[j + 1];
    t[MONT_LIMBS] = carry2;
  }

  for (int i = 0; i < MONT_LIMBS; i++)
    out[i] = t[i];

  if (le32_ge(out, n))
    le32_sub(out, n);
}

// R^2 mod n for the built-in RSA modulus (big-endian).
// R = 2^2048 (Montgomery radix), so R^2 mod n = 2^4096 mod n.
static const uint8_t rsa_n_r2_be[RSA_KEY_SIZE] = {
    0x01, 0x94, 0x10, 0x5F, 0xE0, 0xE6, 0xB1, 0xCD, 0xBB, 0xFA, 0xE8, 0x52,
    0xE8, 0x8B, 0xF9, 0x92, 0x98, 0x67, 0x57, 0x83, 0xED, 0xA9, 0x4B, 0x36,
    0xB1, 0x07, 0x6E, 0xF9, 0xB0, 0x0E, 0x43, 0xC9, 0x7C, 0xFA, 0x18, 0xE9,
    0xCD, 0xA9, 0xC8, 0x05, 0x5C, 0x97, 0x46, 0xD3, 0xA1, 0x9D, 0xDC, 0x3E,
    0xDA, 0x0D, 0xA4, 0xC7, 0x76, 0xA2, 0x9E, 0xC3, 0x54, 0xAB, 0x3E, 0xAC,
    0xD0, 0xF8, 0xCC, 0x75, 0xB2, 0x00, 0x6E, 0xB1, 0xAB, 0xCA, 0x66, 0x65,
    0xBF, 0xB3, 0x6C, 0xA8, 0xA2, 0x0B, 0x02, 0xC3, 0xB7, 0xF3, 0xED, 0x4F,
    0xF1, 0x61, 0x1F, 0xE2, 0x57, 0xBD, 0x5E, 0x8D, 0x10, 0x16, 0xCA, 0x3D,
    0xAF, 0xC5, 0xEF, 0x2E, 0x83, 0xA2, 0x73, 0xB9, 0x2E, 0x4B, 0x65, 0x8E,
    0x6C, 0x32, 0xB8, 0x5E, 0x29, 0xE9, 0xFF, 0x5F, 0x3D, 0xFC, 0x94, 0xBA,
    0xC1, 0xF9, 0x95, 0x22, 0xB5, 0x0F, 0xBA, 0x01, 0x4F, 0x1B, 0x66, 0xCA,
    0x28, 0xCF, 0xE0, 0x06, 0x76, 0x93, 0xDA, 0x5B, 0x0E, 0x63, 0x6D, 0xB6,
    0x93, 0x8F, 0x5E, 0x18, 0x5E, 0x34, 0x82, 0xED, 0x30, 0x05, 0x1B, 0xA2,
    0x24, 0x32, 0x29, 0xE2, 0x8A, 0x50, 0xB1, 0x20, 0x3F, 0xC7, 0x1B, 0x6A,
    0x9E, 0x83, 0x8E, 0x07, 0x57, 0x48, 0x1B, 0x54, 0x2E, 0xC8, 0xA1, 0x19,
    0x66, 0x5C, 0xDE, 0x26, 0x88, 0xC8, 0xBD, 0x05, 0xB6, 0xC1, 0x33, 0xA8,
    0x17, 0xA9, 0xFA, 0x13, 0x52, 0x59, 0xAF, 0x23, 0xAE, 0x66, 0x3D, 0xC1,
    0xDA, 0x68, 0xB1, 0xB5, 0x8B, 0x0B, 0xF7, 0xB6, 0x31, 0xD0, 0xD8, 0x12,
    0x17, 0x2F, 0xC7, 0x14, 0x2F, 0x81, 0x7C, 0x0D, 0x67, 0x8A, 0x8D, 0xF6,
    0xEF, 0x69, 0xBE, 0xDA, 0x43, 0x80, 0x02, 0xDB, 0xA7, 0x2B, 0x27, 0xBB,
    0xEC, 0x88, 0xF1, 0x18, 0x30, 0x48, 0x67, 0x0C, 0xDD, 0x81, 0x40, 0x9D,
    0x40, 0xE9, 0x0A, 0x98};

static void mont_modexp_be256_with_r2(const uint8_t base_be[RSA_KEY_SIZE],
                                      const uint8_t exp_be[RSA_KEY_SIZE],
                                      const uint8_t mod_be[RSA_KEY_SIZE],
                                      const uint8_t r2_be[RSA_KEY_SIZE],
                                      uint8_t out_be[RSA_KEY_SIZE])
{
  // Keep a single heap-allocated context to avoid stack pressure and repeated
  // allocations in the SSH RX path. Not re-entrant.
  static mont2048_ctx *ctx = 0;
  if (!ctx)
  {
    ctx = (mont2048_ctx *)kmalloc(sizeof(mont2048_ctx));
    if (!ctx)
    {
      log_writestring("[CRYPTO] ERROR: mont2048_ctx kmalloc failed\n");
      for (int i = 0; i < RSA_KEY_SIZE; i++)
        out_be[i] = 0;
      return;
    }
  }

  be256_to_le32(mod_be, ctx->n);
  be256_to_le32(r2_be, ctx->r2);
  ctx->n0inv = mont_n0inv32(ctx->n[0]);

  // one = 1
  for (int i = 0; i < MONT_LIMBS; i++)
    ctx->one[i] = 0;
  ctx->one[0] = 1;

  // acc = 1 in Montgomery domain: acc = 1*R mod n = mont_mul(1, R2)
  mont_mul_2048(ctx, ctx->one, ctx->r2, ctx->acc);

  // a = base in Montgomery domain: a = base*R mod n = mont_mul(base, R2)
  be256_to_le32(base_be, ctx->x);
  mont_mul_2048(ctx, ctx->x, ctx->r2, ctx->a);

  // exponentiation (MSB->LSB over big-endian exponent bytes)
  for (int byte_idx = 0; byte_idx < RSA_KEY_SIZE; byte_idx++)
  {
    uint8_t eb = exp_be[byte_idx];
    for (int bit = 7; bit >= 0; bit--)
    {
      mont_mul_2048(ctx, ctx->acc, ctx->acc, ctx->tmp);
      for (int i = 0; i < MONT_LIMBS; i++)
        ctx->acc[i] = ctx->tmp[i];

      if (eb & (1 << bit))
      {
        mont_mul_2048(ctx, ctx->acc, ctx->a, ctx->tmp);
        for (int i = 0; i < MONT_LIMBS; i++)
          ctx->acc[i] = ctx->tmp[i];
      }
    }
  }

  // Convert out of Montgomery domain: out = acc * 1 mod n
  mont_mul_2048(ctx, ctx->acc, ctx->one, ctx->x);
  le32_to_be256(ctx->x, out_be);
}

static void mont_modexp_be256(const uint8_t base_be[RSA_KEY_SIZE],
                              const uint8_t exp_be[RSA_KEY_SIZE],
                              const uint8_t mod_be[RSA_KEY_SIZE],
                              uint8_t out_be[RSA_KEY_SIZE])
{
  mont_modexp_be256_with_r2(base_be, exp_be, mod_be, rsa_n_r2_be, out_be);
}

// Exposed helper for DH (and other moduli): caller provides precomputed R^2 mod mod
// where R = 2^2048. Inputs/outputs are 256-byte big-endian.
void mont_modexp_be256_custom_r2(const uint8_t *base_be, const uint8_t *exp_be,
                                 const uint8_t *mod_be, const uint8_t *r2_be,
                                 uint8_t *out_be)
{
  mont_modexp_be256_with_r2(base_be, exp_be, mod_be, r2_be, out_be);
}

// PKCS#1 v1.5 padding for RSA signing
// Format: 0x00 0x01 [0xFF...] 0x00 [DER-encoded hash algorithm] [hash]
static int pkcs1_v15_pad(const uint8_t *hash, size_t hash_len,
                         const char *hash_algorithm, uint8_t *padded,
                         size_t padded_len)
{
  if (padded_len < hash_len + 11)
  {
    return 0; // Not enough space
  }

  // DER encodings for different hash algorithms
  static const uint8_t sha512_der[] = {
      0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}; // 19 bytes
  static const uint8_t sha256_der[] = {
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}; // 19 bytes
  static const uint8_t sha1_der[] = {0x30, 0x21, 0x30, 0x09, 0x06,
                                     0x05, 0x2b, 0x0e, 0x03, 0x02,
                                     0x1a, 0x05, 0x00, 0x04, 0x14}; // 15 bytes
  // Same as sha256_der, but separate for clarity when used with ssh-rsa
  static const uint8_t sha256_der_for_rsa[] = {
      0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
      0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}; // 19 bytes

  const uint8_t *der;
  size_t der_len;

  if (hash_algorithm && strncmp(hash_algorithm, "sha512", 6) == 0)
  {
    der = sha512_der;
    der_len = sizeof(sha512_der);
  }
  else if (hash_algorithm && strncmp(hash_algorithm, "sha256", 6) == 0)
  {
    der = sha256_der;
    der_len = sizeof(sha256_der);
  }
  else
  {
    // Default to SHA-256 DER (for ssh-rsa with SHA-256 exchange hash)
    // Note: This is non-standard, but we're testing
    der = sha256_der_for_rsa;
    der_len = sizeof(sha256_der_for_rsa);
  }

  size_t padding_len =
      padded_len - hash_len - der_len - 3; // 3 = 0x00 0x01 0x00

  padded[0] = 0x00;
  padded[1] = 0x01;
  for (size_t i = 0; i < padding_len; i++)
  {
    padded[2 + i] = 0xFF;
  }
  padded[2 + padding_len] = 0x00;

  for (size_t i = 0; i < der_len; i++)
  {
    padded[3 + padding_len + i] = der[i];
  }

  for (size_t i = 0; i < hash_len; i++)
  {
    padded[3 + padding_len + der_len + i] = hash[i];
  }

  return 1;
}

// RSA sign: sign hash with private key
// Returns signature length, or 0 on error
static int rsa_sign(const uint8_t *hash, size_t hash_len,
                    const char *hash_algorithm, const rsa_key *key,
                    uint8_t *signature)
{
  // NOTE: RSA signing runs deep in the SSH RX path; keep stack usage low.
#ifdef CRYPTO_TEST_KMALLOC_FAIL
  // Test hook: force first rsa_sign allocation to fail. Build with
  // -DCRYPTO_TEST_KMALLOC_FAIL to exercise error path (zeroed signature, log).
  static int rsa_sign_fail_once;
  uint8_t *padded =
      (rsa_sign_fail_once++ == 0) ? NULL : (uint8_t *)kmalloc(RSA_KEY_SIZE);
#else
  uint8_t *padded = (uint8_t *)kmalloc(RSA_KEY_SIZE);
#endif
  if (!padded)
  {
    log_writestring("[CRYPTO] ERROR: kmalloc failed for padded\n");
    for (int i = 0; i < RSA_KEY_SIZE; i++)
      signature[i] = 0;
    return 0;
  }

  // For tiny test key (n=33), use simple test instead of PKCS#1
  // PKCS#1 padding requires at least 11 bytes overhead, but n=33 is only 1 byte
  if (key->n[RSA_KEY_SIZE - 1] == 0x21) // n=33
  {
    log_writestring("[CRYPTO] Using simple test for tiny RSA key (n=33)\n");
    // Test: sign the number 2
    for (int i = 0; i < RSA_KEY_SIZE; i++)
      padded[i] = 0;
    padded[RSA_KEY_SIZE - 1] = 0x02; // m=2

    log_writestring("[CRYPTO] Test message (last 16 bytes): ");
    for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
    {
      log_write_hex8(padded[i]);
      log_putchar(' ');
    }
    log_putchar('\n');
  }
  else
  {
    // PKCS#1 v1.5 padding (with appropriate DER encoding for hash algorithm)
    if (!pkcs1_v15_pad(hash, hash_len, hash_algorithm, padded, RSA_KEY_SIZE))
    {
      log_writestring("[CRYPTO] ERROR: PKCS#1 padding failed\n");
      kfree(padded);
      for (int i = 0; i < RSA_KEY_SIZE; i++)
        signature[i] = 0;
      return 0;
    }
  }

#ifdef AJOS_SSH_DEBUG
  // Debug: Show first 32 and last 48 bytes of PKCS#1 padded block
  log_writestring("[DEBUG] PKCS#1 padded data first 32 bytes: ");
  for (int i = 0; i < 32; i++)
  {
    log_write_hex8(padded[i]);
    if (i < 31)
      log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[DEBUG] PKCS#1 padded data last 48 bytes (DER+hash): ");
  for (int i = RSA_KEY_SIZE - 48; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(padded[i]);
    if (i < RSA_KEY_SIZE - 1)
      log_putchar(' ');
  }
  log_putchar('\n');
#endif

  // Modular exponentiation: signature = padded^d mod n
  // Initialize signature to zero first
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    signature[i] = 0;
  }

#ifdef AJOS_SSH_DEBUG
  // Debug: Log key components being used
  log_writestring("[CRYPTO] RSA key components:\n");
  log_writestring("[CRYPTO]   Modulus (n) first 16 bytes: ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(key->n[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Exponent (d) first 16 bytes: ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(key->d[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Public exponent (e) first 16 bytes: ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(key->e[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Public exponent (e) last 4 bytes: ");
  for (int i = 252; i < 256; i++)
  {
    log_write_hex8(key->e[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  // Check if e is stored correctly (should be 0x00010001 = 65537)
  int e_at_start = (key->e[0] == 0x00 && key->e[1] == 0x01 &&
                    key->e[2] == 0x00 && key->e[3] == 0x01);
  int e_at_end = (key->e[252] == 0x00 && key->e[253] == 0x01 &&
                  key->e[254] == 0x00 && key->e[255] == 0x01);
  log_writestring("[CRYPTO]   e format: ");
  if (e_at_start)
  {
    log_writestring("big-endian (correct for bigint_mod_exp)\n");
  }
  else if (e_at_end)
  {
    log_writestring(
        "little-endian (WRONG - will cause verification to fail)\n");
  }
  else
  {
    log_writestring("unknown format\n");
  }

  log_writestring(
      "[CRYPTO] Computing RSA signature (this may take a moment)...\n");
  log_writestring("[CRYPTO] Signature computation inputs:\n");
  log_writestring("[CRYPTO]   Padded message (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(padded[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Padded message (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(padded[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Private exponent d (first 4 bytes): ");
  for (int i = 0; i < 4; i++)
  {
    log_write_hex8(key->d[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[CRYPTO]   Modulus n (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(key->n[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
#endif

  // Compute signature using modular exponentiation.
  // (NOTE: RSA correctness is validated against OpenSSH by the SSH handshake.)
  uint8_t *sig_temp = (uint8_t *)kmalloc(RSA_KEY_SIZE);
  if (!sig_temp)
  {
    log_writestring("[CRYPTO] ERROR: kmalloc failed for sig_temp\n");
    kfree(padded);
    for (int i = 0; i < RSA_KEY_SIZE; i++)
      signature[i] = 0;
    return 0;
  }
  for (int i = 0; i < RSA_KEY_SIZE; i++)
    sig_temp[i] = 0;
  mont_modexp_be256(padded, key->d, key->n, sig_temp);

  // Debug: Show sig_temp before padding
#ifdef AJOS_SSH_DEBUG
  log_writestring("[CRYPTO] sig_temp from bigint_mod_exp (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(sig_temp[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
#endif

  // OpenSSH behavior (ssh-rsa.c lines 389-396): If signature is shorter than
  // RSA_size, pad with leading zeros at the START (lower indices) OpenSSH uses:
  // memmove(sig + diff, sig, len); explicit_bzero(sig, diff); This moves the
  // signature to higher indices and zeros the start

  // Find the actual signature length (skip leading zeros)
  int sig_start = 0;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (sig_temp[i] != 0)
    {
      sig_start = i;
      break;
    }
  }

  // If all zeros, signature is invalid
  if (sig_start == RSA_KEY_SIZE)
  {
    log_writestring(
        "[CRYPTO] ERROR: Signature computation produced all zeros!\n");
    kfree(sig_temp);
    kfree(padded);
    for (int i = 0; i < RSA_KEY_SIZE; i++)
      signature[i] = 0;
    return 0;
  }

  size_t sig_len = RSA_KEY_SIZE - sig_start;
  log_writestring("[CRYPTO] Signature from bigint_mod_exp: sig_start=");
  log_write_u32(sig_start);
  log_writestring(", sig_len=");
  log_write_u32(sig_len);
  log_putchar('\n');

  // OpenSSH: If signature is shorter than RSA_size, pad with leading zeros
  if (sig_len < RSA_KEY_SIZE)
  {
    size_t diff = RSA_KEY_SIZE - sig_len;
    // Move signature to higher indices, zero the start (OpenSSH style)
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      signature[i] = 0;
    }
    // Copy signature starting at index 'diff' (padding zeros at start)
    for (size_t i = 0; i < sig_len; i++)
    {
      signature[diff + i] = sig_temp[sig_start + i];
    }
    log_writestring("[CRYPTO] Signature padded (OpenSSH style): original len=");
    log_write_u32(sig_len);
    log_writestring(", padded to ");
    log_write_u32(RSA_KEY_SIZE);
    log_writestring(" bytes (leading zeros at start)\n");
  }
  else
  {
    // Signature is already full length, copy as-is
    for (int i = 0; i < RSA_KEY_SIZE; i++)
    {
      signature[i] = sig_temp[i];
    }
    log_writestring(
        "[CRYPTO] Signature already full length (256 bytes), copied as-is\n");
  }

  // Debug: Show signature after padding
  log_writestring("[CRYPTO] Final signature (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(signature[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  // Verify signature is not all zeros (CRITICAL CHECK)
  int all_zero = 1;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (signature[i] != 0)
    {
      all_zero = 0;
      break;
    }
  }
  if (all_zero)
  {
    log_writestring("[CRYPTO] ERROR: RSA signature is all zeros!\n");
    log_writestring(
        "[CRYPTO] rsa_mod_exp failed - signature computation FAILED\n");
    kfree(sig_temp);
    kfree(padded);
    return 0; // CRITICAL: Return 0 to indicate failure
  }

  // Self-check: signature^e mod n should recover the padded block.
  // With e=65537 this is relatively cheap and catches bigint/RSA bugs early.
  uint8_t *verify_result = (uint8_t *)kmalloc(RSA_KEY_SIZE);
  if (!verify_result)
  {
    log_writestring("[CRYPTO] ERROR: kmalloc failed for verify_result\n");
    kfree(sig_temp);
    kfree(padded);
    return 0;
  }
  mont_modexp_be256(signature, key->e, key->n, verify_result);
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (verify_result[i] != padded[i])
    {
      log_writestring("[CRYPTO] ERROR: RSA signature self-check FAILED\n");
      kfree(verify_result);
      kfree(sig_temp);
      kfree(padded);
      return 0;
    }
  }

  // For tiny test key, verify manually (debug only)
  if (key->n[RSA_KEY_SIZE - 1] == 0x21) // n=33
  {
#ifdef AJOS_SSH_DEBUG
    log_writestring(
        "[CRYPTO] Test verification: signature^e mod n should equal message\n");
#endif
    uint8_t verify[RSA_KEY_SIZE];
    for (int i = 0; i < RSA_KEY_SIZE; i++)
      verify[i] = 0;
    mont_modexp_be256(signature, key->e, key->n, verify);

    log_writestring("[CRYPTO] Verification result (last 16 bytes): ");
    for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
    {
      log_write_hex8(verify[i]);
      log_putchar(' ');
    }
    log_putchar('\n');

    // Check if verify == padded (should be 0x02)
    if (verify[RSA_KEY_SIZE - 1] == padded[RSA_KEY_SIZE - 1])
    {
      log_writestring(
          "[CRYPTO] RSA test PASSED: signature verification works!\n");
    }
    else
    {
      log_writestring("[CRYPTO] RSA test FAILED: verify=");
      log_write_hex8(verify[RSA_KEY_SIZE - 1]);
      log_writestring(", expected=");
      log_write_hex8(padded[RSA_KEY_SIZE - 1]);
      log_putchar('\n');
    }
  }

  kfree(verify_result);
  kfree(sig_temp);
  kfree(padded);
  return RSA_KEY_SIZE;
}

// Get the default RSA host key
// This is a real RSA-2048 key pair generated for testing
// In production, generate a fresh key or load from secure storage
// NOTE: Using non-const arrays initialized at runtime to avoid linker/boot
// issues TEMPORARY: Using minimal initialization to avoid boot hangs
// TEST MODE: Set to 1 to use small test key, 0 to use real 2048-bit key
// NOTE: Test key causes "Invalid key length" error - client expects 2048-bit
// key
#define USE_TEST_RSA_KEY 0

static void get_default_rsa_key(rsa_key *key)
{
#if USE_TEST_RSA_KEY
  // Tiny RSA for debugging: n=33, e=3, d=7
  // Test: m=2, c=2^3 mod 33 = 8, m'=8^7 mod 33 = 2
  // Format: 256-byte big-endian (small numbers at END, LSB at index 255)

  // Clear all arrays
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    key->n[i] = 0;
    key->e[i] = 0;
    key->d[i] = 0;
  }

  // For 256-byte big-endian representation:
  // Small numbers go at the END (LSB at index 255)
  // n = 33 = 0x21
  key->n[RSA_KEY_SIZE - 1] = 0x21;

  // e = 3 = 0x03
  key->e[RSA_KEY_SIZE - 1] = 0x03;

  // d = 7 = 0x07
  key->d[RSA_KEY_SIZE - 1] = 0x07;

  log_writestring("[CRYPTO] Using TINY RSA key (n=33, e=3, d=7)\n");
  log_writestring(
      "[CRYPTO] Key format: 256-byte big-endian (small numbers at end)\n");
  log_writestring(
      "[CRYPTO] Test: m=2, c=2^3 mod 33 = 8, verify: 8^7 mod 33 = 2\n");

#else
  // Real RSA-2048 key pair (generated with verification script)
  // Using runtime initialization to avoid large static const arrays causing
  // boot issues
  static int initialized = 0;
  static uint8_t key_n[256];
  static uint8_t key_e[256];
  static uint8_t key_d[256];

  if (!initialized)
  {
    // Initialize n - avoid large const arrays by initializing byte-by-byte
    // This prevents the compiler from putting large arrays in .rodata
    // NEW VALID RSA-2048 KEY (generated and verified: (2^e)^d mod n = 2)
    uint8_t n_init[] = {
        0x0e, 0xa5, 0x96, 0x78, 0x7a, 0x52, 0xfc, 0xf8, 0x7e, 0xa6, 0x9a, 0x13,
        0xbf, 0xe4, 0x5f, 0x27, 0xed, 0x29, 0xc1, 0x9c, 0x49, 0x0a, 0x32, 0xa5,
        0x0b, 0x37, 0x21, 0x63, 0x46, 0x11, 0x02, 0x9c, 0xcc, 0x46, 0x4a, 0x19,
        0xa1, 0x73, 0x28, 0xfc, 0x80, 0x23, 0xb0, 0x5c, 0xd2, 0xb2, 0x84, 0xad,
        0x8f, 0xfe, 0x46, 0xbf, 0xc6, 0x29, 0x22, 0x50, 0xb1, 0xdf, 0x8a, 0x13,
        0x31, 0x76, 0x40, 0xce, 0x09, 0x81, 0x57, 0xdc, 0xb1, 0xf6, 0xd5, 0x7a,
        0xba, 0xa0, 0x7f, 0x1b, 0x17, 0xb9, 0xc1, 0x53, 0xa5, 0xc9, 0x3c, 0x64,
        0x1b, 0xb5, 0xa2, 0x20, 0x72, 0x6d, 0x50, 0xb7, 0x2a, 0x1d, 0xe1, 0x42,
        0xc5, 0xfe, 0x10, 0xb6, 0x46, 0x20, 0xb4, 0x9f, 0x3e, 0xca, 0xbc, 0x46,
        0x8f, 0x58, 0x60, 0xe3, 0x0f, 0x0d, 0x47, 0x0e, 0x6c, 0x77, 0x4e, 0x66,
        0xf5, 0xc2, 0xcd, 0xf7, 0x6f, 0x75, 0xf5, 0x8f, 0x68, 0xb2, 0x9d, 0x03,
        0xd1, 0x52, 0x41, 0xe9, 0x7a, 0x67, 0x91, 0x75, 0xfb, 0xa1, 0xdc, 0x26,
        0x0a, 0xb0, 0x80, 0xaf, 0xc4, 0x05, 0xfe, 0x2b, 0x4e, 0x1e, 0x9e, 0x35,
        0x3e, 0xf1, 0x17, 0x7b, 0x88, 0x28, 0xd0, 0xaf, 0xc6, 0x3b, 0x11, 0x87,
        0xa9, 0x72, 0x99, 0xce, 0x74, 0x88, 0x38, 0xc5, 0xf0, 0xf5, 0x05, 0x70,
        0x3e, 0x91, 0x0a, 0x83, 0x7b, 0x9c, 0x92, 0x0f, 0x83, 0x4a, 0x88, 0x09,
        0x25, 0x88, 0x64, 0x6d, 0xe2, 0x16, 0x00, 0x4a, 0xd6, 0x24, 0x98, 0xd6,
        0xf6, 0x8a, 0x39, 0x10, 0xdb, 0xba, 0x50, 0x26, 0xb0, 0xfc, 0x3c, 0xa1,
        0xc7, 0xbf, 0x67, 0xb9, 0x81, 0x09, 0x20, 0x2a, 0xbd, 0x6b, 0xd0, 0xbe,
        0x93, 0xab, 0x4d, 0x6b, 0xd2, 0x3e, 0x5a, 0x34, 0x03, 0xde, 0xdb, 0x11,
        0xc9, 0x9f, 0x27, 0xfd, 0x53, 0x2a, 0xf9, 0x71, 0x0f, 0xcb, 0x82, 0xf6,
        0xbc, 0xd7, 0x2e, 0xa7};
    for (int i = 0; i < 256 && i < (int)sizeof(n_init); i++)
      key_n[i] = n_init[i];

    // Initialize e (public exponent = 65537 = 0x010001)
    // Representation is 256-byte big-endian: MSB at index 0, LSB at index 255.
    // So a small exponent lives at the END of the array.
    for (int i = 0; i < 256; i++)
      key_e[i] = 0x00;
    key_e[253] = 0x01;
    key_e[254] = 0x00;
    key_e[255] = 0x01;

    // Initialize d - avoid large const arrays
    // CRITICAL: d must be in BIG-ENDIAN format (MSB at index 0)
    // NEW VALID RSA-2048 PRIVATE KEY (verified: (2^e)^d mod n = 2)
    uint8_t d_init[] = {
        0x06, 0xb7, 0xc6, 0x43, 0x2d, 0xff, 0xe0, 0x4d, 0x6d, 0x71, 0xa6, 0x9b,
        0xc6, 0x58, 0xcd, 0x98, 0x37, 0x7b, 0xfe, 0x74, 0x5b, 0x3f, 0xd5, 0x28,
        0xc3, 0xf3, 0x1e, 0x5a, 0x35, 0x29, 0xda, 0x23, 0xe6, 0xc1, 0x9a, 0x7d,
        0x15, 0x03, 0x07, 0xda, 0x80, 0x3f, 0x5e, 0x45, 0xc4, 0xd1, 0xe2, 0x6e,
        0xe4, 0xeb, 0x80, 0xb1, 0xb7, 0x06, 0xe8, 0xd9, 0x50, 0x2c, 0x32, 0x5d,
        0x49, 0x43, 0x6e, 0xc7, 0xd1, 0xae, 0x44, 0x89, 0x52, 0x0a, 0xdf, 0xb1,
        0x71, 0xe5, 0xe9, 0x46, 0x98, 0xe4, 0x37, 0x1a, 0xd1, 0xa0, 0x72, 0x15,
        0x8c, 0x6c, 0x0b, 0x97, 0x8c, 0x44, 0x3d, 0x50, 0x35, 0x7e, 0x0c, 0xf2,
        0x9e, 0x73, 0x40, 0x61, 0x09, 0xdb, 0x38, 0x5d, 0x0d, 0xe4, 0xd8, 0xe4,
        0x18, 0x1d, 0x36, 0x1b, 0x0e, 0xad, 0x4d, 0x58, 0xfd, 0x40, 0xdf, 0x71,
        0xf3, 0xe8, 0xcc, 0xa5, 0x5f, 0xb7, 0x1f, 0xd0, 0xc8, 0x6f, 0x09, 0x14,
        0xd2, 0x06, 0x5e, 0x98, 0x83, 0x4e, 0xbb, 0x6a, 0x59, 0xfd, 0x65, 0x6f,
        0x59, 0x4c, 0x44, 0x0e, 0xf0, 0xfc, 0x40, 0xe6, 0xd3, 0x62, 0xf7, 0x75,
        0xbc, 0x70, 0x10, 0x85, 0x76, 0x9e, 0x0c, 0x1c, 0x2c, 0x15, 0x24, 0x57,
        0x6e, 0x2e, 0x63, 0x73, 0xff, 0xfc, 0x70, 0x0e, 0xd6, 0x7e, 0x3c, 0xa2,
        0x4c, 0x17, 0xd4, 0xc5, 0xbf, 0xca, 0x11, 0xeb, 0xcf, 0x3b, 0x1f, 0x96,
        0x19, 0x79, 0x4b, 0x92, 0xd3, 0x38, 0xd9, 0x2f, 0x26, 0x98, 0xf0, 0xf8,
        0x48, 0x6f, 0x5b, 0xe1, 0x2d, 0xa3, 0x3f, 0x19, 0x22, 0xa3, 0x27, 0x27,
        0xf3, 0x72, 0x43, 0x08, 0x01, 0x2c, 0x49, 0x43, 0x8c, 0xd5, 0xcb, 0x50,
        0x2b, 0x92, 0x97, 0x70, 0xe2, 0x2e, 0xd6, 0x38, 0x4a, 0x05, 0x6e, 0x75,
        0x78, 0xde, 0x03, 0x76, 0x1c, 0xfe, 0x70, 0xbf, 0xae, 0x16, 0x74, 0x5d,
        0xb7, 0x3d, 0x54, 0xa9};
    for (int i = 0; i < 256 && i < (int)sizeof(d_init); i++)
      key_d[i] = d_init[i];

    initialized = 1;
  }

  // Copy the key components
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    key->n[i] = key_n[i];
    key->e[i] = key_e[i];
    key->d[i] = key_d[i];
  }

  log_writestring(
      "[CRYPTO] Using real RSA-2048 key for SSH host key signing\n");
#endif

  // Initialize p and q (not needed for signing, but initialize anyway)
  for (int i = 0; i < RSA_KEY_SIZE / 2; i++)
  {
    key->p[i] = 0;
    key->q[i] = 0;
  }
}

// Get RSA public key blob in SSH wire format
// Format: string "ssh-rsa" || mpint e || mpint n
// Returns length of blob written to output, or 0 on error
int ssh_get_rsa_public_key_blob(uint8_t *output, size_t output_len)
{
  if (output_len < 300)
    return 0; // Need at least 300 bytes
  
  rsa_key *key = (rsa_key *)kmalloc(sizeof(rsa_key));
  if (!key)
    return 0;
  get_default_rsa_key(key);

  size_t pos = 0;

  // Key type: "ssh-rsa"
  output[pos++] = 0x00;
  output[pos++] = 0x00;
  output[pos++] = 0x00;
  output[pos++] = 0x07; // Length = 7
  const char *key_type = "ssh-rsa";
  for (int i = 0; i < 7; i++)
  {
    output[pos++] = key_type[i];
  }

  // Public exponent e = 65537 (0x00010001)
  // e is stored as big-endian in key.e[256-5] to key.e[255]
  // Format: 0x00 0x01 0x00 0x01 (4 bytes) or 0x01 0x00 0x01 (3 bytes, skip
  // leading zero) Find where e actually starts (skip leading zeros)
  int e_start = 0;
  for (int i = 0; i < 256; i++)
  {
    if (key->e[i] != 0)
    {
      e_start = i;
      break;
    }
  }
  int e_len = 256 - e_start;
  if (e_len == 0)
    e_len = 3; // Default to 3 bytes for 65537

  // Write e as mpint (length + value)
  // mpint format: if first byte >= 0x80, need positive indicator
  if (key->e[e_start] >= 0x80)
  {
    // Need positive indicator byte
    output[pos++] = (e_len + 1) >> 24;
    output[pos++] = ((e_len + 1) >> 16) & 0xFF;
    output[pos++] = ((e_len + 1) >> 8) & 0xFF;
    output[pos++] = (e_len + 1) & 0xFF;
    output[pos++] = 0x00; // Positive indicator
    for (int i = 0; i < e_len; i++)
    {
      output[pos++] = key->e[e_start + i];
    }
  }
  else
  {
    output[pos++] = e_len >> 24;
    output[pos++] = (e_len >> 16) & 0xFF;
    output[pos++] = (e_len >> 8) & 0xFF;
    output[pos++] = e_len & 0xFF;
    for (int i = 0; i < e_len; i++)
    {
      output[pos++] = key->e[e_start + i];
    }
  }

  // Modulus n (2048 bits = 256 bytes)
  // Find actual length (skip leading zeros)
  int n_start = 0;
  for (int i = 0; i < 256; i++)
  {
    if (key->n[i] != 0)
    {
      n_start = i;
      break;
    }
  }
  int n_len = 256 - n_start;
  if (n_len == 0)
    n_len = 256;

  // Write n as mpint (length + value, with positive indicator if needed)
  if (key->n[n_start] >= 0x80)
  {
    // Need positive indicator byte
    output[pos++] = (n_len + 1) >> 24;
    output[pos++] = ((n_len + 1) >> 16) & 0xFF;
    output[pos++] = ((n_len + 1) >> 8) & 0xFF;
    output[pos++] = (n_len + 1) & 0xFF;
    output[pos++] = 0x00; // Positive indicator
    for (int i = 0; i < n_len; i++)
    {
      output[pos++] = key->n[n_start + i];
    }
  }
  else
  {
    output[pos++] = n_len >> 24;
    output[pos++] = (n_len >> 16) & 0xFF;
    output[pos++] = (n_len >> 8) & 0xFF;
    output[pos++] = n_len & 0xFF;
    for (int i = 0; i < n_len; i++)
    {
      output[pos++] = key->n[n_start + i];
    }
  }

  kfree(key);
  return pos;
}

// ============================================================================
// SSH Exchange Hash Construction (RFC 4253 section 8)
// ============================================================================

// Construct SSH exchange hash H for group-exchange
// H = SHA256(V_C || V_S || I_C || I_S || K_S || min || preferred || max || p ||
// g || e || f || K)
// Note: For diffie-hellman-group-exchange-sha256, we use SHA-256, not SHA-512
static void sha256_put_u32be(sha256_ctx *ctx, uint32_t x)
{
  uint8_t t[4];
  t[0] = (x >> 24) & 0xFF;
  t[1] = (x >> 16) & 0xFF;
  t[2] = (x >> 8) & 0xFF;
  t[3] = x & 0xFF;
  sha256_update(ctx, t, 4);
}

static void sha256_put_string(sha256_ctx *ctx, const uint8_t *s, size_t len)
{
  sha256_put_u32be(ctx, (uint32_t)len);
  if (len)
    sha256_update(ctx, s, len);
}

int ssh_compute_exchange_hash(
    const uint8_t *v_c, size_t v_c_len, // Client version string
    const uint8_t *v_s, size_t v_s_len, // Server version string
    const uint8_t *i_c, size_t i_c_len, // Client KEXINIT payload
    const uint8_t *i_s,
    size_t i_s_len,                     // Server KEXINIT payload (IGNORED - use safe_i_s instead)
    const uint8_t *k_s, size_t k_s_len, // Server host key blob
    uint32_t min, uint32_t n,
    uint32_t max,                   // GEX parameters (n = preferred/negotiated size)
    const uint8_t *p, size_t p_len, // Prime p (mpint)
    const uint8_t *g, size_t g_len, // Generator g (mpint)
    const uint8_t *e, size_t e_len, // Client DH public value (mpint)
    const uint8_t *f, size_t f_len, // Server DH public value (mpint)
    const uint8_t *k, size_t k_len, // Shared secret K (mpint)
    uint8_t *hash_out               // Output: 32-byte SHA-256 hash
)
{
  sha256_ctx ctx;
  sha256_init(&ctx);

  // V_C, V_S, I_C, I_S are SSH strings.
  sha256_put_string(&ctx, v_c, v_c_len);
  sha256_put_string(&ctx, v_s, v_s_len);
  sha256_put_string(&ctx, i_c, i_c_len);
  sha256_put_string(&ctx, i_s, i_s_len);

  // K_S is already an SSH string on-wire (length + blob), so hash it as-is.
  if (k_s_len)
    sha256_update(&ctx, k_s, k_s_len);

  // GEX: OpenSSH kexgex_hash omits min/max when they are -1 (wire 0xffffffff).
  // Always includes preferred bit count (n / wantbits).
  if (min != 0xFFFFFFFFu)
    sha256_put_u32be(&ctx, min);
  sha256_put_u32be(&ctx, n);
  if (max != 0xFFFFFFFFu)
    sha256_put_u32be(&ctx, max);

  // p, g, e, f, K are mpint values already encoded on-wire (length + bytes)
  if (p_len) sha256_update(&ctx, p, p_len);
  if (g_len) sha256_update(&ctx, g, g_len);
  if (e_len) sha256_update(&ctx, e, e_len);
  if (f_len) sha256_update(&ctx, f, f_len);
  if (k_len) sha256_update(&ctx, k, k_len);

  sha256_final(&ctx, hash_out);
#ifdef AJOS_SSH_DEBUG
  log_writestring("[CRYPTO] Exchange hash (SHA-256, full 32 bytes): ");
  for (int i = 0; i < 32; i++)
  {
    log_write_hex8(hash_out[i]);
    if (i < 31)
      log_putchar(' ');
  }
  log_putchar('\n');
#endif

  return 1;
}

// ============================================================================
// SSH Transport Key Derivation (RFC 4253 section 7.2)
// ============================================================================
// OpenSSH kex.c: K1 = HASH(K || H || "A" || session_id); letters A,B=IV, C,D=key, E,F=MAC.
static void ssh_kdf_one(const uint8_t *k_mpint, uint16_t k_mpint_len,
                        const uint8_t *h, uint8_t letter, uint8_t *out16)
{
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_mpint, k_mpint_len);  // K first (shared_secret)
  sha256_update(&ctx, h, 32);                 // H (exchange hash)
  sha256_update(&ctx, &letter, 1);            // 'A','B','C','D'
  sha256_update(&ctx, h, 32);                 // session_id = H
  uint8_t digest[32];
  sha256_final(&ctx, digest);
  for (int i = 0; i < 16; i++)
    out16[i] = digest[i];
}

// Same KDF but output full 32 bytes (for MAC keys E, F).
static void ssh_kdf_one_32(const uint8_t *k_mpint, uint16_t k_mpint_len,
                           const uint8_t *h, uint8_t letter, uint8_t *out32)
{
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, k_mpint, k_mpint_len);
  sha256_update(&ctx, h, 32);
  sha256_update(&ctx, &letter, 1);
  sha256_update(&ctx, h, 32);
  sha256_final(&ctx, out32);
}

// Derive recv/send IV, key, and optional MAC keys. recv_mac_key/send_mac_key may be NULL.
void ssh_derive_transport_keys(const uint8_t *exchange_hash,
                                const uint8_t *k_mpint, uint16_t k_mpint_len,
                                uint8_t *recv_iv, uint8_t *recv_key,
                                uint8_t *send_iv, uint8_t *send_key,
                                uint8_t *recv_mac_key, uint8_t *send_mac_key)
{
  ssh_kdf_one(k_mpint, k_mpint_len, exchange_hash, 'A', recv_iv);
  ssh_kdf_one(k_mpint, k_mpint_len, exchange_hash, 'B', send_iv);
  ssh_kdf_one(k_mpint, k_mpint_len, exchange_hash, 'C', recv_key);
  ssh_kdf_one(k_mpint, k_mpint_len, exchange_hash, 'D', send_key);
  if (recv_mac_key)
    ssh_kdf_one_32(k_mpint, k_mpint_len, exchange_hash, 'E', recv_mac_key);
  if (send_mac_key)
    ssh_kdf_one_32(k_mpint, k_mpint_len, exchange_hash, 'F', send_mac_key);
}

// Derive using K value only (no 4-byte length). Some clients use this for KDF.
void ssh_derive_transport_keys_k_value_only(const uint8_t *exchange_hash,
                                             const uint8_t *k_value, uint16_t k_value_len,
                                             uint8_t *recv_iv, uint8_t *recv_key,
                                             uint8_t *send_iv, uint8_t *send_key,
                                             uint8_t *recv_mac_key, uint8_t *send_mac_key)
{
  ssh_kdf_one(k_value, k_value_len, exchange_hash, 'A', recv_iv);
  ssh_kdf_one(k_value, k_value_len, exchange_hash, 'B', send_iv);
  ssh_kdf_one(k_value, k_value_len, exchange_hash, 'C', recv_key);
  ssh_kdf_one(k_value, k_value_len, exchange_hash, 'D', send_key);
  if (recv_mac_key)
    ssh_kdf_one_32(k_value, k_value_len, exchange_hash, 'E', recv_mac_key);
  if (send_mac_key)
    ssh_kdf_one_32(k_value, k_value_len, exchange_hash, 'F', send_mac_key);
}

// KDF known-answer test (RFC 4253): K = mpint(1), H = 32 zero bytes,
// letter 'A' -> first 16 bytes of SHA-256(K||H||'A'||H) must match reference.
static const uint8_t kdf_kat_k[] = { 0x00, 0x00, 0x00, 0x01, 0x01 };
static const uint8_t kdf_kat_h[32] = { 0 };
static const uint8_t kdf_kat_expected[16] = {
  0x6b, 0x1e, 0x7a, 0x45, 0x72, 0x4d, 0x96, 0xf6,
  0xe3, 0x47, 0xa1, 0xce, 0xa6, 0x61, 0xd8, 0xf9
};

void ssh_kdf_selftest(void)
{
  uint8_t out[16];
  ssh_kdf_one(kdf_kat_k, sizeof(kdf_kat_k), kdf_kat_h, 'A', out);
  int ok = 1;
  for (int i = 0; i < 16; i++)
    if (out[i] != kdf_kat_expected[i])
      ok = 0;
  if (ok)
    log_writestring("[CRYPTO] SSH KDF selftest OK\n");
  else
  {
    log_writestring("[CRYPTO] SSH KDF selftest FAIL; got: ");
    for (int i = 0; i < 16; i++)
    {
      log_write_hex8(out[i]);
      if (i < 15) log_putchar(' ');
    }
    log_writestring("\n");
  }
}

// DH known-answer test: K = e^y mod p with p=23, g=5, e=6, y=15 -> K = 8
// (6^15 mod 23 = 8). Verifies bigint_mod_exp for SSH key exchange.
void ssh_dh_selftest(void)
{
  uint8_t p_val[RSA_KEY_SIZE], g_val[RSA_KEY_SIZE], e_val[RSA_KEY_SIZE];
  uint8_t y[RSA_KEY_SIZE], k_val[RSA_KEY_SIZE];
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    p_val[i] = g_val[i] = e_val[i] = y[i] = k_val[i] = 0;
  }
  p_val[RSA_KEY_SIZE - 1] = 23;
  g_val[RSA_KEY_SIZE - 1] = 5;
  e_val[RSA_KEY_SIZE - 1] = 6;
  y[RSA_KEY_SIZE - 1] = 15;

  bigint_mod_exp(e_val, y, p_val, k_val);

  int ok = (k_val[RSA_KEY_SIZE - 1] == 8);
  for (int i = 0; i < RSA_KEY_SIZE - 1 && ok; i++)
    ok = (k_val[i] == 0);

  if (ok)
    log_writestring("[CRYPTO] SSH DH selftest OK (6^15 mod 23 = 8)\n");
  else
  {
    log_writestring("[CRYPTO] SSH DH selftest FAIL; k_val last 4 bytes: ");
    for (int i = RSA_KEY_SIZE - 4; i < RSA_KEY_SIZE; i++)
    {
      log_write_hex8(k_val[i]);
      if (i < RSA_KEY_SIZE - 1) log_putchar(' ');
    }
    log_writestring(" (expected 0 0 0 8)\n");
  }
}

// ============================================================================
// AES-128 (one block encrypt) and CTR mode for SSH transport
// ============================================================================
#define AES128_BLOCK 16
#define AES128_ROUNDS 10

static const uint8_t aes_sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
  0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
  0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
  0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
  0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
  0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
  0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
  0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
  0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
  0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
  0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
  0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
  0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
  0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
  0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
  0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
  0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t aes_rcon[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint8_t aes_gf2_mul(uint8_t a, uint8_t b)
{
  uint8_t p = 0;
  for (int i = 0; i < 8; i++)
  {
    if (b & 1)
      p ^= a;
    if (a & 0x80)
      a = (a << 1) ^ 0x1b;
    else
      a <<= 1;
    b >>= 1;
  }
  return p;
}

static void aes128_keyschedule(const uint8_t *key, uint8_t *round_keys)
{
  for (int i = 0; i < 16; i++)
    round_keys[i] = key[i];
  /* RotWord then SubWord on previous word (bytes 12..15): (k12,k13,k14,k15) ->
   * (S(k13),S(k14),S(k15),S(k12)) — FIPS-197 key expansion. */
  for (int i = 1; i <= AES128_ROUNDS; i++)
  {
    int base = (i - 1) * 16;
    int next = i * 16;
    round_keys[next + 0] =
        aes_sbox[round_keys[base + 13]] ^ round_keys[base + 0] ^ aes_rcon[i];
    round_keys[next + 1] = aes_sbox[round_keys[base + 14]] ^ round_keys[base + 1];
    round_keys[next + 2] = aes_sbox[round_keys[base + 15]] ^ round_keys[base + 2];
    round_keys[next + 3] = aes_sbox[round_keys[base + 12]] ^ round_keys[base + 3];
    for (int j = 0; j < 12; j++)
      round_keys[next + 4 + j] = round_keys[base + 4 + j] ^ round_keys[next + j];
  }
}

/* State is column-major: column c = s[4*c..4*c+3] (FIPS-197). */
static inline void aes_mixcolumns(uint8_t *s)
{
  uint8_t t[4];
  for (int c = 0; c < 4; c++)
  {
    int b = 4 * c;
    t[0] = s[b];
    t[1] = s[b + 1];
    t[2] = s[b + 2];
    t[3] = s[b + 3];
    s[b] = aes_gf2_mul(t[0], 2) ^ aes_gf2_mul(t[1], 3) ^ t[2] ^ t[3];
    s[b + 1] = t[0] ^ aes_gf2_mul(t[1], 2) ^ aes_gf2_mul(t[2], 3) ^ t[3];
    s[b + 2] = t[0] ^ t[1] ^ aes_gf2_mul(t[2], 2) ^ aes_gf2_mul(t[3], 3);
    s[b + 3] = aes_gf2_mul(t[0], 3) ^ t[1] ^ t[2] ^ aes_gf2_mul(t[3], 2);
  }
}

static void aes128_encrypt_block(const uint8_t *round_keys, const uint8_t *in,
                                 uint8_t *out)
{
  uint8_t s[16];
  for (int i = 0; i < 16; i++)
    s[i] = in[i] ^ round_keys[i];
  for (int r = 1; r < AES128_ROUNDS; r++)
  {
    for (int i = 0; i < 16; i++)
      s[i] = aes_sbox[s[i]];
    uint8_t t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    t = s[2];
    s[2] = s[10];
    s[10] = t;
    t = s[6];
    s[6] = s[14];
    s[14] = t;
    t = s[3];
    s[3] = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = t;
    aes_mixcolumns(s);
    for (int i = 0; i < 16; i++)
      s[i] ^= round_keys[r * 16 + i];
  }
  for (int i = 0; i < 16; i++)
    s[i] = aes_sbox[s[i]];
  uint8_t t = s[1];
  s[1] = s[5];
  s[5] = s[9];
  s[9] = s[13];
  s[13] = t;
  /* Row 2: shift left by 2 (same as middle rounds; was missing — broke FIPS-197). */
  t = s[2];
  s[2] = s[10];
  s[10] = t;
  t = s[6];
  s[6] = s[14];
  s[14] = t;
  t = s[3];
  s[3] = s[15];
  s[15] = s[11];
  s[11] = s[7];
  s[7] = t;
  for (int i = 0; i < 16; i++)
    out[i] = s[i] ^ round_keys[AES128_ROUNDS * 16 + i];
}

// One block of keystream (for debug): out = AES_Encrypt(key, ctr). ctr is not modified.
//
// Callers that CTR-encrypt/decrypt a multi-block buffer (src/tls.c's GCM
// path, in particular) call this once per 16-byte block with the SAME key
// each time — a 16KB TLS record is 1024 calls. Recomputing the key
// schedule (11 round keys, each needing S-box lookups) on every one of
// those calls when the key hasn't changed was the dominant cost measured
// in real page fetches (a table-based GHASH barely moved the needle,
// which was the tell that the bottleneck was here, not there). Caching
// the schedule for the most-recently-used key turns the common case
// (many calls in a row, same key) into a cheap 16-byte compare.
static uint8_t aes128_ks_cache_key[16];
static uint8_t aes128_ks_cache_rk[16 * (AES128_ROUNDS + 1)];
static int aes128_ks_cache_valid = 0;

void aes128_ctr_keystream_block(const uint8_t *key, const uint8_t *ctr, uint8_t *out)
{
  int stale = !aes128_ks_cache_valid;
  if (!stale) {
    for (int i = 0; i < 16; i++) {
      if (aes128_ks_cache_key[i] != key[i]) {
        stale = 1;
        break;
      }
    }
  }
  if (stale) {
    aes128_keyschedule(key, aes128_ks_cache_rk);
    for (int i = 0; i < 16; i++)
      aes128_ks_cache_key[i] = key[i];
    aes128_ks_cache_valid = 1;
  }
  aes128_encrypt_block(aes128_ks_cache_rk, ctr, out);
}

// CTR: encrypt ctr (16 bytes) with key, XOR into data (len bytes), then increment ctr (big-endian).
void aes128_ctr_crypt(uint8_t *key, uint8_t *ctr, uint8_t *data, int len)
{
  uint8_t round_keys[16 * (AES128_ROUNDS + 1)];
  aes128_keyschedule(key, round_keys);
  int pos = 0;
  uint8_t block[16];
  while (pos < len)
  {
    aes128_encrypt_block(round_keys, ctr, block);
    int n = 16;
    if (pos + n > len)
      n = len - pos;
    for (int i = 0; i < n; i++)
      data[pos + i] ^= block[i];
    pos += n;
    for (int i = 15; i >= 0; i--)
    {
      if (++ctr[i] != 0)
        break;
    }
  }
}

/* NIST AES-128 ECB single-block test vector (FIPS-197). */
void ssh_aes128_selftest(void)
{
  static const uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  static const uint8_t pt[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                                 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  static const uint8_t exp[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
                                  0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a};
  uint8_t round_keys[16 * (AES128_ROUNDS + 1)];
  uint8_t out[16];
  aes128_keyschedule(key, round_keys);
  aes128_encrypt_block(round_keys, pt, out);
  int ok = 1;
  for (int i = 0; i < 16; i++)
    if (out[i] != exp[i])
      ok = 0;
  if (ok)
    log_writestring("[CRYPTO] AES-128 ECB selftest OK\n");
  else
  {
    log_writestring("[CRYPTO] AES-128 ECB selftest FAIL\n");
  }
}

// ============================================================================
// SSH Signature Encoding
// ============================================================================

// Encode RSA signature in SSH wire format (OpenSSH style)
// Format: string algorithm_name || string signature_blob
// Based on OpenSSH ssh-rsa.c lines 402-403:
//   sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))  // Algorithm name
//   sshbuf_put_string(b, sig, slen)                       // Signature blob
//   (raw bytes)
//
// sshbuf_put_cstring: 4-byte length + string bytes (no null terminator)
// sshbuf_put_string: 4-byte length + raw bytes
int ssh_encode_signature(const uint8_t *signature, size_t sig_len,
                         const char *algorithm, uint8_t *output,
                         size_t *output_len)
{
  // Calculate algorithm name length (OpenSSH: strlen, no null terminator)
  size_t alg_len = 0;
  while (algorithm[alg_len] != '\0' && alg_len < 32)
    alg_len++;

  // Required space: algorithm string (4 + alg_len) + signature blob (4 +
  // sig_len)
  if (*output_len < 4 + alg_len + 4 + sig_len)
  {
    return 0; // Not enough space
  }

  size_t pos = 0;

  // Algorithm name (OpenSSH: sshbuf_put_cstring = 4-byte length + string bytes)
  output[pos++] = (alg_len >> 24) & 0xFF;
  output[pos++] = (alg_len >> 16) & 0xFF;
  output[pos++] = (alg_len >> 8) & 0xFF;
  output[pos++] = alg_len & 0xFF;
  for (size_t i = 0; i < alg_len; i++)
  {
    output[pos++] = algorithm[i];
  }

  // Signature blob (OpenSSH: sshbuf_put_string = 4-byte length + raw bytes)
  // For RSA, this is the raw RSA signature bytes (exactly RSA_KEY_SIZE bytes)
  // NO mpint encoding, NO positive indicator - just raw bytes
  output[pos++] = (sig_len >> 24) & 0xFF;
  output[pos++] = (sig_len >> 16) & 0xFF;
  output[pos++] = (sig_len >> 8) & 0xFF;
  output[pos++] = sig_len & 0xFF;

  // Write raw signature bytes (OpenSSH: exactly sig_len bytes, no encoding)
  for (size_t i = 0; i < sig_len; i++)
  {
    output[pos++] = signature[i];
  }

  // Debug: Log signature encoding (OpenSSH format)
  log_writestring("[CRYPTO] Signature encoding (OpenSSH format):\n");
  log_writestring("[CRYPTO]   Algorithm: ");
  log_writestring(algorithm);
  log_writestring(" (");
  log_write_u32(alg_len);
  log_writestring(" bytes)\n");
  log_writestring("[CRYPTO]   Signature blob: ");
  log_write_u32(sig_len);
  log_writestring(" raw bytes\n");

  *output_len = pos;
  return 1;
}

// ============================================================================
// Complete SSH Signature Generation
// ============================================================================

// Complete function to compute exchange hash, sign it, and encode for SSH
int ssh_sign_exchange_hash(
    const uint8_t *v_c, size_t v_c_len, const uint8_t *v_s, size_t v_s_len,
    const uint8_t *i_c, size_t i_c_len, const uint8_t *i_s, size_t i_s_len,
    const uint8_t *k_s, size_t k_s_len, uint32_t min, uint32_t n, uint32_t max,
    const uint8_t *p, size_t p_len, const uint8_t *g, size_t g_len,
    const uint8_t *e, size_t e_len, const uint8_t *f, size_t f_len,
    const uint8_t *k, size_t k_len, const char *signature_algorithm,
    uint8_t *signature_out, size_t *signature_out_len)
{
  // Step 1: Compute exchange hash (SHA-256 for
  // diffie-hellman-group-exchange-sha256)
  uint8_t exchange_hash_sha256[32];
  if (!ssh_compute_exchange_hash(v_c, v_c_len, v_s, v_s_len, i_c, i_c_len, i_s,
                                 i_s_len, k_s, k_s_len, min, n, max, p, p_len,
                                 g, g_len, e, e_len, f, f_len, k, k_len,
                                 exchange_hash_sha256))
  {
    return 0;
  }

  // Debug: Log complete exchange hash (needed to validate OpenSSH signature
  // failures).
  log_writestring("[CRYPTO] Exchange hash H (SHA-256, 32 bytes): ");
  for (int i = 0; i < 32; i++)
  {
    log_write_hex8(exchange_hash_sha256[i]);
    if (i < 31)
      log_putchar(' ');
  }
  log_putchar('\n');

  // Step 2: Get RSA key (heap to reduce stack pressure)
  rsa_key *key = (rsa_key *)kmalloc(sizeof(rsa_key));
  if (!key)
    return 0;
  get_default_rsa_key(key);

  // Step 3: Determine hash algorithm based on signature algorithm (OpenSSH
  // style) OpenSSH behavior (ssh-rsa.c lines 372-378):
  // - Hash the data first with the appropriate algorithm (SHA-1, SHA-256, or
  // SHA-512)
  // - Then sign the hash using PKCS#1 v1.5 with matching DER encoding
  //
  // For rsa-sha2-512: Hash exchange hash with SHA-512, sign with SHA-512 DER
  // For rsa-sha2-256: Hash exchange hash with SHA-256, sign with SHA-256 DER
  // For ssh-rsa: Hash exchange hash with SHA-1, sign with SHA-1 DER
  uint8_t hash_to_sign[64];
  size_t hash_to_sign_len = 0;
  const char *der_algorithm = "sha512";

  if (signature_algorithm &&
      (strncmp(signature_algorithm, "rsa-sha2-512", 12) == 0 ||
       strncmp(signature_algorithm, "rsa-sha2-256", 12) == 0))
  {
    if (strncmp(signature_algorithm, "rsa-sha2-512", 12) == 0)
    {
      // OpenSSH: For rsa-sha2-512, hash the exchange hash with SHA-512
      // Then sign using PKCS#1 v1.5 with SHA-512 DER encoding
      sha512(exchange_hash_sha256, 32, hash_to_sign);
      hash_to_sign_len = 64;
      der_algorithm = "sha512";
      log_writestring(
          "[CRYPTO] Signature: rsa-sha2-512 (SHA-512 over H)\n");
    }
    else
    {
      // OpenSSH: For rsa-sha2-256, hash the exchange hash with SHA-256
      // Then sign using PKCS#1 v1.5 with SHA-256 DER encoding
      for (int i = 0; i < 32; i++)
      {
        hash_to_sign[i] = exchange_hash_sha256[i];
      }
      hash_to_sign_len = 32;
      der_algorithm = "sha256";
      log_writestring("[CRYPTO] Signature: rsa-sha2-256 (NOTE: uses H directly)\n");
    }
  }
  else
  {
    // OpenSSH: For ssh-rsa, hash the exchange hash with SHA-1
    // Since we don't have SHA-1, we'll use SHA-256 but this may fail
    // TODO: Implement SHA-1 for full compatibility
    sha256(exchange_hash_sha256, 32, hash_to_sign);
    hash_to_sign_len = 32;
    der_algorithm =
        "sha1"; // Use SHA-1 DER encoding even though we hashed with SHA-256
#ifdef AJOS_SSH_DEBUG
    log_writestring("[CRYPTO] Using ssh-rsa: hashed exchange hash with SHA-256 "
                    "(SHA-1 not available)\n");
    log_writestring("[CRYPTO] WARNING: Using SHA-256 hash with SHA-1 DER may "
                    "cause verification to fail\n");
#endif
  }

  // Debug: log the exact bytes that go into RSA padding.
  log_writestring("[CRYPTO] Hash input to RSA padding (");
  log_write_u32((uint32_t)hash_to_sign_len);
  log_writestring(" bytes): ");
  for (size_t i = 0; i < hash_to_sign_len; i++)
  {
    log_write_hex8(hash_to_sign[i]);
    if (i + 1 < hash_to_sign_len)
      log_putchar(' ');
  }
  log_putchar('\n');

  // Step 4: Sign the hash with RSA (OpenSSH style)
  // OpenSSH: RSA_sign() returns signature, then pads with leading zeros if
  // needed
  uint8_t raw_signature[RSA_KEY_SIZE];
  int sig_len = rsa_sign(hash_to_sign, hash_to_sign_len, der_algorithm, key,
                         raw_signature);
  if (sig_len == 0)
  {
    kfree(key);
    return 0;
  }
  kfree(key);

  // OpenSSH ensures signature is exactly RSA_KEY_SIZE bytes
  // (already handled in rsa_sign with padding, but verify)
  if (sig_len != RSA_KEY_SIZE)
  {
    log_writestring("[CRYPTO] ERROR: Signature length mismatch: got ");
    log_write_u32(sig_len);
    log_writestring(", expected ");
    log_write_u32(RSA_KEY_SIZE);
    log_putchar('\n');
    return 0;
  }

  // Verify signature is not all zeros before encoding
  int sig_all_zero = 1;
  for (int i = 0; i < sig_len; i++)
  {
    if (raw_signature[i] != 0)
    {
      sig_all_zero = 0;
      break;
    }
  }
  if (sig_all_zero)
  {
    log_writestring(
        "[CRYPTO] ERROR: RSA signature is all zeros, cannot encode!\n");
    return 0;
  }

  // Debug: log full raw RSA signature bytes so we can verify off-box.
  log_writestring("[CRYPTO] Raw RSA signature (256 bytes):\n");
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(raw_signature[i]);
    if ((i % 16) == 15)
      log_putchar('\n');
    else
      log_putchar(' ');
  }

  // Step 5: Encode signature for SSH
  size_t encoded_len = *signature_out_len;
  if (!ssh_encode_signature(raw_signature, sig_len,
                            signature_algorithm ? signature_algorithm
                                                : "rsa-sha2-512",
                            signature_out, &encoded_len))
  {
    log_writestring("[CRYPTO] ERROR: ssh_encode_signature failed!\n");
    return 0;
  }

#ifdef AJOS_SSH_DEBUG
  // Debug: Log complete encoded signature (first 64 bytes for visibility)
  log_writestring("[CRYPTO] Encoded signature (first 64 bytes of ");
  log_write_u32(encoded_len);
  log_writestring(" total):\n");
  for (size_t i = 0; i < encoded_len && i < 64; i++)
  {
    log_write_hex8(signature_out[i]);
    if ((i + 1) % 16 == 0)
    {
      log_putchar('\n');
    }
    else
    {
      log_putchar(' ');
    }
  }
  if (encoded_len > 64)
  {
    log_writestring("... (truncated, see structure below)\n");
  }
  else
  {
    log_putchar('\n');
  }

  // Also log structure breakdown
  if (encoded_len >= 4)
  {
    uint32_t algo_len = (signature_out[0] << 24) | (signature_out[1] << 16) |
                        (signature_out[2] << 8) | signature_out[3];
    log_writestring("[CRYPTO]   Algorithm (");
    log_write_u32(algo_len);
    log_writestring(" bytes): ");
    for (uint32_t i = 0; i < algo_len && i < 20; i++)
    {
      log_putchar(signature_out[4 + i]);
    }
    log_putchar('\n');

    if (encoded_len >= 4 + algo_len + 4)
    {
      uint32_t sig_blob_len = (signature_out[4 + algo_len] << 24) |
                              (signature_out[4 + algo_len + 1] << 16) |
                              (signature_out[4 + algo_len + 2] << 8) |
                              (signature_out[4 + algo_len + 3]);
      log_writestring("[CRYPTO]   Signature blob (raw bytes, ");
      log_write_u32(sig_blob_len);
      log_writestring(" bytes)\n");
    }
  }
#endif

  *signature_out_len = encoded_len;
  return 1;
}

// Test function for RSA modular exponentiation
// This tests the fix for the leading zero bits bug
// Minimal test: 2^3 mod 5 = 3
void test_simple_modexp(void)
{
  log_writestring("\n[TEST] Simple modular exponentiation test: 2^3 mod 5 = 3\n");

  // Create small numbers in 256-byte big-endian format
  // 2 = [0, 0, ..., 0, 2] (LSB at index 255)
  // 3 = [0, 0, ..., 0, 3] (LSB at index 255)
  // 5 = [0, 0, ..., 0, 5] (LSB at index 255)

  uint8_t base[RSA_KEY_SIZE];
  uint8_t exp[RSA_KEY_SIZE];
  uint8_t mod[RSA_KEY_SIZE];
  uint8_t result[RSA_KEY_SIZE];
  uint8_t expected[RSA_KEY_SIZE];

  // Initialize to zero
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    base[i] = 0;
    exp[i] = 0;
    mod[i] = 0;
    result[i] = 0;
    expected[i] = 0;
  }

  // Set values (big-endian: MSB at 0, LSB at 255)
  base[RSA_KEY_SIZE - 1] = 2;     // base = 2
  exp[RSA_KEY_SIZE - 1] = 3;      // exp = 3
  mod[RSA_KEY_SIZE - 1] = 5;      // mod = 5
  expected[RSA_KEY_SIZE - 1] = 3; // expected = 3

  log_writestring("[TEST] Computing 2^3 mod 5...\n");
  bigint_mod_exp(base, exp, mod, result);

  log_writestring("[TEST] Result (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  log_writestring("[TEST] Expected (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(expected[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  // Check if result == expected
  int correct = 1;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (result[i] != expected[i])
    {
      correct = 0;
      log_writestring("[TEST] Mismatch at byte ");
      log_write_u32(i);
      log_writestring(": got ");
      log_write_hex8(result[i]);
      log_writestring(", expected ");
      log_write_hex8(expected[i]);
      log_putchar('\n');
      break;
    }
  }

  if (correct)
  {
    log_writestring("[TEST] SUCCESS: 2^3 mod 5 = 3 (correct)\n");
  }
  else
  {
    log_writestring("[TEST] FAILURE: 2^3 mod 5 != 3 (bug found!)\n");
  }
  log_putchar('\n');
}

void test_rsa_modexp(void)
{
  log_writestring("\n[TEST] Starting RSA modular exponentiation test\n");
  log_writestring("[TEST] Testing: 2^65537 mod n (where n is the RSA modulus)\n");

  // Get the RSA key
  rsa_key key;
  get_default_rsa_key(&key);

  // Test case: base = 2, exponent = e (65537), modulus = n
  uint8_t base[RSA_KEY_SIZE];
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    base[i] = 0;
  }
  base[RSA_KEY_SIZE - 1] = 0x02; // base = 2

  uint8_t result[RSA_KEY_SIZE];

  log_writestring("[TEST] Computing 2^e mod n...\n");
  mont_modexp_be256(base, key.e, key.n, result);

  log_writestring("[TEST] Result (first 32 bytes): ");
  for (int i = 0; i < 32; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  log_writestring("[TEST] Result (last 32 bytes): ");
  for (int i = RSA_KEY_SIZE - 32; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  // Now test the reverse: result^d mod n should equal 2
  log_writestring("\n[TEST] Verifying: result^d mod n should equal 2\n");
  uint8_t verified[RSA_KEY_SIZE];
  mont_modexp_be256(result, key.d, key.n, verified);

  log_writestring("[TEST] Verified result (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(verified[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  // Check if it equals 2
  int correct = 1;
  for (int i = 0; i < RSA_KEY_SIZE - 1; i++)
  {
    if (verified[i] != 0)
    {
      correct = 0;
      break;
    }
  }
  if (verified[RSA_KEY_SIZE - 1] != 0x02)
  {
    correct = 0;
  }

  if (correct)
  {
    log_writestring("[TEST] SUCCESS: RSA modular exponentiation is working correctly!\n");
  }
  else
  {
    log_writestring("[TEST] FAILURE: RSA modular exponentiation produced wrong result!\n");
  }

  log_writestring("[TEST] Test complete\n\n");
}

// Test RSA signature computation and verification directly
void test_rsa_signature_direct(void)
{
  log_writestring("\n[TEST] Direct RSA signature computation and verification test\n");
  log_writestring("[TEST] This tests: padded^d mod n, then (signature)^e mod n == padded\n");
  
  // Get the RSA key
  rsa_key key;
  get_default_rsa_key(&key);
  
  // Create a test padded message via the real PKCS#1 v1.5 routine.
  // (The previous hand-built version had an out-of-bounds write.)
  uint8_t test_hash[32];
  for (int i = 0; i < 32; i++)
    test_hash[i] = (uint8_t)(0xAA + i);

  uint8_t padded[RSA_KEY_SIZE];
  if (!pkcs1_v15_pad(test_hash, sizeof(test_hash), "sha256", padded, RSA_KEY_SIZE))
  {
    log_writestring("[TEST] ERROR: pkcs1_v15_pad failed in test\n");
    return;
  }
  
  log_writestring("[TEST] Test padded message (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(padded[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[TEST] Test padded message (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(padded[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  
  // Step 1: Compute signature = padded^d mod n
  log_writestring("\n[TEST] Step 1: Computing signature = padded^d mod n...\n");
  uint8_t signature[RSA_KEY_SIZE];
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    signature[i] = 0;
  }
  mont_modexp_be256(padded, key.d, key.n, signature);
  
  log_writestring("[TEST] Signature (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(signature[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[TEST] Signature (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(signature[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  
  // Step 2: Verify signature^e mod n == padded
  log_writestring("\n[TEST] Step 2: Verifying signature^e mod n == padded...\n");
  uint8_t verify_result[RSA_KEY_SIZE];
  mont_modexp_be256(signature, key.e, key.n, verify_result);
  
  log_writestring("[TEST] Verification result (first 16 bytes): ");
  for (int i = 0; i < 16; i++)
  {
    log_write_hex8(verify_result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  log_writestring("[TEST] Verification result (last 16 bytes): ");
  for (int i = RSA_KEY_SIZE - 16; i < RSA_KEY_SIZE; i++)
  {
    log_write_hex8(verify_result[i]);
    log_putchar(' ');
  }
  log_putchar('\n');
  
  // Compare
  int match = 1;
  int first_mismatch = -1;
  int mismatch_count = 0;
  for (int i = 0; i < RSA_KEY_SIZE; i++)
  {
    if (verify_result[i] != padded[i])
    {
      match = 0;
      mismatch_count++;
      if (first_mismatch < 0)
        first_mismatch = i;
    }
  }
  
  if (match)
  {
    log_writestring("[TEST] SUCCESS: signature^e mod n == padded (RSA signature works!)\n");
  }
  else
  {
    log_writestring("[TEST] FAILURE: signature^e mod n != padded (RSA signature broken!)\n");
    log_writestring("[TEST] Mismatches: ");
    log_write_u32(mismatch_count);
    log_writestring(" out of 256 bytes\n");
    log_writestring("[TEST] First mismatch at byte ");
    log_write_u32(first_mismatch);
    log_writestring("\n[TEST] Expected (padded, byte ");
    log_write_u32(first_mismatch);
    log_writestring("): ");
    log_write_hex8(padded[first_mismatch]);
    log_writestring("\n[TEST] Got (verify_result, byte ");
    log_write_u32(first_mismatch);
    log_writestring("): ");
    log_write_hex8(verify_result[first_mismatch]);
    log_putchar('\n');
  }
  
  log_writestring("[TEST] Direct signature test complete\n\n");
}
