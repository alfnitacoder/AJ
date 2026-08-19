/**
 * Minimal soft-float math for LLM inference.
 * AJOS uses -msoft-float -nostdlib, so we provide these.
 */
#include <stdint.h>

/* Bit-cast for float <-> uint32 */
static inline float u32_to_float(uint32_t u) {
  union {
    uint32_t u;
    float f;
  } x;
  x.u = u;
  return x.f;
}
static inline uint32_t float_to_u32(float f) {
  union {
    float f;
    uint32_t u;
  } x;
  x.f = f;
  return x.u;
}

float sqrtf(float x) {
  if (x <= 0.0f)
    return 0.0f;
  float res;
  __asm__ volatile("fsqrt" : "=t"(res) : "0"(x));
  return res;
}

float expf(float x) {
  if (x < -88.0f)
    return 0.0f;
  if (x > 88.0f)
    return 1e37f;

  float res;
  float log2e = 1.44269504089f;
  __asm__ volatile("fld %1\n\t"
                   "fmul %2\n\t"
                   "fld %%st(0)\n\t"
                   "frndint\n\t"
                   "fsub %%st(0), %%st(1)\n\t"
                   "fxch %%st(1)\n\t"
                   "f2xm1\n\t"
                   "fld1\n\t"
                   "faddp\n\t"
                   "fscale\n\t"
                   "fstp %%st(1)\n\t"
                   : "=t"(res)
                   : "m"(x), "m"(log2e));
  return res;
}

float cosf(float x) {
  while (x > 3.14159265f)
    x -= 6.28318531f;
  while (x < -3.14159265f)
    x += 6.28318531f;
  float x2 = x * x;
  return 1.0f - x2 * 0.5f + x2 * x2 * 0.041666667f -
         x2 * x2 * x2 * 0.0013888889f;
}

float sinf(float x) {
  while (x > 3.14159265f)
    x -= 6.28318531f;
  while (x < -3.14159265f)
    x += 6.28318531f;
  float x2 = x * x;
  return x * (1.0f - x2 * 0.16666667f + x2 * x2 * 0.0083333333f);
}

float logf(float x) {
  if (x <= 0.0f)
    return -1e37f;
  float res;
  float ln2_inv =
      0.69314718056f; /* log2(e) actually, wait. loge(x) = log2(x) * ln(2) */
  float ln2 = 0.69314718056f;
  __asm__ volatile("fldln2\n\t"
                   "fld %1\n\t"
                   "fyl2x"
                   : "=t"(res)
                   : "m"(x)
                   : "st(1)");
  return res;
}

float powf(float base, float exp) {
  if (base <= 0.0f)
    return 0.0f;
  if (exp == 0.0f)
    return 1.0f;
  /* pow(a,b) = exp(b * log(a)) */
  return expf(exp * logf(base));
}
