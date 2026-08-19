# RSA Bug Analysis: bigint_mod_exp

## Summary

**OpenSSH has NO portable RSA** - `ssh-rsa.c` requires OpenSSL's BIGNUM library. We must fix your `bigint_mod_exp` implementation.

## The Bug

From the test logs, the RSA computation completes but verification fails. This suggests `bigint_mod_exp` is producing incorrect results.

## Potential Issues

### Issue 1: bigint_mul Indexing (Most Likely)

Looking at `bigint_mul`:
```c
for (int i = RSA_KEY_SIZE - 1; i >= 0; i--)  // i: 255 → 0 (LSB to MSB of a)
  for (int j = RSA_KEY_SIZE - 1; j >= 0; j--)  // j: 255 → 0 (LSB to MSB of b)
    result[i + j + 1] = ...
```

**Problem**: For big-endian numbers where MSB is at index 0:
- `a[255]` is LSB of `a`
- `b[255]` is LSB of `b`
- When we multiply LSB × LSB, the result should go to LSB of product
- But `result[255 + 255 + 1] = result[511]` is correct for 512-byte result (LSB at end)

**However**: The carry propagation might be wrong. When `i=0` (MSB of a) and `j=0` (MSB of b), we're multiplying MSB × MSB, which should produce the MSB of the result at `result[0 + 0 + 1] = result[1]`. But the MSB should be at `result[0]`!

**Fix**: For big-endian schoolbook multiplication, we need to adjust the indexing.

### Issue 2: bigint_mod Shift-and-Subtract

The shift-and-subtract algorithm in `bigint_mod` processes bits from MSB to LSB of input `a`, but builds result from LSB to MSB. This might be correct, but the bit-setting logic at line 648:

```c
if ((byte >> bit) & 1)
{
  result[RSA_KEY_SIZE - 1] |= 1;  // Always sets LSB
}
```

This always sets the LSB, which is correct if we're building the result from LSB up. But we need to verify the shift direction matches.

### Issue 3: Endianness Confusion

The code has comments saying "big-endian (MSB at index 0)", but the operations iterate from LSB to MSB. This is correct for arithmetic (carry propagates LSB→MSB), but we need to ensure consistency.

## Recommended Fix Strategy

1. **Create a simple test case** (2^3 mod 5 = 3) to verify `bigint_mod_exp`
2. **Fix `bigint_mul` indexing** if needed
3. **Verify `bigint_mod`** produces correct results
4. **Test with known RSA values** (small key first)

## Next Steps

1. Add a minimal test function
2. Test with small numbers (2^3 mod 5)
3. Fix the bug
4. Verify with real RSA key
