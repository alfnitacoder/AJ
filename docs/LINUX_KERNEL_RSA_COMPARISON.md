# Linux Kernel RSA Implementation Comparison

## Key Differences Between Linux Kernel and Our Implementation

### Linux Kernel (`mpi_powm` in `lib/crypto/mpi/mpi-pow.c`)

1. **Data Representation:**
   - Uses MPI (Multiple Precision Integer) with limbs (32/64-bit words)
   - Little-endian within limbs
   - Variable-size numbers

2. **Algorithm Flow:**
   - Line 146: Start with `result = base_reduced`
   - Line 166: Shift out first 1 bit: `e = (e << c) << 1;`
   - Lines 180-243: Main loop:
     - **ALWAYS square first** (lines 184-202)
     - Then check if bit is set: `if ((mpi_limb_signed_t) e < 0)` (line 214)
     - If bit is set, multiply (lines 215-238)
     - Shift exponent left: `e <<= 1` (line 240)

3. **Modular Reduction:**
   - Normalizes modulus first (shifts to set MSB)
   - Uses `mpihelp_divrem` for modular reduction
   - Reduces after each square and multiply

### Our Implementation (`bigint_mod_exp` in `src/crypto.c`)

1. **Data Representation:**
   - Fixed-size 256-byte arrays
   - Big-endian (MSB at index 0, LSB at index 255)

2. **Algorithm Flow:**
   - Start with `result = 1`
   - Find first 1 bit, set `result = base_reduced`, skip processing it
   - Main loop:
     - Check bit value first
     - **Then square** (line 1128)
     - If bit is set, multiply (lines 1183-1237)
   
3. **Modular Reduction:**
   - Uses `bigint_mod` with fast path for numbers < 2^2048
   - Reduces after each square and multiply

## Critical Observation

**Both algorithms should be mathematically equivalent**, but there's a subtle difference in order:

- **Linux kernel:** Square → Check bit → Multiply (if bit set)
- **Our code:** Check bit → Square → Multiply (if bit set)

The order shouldn't matter mathematically, but let's verify our implementation matches the standard square-and-multiply algorithm.

## Standard Square-and-Multiply Algorithm

For exponentiation `base^exp mod n`:
1. Start with `result = 1`
2. For each bit from MSB to LSB:
   - Square: `result = result^2 mod n`
   - If bit is 1, multiply: `result = result * base mod n`

**Our implementation matches this!** We:
- Start with `result = 1`
- Find first 1 bit and set `result = base_reduced` (equivalent to starting with base)
- For each subsequent bit: square, then multiply if bit is set

## Potential Issues to Investigate

1. **Multiplication indexing** - Verify `bigint_mul` position calculation
2. **Modular reduction** - Verify `bigint_mod` fast path correctness
3. **Base reduction** - Verify `base_512` construction for `bigint_mod`
4. **Exponent bit processing** - Verify we're processing bits in correct order

## Next Steps

The detailed logging we added should help identify where the computation diverges. Run `test_rsa` to see:
- Intermediate values during exponentiation
- Exact byte mismatches during verification
- Step-by-step signature computation
