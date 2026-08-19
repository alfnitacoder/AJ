# OpenSSH Crypto: What's Portable vs. What Requires OpenSSL

## TL;DR: You're Partially Right

**OpenSSH has portable crypto for:**
- ✅ AES (Rijndael) - `rijndael.c` - Pure C, no dependencies
- ✅ ChaCha20 - `chacha.c` - Pure C, no dependencies  
- ✅ Poly1305 - `poly1305.c` - Pure C, no dependencies
- ✅ MD5, SHA1, SHA2 - `openbsd-compat/sha*.c` - Pure C, no dependencies
- ✅ HMAC - `hmac.c` - Pure C, uses digest functions

**OpenSSH REQUIRES OpenSSL for:**
- ❌ RSA - `ssh-rsa.c` - Uses OpenSSL's BIGNUM and RSA
- ❌ Diffie-Hellman - `dh.c` - Uses OpenSSL's BIGNUM and DH
- ❌ Big Integer Math - All RSA/DH operations need BIGNUM

## The Reality

### What You Can Replace Immediately

**Replace your SHA-256/SHA-512 with OpenSSH's:**
```c
// Instead of your crypto.c SHA functions, use:
#include "openbsd-compat/sha2.h"

// OpenSSH's API:
SHA256_CTX ctx;
SHA256_Init(&ctx);
SHA256_Update(&ctx, data, len);
SHA256_Final(digest, &ctx);
```

**Replace your AES with OpenSSH's Rijndael:**
```c
// Instead of your custom AES, use:
#include "rijndael.h"

rijndael_ctx ctx;
rijndael_set_key(&ctx, key, keylen, 1);  // 1 = encrypt
rijndael_encrypt(&ctx, plaintext, ciphertext);
```

**Use ChaCha20-Poly1305 (modern, fast):**
```c
#include "chacha.h"
#include "poly1305.h"

// ChaCha20-Poly1305 is the preferred cipher in modern OpenSSH
```

### What You CANNOT Replace (Without Porting OpenSSL)

**RSA and DH require big integer math (BIGNUM):**

OpenSSH's `ssh-rsa.c` and `dh.c` are just wrappers around OpenSSL:
```c
// From ssh-rsa.c:
#include <openssl/bn.h>      // Big Number library
#include <openssl/evp.h>     // High-level crypto API
#include <openssl/rsa.h>     // RSA operations

// All RSA operations use OpenSSL:
RSA *rsa = EVP_PKEY_get0_RSA(key->pkey);
RSA_sign(...);  // OpenSSL function
```

**Your options for RSA/DH:**

1. **Keep your `crypto.c`** (fix the bug) - ✅ Recommended
   - You already have `bigint_mod_exp` (just needs fixing)
   - No porting work
   - Already integrated

2. **Port OpenSSL's BIGNUM library** - ❌ Not recommended
   - ~10,000+ lines of complex code
   - Months of work
   - Overkill for your needs

3. **Use a minimal BIGNUM library** - ⚠️ Possible but risky
   - Libraries like `libtommath` or `mpdecimal`
   - Still significant porting work
   - May have bugs

## Recommended Approach

### Phase 1: Use OpenSSH's Portable Crypto (Easy Wins)

**Replace immediately:**
1. ✅ SHA-256/SHA-512 → `openbsd-compat/sha2.c`
2. ✅ AES → `rijndael.c`  
3. ✅ HMAC → `hmac.c` (uses your digest)
4. ✅ ChaCha20-Poly1305 → `chacha.c` + `poly1305.c`

**Keep your custom:**
- RSA (`bigint_mod_exp` - just fix the bug)
- DH (if you have it, or port OpenSSH's DH logic but use your bigint)

### Phase 2: Fix Your RSA Bug

Instead of porting OpenSSL's BIGNUM (huge effort), **fix your `bigint_mod_exp` bug**. This is a 1-2 day fix vs. weeks of porting.

### Phase 3: Consider Minimal BIGNUM (Optional)

If you want to use OpenSSH's `ssh-rsa.c` and `dh.c` exactly as-is, you'd need to port a BIGNUM library. But this is **not necessary** - your custom RSA works fine once the bug is fixed.

## File Mapping: What to Use

| Your File | OpenSSH Replacement | Status |
|-----------|-------------------|--------|
| `crypto.c` SHA-256 | `openbsd-compat/sha2.c` | ✅ Replace |
| `crypto.c` SHA-512 | `openbsd-compat/sha2.c` | ✅ Replace |
| `crypto.c` RSA | Keep yours (fix bug) | ⚠️ Keep |
| `crypto.c` DH | Keep yours OR port OpenSSH's logic | ⚠️ Either |
| Custom AES | `rijndael.c` | ✅ Replace |
| - | `chacha.c` + `poly1305.c` | ✅ Add (modern cipher) |
| - | `hmac.c` | ✅ Add |

## Action Plan

### Step 1: Replace Hashes (1 hour)
```bash
# Copy OpenSSH's SHA implementations
cp openssh-portable/openbsd-compat/sha2.c src/openssh/
cp openssh-portable/openbsd-compat/sha2.h include/openssh/
cp openssh-portable/openbsd-compat/sha1.c src/openssh/
cp openssh-portable/openbsd-compat/sha1.h include/openssh/

# Update your code to use OpenSSH's API
# Replace: sha256(data, len, digest)
# With:    SHA256_Init/Update/Final
```

### Step 2: Replace AES (2 hours)
```bash
# Copy Rijndael
cp openssh-portable/rijndael.c src/openssh/
cp openssh-portable/rijndael.h include/openssh/

# Update your encryption to use rijndael_* functions
```

### Step 3: Add Modern Ciphers (2 hours)
```bash
# Copy ChaCha20-Poly1305
cp openssh-portable/chacha.c src/openssh/
cp openssh-portable/chacha.h include/openssh/
cp openssh-portable/poly1305.c src/openssh/
cp openssh-portable/poly1305.h include/openssh/
```

### Step 4: Keep Your RSA (Fix Bug)
- Don't replace RSA - fix your `bigint_mod_exp` bug
- Your implementation is fine, just has a math bug
- OpenSSH's RSA requires OpenSSL (not portable)

## Why Keep Your RSA?

1. **OpenSSH's RSA is not portable** - requires OpenSSL BIGNUM
2. **Your RSA is almost correct** - just needs bug fix
3. **Porting BIGNUM is huge** - 10,000+ lines, months of work
4. **Your bigint is sufficient** - once fixed, it works fine

## Conclusion

**You're right to question `crypto.c`**, but the answer is:

- ✅ **Replace**: SHA, AES, add ChaCha20-Poly1305 (use OpenSSH's portable crypto)
- ⚠️ **Keep & Fix**: RSA, DH (OpenSSH's requires OpenSSL, not worth porting)

**Total effort:**
- Replace hashes/ciphers: ~1 day
- Fix RSA bug: ~1-2 days  
- Port OpenSSL BIGNUM: ~1-2 months ❌

**Recommendation: Hybrid approach** - Use OpenSSH's portable crypto where possible, keep your RSA/DH (just fix the bug).
