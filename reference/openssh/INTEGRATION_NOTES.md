# OpenSSH Integration Notes

## Files Copied
- `ssh-rsa.c` - RSA signing/verification (uses OpenSSL)
- `sshbuf-getput-basic.c` - Buffer manipulation functions
- `sshbuf.c`, `sshbuf.h` - Buffer structure
- `kex.c`, `kexgex.c`, `kexgexs.c` - Key exchange logic
- `sshkey.c`, `sshkey.h` - Key handling
- `ssherr.c`, `ssherr.h` - Error codes
- `digest.h`, `digest-openssl.c`, `digest-libc.c` - Hash functions

## Key Algorithms Extracted

### RSA Signing (from ssh-rsa.c:343-421)

**OpenSSH's `ssh_rsa_sign` function:**
1. Hash the data with appropriate algorithm (SHA-1, SHA-256, or SHA-512)
2. Call `RSA_sign()` which handles PKCS#1 v1.5 padding
3. If signature is shorter than `RSA_size()`, pad with leading zeros:
   ```c
   if (len < slen) {
       size_t diff = slen - len;
       memmove(sig + diff, sig, len);
       explicit_bzero(sig, diff);
   }
   ```
4. Encode signature:
   ```c
   sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg));  // Algorithm name
   sshbuf_put_string(b, sig, slen);                       // Signature blob
   ```

**Our Implementation (src/crypto.c):**
- ✅ Hash selection based on algorithm (rsa-sha2-512, rsa-sha2-256, ssh-rsa)
- ✅ PKCS#1 v1.5 padding with DER encoding
- ✅ Signature padding with leading zeros (lines 1170-1208)
- ✅ OpenSSH-style encoding (lines 1788-1845)

### Buffer Manipulation (from sshbuf-getput-basic.c)

**Key Functions:**
- `sshbuf_put_cstring()` - Writes 4-byte length + string bytes (no null terminator)
- `sshbuf_put_string()` - Writes 4-byte length + raw bytes

**Our Implementation:**
- ✅ `ssh_encode_signature()` uses same format (lines 1813-1832)

## Differences

### OpenSSH Uses:
- OpenSSL's `RSA_sign()` for signing
- OpenSSL's `BN` (Bignum) for big integer operations
- System malloc/free
- Standard C library functions

### AJOS Uses:
- Custom `bigint_mod_exp()` for RSA computation
- Custom `pkcs1_v15_pad()` for padding
- Kernel heap (`kmalloc`/`kfree`)
- Minimal C library (no stdlib)

## Status

✅ **RSA Signing Logic**: Implemented and matches OpenSSH format
✅ **Signature Encoding**: Matches OpenSSH's `sshbuf_put_cstring` + `sshbuf_put_string`
✅ **Hash Algorithm Selection**: Matches OpenSSH's logic
✅ **Signature Padding**: Matches OpenSSH's leading-zero padding

## Remaining Issues

1. **I_S Corruption**: Server KEXINIT payload is being corrupted in exchange hash
2. **RSA Key**: Need to verify 2048-bit key format is correct
3. **Network Stability**: Network drops during long RSA computation

## Next Steps

1. Fix I_S corruption issue (memory corruption or copy bug)
2. Verify RSA key format matches OpenSSH expectations
3. Test with real 2048-bit key (disabled test key)
