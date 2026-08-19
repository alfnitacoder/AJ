# SSH Host Key Signature Implementation Guide

## Overview

This document explains how to implement valid SSH host key signatures to make the AJOS SSH server compatible with standard SSH clients (like OpenSSH).

## Current Status

The SSH server currently uses **dummy signatures** that are rejected by real SSH clients. The handshake completes, but clients disconnect after signature verification fails.

## Required Components

### 1. Exchange Hash (H) Construction

The exchange hash H is computed as:

```
H = SHA-512(V_C || V_S || I_C || I_S || K_S || min || preferred || max || p || g || e || f)
```

Where:
- **V_C**: Client version string (e.g., "SSH-2.0-OpenSSH_9.9\r\n")
- **V_S**: Server version string (e.g., "SSH-2.0-AJOS_1.0\r\n")
- **I_C**: Client KEXINIT payload (raw bytes, without packet framing)
- **I_S**: Server KEXINIT payload (raw bytes, without packet framing)
- **K_S**: Server host public key blob (SSH wire format)
- **min, preferred, max**: Group-exchange parameters (uint32, big-endian)
- **p**: Prime p (mpint format: [length(4)] [value...])
- **g**: Generator g (mpint format)
- **e**: Client DH public value (mpint format)
- **f**: Server DH public value (mpint format)

**Implementation**: See `src/crypto.c::ssh_compute_exchange_hash()`

### 2. SHA-512 Hashing

The exchange hash is hashed with SHA-512:

```
hash = SHA-512(H)
```

**Implementation**: See `src/crypto.c::sha512()`

### 3. RSA Signing with PKCS#1 v1.5 Padding

The hash is signed using RSA with PKCS#1 v1.5 padding:

```
padded = 0x00 || 0x01 || [0xFF...] || 0x00 || [DER-encoded hash algorithm] || hash
signature = padded^d mod n
```

Where:
- **d**: RSA private exponent
- **n**: RSA modulus
- **DER encoding**: ASN.1 DER structure identifying SHA-512

**Implementation**: See `src/crypto.c::pkcs1_v15_pad()` and `rsa_sign()`

### 4. SSH Signature Encoding

The signature is encoded in SSH wire format:

```
string "rsa-sha2-512" || string signature_blob
```

Where `signature_blob` is the raw RSA signature bytes (256 bytes for 2048-bit key).

**Implementation**: See `src/crypto.c::ssh_encode_signature()`

## Integration Steps

### Step 1: Store Exchange Hash Components

During the SSH handshake, store all components needed for the exchange hash:

1. **Client version (V_C)**: Store in `ssh_handle_version()`
2. **Server version (V_S)**: Use `SSH_VERSION_STRING`
3. **Client KEXINIT (I_C)**: Store in `ssh_handle_kexinit()`
4. **Server KEXINIT (I_S)**: Store when sending KEXINIT
5. **Host key (K_S)**: Store when constructing GEX_REPLY
6. **GEX parameters**: Store in `ssh_handle_kexdh_gex_request()`
7. **Prime p, generator g**: Store in `ssh_handle_kexdh_gex_request()`
8. **Client DH value (e)**: Store in `ssh_handle_kexdh_gex_init()`
9. **Server DH value (f)**: Store when constructing GEX_REPLY

### Step 2: Compute Exchange Hash

When all components are available (in `ssh_handle_kexdh_gex_init()`), compute:

```c
uint8_t exchange_hash[64];
ssh_compute_exchange_hash(
  conn->v_c, conn->v_c_len,
  (uint8_t*)SSH_VERSION_STRING, SSH_VERSION_LEN,
  conn->i_c, conn->i_c_len,
  conn->i_s, conn->i_s_len,
  conn->k_s, conn->k_s_len,
  conn->gex_min, conn->gex_preferred, conn->gex_max,
  conn->gex_p, conn->gex_p_len,
  conn->gex_g, conn->gex_g_len,
  conn->gex_e, conn->gex_e_len,
  conn->gex_f, conn->gex_f_len,
  exchange_hash
);
```

### Step 3: Sign the Hash

Sign the exchange hash with RSA:

```c
// NOTE: Requires a real RSA key pair
rsa_key host_key = {
  .n = { /* 2048-bit modulus */ },
  .e = { /* public exponent (usually 65537) */ },
  .d = { /* private exponent */ }
};

uint8_t signature[256];
int sig_len = rsa_sign(exchange_hash, 64, &host_key, signature);
```

### Step 4: Encode and Send Signature

Encode the signature in SSH wire format and include it in GEX_REPLY:

```c
uint8_t encoded_sig[512];
size_t encoded_len = sizeof(encoded_sig);
ssh_encode_signature(signature, sig_len, encoded_sig, &encoded_len);

// Include encoded_sig in GEX_REPLY packet
```

## Critical Implementation Notes

### RSA Key Pair Required

**You must generate a real RSA-2048 key pair**. The current implementation uses dummy keys that will never work.

Options:
1. **Generate externally**: Use `ssh-keygen -t rsa -b 2048` and extract n, e, d
2. **Generate at runtime**: Implement RSA key generation (complex)
3. **Hardcode a test key**: For development only (not secure)

### Big Integer Arithmetic

The RSA implementation requires proper big integer arithmetic for:
- Modular exponentiation (`a^b mod n`)
- Modular multiplication
- Efficient modular reduction (Montgomery method recommended)

**Current Status**: `src/crypto.c` includes a stub for `rsa_mod_exp()`. This must be replaced with a real implementation.

### Common Pitfalls

1. **Wrong exchange hash order**: Components must be concatenated in exact order per RFC 4253
2. **Missing version strings**: V_C and V_S must include `\r\n` terminators
3. **KEXINIT payload format**: I_C and I_S are the raw payload bytes, not the full SSH packet
4. **mpint encoding**: All DH values must be in mpint format (length prefix + value)
5. **Signature encoding**: SSH expects raw signature bytes, not ASN.1 wrapped
6. **PKCS#1 padding**: Must use exact format: `00 01 [FF...] 00 [DER] [hash]`
7. **Big-endian**: All multi-byte integers must be big-endian

### Testing

To verify the implementation:

1. **Compute exchange hash**: Compare with OpenSSH's debug output (`ssh -vvv`)
2. **Verify signature**: Use OpenSSL to verify: `openssl dgst -sha512 -verify pubkey.pem -signature sig.bin hash.bin`
3. **Test with real client**: Connect with OpenSSH and verify it accepts the signature

## File Structure

- `src/crypto.c`: SHA-512, exchange hash, RSA framework
- `include/crypto.h`: Public API
- `src/ssh.c`: SSH protocol handling (needs integration)

## Next Steps

1. ✅ SHA-512 implementation (complete)
2. ✅ Exchange hash construction (complete)
3. ✅ PKCS#1 padding (complete)
4. ⚠️ RSA modular exponentiation (stub - needs real implementation)
5. ⚠️ RSA key pair generation/loading (needs implementation)
6. ⚠️ Integration into SSH handshake (needs implementation)

## References

- RFC 4253: SSH Transport Layer Protocol
- RFC 4419: Diffie-Hellman Group Exchange
- RFC 3447: PKCS #1: RSA Cryptography Specifications
- RFC 6234: US Secure Hash Algorithms (SHA)
