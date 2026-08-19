# SSH Signature Debugging - Next Steps

## Current Status
- ✅ Exchange hash computation (SHA-256)
- ✅ Hashing exchange hash with SHA-512
- ✅ RSA signing with PKCS#1 v1.5 padding
- ✅ Signature encoding (mpint format)
- ❌ OpenSSH still rejects signature with "incorrect signature"

## Next Steps to Debug

### Step 1: Verify Exchange Hash Computation
**Goal**: Ensure our exchange hash matches what OpenSSH computes

**Action**:
1. Run OpenSSH client with maximum verbosity: `ssh -vvv user@127.0.0.1 -p 2222`
2. Look for debug output showing the exchange hash (H) computation
3. Compare with our logged exchange hash (first 16 bytes: `BD 46 E2 DB...`)
4. Verify each component is included in the correct order:
   - V_C (client version string)
   - V_S (server version string) 
   - I_C (client KEXINIT payload)
   - I_S (server KEXINIT payload)
   - K_S (server host key blob)
   - min, n, max (uint32, big-endian)
   - p, g, e, f, K (mpint format)

**Check**:
- Are version strings including `\r\n` terminators?
- Are KEXINIT payloads excluding the message type byte (20)?
- Are all mpints properly formatted (length prefix + value, no unnecessary leading zeros)?

### Step 2: Test Signature Verification with OpenSSL
**Goal**: Isolate whether the issue is in hash computation or signature generation

**Action**:
1. Extract the exchange hash from our logs
2. Extract the signature from our logs
3. Use OpenSSL to verify:
   ```bash
   # Save exchange hash to file
   echo "BD46E2DB..." | xxd -r -p > exchange_hash.bin
   
   # Save signature to file  
   echo "03518569..." | xxd -r -p > signature.bin
   
   # Verify with OpenSSL (need to extract public key first)
   openssl dgst -sha512 -verify pubkey.pem -signature signature.bin exchange_hash.bin
   ```

**Expected**: If OpenSSL verifies correctly, the issue is in SSH encoding. If not, the issue is in signature computation.

### Step 3: Verify Signature Blob Format
**Goal**: Ensure signature blob in GEX_REPLY matches RFC 4253 exactly

**Current Format**:
```
string "rsa-sha2-512" (4-byte length + 12 bytes)
string signature_blob (4-byte length + mpint-encoded signature)
```

**Check**:
- Is the signature blob correctly encoded as mpint?
- Are we skipping leading zeros correctly?
- Is the positive indicator byte (0x00) added when MSB is set?

**Action**: Add hex dump of the complete signature field in GEX_REPLY packet

### Step 4: Verify RSA Key Pair
**Goal**: Ensure the embedded RSA key matches the public key blob sent to client

**Action**:
1. Extract the public key blob (K_S) from logs
2. Parse it to get n and e
3. Compare with embedded key in `get_default_rsa_key()`
4. Verify the key pair is valid: `n = p * q`, `e * d ≡ 1 (mod φ(n))`

**Check**: The fingerprint shown by OpenSSH (`SHA256:gAw785YLFHNZQH8AcnWZ9PdrO/DPLD1UEm3V+cuC0oo`) should match our key.

### Step 5: Try ssh-rsa Algorithm
**Goal**: Test if the issue is specific to `rsa-sha2-512`

**Action**:
1. Temporarily change signature algorithm to `ssh-rsa`
2. For `ssh-rsa`, sign the exchange hash directly with SHA-1 (or SHA-256)
3. Test if OpenSSH accepts this signature

**Note**: This helps isolate if the issue is in:
- The signature algorithm identifier
- The hash algorithm used
- The general signature format

### Step 6: Packet-Level Debugging
**Goal**: Capture exact bytes sent in GEX_REPLY signature field

**Action**:
1. Add hex dump of complete GEX_REPLY packet before sending
2. Compare with what OpenSSH expects (from packet capture or RFC)
3. Verify:
   - Packet structure: packet_length, padding_length, payload, padding, MAC
   - Signature field format within payload
   - Byte order (big-endian for all multi-byte integers)

### Step 7: Compare with Reference Implementation
**Goal**: Find a working SSH server implementation and compare

**Action**:
1. Look at OpenSSH source code for signature generation
2. Compare with libssh or other SSH implementations
3. Check if there are any subtle differences in:
   - Exchange hash construction
   - Signature encoding
   - Packet format

## Immediate Action Items

### Priority 1: Exchange Hash Verification
1. Add detailed logging of each exchange hash component
2. Log the complete exchange hash (all 32 bytes, not just first 16)
3. Compare with OpenSSH debug output

### Priority 2: Signature Format Verification  
1. Add hex dump of complete encoded signature
2. Verify mpint encoding is correct
3. Check if signature blob length matches expected size

### Priority 3: Test with Simpler Algorithm
1. Try `ssh-rsa` instead of `rsa-sha2-512`
2. This may reveal if the issue is algorithm-specific

## Tools Needed

1. **OpenSSL**: For signature verification testing
2. **Wireshark/tcpdump**: For packet capture and analysis
3. **OpenSSH debug output**: For comparing exchange hash
4. **Hex dump utilities**: For byte-by-byte comparison

## Expected Outcome

After completing these steps, we should be able to identify:
- Whether the issue is in exchange hash computation
- Whether the issue is in signature generation
- Whether the issue is in signature encoding/format
- The exact byte sequence that differs from what OpenSSH expects

## Current Debug Output

From latest test:
- Exchange hash (SHA-256, first 16 bytes): `BD 46 E2 DB 6B 80 2A 8C CC DE 14 CA B5 8A B7 37`
- Hashed with SHA-512 (first 16 bytes): `5A 2F 14 F0 2A 7E B5 F8 D0 54 A4 C4 E2 49 94 84`
- Raw RSA signature (first 32 bytes): `03 51 85 69 48 B9 19 DF 34 D5 1D 83 F0 AA 07 B8 B5 80 E8 FB 1D 7E B9 B4 33 23 3D A6 E6 DE 81 C7`
- Encoded signature length: 276 bytes

## Notes

- The signature is being computed (not all zeros)
- The encoding format looks correct (mpint)
- The issue is likely a subtle mismatch in:
  - Exchange hash component encoding
  - Signature blob format
  - Packet structure
