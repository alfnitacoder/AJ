# SSH Signature Debugging Prompt

You are an expert in SSH protocol implementation (RFC 4253, RFC 4419, RFC 8332) and low-level cryptography.

I am building a from-scratch SSH server and I am stuck on the following very common bug:

The OpenSSH client fails with:

    ssh_dispatch_run_fatal: Connection to 127.0.0.1 port 2222: incorrect signature

This happens right after the server sends SSH_MSG_KEXDH_GEX_REPLY (type 33) + NEWKEYS.

## Server Log Evidence

- Negotiated signature algorithm: `rsa-sha2-512`
- Exchange hash is computed with SHA-256 (correct for `diffie-hellman-group-exchange-sha256`)
- Signing with real RSA-2048 key
- Exchange hash H (SHA-256, 32 bytes): `84 84 15 BA 18 5...` (first bytes shown)
- For `rsa-sha2-512`: Hashing H with SHA-512 to get 64 bytes, then signing
- Hash to sign (first 16 bytes): `AC D7 B0 D8 FF 64...`
- Raw RSA signature starts with: `03 0D F5 F8 17 63 89...`
- Encoded signature: `"rsa-sha2-512"` string (12 bytes) + 256-byte mpint blob (total encoded length 276)
- K_S blob length = 278 bytes
- I_C len=1558, I_S len=299 (payload lengths, **excluding** message type byte - this was fixed)
- Total hash input: 3505 bytes (was 3509 before I_C/I_S fix)

The client accepts the host key blob, but **rejects the signature** over the exchange hash H.

## What I've Already Fixed

1. ✅ **I_C and I_S lengths**: Fixed off-by-one error (was 1559/300, now 1558/299)
   - These are now the payload lengths without the message type byte, per RFC 4253

2. ✅ **Exchange hash computation**: Using SHA-256 for `diffie-hellman-group-exchange-sha256`
   - Components: V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K

3. ✅ **Signature encoding**: Signature blob is a string containing an mpint
   - Format: `[4-byte string length] [algorithm name] [4-byte string length] [mpint signature]`
   - Currently keeping all 256 bytes (not stripping leading zeros)
   - Adding 0x00 positive indicator only if first byte >= 0x80

4. ✅ **RSA key pair**: Using a valid 2048-bit RSA key
   - The key fingerprint matches what OpenSSH shows
   - Modular exponentiation produces non-zero signatures

## Current Implementation Details

For `rsa-sha2-512`:
1. Compute exchange hash H = SHA-256(exchange data) → 32 bytes
2. Hash H with SHA-512 → 64 bytes
3. Sign the 64-byte hash using RSA with PKCS#1 v1.5 padding
4. PKCS#1 padding uses SHA-512 DER encoding (19 bytes)
5. Encode signature as: `"rsa-sha2-512"` + mpint(signature)

## Your Task

Analyze the provided information and tell me **exactly** what is most likely wrong and how to fix it.

Focus especially on these common causes of "incorrect signature" in home-grown SSH servers:

1. **Signing the wrong value** (re-hashing H incorrectly, or not hashing H at all for rsa-sha2-512)
2. **Using wrong hash algorithm in PKCS#1 v1.5 padding** (SHA-256 instead of SHA-512 for rsa-sha2-512)
3. **Incorrect mpint encoding of the RSA signature blob** (adding extra 0x00, stripping leading zeros incorrectly, wrong length)
4. **Wrong content or length of I_C / I_S** in the exchange hash construction (already fixed, but verify)
5. **Including message type byte in I_C or I_S** (already fixed, but verify)
6. **Wrong order or missing/wrong component in H** = SHA256(V_C || V_S || I_C || I_S || K_S || min || n || max || p || g || e || f || K)
7. **PKCS#1 v1.5 padding format mistake** (wrong DER OID, bad FF padding, incorrect hash length in DER)
8. **Bigint/mpint encoding issues** in K_S, p, g, e, f, K (leading zeros, sign byte, etc.)

## Most Suspicious Observations

- I_C len=1558, I_S len=299 → **These are now correct** (payload without message type)
- Signature encoded length 276 = 4 + 12 + 4 + 256 → **Looks correct**
- Raw signature starts with `03` → Unusual but possible (not all zeros)
- Hash input 3505 bytes → **Reduced from 3509 after I_C/I_S fix**
- **Current approach**: Hash H (SHA-256) with SHA-512 → 64 bytes, then sign with SHA-512 DER

## Questions to Answer

1. **For `rsa-sha2-512`**: Should I hash the exchange hash H (SHA-256) with SHA-512 first, then sign the 64-byte result? Or should I sign H directly (32 bytes) using PKCS#1 with SHA-512 DER?

2. **PKCS#1 padding**: When using SHA-512 DER, should the hash value in the padding be 64 bytes (SHA-512 output) or 32 bytes (the original exchange hash)?

3. **Signature mpint**: Should RSA signatures always be exactly 256 bytes (no stripping), or should leading zeros be stripped like other mpints?

4. **Exchange hash components**: Are all components (especially K_S, p, g, e, f, K) correctly encoded as mpints/strings with proper length prefixes?

## Additional Context

- Low-level RSA implementation (bigint_mod_exp + modular multiplication) appears correct (produces non-zero signatures)
- The issue is specifically in signature verification - OpenSSH accepts the host key but rejects the signature
- All other SSH handshake steps work (version exchange, KEXINIT, GEX_REQUEST/GROUP/INIT)

## What I Need

Please prioritize the **top 2-3 most probable causes** based on the evidence.

For each cause you suspect:
- Explain why it matches the symptoms
- Show exactly which part of the code/log indicates the problem
- Give the precise fix (code change or correction)

If you need more information (e.g., full `ssh_sign_exchange_hash` function, full `bigint_mod_exp`, full `pkcs1_v15_pad`, full exchange hash buffer dump), tell me what to provide.

Help me finally get past host key verification!
