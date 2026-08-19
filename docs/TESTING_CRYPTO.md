# Testing crypto (RSA sign and error paths)

**If you see "incorrect signature" when connecting:** You may have previously built with `run-console-test-crypto-fail` (which forces the first RSA sign to fail). Do a clean normal build: `make run-console`. This now removes `crypto.o` so the crypto module is rebuilt without the test hook. If you still see the error, check the QEMU console for `[CRYPTO] ERROR: kmalloc failed for padded` (if present, an old test build is still in use).

**Transport encryption:** After NEWKEYS, the server now derives session keys (RFC 4253) and uses AES-128-CTR to decrypt/encrypt. The SSH connection should complete (service request, auth, channel) instead of hanging. The test script still has a 15s timeout as a fallback.

## Happy path (normal SSH)

1. Build and run:
   ```bash
   make && make run-console
   ```
2. In another terminal, after the OS has booted (~10–15 s) and you see SSHD on port 22:
   ```bash
   ./test_ssh_connect.sh
   ```
   Or: `ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2226 user@127.0.0.1`
3. If the host key is accepted (no "incorrect signature"), `rsa_sign()` ran successfully.

## Error path (kmalloc failure in rsa_sign)

This checks that when the first allocation in `rsa_sign` fails, the function logs, zeroes the output buffer, and returns 0.

1. Run the test build that forces one allocation failure:
   ```bash
   make run-console-test-crypto-fail
   ```
2. In the QEMU console you should see:
   - `[CRYPTO] ERROR: kmalloc failed for padded`
   when the first SSH key exchange runs.
3. From the host, try SSH; the connection should fail (e.g. key exchange or signature error). The first sign used the failure path; a retry might succeed because the hook only fails once.

To remove the test hook, build normally without `-DCRYPTO_TEST_KMALLOC_FAIL` (e.g. `make run-console`).
