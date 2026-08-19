# OpenSSH Reference Files

These files are copied from the PSIPK-SSH (OpenSSH) project for reference.

## Purpose

We use these files to understand OpenSSH's implementation details, particularly:
- RSA signing format and encoding
- Buffer manipulation functions
- Key exchange protocol flow

## Important Note

**These files are NOT compiled into AJOS.** They depend on OpenSSL and system libraries that AJOS doesn't have. Instead, we:

1. Study the algorithms and formats
2. Adapt the logic to work with AJOS's minimal environment
3. Implement equivalent functionality in `src/crypto.c` and `src/ssh.c`

## Key Files

- `ssh-rsa.c` - RSA signing implementation (lines 343-421 are key)
- `sshbuf-getput-basic.c` - Buffer encoding functions
- `kexgexs.c` - Server-side key exchange

## Integration Status

See `INTEGRATION_NOTES.md` for details on what we've implemented.
