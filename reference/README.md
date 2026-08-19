# Reference Code

This directory contains reference implementations from other projects.

## OpenSSH (PSIPK-SSH)

The PSIPK-SSH project is kept as a separate reference project at:
`/Users/ageorge/PSIPK-SSH`

Key files we reference:
- `ssh-rsa.c` - RSA signing implementation
- `sshbuf-getput-basic.c` - Buffer manipulation
- `sshd.c` - SSH daemon structure
- `kex.c`, `kexgex.c` - Key exchange logic

We adapt the logic from these files into AJOS's implementation in `src/ssh.c` and `src/crypto.c`.
