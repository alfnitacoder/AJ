# OpenSSH Porting Quick Start Guide

This is a condensed version of the full porting plan. Use this for immediate action items.

## Immediate Next Steps (Do These First)

### 1. Create Compatibility Layer (5 minutes)
```bash
# Already created: include/ajos_compat.h
# Review and customize for your kernel
```

### 2. Create Stub File (10 minutes)
Create `src/openssh_stubs.c`:
```c
#include "ajos_compat.h"

// File I/O stubs
int open(const char *path, int flags, ...) { return -1; }
int close(int fd) { return -1; }
ssize_t read(int fd, void *buf, size_t count) { return -1; }
ssize_t write(int fd, const void *buf, size_t count) { return -1; }

// Process stubs
pid_t fork(void) { return -1; }
int execve(const char *path, char *const argv[], char *const envp[]) { return -1; }
pid_t waitpid(pid_t pid, int *status, int options) { return -1; }

// User/group stubs
struct passwd *getpwnam(const char *name) { return NULL; }
struct group *getgrnam(const char *name) { return NULL; }
```

### 3. Copy Buffer Files (15 minutes)
```bash
mkdir -p src/openssh
cp openssh-portable/sshbuf.c src/openssh/
cp openssh-portable/sshbuf.h include/openssh/
cp openssh-portable/sshbuf-getput-basic.c src/openssh/
cp openssh-portable/sshbuf-getput-crypto.c src/openssh/
cp openssh-portable/sshbuf-misc.c src/openssh/
```

### 4. Modify Buffer Allocator (5 minutes)
Edit `src/openssh/sshbuf.c`, find:
```c
#define SSH_BUFFER_ALLOC(x) malloc(x)
#define SSH_BUFFER_FREE(x) free(x)
```

Replace with:
```c
#include "ajos_compat.h"
#define SSH_BUFFER_ALLOC(x) kmalloc(x)
#define SSH_BUFFER_FREE(x) kfree(x)
```

### 5. Test Buffer Compilation (10 minutes)
Add to Makefile:
```makefile
OPENSSH_OBJ = src/openssh/sshbuf.o \
              src/openssh/sshbuf-getput-basic.o \
              src/openssh/sshbuf-getput-crypto.o \
              src/openssh/sshbuf-misc.o \
              src/openssh_stubs.o

KERNEL_OBJ += $(OPENSSH_OBJ)
```

Try compiling:
```bash
make 2>&1 | head -20
```

Fix errors one by one.

## File Priority List

### Must Copy First (Core Protocol)
1. `sshbuf.c`, `sshbuf.h` - Buffer API
2. `sshbuf-getput-basic.c` - Basic operations
3. `sshbuf-getput-crypto.c` - Crypto operations
4. `sshbuf-misc.c` - Utilities
5. `packet.c`, `packet.h` - Packet framing
6. `dispatch.c`, `dispatch.h` - Message dispatch
7. `kex.c`, `kex.h` - KEX state machine
8. `kexgex.c`, `kexgexs.c` - DH Group Exchange

### Copy After Buffer Works
9. `sshkey.c`, `sshkey.h` - Host key operations
10. `ssh-rsa.c` - RSA signing (you may have this)
11. `digest-openssl.c` or `digest-libc.c` - Hash functions
12. `auth2.c`, `auth2.h` - Authentication
13. `auth2-password.c` - Password auth

### Copy After Auth Works
14. `channels.c`, `channels.h` - Channel multiplexing
15. `session.c`, `session.h` - Session management

## Integration Pattern

### TCP → SSH Bridge
```c
// In your ssh.c or new ajos_ssh.c
struct ajos_ssh_connection {
    struct tcp_pcb *pcb;
    struct ssh *ssh;  // OpenSSH's connection struct
    // ... your state
};

// TCP data callback
void ajos_ssh_tcp_read(struct tcp_pcb *pcb, void *data, size_t len) {
    struct ajos_ssh_connection *conn = pcb->user_data;
    // Feed to OpenSSH
    ssh_packet_process(conn->ssh, data, len);
}

// SSH send callback
void ajos_ssh_send(struct ssh *ssh, const void *data, size_t len) {
    struct ajos_ssh_connection *conn = ssh_get_app_data(ssh);
    tcp_send_data(conn->pcb, data, len);
}
```

## Common Compilation Errors & Fixes

### Error: `undefined reference to 'malloc'`
**Fix**: Include `ajos_compat.h` in the file, or add to Makefile CFLAGS:
```makefile
CFLAGS += -include include/ajos_compat.h
```

### Error: `undefined reference to 'strdup'`
**Fix**: Already handled in `ajos_compat.h`

### Error: `undefined reference to 'getentropy'`
**Fix**: Implement in `ajos_compat.h` or `openssh_stubs.c`

### Error: `undefined reference to 'logit'`
**Fix**: Already defined in `ajos_compat.h`

### Error: `incompatible pointer types`
**Fix**: Cast or fix type definitions in `ajos_compat.h`

## Testing Strategy

1. **Test Buffer Layer**:
   ```c
   struct sshbuf *buf = sshbuf_new();
   sshbuf_put_string(buf, "test", 4);
   // Verify it works
   sshbuf_free(buf);
   ```

2. **Test Packet Parsing**:
   - Feed known SSH packet bytes
   - Verify `ssh_packet_read()` parses correctly

3. **Test KEX**:
   - Use your existing KEX code
   - Gradually replace with OpenSSH's KEX

## Estimated Timeline

- **Day 1**: Compatibility layer + buffer files (working)
- **Day 2-3**: Packet layer + KEX integration
- **Day 4-5**: Fix signature verification (current blocker)
- **Day 6-8**: Encryption/MAC
- **Day 9-10**: Authentication
- **Day 11-12**: Shell access

**Total**: ~2 weeks for basic working SSH server

## Key Principles

1. **Start Small**: Get buffer layer working first
2. **Fix One Thing at a Time**: Don't try to port everything at once
3. **Test Frequently**: Compile after each small change
4. **Keep Your Code**: Don't delete your existing SSH code until OpenSSH version works
5. **Gradual Migration**: Run both implementations side-by-side initially

## When You Get Stuck

1. Check `ajos_compat.h` - missing function?
2. Check `openssh_stubs.c` - missing stub?
3. Check Makefile - file not compiled?
4. Check includes - wrong path?
5. Read OpenSSH source - understand what it needs

Good luck! 🚀
