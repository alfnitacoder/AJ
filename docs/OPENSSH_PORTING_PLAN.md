# OpenSSH Portable Porting Plan for AJOS Kernel

## Executive Summary

This document provides a structured plan to port OpenSSH portable codebase into AJOS kernel, focusing on reusing maximum code while working within kernel constraints (no libc, custom memory management, no POSIX).

**Goal**: SSH-2.0 server with password authentication and basic shell access.

---

## 1. Which Parts of OpenSSH Are Most Reusable?

### ✅ Highly Reusable (Core Protocol Logic)

1. **Packet Layer** (`packet.c`, `packet.h`)
   - SSH packet framing (length, padding, MAC)
   - Packet type definitions
   - Can be adapted to work with `tcp_pcb` callbacks

2. **Key Exchange (KEX)** (`kex.c`, `kex.h`, `kex*.c`)
   - `kex.c` - Main KEX state machine
   - `kexgex.c` - Diffie-Hellman Group Exchange (what you're using)
   - `kexgexs.c` - Server-side GEX
   - Algorithm negotiation logic
   - **Reusable with minimal changes** - mostly pure protocol logic

3. **Buffer Management** (`sshbuf.c`, `sshbuf.h`, `sshbuf-getput-*.c`)
   - `sshbuf` is OpenSSH's buffer API (replaces old `Buffer`)
   - Already designed to work with custom memory allocators
   - **Highly reusable** - just replace `malloc`/`free` with `kmalloc`/`kfree`

4. **Crypto Primitives** (`digest-*.c`, `cipher-*.c`, `kex-*.c`)
   - Hash functions (SHA-256, SHA-512)
   - Diffie-Hellman implementations
   - **Reusable** - pure crypto math

5. **Host Key Management** (`sshkey.c`, `sshkey.h`)
   - Key parsing, encoding, signing
   - **Partially reusable** - remove file I/O, keep in-memory operations

6. **Authentication** (`auth2.c`, `auth2-*.c`)
   - `auth2.c` - Main auth state machine
   - `auth2-password.c` - Password authentication
   - **Reusable** - mostly protocol logic, just stub out PAM/user lookup

7. **Channel Management** (`channels.c`, `channels.h`)
   - Channel allocation, multiplexing
   - **Reusable** - pure state machine logic

8. **Session Management** (`session.c`, `session.h`)
   - Session setup, environment, command execution
   - **Partially reusable** - remove fork/exec, adapt to your process model

### ⚠️ Partially Reusable (Needs Heavy Modification)

1. **SSHd Main Loop** (`sshd.c`)
   - Connection handling, dispatch table
   - **Needs rewrite** - replace `select`/`poll` with TCP callbacks
   - Replace `fork` with your process/session model

2. **Buffer I/O** (`sshbuf-io.c`)
   - File descriptor I/O
   - **Rewrite** - use `tcp_pcb` read/write instead

3. **Random Number Generation** (`entropy.c`, `random.c`)
   - **Rewrite** - use your kernel's entropy source (TSC, interrupts, etc.)

4. **Logging** (`log.c`, `log.h`)
   - **Replace** - use your `log_writestring` functions

### ❌ Not Reusable (Must Rewrite)

1. **Process Management** (`monitor.c`, `sandbox.c`)
   - Fork, exec, privilege separation
   - **Rewrite** - use your kernel's process model

2. **File I/O** (all `open`/`read`/`write`/`close`)
   - Config file reading, key file loading
   - **Rewrite** - use your filesystem or hardcode configs

3. **Network I/O** (`servconf.c` network setup)
   - Socket creation, `select`/`poll`
   - **Rewrite** - use your `tcp_pcb` directly

4. **PAM Integration** (`auth-pam.c`)
   - **Remove** - implement your own user/password checking

5. **Terminal/PTY** (`pty.c`, `pty.h`)
   - **Rewrite** - adapt to your console/keyboard driver

---

## 2. Suggested Architecture

### 2.1 Packet Layer Integration

```
Your TCP Layer          OpenSSH Packet Layer
─────────────────       ─────────────────────
tcp_pcb                 ssh_packet (from packet.c)
  │                         │
  ├─> on_data() ────────────┼─> ssh_packet_process()
  │                         │     ├─> Parse packet header
  │                         │     ├─> Read payload
  │                         │     └─> Dispatch to handler
  │                         │
  └─< send_packet() <───────┴─< ssh_packet_send()
```

**Implementation Strategy**:
- Create `ajos_ssh_connection` struct that wraps `tcp_pcb` and OpenSSH's `ssh` struct
- Implement `ajos_ssh_tcp_read()` callback that feeds data to `ssh_packet_process()`
- Implement `ajos_ssh_tcp_write()` that sends data via `tcp_pcb->send()`

### 2.2 Buffer API Adaptation

OpenSSH's `sshbuf` is already allocator-agnostic:

```c
// In sshbuf.c, replace:
#define SSH_BUFFER_ALLOC(x) malloc(x)
#define SSH_BUFFER_FREE(x) free(x)

// With:
#define SSH_BUFFER_ALLOC(x) kmalloc(x)
#define SSH_BUFFER_FREE(x) kfree(x)
```

**Files to modify**:
- `sshbuf.c` - Replace allocator macros
- `sshbuf-misc.c` - Same

### 2.3 Dispatch Table and State Machine

OpenSSH uses a dispatch table pattern:

```c
// From packet.c
struct ssh_dispatch {
    int type;
    int (*handler)(struct ssh *);
};

// Your integration:
void ajos_ssh_handle_packet(struct ajos_ssh_connection *conn) {
    struct ssh *ssh = conn->ssh;
    int packet_type = ssh_packet_peek_type(ssh);
    
    // Call OpenSSH's dispatch handler
    ssh_dispatch_run(ssh, packet_type, NULL);
}
```

**Key Files**:
- `packet.c` - Dispatch logic (reusable)
- `dispatch.c` - Handler registration (reusable)

### 2.4 Memory Management

**Strategy**: Replace all OpenSSH memory calls with kernel equivalents:

| OpenSSH | AJOS Kernel |
|---------|-------------|
| `malloc` | `kmalloc` |
| `free` | `kfree` |
| `calloc` | `kmalloc` + `memset` |
| `realloc` | `kmalloc` + `memcpy` + `kfree` |
| `strdup` | `kmalloc` + `strcpy` |

**Files to modify**:
- Create `ajos_compat.h` with macros:
  ```c
  #define malloc(x) kmalloc(x)
  #define free(x) kfree(x)
  #define calloc(n, s) ({ void *p = kmalloc((n)*(s)); if(p) memset(p,0,(n)*(s)); p; })
  ```

---

## 3. Minimal Viable Subset (Password Auth)

### Phase 1: Core Files (15-20 files)

**Packet & Protocol**:
1. `packet.c`, `packet.h` - Packet framing
2. `dispatch.c`, `dispatch.h` - Message dispatch
3. `sshbuf.c`, `sshbuf.h` - Buffer API
4. `sshbuf-getput-basic.c` - Basic buffer operations
5. `sshbuf-getput-crypto.c` - Crypto buffer operations
6. `sshbuf-misc.c` - Buffer utilities

**Key Exchange**:
7. `kex.c`, `kex.h` - KEX state machine
8. `kexgex.c`, `kexgexs.c` - DH Group Exchange
9. `kexgexc.c` - Client-side (if needed for testing)

**Crypto**:
10. `digest-openssl.c` or `digest-libc.c` - Hash functions
11. `cipher.c`, `cipher.h` - Cipher interface
12. `ssh-rsa.c` - RSA signing (you already have this)

**Host Keys**:
13. `sshkey.c`, `sshkey.h` - Key operations
14. `sshkey-*.c` - Key encoding/decoding

**Authentication**:
15. `auth2.c`, `auth2.h` - Auth state machine
16. `auth2-password.c` - Password auth

**Session**:
17. `session.c`, `session.h` - Session management
18. `channels.c`, `channels.h` - Channel multiplexing

**Integration Layer** (your code):
19. `ajos_ssh.c` - Your TCP→SSH bridge
20. `ajos_ssh.h` - Your connection struct

### Phase 2: After KEX Works (Encryption/MAC)

21. `mac.c`, `mac.h` - MAC computation
22. `cipher-aes*.c` - AES encryption
23. `poly1305.c` - ChaCha20-Poly1305 (if using)

### Phase 3: Shell Access

24. `pty.c`, `pty.h` - Terminal handling (rewrite for your console)
25. `servconf.c` - Config (simplified, hardcoded)

---

## 4. Concrete First Steps (12 Actions)

### Step 1: Create Directory Structure
```bash
mkdir -p src/openssh/{packet,kex,auth2,crypto,buffer}
mkdir -p include/openssh
```

### Step 2: Copy Core Buffer Files
Copy these 6 files from OpenSSH:
- `sshbuf.c`, `sshbuf.h`
- `sshbuf-getput-basic.c`
- `sshbuf-getput-crypto.c`
- `sshbuf-misc.c`
- `sshbuf-io.c` (will rewrite later)

### Step 3: Create Compatibility Layer
Create `include/ajos_compat.h`:
```c
#ifndef AJOS_COMPAT_H
#define AJOS_COMPAT_H

#include "kernel.h"  // Your kernel headers

// Memory
#define malloc(x) kmalloc(x)
#define free(x) kfree(x)
#define calloc(n, s) ({ \
    void *_p = kmalloc((n)*(s)); \
    if(_p) memset(_p, 0, (n)*(s)); \
    _p; \
})
#define realloc(p, s) ({ \
    void *_p = kmalloc(s); \
    if(_p && p) { memcpy(_p, p, /* old size */); kfree(p); } \
    _p; \
})

// String
#define strdup(s) ({ \
    size_t _len = strlen(s) + 1; \
    char *_p = kmalloc(_len); \
    if(_p) memcpy(_p, s, _len); \
    _p; \
})

// Logging (replace OpenSSH's log functions)
#define fatal(...) do { \
    log_writestring("[SSH FATAL] "); \
    /* format and log */ \
} while(0)

#define error(...) do { \
    log_writestring("[SSH ERROR] "); \
    /* format and log */ \
} while(0)

// Stub out POSIX
#define getpid() 1
#define getuid() 0
#define getgid() 0
#define setsid() 0
#define setuid(x) 0
#define setgid(x) 0

#endif
```

### Step 4: Copy Packet Files
Copy:
- `packet.c`, `packet.h`
- `dispatch.c`, `dispatch.h`

Modify `packet.c`:
- Replace `read()`/`write()` with your TCP callbacks
- Replace `select()` with direct TCP polling

### Step 5: Copy KEX Files
Copy:
- `kex.c`, `kex.h`
- `kexgex.c`, `kexgexs.c`

These should compile with minimal changes (mostly protocol logic).

### Step 6: Copy Buffer Files
Copy the 6 buffer files from Step 2.

Modify `sshbuf.c`:
- Replace `SSH_BUFFER_ALLOC`/`SSH_BUFFER_FREE` macros with `kmalloc`/`kfree`

### Step 7: Copy Crypto Files
Copy:
- `digest-openssl.c` or `digest-libc.c` (whichever is simpler)
- `ssh-rsa.c` (you may already have this)

### Step 8: Copy Host Key Files
Copy:
- `sshkey.c`, `sshkey.h`
- `sshkey-common.c`

Modify to remove file I/O, keep in-memory operations.

### Step 9: Create Integration Layer
Create `src/ajos_ssh.c`:
```c
#include "ajos_compat.h"
#include "openssh/ssh.h"
#include "openssh/packet.h"
#include "tcp.h"  // Your TCP stack

struct ajos_ssh_connection {
    struct tcp_pcb *pcb;
    struct ssh *ssh;
    // ... your connection state
};

// TCP read callback
void ajos_ssh_tcp_read(struct tcp_pcb *pcb, void *data, size_t len) {
    struct ajos_ssh_connection *conn = pcb->user_data;
    // Feed data to OpenSSH packet layer
    ssh_packet_process(conn->ssh, data, len);
}

// TCP write callback  
void ajos_ssh_tcp_write(struct ajos_ssh_connection *conn, const void *data, size_t len) {
    tcp_send(conn->pcb, data, len);
}
```

### Step 10: Stub Out Missing Functions
Create `src/openssh_stubs.c`:
```c
// Stub out file I/O
int open(const char *path, int flags, ...) { return -1; }
int close(int fd) { return -1; }
ssize_t read(int fd, void *buf, size_t count) { return -1; }
ssize_t write(int fd, const void *buf, size_t count) { return -1; }

// Stub out process management
pid_t fork(void) { return -1; }  // You'll handle this differently
int execve(const char *path, char *const argv[], char *const envp[]) { return -1; }

// Stub out user/group
struct passwd *getpwnam(const char *name) { return NULL; }  // Implement your own
int setresuid(uid_t ruid, uid_t euid, uid_t suid) { return 0; }

// Stub out entropy (implement your own)
int getentropy(void *buf, size_t len) {
    // Use your kernel's entropy source
    return 0;
}
```

### Step 11: Modify Makefile
Add OpenSSH files to your build:
```makefile
OPENSSH_SRC = src/openssh/sshbuf.c \
              src/openssh/packet.c \
              src/openssh/kex.c \
              # ... etc

OPENSSH_OBJ = $(OPENSSH_SRC:.c=.o)

KERNEL_OBJ += $(OPENSSH_OBJ)
```

### Step 12: Test Compilation
Try to compile just the buffer layer first:
```bash
make 2>&1 | grep -E "(error|undefined)"
```

Fix compilation errors one by one:
- Missing includes → add to `ajos_compat.h`
- Missing functions → add to `openssh_stubs.c`
- Type mismatches → fix or cast

---

## 5. Common Kernel Pitfalls

### 5.1 Memory Management

**Problem**: OpenSSH assumes `malloc` can fail gracefully.

**Solution**: 
- Your `kmalloc` should return `NULL` on failure
- Check all allocations in critical paths
- Consider pre-allocating connection structures

### 5.2 No Threads / Blocking Calls

**Problem**: OpenSSH uses blocking I/O (`read()`, `select()`).

**Solution**:
- Make all I/O non-blocking
- Use TCP callbacks for async I/O
- Implement state machine that can be resumed

**Example**:
```c
// Instead of blocking read:
int n = read(fd, buf, len);

// Use callback:
void on_tcp_data(struct tcp_pcb *pcb, void *data, size_t len) {
    // Process data immediately
    ssh_packet_process(ssh, data, len);
}
```

### 5.3 Interrupt Safety / Reentrancy

**Problem**: OpenSSH code may not be interrupt-safe.

**Solution**:
- Disable interrupts during critical sections
- Use locks if you have them
- Avoid shared state between interrupt and main context

**Example**:
```c
void ajos_ssh_process_packet(struct ajos_ssh_connection *conn) {
    __asm__ volatile("cli");  // Disable interrupts
    ssh_packet_process(conn->ssh, data, len);
    __asm__ volatile("sti");  // Re-enable
}
```

### 5.4 Random Number Generation

**Problem**: OpenSSH expects `/dev/urandom` or `getentropy()`.

**Solution**: Implement your own entropy source:
```c
// In your kernel
uint32_t ajos_get_random(void) {
    // Mix TSC, interrupt timing, network packets, etc.
    static uint32_t seed = 0;
    uint64_t tsc = rdtsc();
    seed = seed * 1103515245 + (tsc & 0xFFFFFFFF) + 12345;
    return seed;
}

// Stub for OpenSSH
int getentropy(void *buf, size_t len) {
    uint8_t *p = buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = ajos_get_random() & 0xFF;
    }
    return 0;
}
```

### 5.5 Constant-Time Crypto

**Problem**: Some OpenSSH crypto may leak timing information.

**Solution**:
- Your existing `bigint_mod_exp` should be constant-time
- Avoid branches on secret data
- Use constant-time comparisons for MACs

---

## 6. Recommended Implementation Order

### Phase 1: Basic KEX (You're Here)
✅ Version exchange
✅ KEXINIT negotiation  
✅ Diffie-Hellman Group Exchange
✅ Host key signing
⏳ **Fix signature verification** ← Current blocker

### Phase 2: Encryption & MAC (After KEX Works)
1. Implement `cipher.c` interface
2. Add AES-CTR or ChaCha20 encryption
3. Implement `mac.c` for HMAC
4. Enable encryption after NEWKEYS
5. Test encrypted packet exchange

### Phase 3: Authentication
1. Port `auth2.c` state machine
2. Implement `auth2-password.c`
3. Create `ajos_user_check()` function:
   ```c
   int ajos_user_check(const char *user, const char *pass) {
       // Check against your user database
       return (strcmp(user, "user") == 0 && 
               strcmp(pass, "password") == 0);
   }
   ```
4. Wire up to OpenSSH's auth handlers

### Phase 4: Channel & Session
1. Port `channels.c` for multiplexing
2. Create single channel for shell (no PTY initially)
3. Port `session.c` (simplified)
4. Wire shell execution to your process model

### Phase 5: Shell Access
1. Create `ajos_ssh_shell()` function:
   ```c
   void ajos_ssh_shell(struct ajos_ssh_connection *conn) {
       // Read commands from SSH channel
       // Execute via your shell
       // Write output back to channel
   }
   ```
2. Implement basic PTY (if needed)
3. Handle terminal size, signals

### Phase 6: Polish
1. Rekeying (optional initially)
2. Public key authentication
3. Multiple channels
4. Subsystem support

---

## 7. Quick Start Checklist

- [ ] Create `include/ajos_compat.h` with memory/string stubs
- [ ] Create `src/openssh_stubs.c` with POSIX stubs
- [ ] Copy 6 buffer files, modify allocators
- [ ] Copy packet files, adapt to TCP callbacks
- [ ] Copy KEX files (minimal changes)
- [ ] Create `ajos_ssh.c` integration layer
- [ ] Test buffer layer compilation
- [ ] Test packet layer compilation
- [ ] Wire up TCP→SSH callbacks
- [ ] Test KEX with your existing code
- [ ] Fix signature verification (current issue)
- [ ] Add encryption/MAC
- [ ] Add password auth
- [ ] Add shell access

---

## 8. Files Reference

### Must Copy (Core Protocol)
```
openssh-portable/
├── sshbuf.c, sshbuf.h
├── sshbuf-getput-basic.c
├── sshbuf-getput-crypto.c
├── sshbuf-misc.c
├── packet.c, packet.h
├── dispatch.c, dispatch.h
├── kex.c, kex.h
├── kexgex.c, kexgexs.c
├── sshkey.c, sshkey.h
├── ssh-rsa.c
├── digest-openssl.c (or digest-libc.c)
├── auth2.c, auth2.h
├── auth2-password.c
├── channels.c, channels.h
└── session.c, session.h
```

### Modify Heavily
- `packet.c` - Replace I/O with TCP callbacks
- `sshbuf-io.c` - Rewrite for TCP
- `session.c` - Remove fork/exec, adapt to your process model

### Stub Out
- All file I/O (`open`, `read`, `write`, `close`)
- Process management (`fork`, `exec`, `waitpid`)
- User/group (`getpwnam`, `getgrnam`)
- Entropy (`getentropy`, `/dev/urandom`)

---

## 9. Testing Strategy

1. **Unit Test Buffer Layer**: Create simple test that allocates/frees buffers
2. **Test Packet Parsing**: Feed known SSH packets, verify parsing
3. **Test KEX**: Use your existing KEX code, verify OpenSSH integration
4. **Test Auth**: Hardcode user/pass, verify auth flow
5. **Test Shell**: Simple echo command, verify output

---

## 10. Estimated Effort

- **Phase 1 (KEX)**: 2-3 days (you're 80% there)
- **Phase 2 (Encryption)**: 3-5 days
- **Phase 3 (Auth)**: 2-3 days
- **Phase 4 (Channels)**: 2-3 days
- **Phase 5 (Shell)**: 3-5 days

**Total**: ~2-3 weeks for basic working SSH server

---

## Next Immediate Actions

1. **Fix current signature issue** (your `bigint_mod_exp` bug)
2. **Create compatibility layer** (`ajos_compat.h`)
3. **Copy buffer files** and test compilation
4. **Gradually integrate** OpenSSH code alongside your existing SSH implementation

Good luck! The OpenSSH codebase is well-structured and mostly protocol-agnostic, so with careful porting you should be able to reuse 60-70% of it.
