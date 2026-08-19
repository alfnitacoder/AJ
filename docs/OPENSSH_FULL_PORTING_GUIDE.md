# OpenSSH Portable → AJOS Kernel: Complete Porting Guide

**Author**: Expert kernel developer perspective  
**Goal**: Replace custom SSH implementation with OpenSSH portable code  
**Timeline**: 2-3 weeks for basic password auth + shell, 1-2 months for full features

---

## Executive Summary

**Reality Check**: Porting OpenSSH to a kernel is **hard but achievable**. You can reuse ~60-70% of the codebase, but the integration layer will be significant. The good news: OpenSSH's architecture (packet layer, state machines, buffer API) is well-suited for kernel porting.

**Critical Decision**: You have two paths:
1. **Fix your RSA bug** (1-2 days) → Continue with your implementation
2. **Port OpenSSH** (2-3 weeks) → More work upfront, but eliminates future bugs

**Recommendation**: Fix the RSA bug first (it's a math bug, not architectural), then gradually port OpenSSH piece-by-piece. This gives you a working baseline while you port.

---

## 1. Minimal File Subset (Phase 1: KEX + Auth)

### Core Protocol Files (Must Have)

**Buffer Layer** (Already started ✅):
- `sshbuf.c`, `sshbuf.h`
- `sshbuf-getput-basic.c`
- `sshbuf-getput-crypto.c`
- `sshbuf-misc.c`
- `ssherr.c`, `ssherr.h`

**Packet Layer** (Critical):
- `packet.c`, `packet.h` - Packet framing, encryption, MAC
- `dispatch.c`, `dispatch.h` - Message type dispatch table
- `ssh.c`, `ssh.h` - Main SSH connection structure

**Key Exchange**:
- `kex.c`, `kex.h` - KEX state machine
- `kexgexs.c` - Server-side DH Group Exchange
- `kexgex.c` - Shared GEX logic

**Host Keys**:
- `sshkey.c`, `sshkey.h` - Key operations (signing, encoding)
- `ssh-rsa.c` - RSA-specific operations (you may keep your own)

**Authentication**:
- `auth2.c`, `auth2.h` - Auth state machine
- `auth2-password.c` - Password authentication

**Session/Channels** (Phase 2):
- `channels.c`, `channels.h` - Channel multiplexing
- `session.c`, `session.h` - Session management

**Total Phase 1**: ~20 files

### Files to Skip Initially

- `sshd.c` - Main server loop (you'll write your own)
- `monitor.c`, `sandbox.c` - Process management
- `servconf.c` - Config file parsing (hardcode configs)
- `log.c` - Use your `log_writestring`
- `sshbuf-io.c` - File I/O (rewrite for TCP)
- `pty.c` - Terminal handling (adapt later)

---

## 2. Biggest Porting Challenges & Solutions

### Challenge 1: Memory Management

**Problem**: OpenSSH uses `malloc`/`free` everywhere, assumes they can fail.

**Solution**: Create comprehensive compatibility layer:

```c
// include/ajos_compat.h

// Memory allocation (must return NULL on failure)
#define malloc(x) kmalloc(x)
#define free(x) kfree(x)
#define calloc(n, s) ({ \
    void *_p = kmalloc((n) * (s)); \
    if (_p) memset(_p, 0, (n) * (s)); \
    _p; \
})

// realloc is trickier - implement wrapper
static inline void *ajos_realloc(void *ptr, size_t old_size, size_t new_size) {
    void *new_ptr = kmalloc(new_size);
    if (!new_ptr) return NULL;
    if (ptr) {
        memcpy(new_ptr, ptr, (old_size < new_size) ? old_size : new_size);
        kfree(ptr);
    }
    return new_ptr;
}
#define realloc(p, s) ajos_realloc(p, /* track old size */, s)

// String duplication
#define strdup(s) ({ \
    size_t _len = strlen(s) + 1; \
    char *_p = kmalloc(_len); \
    if (_p) memcpy(_p, s, _len); \
    _p; \
})
```

**Files to modify**:
- `sshbuf.c`: Already done ✅
- `packet.c`: Check all allocations
- `kex.c`: Check allocations
- `auth2.c`: Check allocations

**Pitfall**: OpenSSH assumes `realloc` preserves data. Your `kmalloc` may not, so track old sizes.

---

### Challenge 2: I/O Layer (TCP Callbacks → OpenSSH Packets)

**Problem**: OpenSSH expects file descriptors with `read()`/`write()`. You have `tcp_pcb` callbacks.

**Solution**: Create I/O adapter layer:

```c
// src/ajos_ssh_io.c

#include "openssh/ssh.h"
#include "openssh/packet.h"
#include "net.h"

// Per-connection state
struct ajos_ssh_connection {
    struct tcp_pcb *pcb;
    struct ssh *ssh;  // OpenSSH's main structure
    uint8_t rx_buffer[65536];  // TCP receive buffer
    size_t rx_len;
    uint8_t tx_buffer[65536];  // TCP send buffer
    size_t tx_len;
};

// TCP receive callback → Feed to OpenSSH
void ajos_ssh_tcp_receive(struct tcp_pcb *pcb, const uint8_t *data, size_t len) {
    struct ajos_ssh_connection *conn = pcb->user_data;
    
    // Append to receive buffer
    if (conn->rx_len + len > sizeof(conn->rx_buffer)) {
        // Buffer overflow - disconnect
        tcp_close(pcb);
        return;
    }
    memcpy(conn->rx_buffer + conn->rx_len, data, len);
    conn->rx_len += len;
    
    // Feed to OpenSSH packet layer
    // OpenSSH's packet.c expects: ssh_packet_process_read(ssh)
    // We need to implement a custom read function
    ssh_packet_process_read(conn->ssh);
}

// OpenSSH wants to send data → Write to TCP
static int ajos_ssh_write(struct ssh *ssh, const void *buf, size_t len) {
    struct ajos_ssh_connection *conn = ssh_get_app_data(ssh);
    
    // Send via TCP
    tcp_send_data(conn->pcb, buf, len);
    return len;  // Return bytes written
}

// OpenSSH wants to read data → Read from TCP buffer
static int ajos_ssh_read(struct ssh *ssh, void *buf, size_t len) {
    struct ajos_ssh_connection *conn = ssh_get_app_data(ssh);
    
    if (conn->rx_len < len) {
        return 0;  // Not enough data yet
    }
    
    memcpy(buf, conn->rx_buffer, len);
    // Shift buffer
    memmove(conn->rx_buffer, conn->rx_buffer + len, conn->rx_len - len);
    conn->rx_len -= len;
    
    return len;
}

// Hook into OpenSSH's I/O
void ajos_ssh_init_io(struct ajos_ssh_connection *conn) {
    // Set custom I/O functions
    ssh_set_io_callbacks(conn->ssh, &ajos_ssh_io_callbacks);
}
```

**Key Files to Modify**:
- `packet.c`: Replace `read()`/`write()` calls with your callbacks
- `sshbuf-io.c`: Rewrite completely for TCP

**Pitfall**: OpenSSH's packet layer expects blocking I/O. You must implement buffering.

---

### Challenge 3: Non-Blocking State Machine

**Problem**: OpenSSH uses `select()`/`poll()` to wait for data. You have event-driven callbacks.

**Solution**: Drive OpenSSH's dispatch from your TCP callback:

```c
// src/ajos_ssh.c

void ajos_ssh_handle_packet(struct ajos_ssh_connection *conn) {
    struct ssh *ssh = conn->ssh;
    
    // Check if we have a complete packet
    if (!ssh_packet_have_data(ssh)) {
        return;  // Wait for more data
    }
    
    // Get packet type
    int packet_type = ssh_packet_peek_type(ssh);
    
    // Dispatch to OpenSSH's handler
    int r = ssh_dispatch_run(ssh, packet_type, NULL);
    
    if (r != 0) {
        // Error - disconnect
        tcp_close(conn->pcb);
    }
}

// Called from TCP receive callback
void ajos_ssh_tcp_receive(struct tcp_pcb *pcb, const uint8_t *data, size_t len) {
    struct ajos_ssh_connection *conn = pcb->user_data;
    
    // Buffer data (see Challenge 2)
    // ...
    
    // Try to process packet
    ajos_ssh_handle_packet(conn);
}
```

**Key Insight**: OpenSSH's `ssh_dispatch_run()` is already non-blocking - it processes one packet and returns. You just need to call it from your TCP callback.

---

### Challenge 4: Entropy / Random Numbers

**Problem**: OpenSSH expects `/dev/urandom` or `getentropy()`. You have basic RNG.

**Solution**: Implement entropy source:

```c
// src/ajos_entropy.c

#include <stdint.h>

// Mix multiple entropy sources
static uint32_t ajos_entropy_seed = 0;

uint32_t ajos_get_random_u32(void) {
    extern uint32_t pit_ticks;
    extern uint64_t tsc_read(void);
    
    uint64_t tsc = tsc_read();
    uint32_t ticks = pit_ticks;
    
    // Linear congruential generator (not cryptographically secure, but works)
    ajos_entropy_seed = ajos_entropy_seed * 1103515245 + (tsc & 0xFFFFFFFF) + ticks + 12345;
    
    return ajos_entropy_seed;
}

// OpenSSH compatibility
int getentropy(void *buf, size_t len) {
    uint8_t *p = (uint8_t *)buf;
    for (size_t i = 0; i < len; i++) {
        p[i] = ajos_get_random_u32() & 0xFF;
    }
    return 0;
}

// For arc4random (if OpenSSH uses it)
uint32_t arc4random(void) {
    return ajos_get_random_u32();
}

void arc4random_buf(void *buf, size_t len) {
    getentropy(buf, len);
}
```

**Pitfall**: Your RNG may not be cryptographically secure. For production, improve it (mix network packet timing, interrupt timing, etc.).

---

### Challenge 5: No Fork/Exec (Session Management)

**Problem**: OpenSSH's `session.c` uses `fork()`/`exec()` to spawn shells.

**Solution**: Adapt to your process model:

```c
// src/ajos_ssh_session.c

// Instead of fork/exec, create a session structure
struct ajos_ssh_session {
    struct ajos_ssh_connection *conn;
    char command[256];  // Command to execute
    int pid;  // Your process ID (if you have processes)
    // ... session state
};

// OpenSSH calls: do_exec_pty(ssh, command)
// You implement:
int ajos_ssh_do_exec(struct ajos_ssh_connection *conn, const char *command) {
    // Create session
    struct ajos_ssh_session *session = kmalloc(sizeof(*session));
    session->conn = conn;
    strncpy(session->command, command, sizeof(session->command) - 1);
    
    // Execute command via your shell
    shell_execute(command);
    
    // Return output via SSH channel
    // ...
}
```

**Key Files to Modify**:
- `session.c`: Remove all `fork()`/`exec()` calls, replace with your process model
- `channels.c`: Adapt channel I/O to your console/keyboard

---

### Challenge 6: User Authentication

**Problem**: OpenSSH uses PAM or `/etc/passwd`. You have custom auth.

**Solution**: Implement custom auth function:

```c
// src/ajos_ssh_auth.c

#include "openssh/auth2.h"

// OpenSSH calls: auth_password(ssh, password)
// You implement:
int ajos_auth_password(const char *username, const char *password) {
    // Check against your user database
    // You already have auth.c - reuse it
    extern int auth_check_password(const char *user, const char *pass);
    return auth_check_password(username, password);
}

// Hook into OpenSSH's auth2-password.c
// Modify auth2-password.c to call ajos_auth_password() instead of PAM
```

**Files to Modify**:
- `auth2-password.c`: Replace PAM calls with `ajos_auth_password()`

---

## 3. Integration Architecture

### 3.1 Connection Structure

```c
// include/ajos_ssh.h

#include "openssh/ssh.h"
#include "net.h"

struct ajos_ssh_connection {
    // TCP layer
    struct tcp_pcb *pcb;
    
    // OpenSSH layer
    struct ssh *ssh;  // OpenSSH's main connection structure
    
    // Buffering
    uint8_t rx_buffer[65536];
    size_t rx_len;
    uint8_t tx_buffer[65536];
    size_t tx_len;
    
    // State
    int authenticated;
    int channels_open;
    
    // Your custom state (if needed)
    // ...
};
```

### 3.2 TCP → OpenSSH Bridge

```
┌─────────────────┐
│   TCP Stack     │
│  (tcp_pcb)      │
└────────┬────────┘
         │ on_receive(data, len)
         ▼
┌─────────────────┐
│ ajos_ssh_io.c   │  ← Buffer TCP data
│ (I/O Adapter)   │
└────────┬────────┘
         │ ssh_packet_process_read()
         ▼
┌─────────────────┐
│  packet.c       │  ← Parse SSH packets
│  (OpenSSH)      │
└────────┬────────┘
         │ ssh_dispatch_run()
         ▼
┌─────────────────┐
│  kex.c          │  ← Handle KEX
│  auth2.c        │  ← Handle auth
│  channels.c     │  ← Handle channels
└────────┬────────┘
         │ ssh_packet_send()
         ▼
┌─────────────────┐
│ ajos_ssh_io.c  │  ← Send via TCP
└────────┬───────┘
         │ tcp_send_data()
         ▼
┌─────────────────┐
│   TCP Stack     │
└─────────────────┘
```

### 3.3 Main Integration Point

```c
// src/ajos_ssh_main.c

void ajos_ssh_init(void) {
    // Initialize OpenSSH
    ssh_init();
    
    // Start TCP listener
    struct tcp_pcb *listen_pcb = tcp_get_free_pcb();
    listen_pcb->local_port = 22;
    listen_pcb->local_ip = 0;  // Listen on all interfaces
    listen_pcb->state = TCP_LISTEN;
    
    // Register accept callback
    tcp_register_accept_callback(listen_pcb, ajos_ssh_accept);
}

void ajos_ssh_accept(struct tcp_pcb *new_pcb) {
    // Allocate connection
    struct ajos_ssh_connection *conn = kmalloc(sizeof(*conn));
    conn->pcb = new_pcb;
    new_pcb->user_data = conn;
    
    // Initialize OpenSSH connection
    conn->ssh = ssh_alloc_session();
    ssh_set_app_data(conn->ssh, conn);
    
    // Set I/O callbacks
    ajos_ssh_init_io(conn);
    
    // Register TCP callbacks
    tcp_register_receive_callback(new_pcb, ajos_ssh_tcp_receive);
    tcp_register_close_callback(new_pcb, ajos_ssh_tcp_close);
    
    // Send SSH version string
    ajos_ssh_send_version(conn);
}
```

---

## 4. Actionable Step-by-Step Plan (15 Steps)

### Phase 1: Foundation (Days 1-3)

**Step 1**: Create compatibility layer
- [ ] Create `include/ajos_compat.h` with memory/string macros
- [ ] Create `src/ajos_stubs.c` with POSIX stubs (`getpid`, `getuid`, etc.)
- [ ] Test: Compile empty file that includes `ajos_compat.h`

**Step 2**: Copy and adapt buffer layer (already started ✅)
- [ ] Verify `sshbuf.c` uses `kmalloc`/`kfree`
- [ ] Test: Create buffer, add data, free buffer
- [ ] Fix any remaining compilation errors

**Step 3**: Copy packet layer
- [ ] Copy `packet.c`, `packet.h` to `src/openssh/`
- [ ] Copy `dispatch.c`, `dispatch.h`
- [ ] Copy `ssh.c`, `ssh.h` (main SSH structure)
- [ ] Modify `packet.c`: Replace `read()`/`write()` with stubs (we'll implement later)
- [ ] Test: Compile packet layer (may have errors, fix incrementally)

**Step 4**: Create I/O adapter
- [ ] Create `src/ajos_ssh_io.c` with TCP→OpenSSH bridge
- [ ] Implement `ajos_ssh_read()` and `ajos_ssh_write()`
- [ ] Hook into OpenSSH's I/O system
- [ ] Test: Can you call `ssh_packet_process_read()`?

### Phase 2: Key Exchange (Days 4-7)

**Step 5**: Copy KEX files
- [ ] Copy `kex.c`, `kex.h`
- [ ] Copy `kexgexs.c`, `kexgex.c`
- [ ] Fix compilation errors (mostly missing includes)
- [ ] Test: Can you create a KEX structure?

**Step 6**: Copy host key files
- [ ] Copy `sshkey.c`, `sshkey.h`
- [ ] Copy `ssh-rsa.c` (or keep your own)
- [ ] Modify to remove file I/O (hardcode key in memory)
- [ ] Test: Can you load a key and sign data?

**Step 7**: Integrate KEX with your TCP
- [ ] Wire up `ajos_ssh_handle_packet()` to call `ssh_dispatch_run()`
- [ ] Register KEX handlers
- [ ] Test: Can you receive KEXINIT and respond?

**Step 8**: Fix signature computation
- [ ] Either fix your `bigint_mod_exp` bug, OR
- [ ] Use OpenSSH's RSA implementation (if you ported it)
- [ ] Test: Does signature verification pass?

### Phase 3: Authentication (Days 8-10)

**Step 9**: Copy auth files
- [ ] Copy `auth2.c`, `auth2.h`
- [ ] Copy `auth2-password.c`
- [ ] Modify `auth2-password.c` to call your `auth_check_password()`
- [ ] Test: Can you receive USERAUTH_REQUEST?

**Step 10**: Wire up auth
- [ ] Register auth handlers in dispatch table
- [ ] Test: Can you authenticate with password?

### Phase 4: Channels & Session (Days 11-14)

**Step 11**: Copy channel files
- [ ] Copy `channels.c`, `channels.h`
- [ ] Copy `session.c`, `session.h`
- [ ] Modify `session.c` to remove `fork()`/`exec()`
- [ ] Test: Can you open a channel?

**Step 12**: Implement shell execution
- [ ] Create `ajos_ssh_shell()` function
- [ ] Wire channel data to your shell
- [ ] Wire shell output to channel
- [ ] Test: Can you execute a command?

**Step 13**: Handle channel requests
- [ ] Implement PTY request (simplified)
- [ ] Implement shell request
- [ ] Test: Can you get a shell prompt?

### Phase 5: Polish (Days 15+)

**Step 14**: Add encryption/MAC
- [ ] Copy `cipher.c`, `mac.c`
- [ ] Implement AES or ChaCha20
- [ ] Enable encryption after NEWKEYS
- [ ] Test: Are packets encrypted?

**Step 15**: Cleanup and testing
- [ ] Remove your old SSH code (or keep as fallback)
- [ ] Test with multiple clients
- [ ] Fix memory leaks
- [ ] Test edge cases (disconnect, timeout, etc.)

---

## 5. Cryptography Decision

### Option A: Keep Your Crypto (Recommended Initially)

**Pros**:
- Already integrated
- You understand it
- Less porting work

**Cons**:
- May have bugs (like your RSA issue)
- Not as well-tested as OpenSSH's

**Action**: Fix your `bigint_mod_exp` bug, keep using it for now.

### Option B: Use OpenSSH's Crypto

**Pros**:
- Well-tested
- More algorithms
- Better performance (often)

**Cons**:
- More porting work
- May depend on OpenSSL (need to port or use libcrypto-free version)

**Files to Port** (if choosing Option B):
- `digest-openssl.c` or `digest-libc.c` (SHA-256, SHA-512)
- `cipher-aes*.c` (AES encryption)
- `ssh-rsa.c` (RSA operations)
- `dh.c` (Diffie-Hellman)

**Recommendation**: Start with Option A, gradually migrate to Option B if needed.

---

## 6. Common Pitfalls & Solutions

### Pitfall 1: Memory Leaks

**Problem**: OpenSSH allocates many small buffers. Easy to leak.

**Solution**:
- Use valgrind-equivalent (if available) or manual tracking
- Pre-allocate connection structures
- Check all `kmalloc` calls have matching `kfree`

**Example**:
```c
// BAD: Leak if error
void *buf = kmalloc(1024);
if (error) return;  // Leak!
kfree(buf);

// GOOD: Always free
void *buf = kmalloc(1024);
if (error) {
    kfree(buf);
    return;
}
kfree(buf);
```

### Pitfall 2: Stack Overflow

**Problem**: OpenSSH uses large stack buffers (packets can be 64KB).

**Solution**:
- Use heap allocation for large buffers
- Check stack usage with `-fstack-usage`
- Limit packet sizes

**Example**:
```c
// BAD: 64KB on stack
uint8_t packet[65536];

// GOOD: Heap allocation
uint8_t *packet = kmalloc(65536);
// ... use packet ...
kfree(packet);
```

### Pitfall 3: Reentrancy

**Problem**: TCP callback can fire during OpenSSH processing.

**Solution**:
- Use reentrancy guards
- Disable interrupts during critical sections
- Queue packets if processing

**Example**:
```c
struct ajos_ssh_connection {
    int processing;  // Reentrancy guard
    // ...
};

void ajos_ssh_handle_packet(struct ajos_ssh_connection *conn) {
    if (conn->processing) {
        // Queue packet for later
        queue_packet(conn, packet);
        return;
    }
    
    conn->processing = 1;
    __asm__ volatile("cli");  // Disable interrupts
    
    ssh_dispatch_run(conn->ssh, packet_type, NULL);
    
    __asm__ volatile("sti");  // Re-enable
    conn->processing = 0;
    
    // Process queued packets
    process_queued_packets(conn);
}
```

### Pitfall 4: Blocking Calls

**Problem**: OpenSSH may call blocking functions (even if you stubbed them).

**Solution**:
- Audit all function calls
- Replace blocking calls with non-blocking equivalents
- Use state machines

**Example**:
```c
// BAD: Blocking (if implemented)
int n = read(fd, buf, len);

// GOOD: Non-blocking
int n = ajos_ssh_read(conn, buf, len);
if (n == 0) {
    // Not ready yet, return and try later
    return;
}
```

### Pitfall 5: Unaligned Access

**Problem**: OpenSSH may assume aligned memory (x86 is forgiving, but be careful).

**Solution**:
- Use `memcpy` for unaligned access
- Check alignment before casting

**Example**:
```c
// BAD: May be unaligned
uint32_t *p = (uint32_t *)data;
uint32_t val = *p;

// GOOD: Safe
uint32_t val;
memcpy(&val, data, sizeof(val));
```

### Pitfall 6: Endianness

**Problem**: OpenSSH assumes network byte order (big-endian). x86 is little-endian.

**Solution**:
- Use `htonl`/`ntohl` for network data
- OpenSSH already handles this, but check your integration

---

## 7. Realistic Milestone Order

### Milestone 1: KEX Complete (Week 1)
- [ ] Version exchange works
- [ ] KEXINIT negotiation works
- [ ] DH Group Exchange completes
- [ ] Host key signature verifies ✅
- [ ] NEWKEYS exchanged

**Success Criteria**: Client accepts host key, no "incorrect signature" error.

### Milestone 2: Encryption Active (Week 1-2)
- [ ] Encryption keys derived
- [ ] Packets encrypted after NEWKEYS
- [ ] MAC verification works
- [ ] Encrypted packet exchange

**Success Criteria**: `ssh -vvv` shows encrypted packets.

### Milestone 3: Password Auth (Week 2)
- [ ] USERAUTH_REQUEST received
- [ ] Password checked
- [ ] USERAUTH_SUCCESS sent
- [ ] Service accepted

**Success Criteria**: Can authenticate with password.

### Milestone 4: Channel Open (Week 2)
- [ ] CHANNEL_OPEN received
- [ ] CHANNEL_OPEN_CONFIRMATION sent
- [ ] Channel data flows

**Success Criteria**: Channel established, no errors.

### Milestone 5: Shell Access (Week 3)
- [ ] Shell request handled
- [ ] Command execution works
- [ ] Output sent back
- [ ] Basic interactivity

**Success Criteria**: Can run `ls`, `pwd`, etc. and see output.

### Milestone 6: Full Session (Week 3+)
- [ ] PTY handling (if needed)
- [ ] Terminal size
- [ ] Signal handling
- [ ] Clean disconnect

**Success Criteria**: Full interactive shell works.

---

## 8. Brutal Reality Check

### What's Achievable in 2-3 Weeks
✅ Basic SSH server (password auth + shell)  
✅ KEX with working signatures  
✅ Encrypted packet exchange  
✅ Simple command execution  

### What Will Take 1-2 Months
⏳ Public key authentication  
⏳ Rekeying  
⏳ Multiple channels  
⏳ Subsystem support (sftp)  
⏳ Full PTY support  
⏳ Signal handling  

### What May Never Work (Without Major Effort)
❌ Privilege separation (requires process model)  
❌ Complex sandboxing  
❌ Full OpenSSH feature parity  

### Recommendation
**Start with Milestone 1-5 (2-3 weeks)**. Get basic SSH working, then decide if you need more features. Most users just need password auth + shell, which is achievable.

---

## 9. Quick Reference: File Mapping

| OpenSSH File | Your File | Status |
|-------------|-----------|--------|
| `sshbuf.c` | `src/openssh/sshbuf.c` | ✅ Done |
| `packet.c` | `src/openssh/packet.c` | ⏳ To do |
| `kex.c` | `src/openssh/kex.c` | ⏳ To do |
| `auth2-password.c` | `src/openssh/auth2-password.c` | ⏳ To do |
| `channels.c` | `src/openssh/channels.c` | ⏳ To do |
| `session.c` | `src/openssh/session.c` | ⏳ To do |
| `sshd.c` | `src/ajos_ssh_main.c` | ⏳ Rewrite |
| `sshbuf-io.c` | `src/ajos_ssh_io.c` | ⏳ Rewrite |

---

## 10. Next Immediate Actions

1. **Fix your RSA bug** (1-2 days) - This unblocks you immediately
2. **Create `ajos_compat.h`** (2 hours) - Foundation for everything
3. **Copy `packet.c` and adapt** (1 day) - Core protocol layer
4. **Create I/O adapter** (1 day) - Bridge TCP to OpenSSH
5. **Test KEX with OpenSSH** (2 days) - Verify integration works

**Total**: ~1 week to get OpenSSH KEX working alongside your code.

---

## Conclusion

Porting OpenSSH to a kernel is **hard but doable**. The key is:
1. Start small (buffer layer ✅)
2. Build incrementally (packet → KEX → auth → channels)
3. Fix one thing at a time
4. Test constantly

**You're already 20% there** (buffer layer works). The next 80% is integration work, not rewriting protocol logic.

Good luck! 🚀
