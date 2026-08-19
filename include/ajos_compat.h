#ifndef AJOS_COMPAT_H
#define AJOS_COMPAT_H

// Compatibility layer for porting OpenSSH to AJOS kernel
// This file provides POSIX/libc replacements for kernel environment

#include "kernel.h"  // Your kernel headers

// Standard types (define manually since -nostdinc)
#ifndef _STDDEF_H
#define _STDDEF_H
typedef unsigned long size_t;
typedef long ssize_t;
typedef int ptrdiff_t;
#endif

#ifndef _STDINT_H
#define _STDINT_H
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef long long int64_t;
#endif

#ifndef _STDARG_H
#define _STDARG_H
typedef __builtin_va_list va_list;
#define va_start(v,l) __builtin_va_start(v,l)
#define va_end(v) __builtin_va_end(v)
#define va_arg(v,l) __builtin_va_arg(v,l)
#define va_copy(dest, src) __builtin_va_copy(dest, src)
#define VA_COPY(dest, src) va_copy(dest, src)
#endif

// SIZE_MAX (maximum value for size_t)
#ifndef SIZE_MAX
#define SIZE_MAX ((size_t)-1)
#endif

// ============================================================================
// Memory Management (replace libc malloc with kernel kmalloc)
// ============================================================================

extern void *kmalloc(uint32_t size);
extern void kfree(void *ptr);
extern void *memset(void *s, int c, size_t n);
extern void *memcpy(void *dest, const void *src, size_t n);
extern void *memmove(void *dest, const void *src, size_t n);
extern void *memchr(const void *s, int c, size_t n);
extern int memcmp(const void *s1, const void *s2, size_t n);

#define malloc(x) kmalloc(x)
#define free(x) kfree(x)

// calloc(n, size) = allocate and zero-initialize
#define calloc(n, size) ({ \
    void *_p = kmalloc((n) * (size)); \
    if (_p) memset(_p, 0, (n) * (size)); \
    _p; \
})

// realloc(p, size) = allocate new, copy old, free old
// Note: This doesn't preserve old size, so use carefully
#define realloc(p, size) ({ \
    void *_p = kmalloc(size); \
    if (_p && p) { \
        /* Warning: We don't know old size, so this is unsafe */ \
        /* Better to avoid realloc in kernel code */ \
    } \
    if (p) kfree(p); \
    _p; \
})

// OpenBSD-specific functions
// freezero(ptr, size) - free and zero memory (security)
static inline void freezero(void *ptr, size_t size) {
    if (ptr) {
        memset(ptr, 0, size);
        kfree(ptr);
    }
}

// explicit_bzero(ptr, size) - zero memory explicitly (security)
static inline void explicit_bzero(void *ptr, size_t size) {
    if (ptr) {
        memset(ptr, 0, size);
        // Memory barrier to prevent optimization
        __asm__ volatile("" ::: "memory");
    }
}

// ROUNDUP(x, y) - round x up to nearest multiple of y
#define ROUNDUP(x, y) ((((x) + (y) - 1) / (y)) * (y))

// recallocarray(ptr, oldnmemb, newnmemb, size) - realloc with zero-initialization
static inline void *recallocarray(void *ptr, size_t oldnmemb, size_t newnmemb, size_t size) {
    void *newptr = kmalloc(newnmemb * size);
    if (!newptr) return NULL;
    memset(newptr, 0, newnmemb * size);
    if (ptr) {
        size_t copysize = (oldnmemb < newnmemb) ? oldnmemb : newnmemb;
        memcpy(newptr, ptr, copysize * size);
        kfree(ptr);
    }
    return newptr;
}

// ============================================================================
// String Functions
// ============================================================================

extern size_t strlen(const char *s);
extern char *strcpy(char *dest, const char *src);
extern char *strncpy(char *dest, const char *src, size_t n);
extern int strcmp(const char *s1, const char *s2);
extern int strncmp(const char *s1, const char *s2, size_t n);
extern char *strdup(const char *s);

// strdup implementation
static inline char *ajos_strdup(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s) + 1;
    char *p = kmalloc(len);
    if (p) memcpy(p, s, len);
    return p;
}

#define strdup(s) ajos_strdup(s)

// ============================================================================
// Logging (replace OpenSSH's log functions with your kernel logging)
// ============================================================================

extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void log_write_hex8(uint8_t v);

// vsnprintf - minimal implementation for OpenSSH
// This is a very basic implementation - just returns 0 for size calculation
static inline int vsnprintf(char *str, size_t size, const char *format, va_list ap) {
    // Stub implementation - OpenSSH uses this to calculate buffer size
    // For now, just return 0 (will need proper implementation later)
    (void)str;
    (void)size;
    (void)format;
    (void)ap;
    return 0;
}

// Simple printf-like function (basic implementation)
static inline void ajos_log_printf(const char *fmt, ...) {
    // Very basic implementation - just log the format string
    // For full printf, you'd need to implement vsnprintf
    log_writestring(fmt);
}

// OpenSSH logging macros
#define fatal(...) do { \
    log_writestring("[SSH FATAL] "); \
    ajos_log_printf(__VA_ARGS__); \
    log_putchar('\n'); \
} while(0)

#define error(...) do { \
    log_writestring("[SSH ERROR] "); \
    ajos_log_printf(__VA_ARGS__); \
    log_putchar('\n'); \
} while(0)

#define logit(...) do { \
    log_writestring("[SSH] "); \
    ajos_log_printf(__VA_ARGS__); \
    log_putchar('\n'); \
} while(0)

#define debug(...) do { \
    log_writestring("[SSH DEBUG] "); \
    ajos_log_printf(__VA_ARGS__); \
    log_putchar('\n'); \
} while(0)

#define verbose(...) do { \
    log_writestring("[SSH VERBOSE] "); \
    ajos_log_printf(__VA_ARGS__); \
    log_putchar('\n'); \
} while(0)

// ============================================================================
// Process/User Management (stub out - not applicable in kernel)
// ============================================================================

typedef int pid_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;

#define getpid() 1
#define getuid() 0
#define getgid() 0
#define setsid() 0
#define setuid(x) 0
#define setgid(x) 0
#define setresuid(ruid, euid, suid) 0
#define setresgid(rgid, egid, sgid) 0

// User/group structures (stub)
struct passwd {
    char *pw_name;
    uid_t pw_uid;
    gid_t pw_gid;
};

struct group {
    char *gr_name;
    gid_t gr_gid;
};

// Stub implementations (you'll need to implement these based on your user system)
static inline struct passwd *getpwnam(const char *name) {
    // TODO: Implement your user lookup
    return NULL;
}

static inline struct group *getgrnam(const char *name) {
    // TODO: Implement your group lookup
    return NULL;
}

// ============================================================================
// File I/O (stub out - use your filesystem or hardcode configs)
// ============================================================================

typedef int FILE;
#define NULL_FILE ((FILE *)0)

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 4
#define O_TRUNC 8

// Stub file operations
static inline int open(const char *path, int flags, ...) {
    // TODO: Use your filesystem API
    return -1;
}

static inline int close(int fd) {
    return -1;
}

static inline ssize_t read(int fd, void *buf, size_t count) {
    // TODO: Use your filesystem API
    return -1;
}

static inline ssize_t write(int fd, const void *buf, size_t count) {
    // TODO: Use your filesystem API
    return -1;
}

// ============================================================================
// Process Management (stub out - use your process model)
// ============================================================================

static inline pid_t fork(void) {
    // You'll handle this differently - maybe create a new process struct
    return -1;
}

static inline int execve(const char *path, char *const argv[], char *const envp[]) {
    // Use your process execution API
    return -1;
}

static inline pid_t waitpid(pid_t pid, int *status, int options) {
    return -1;
}

// ============================================================================
// Random Number Generation (implement using your entropy source)
// ============================================================================

// TODO: Implement this using your kernel's entropy source
// (TSC, interrupt timing, network packets, etc.)
static inline int getentropy(void *buf, size_t len) {
    // Example: Use TSC-based PRNG
    // You should implement a proper entropy source
    extern uint64_t rdtsc(void);
    uint8_t *p = (uint8_t *)buf;
    static uint32_t seed = 0;
    
    for (size_t i = 0; i < len; i++) {
        uint64_t tsc = rdtsc();
        seed = seed * 1103515245 + (tsc & 0xFFFFFFFF) + 12345;
        p[i] = (seed >> 16) & 0xFF;
    }
    return 0;
}

// ============================================================================
// Time Functions
// ============================================================================

typedef long time_t;
struct timespec {
    time_t tv_sec;
    long tv_nsec;
};

static inline int clock_gettime(int clk_id, struct timespec *tp) {
    // TODO: Use your kernel's time source
    if (tp) {
        tp->tv_sec = 0;
        tp->tv_nsec = 0;
    }
    return 0;
}

// ============================================================================
// Signal Handling (stub out - not applicable in kernel)
// ============================================================================

typedef void (*sighandler_t)(int);
#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)

static inline sighandler_t signal(int signum, sighandler_t handler) {
    return SIG_DFL;
}

// ============================================================================
// Network (use your TCP stack instead)
// ============================================================================

// These are stubbed - you'll use your tcp_pcb directly
typedef int socket_t;
#define INVALID_SOCKET (-1)

// ============================================================================
// Other POSIX Stubs
// ============================================================================

#define EINVAL 22
#define ENOENT 2
#define EACCES 13
#define EPIPE 32
#define errno (*__errno_location())

// timingsafe_bcmp - constant-time memory comparison
static inline int timingsafe_bcmp(const void *a, const void *b, size_t len) {
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    int result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= pa[i] ^ pb[i];
    }
    return result;
}

// memmem - find substring in memory
static inline void *memmem(const void *haystack, size_t haystacklen,
                           const void *needle, size_t needlelen) {
    const uint8_t *h = (const uint8_t *)haystack;
    const uint8_t *n = (const uint8_t *)needle;
    
    if (needlelen == 0) return (void *)h;
    if (needlelen > haystacklen) return NULL;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        // Manual byte-by-byte comparison (memcmp not available)
        int match = 1;
        for (size_t j = 0; j < needlelen; j++) {
            if (h[i + j] != n[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

// fprintf - stub (not available in kernel)
static inline int fprintf(void *stream, const char *format, ...) {
    (void)stream;
    (void)format;
    return 0;
}

// isascii - check if character is ASCII
static inline int isascii(int c) {
    return (c >= 0 && c <= 127);
}

// isprint - check if character is printable
static inline int isprint(int c) {
    return (c >= 32 && c <= 126);
}

// Simple errno implementation
static int __ajos_errno = 0;
static inline int *__errno_location(void) {
    return &__ajos_errno;
}

// ============================================================================
// OpenSSH-specific compatibility
// ============================================================================

// OpenSSH uses these for buffer allocation
// These will be defined in sshbuf.c after you modify it
#ifndef SSH_BUFFER_ALLOC
#define SSH_BUFFER_ALLOC(x) kmalloc(x)
#endif

#ifndef SSH_BUFFER_FREE
#define SSH_BUFFER_FREE(x) kfree(x)
#endif

#endif // AJOS_COMPAT_H
