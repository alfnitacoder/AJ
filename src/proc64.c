/* proc64.c - ring-3 processes for the AJOS x86-64 port (milestone 16).
 *
 * fork / execve / waitpid plus a preemptive round-robin scheduler. The
 * kernel stays non-preemptible (syscall runs with IF clear; the timer
 * only switches when the interrupted CS is ring 3). Each process owns a
 * code frame and a stack frame. Only the running process is mapped into
 * the shared user window at 1TB; a switch remaps that window. Private
 * page tables are milestone 18.
 *
 * User images are position-independent and at most one page. The boot
 * test runs an embedded FORKDEMO that forks, waits, and execs CHILD64.
 * The M10 demo and the shell `run` path still have no current process:
 * their exit syscall falls into the shell, as before.
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

#define USER_BASE    0x10000000000ull
#define USER_STACK   0x10000100000ull
#define USER_STACK_TOP (USER_STACK + 4096ull)
#define PAGE         4096u
#define MAX_PROCS    8
#define QUANTUM      10          /* PIT ticks; 100Hz -> 100ms, matching i386 */

#define ST_FREE   0
#define ST_RUN    1
#define ST_SLEEP  2
#define ST_WAIT   3
#define ST_ZOMBIE 4

struct uctx {
    u64 rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    u64 r8, r9, r10, r11, r12, r13, r14, r15;
    u64 rip, rflags;
};

struct proc {
    int state;
    u32 pid;
    u32 ppid;
    u32 exit_code;
    u64 wake;
    u64 wpid;            /* waitpid pid filter; 0 = any child */
    u64 wstatus;         /* user virtual address of the status word */
    u64 code_phys;
    u64 stack_phys;
    int background;          /* spawned by the shell with '&' */
    char name[16];
    struct uctx ctx;
};

/* Filled by syscall_entry before the C handler runs. */
struct uctx proc64_snap;

extern u64 pmm64_alloc_frame(void);
extern void pmm64_free_frame(u64 phys);
extern void vm64_map_user(u64 vaddr, u64 paddr, int noexec);
extern u64 timer64_ticks(void);
extern void timer64_tick(void);
extern void timer64_wait(u64 ticks);
extern int fat64_read_file(const char *name, void *out, unsigned int cap);
extern void sh64_run(void) __attribute__((noreturn));
extern void proc64_iret_user(struct uctx *ctx) __attribute__((noreturn));
extern int proc_save_kernel(void);
extern void proc_restore_kernel(void) __attribute__((noreturn));

extern u8 _binary_forkdemo64_bin_start[];
extern u8 _binary_forkdemo64_bin_end[];
extern u8 _binary_child64_bin_start[];
extern u8 _binary_child64_bin_end[];
extern u8 _binary_m17demo_bin_start[];
extern u8 _binary_m17demo_bin_end[];

static struct proc procs[MAX_PROCS];
static struct proc *current;
static u32 next_pid = 1;
static int kernel_armed;
static int preempt_noted;
static int slice;
static int rr;
/* shell_poll_mode: background pump. Return to the shell instead of hlt
 * when the only user tasks are sleeping, and yield after one quantum.
 * focus_pid: foreground wait. 0 = none, 0xffffffff = any shell child. */
static int shell_poll_mode;
static u32 focus_pid;

#define COM1 0x3F8
static inline void outb(u16 port, u8 val)
{
    __asm__ __volatile__("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline u8 inb(u16 port)
{
    u8 v;
    __asm__ __volatile__("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static void ser_putc(char c)
{
    int spins = 100000;
    while (!(inb(COM1 + 5) & 0x20)) {
        if (--spins <= 0) return;
    }
    outb(COM1, (u8)c);
}
static void ser_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') ser_putc('\r');
        ser_putc(*s++);
    }
}
static void ser_put_dec(u64 v)
{
    char buf[21];
    int i = 0;
    if (!v) { ser_putc('0'); return; }
    while (v) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i) ser_putc(buf[--i]);
}

static void memzero(void *d, u32 n)
{
    u8 *p = (u8 *)d;
    while (n--) *p++ = 0;
}
static void memcopy(void *d, const void *s, u32 n)
{
    u8 *dd = (u8 *)d;
    const u8 *ss = (const u8 *)s;
    while (n--) *dd++ = *ss++;
}

static void name_set(struct proc *p, const char *s)
{
    int i = 0;
    if (!s) s = "?";
    while (s[i] && i < 15) { p->name[i] = s[i]; i++; }
    p->name[i] = 0;
}

static struct proc *proc_by_pid(u32 pid)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++)
        if (procs[i].state != ST_FREE && procs[i].pid == pid)
            return &procs[i];
    return 0;
}

static void proc_release(struct proc *p)
{
    if (p->code_phys) pmm64_free_frame(p->code_phys);
    if (p->stack_phys) pmm64_free_frame(p->stack_phys);
    memzero(p, sizeof(*p));
}

static struct proc *proc_slot(void)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++) {
        if (procs[i].state == ST_FREE) {
            memzero(&procs[i], sizeof(procs[i]));
            procs[i].pid = next_pid++;
            if (next_pid == 0) next_pid = 1;
            return &procs[i];
        }
    }
    return 0;
}

/* User window VA -> that process's physical frame. 0 if it isn't in the window. */
static u64 uvirt_to_phys(struct proc *p, u64 v)
{
    if (!p) return 0;
    if (v >= USER_BASE && v < USER_BASE + PAGE)
        return p->code_phys + (v - USER_BASE);
    if (v >= USER_STACK && v < USER_STACK + PAGE)
        return p->stack_phys + (v - USER_STACK);
    return 0;
}

static int ustr(struct proc *p, u64 uaddr, char *dst, int cap)
{
    int i;
    if (cap < 2) return 0;
    for (i = 0; i < cap - 1; i++) {
        u64 phys = uvirt_to_phys(p, uaddr + (u64)i);
        char c;
        if (!phys) return 0;
        c = *(volatile char *)phys;
        dst[i] = c;
        if (c == 0) return 1;
        if (c < 32 || c > 126) return 0;
    }
    return 0;
}

static int uwrite64(struct proc *p, u64 uaddr, u64 val)
{
    u64 phys;
    if (!uaddr || (uaddr & 7)) return 0;
    phys = uvirt_to_phys(p, uaddr);
    if (!phys || !uvirt_to_phys(p, uaddr + 7)) return 0;
    *(volatile u64 *)phys = val;
    return 1;
}

static void map_proc(struct proc *p)
{
    vm64_map_user(USER_BASE, p->code_phys, 0);
    vm64_map_user(USER_STACK, p->stack_phys, 1);
}

static int alloc_frames(struct proc *p)
{
    p->code_phys = pmm64_alloc_frame();
    p->stack_phys = pmm64_alloc_frame();
    if (!p->code_phys || !p->stack_phys) {
        if (p->code_phys) pmm64_free_frame(p->code_phys);
        if (p->stack_phys) pmm64_free_frame(p->stack_phys);
        p->code_phys = p->stack_phys = 0;
        return 0;
    }
    memzero((void *)p->code_phys, PAGE);
    memzero((void *)p->stack_phys, PAGE);
    return 1;
}

static int load_image(struct proc *p, const u8 *img, u32 size)
{
    if (!img || !size || size > PAGE) return 0;
    memzero((void *)p->code_phys, PAGE);
    memzero((void *)p->stack_phys, PAGE);
    memcopy((void *)p->code_phys, img, size);
    memzero(&p->ctx, sizeof p->ctx);
    p->ctx.rip = USER_BASE;
    p->ctx.rsp = USER_STACK_TOP;
    p->ctx.rflags = 0x202;
    return 1;
}

static void snap_to_ctx(struct proc *p)
{
    p->ctx = proc64_snap;
    p->ctx.rflags |= 2;          /* reserved bit, always set */
}

static void wake_sleepers(void)
{
    u64 now = timer64_ticks();
    int i;
    for (i = 0; i < MAX_PROCS; i++) {
        if (procs[i].state == ST_SLEEP && (long long)(now - procs[i].wake) >= 0)
            procs[i].state = ST_RUN;
    }
}

static int is_child(struct proc *c, struct proc *parent, u64 pid)
{
    if (c->state == ST_FREE || c == parent) return 0;
    if (c->ppid != parent->pid) return 0;
    if (pid != 0 && c->pid != pid) return 0;
    return 1;
}

/* Reap one matching zombie. Returns 1 and sets *out_pid on success. */
static int reap_one(struct proc *parent, u64 pid, u64 status_u, u64 *out_pid)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++) {
        struct proc *c = &procs[i];
        u32 reaped, code;
        if (!is_child(c, parent, pid) || c->state != ST_ZOMBIE)
            continue;
        reaped = c->pid;
        code = c->exit_code;
        if (status_u)
            uwrite64(parent, status_u, code);
        proc_release(c);
        *out_pid = reaped;
        return 1;
    }
    return 0;
}

static int has_child(struct proc *parent, u64 pid)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++)
        if (is_child(&procs[i], parent, pid))
            return 1;
    return 0;
}

static void complete_waits(void)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++) {
        struct proc *p = &procs[i];
        u64 reaped = 0;
        if (p->state != ST_WAIT) continue;
        if (reap_one(p, p->wpid, p->wstatus, &reaped)) {
            p->ctx.rax = reaped;
            p->state = ST_RUN;
        } else if (!has_child(p, p->wpid)) {
            p->ctx.rax = (u64)-1;
            p->state = ST_RUN;
        }
    }
}

static struct proc *pick_next(struct proc *cur, int allow_same)
{
    int i, start;
    start = cur ? (int)(cur - procs) : rr;
    for (i = 1; i <= MAX_PROCS; i++) {
        int idx = (start + i) % MAX_PROCS;
        if (&procs[idx] == cur && !allow_same) continue;
        if (procs[idx].state == ST_RUN && procs[idx].code_phys) {
            rr = idx;
            return &procs[idx];
        }
    }
    return 0;
}

static int any_sleeping(void)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++)
        if (procs[i].state == ST_SLEEP) return 1;
    return 0;
}

static void proc64_dispatch_next(void) __attribute__((noreturn));

/* 1 when a foreground shell wait should resume (target zombie or gone). */
static int focus_done(void)
{
    int i, saw = 0;
    if (!focus_pid) return 0;
    for (i = 0; i < MAX_PROCS; i++) {
        struct proc *p = &procs[i];
        if (p->state == ST_FREE || p->ppid != 0) continue;
        if (focus_pid != 0xffffffffu && p->pid != focus_pid) continue;
        saw = 1;
        if (p->state == ST_ZOMBIE) return 1;
    }
    return saw ? 0 : 1;
}

static void proc64_dispatch_next(void)
{
    for (;;) {
        struct proc *n;
        __asm__ volatile("cli" ::: "memory");
        wake_sleepers();
        complete_waits();
        if (focus_done()) {
            current = 0;
            if (kernel_armed)
                proc_restore_kernel();
        }
        n = pick_next(0, 1);
        if (n) {
            current = n;
            map_proc(n);
            proc64_iret_user(&n->ctx);
        }
        current = 0;
        /* Background pump must not sleep inside the scheduler: the shell
         * still has to poll the NIC. A foreground wait stays here. */
        if (shell_poll_mode && kernel_armed)
            proc_restore_kernel();
        if (!any_sleeping()) {
            if (kernel_armed)
                proc_restore_kernel();
            for (;;)
                __asm__ volatile("hlt");
        }
        __asm__ volatile("sti; hlt; cli" ::: "memory");
    }
}

static struct proc *spawn_image(const char *name, const u8 *img, u32 size, u32 ppid)
{
    struct proc *p = proc_slot();
    if (!p) return 0;
    p->ppid = ppid;
    name_set(p, name);
    if (!alloc_frames(p) || !load_image(p, img, size)) {
        proc_release(p);
        return 0;
    }
    p->state = ST_RUN;
    return p;
}

static void ctx_from_frame(struct proc *p, u64 *fr)
{
    /* fr layout matches isr64_stub_32: r15 at [0] ... rax at [14], then
     * the CPU frame rip, cs, rflags, rsp, ss. */
    p->ctx.r15 = fr[0];  p->ctx.r14 = fr[1];  p->ctx.r13 = fr[2];
    p->ctx.r12 = fr[3];  p->ctx.r11 = fr[4];  p->ctx.r10 = fr[5];
    p->ctx.r9  = fr[6];  p->ctx.r8  = fr[7];  p->ctx.rbp = fr[8];
    p->ctx.rdi = fr[9];  p->ctx.rsi = fr[10]; p->ctx.rdx = fr[11];
    p->ctx.rcx = fr[12]; p->ctx.rbx = fr[13]; p->ctx.rax = fr[14];
    p->ctx.rip = fr[15];
    p->ctx.rflags = fr[17] | 2;
    p->ctx.rsp = fr[18];
}

static void frame_from_ctx(const struct proc *p, u64 *fr)
{
    fr[0]  = p->ctx.r15; fr[1]  = p->ctx.r14; fr[2]  = p->ctx.r13;
    fr[3]  = p->ctx.r12; fr[4]  = p->ctx.r11; fr[5]  = p->ctx.r10;
    fr[6]  = p->ctx.r9;  fr[7]  = p->ctx.r8;  fr[8]  = p->ctx.rbp;
    fr[9]  = p->ctx.rdi; fr[10] = p->ctx.rsi; fr[11] = p->ctx.rdx;
    fr[12] = p->ctx.rcx; fr[13] = p->ctx.rbx; fr[14] = p->ctx.rax;
    fr[15] = p->ctx.rip;
    fr[16] = 0x2B;
    fr[17] = p->ctx.rflags | 2;
    fr[18] = p->ctx.rsp;
    fr[19] = 0x23;
}

/* Timer IRQ. Ring 0: count a tick. Ring 3: maybe preempt. */
void proc64_on_timer(u64 *fr)
{
    u64 cs;
    timer64_tick();
    outb(0x20, 0x20);
    cs = fr[16];
    if ((cs & 3) != 3) return;
    if (!current || current->state != ST_RUN) return;

    if (++slice < QUANTUM) return;
    slice = 0;
    wake_sleepers();
    complete_waits();
    /* Hand the CPU back to the shell after one quantum of a background job. */
    if (shell_poll_mode && kernel_armed) {
        ctx_from_frame(current, fr);
        current = 0;
        proc_restore_kernel();
    }
    {
        struct proc *n = pick_next(current, 0);
        if (!n || n == current) return;
        ctx_from_frame(current, fr);
        if (!preempt_noted) {
            ser_puts(" PREEMPT-OK-16\n");
            preempt_noted = 1;
        }
        current = n;
        map_proc(n);
        frame_from_ctx(n, fr);
    }
}

static u64 sys_fork(void)
{
    struct proc *child;
    if (!current || current->state != ST_RUN) return (u64)-1;
    child = proc_slot();
    if (!child) return (u64)-1;
    child->ppid = current->pid;
    name_set(child, current->name);
    if (!alloc_frames(child)) {
        proc_release(child);
        return (u64)-1;
    }
    memcopy((void *)child->code_phys, (void *)current->code_phys, PAGE);
    memcopy((void *)child->stack_phys, (void *)current->stack_phys, PAGE);
    snap_to_ctx(child);
    child->ctx.rax = 0;
    child->state = ST_RUN;
    ser_puts(" proc64: fork pid ");
    ser_put_dec(current->pid);
    ser_puts(" -> ");
    ser_put_dec(child->pid);
    ser_puts("\n");
    return child->pid;
}

static const u8 *embedded_image(const char *name, u32 *size_out)
{
    if (name[0] == 'C' && name[1] == 'H' && name[2] == 'I' && name[3] == 'L' &&
        name[4] == 'D' && name[5] == '6' && name[6] == '4' && name[7] == 0) {
        *size_out = (u32)(_binary_child64_bin_end - _binary_child64_bin_start);
        return _binary_child64_bin_start;
    }
    return 0;
}

static u64 sys_execve(void)
{
    char path[40];
    const u8 *img;
    u32 size = 0;
    static u8 fatbuf[PAGE];
    if (!current) return (u64)-1;
    if (!ustr(current, proc64_snap.rdi, path, (int)sizeof(path)))
        return (u64)-1;
    img = embedded_image(path, &size);
    if (!img) {
        int n = fat64_read_file(path, fatbuf, PAGE);
        if (n <= 0) return (u64)-1;
        img = fatbuf;
        size = (u32)n;
    }
    if (!load_image(current, img, size)) return (u64)-1;
    name_set(current, path);
    ser_puts(" proc64: execve ");
    ser_puts(path);
    ser_puts("\n");
    map_proc(current);
    proc64_iret_user(&current->ctx);
}

static u64 sys_waitpid(void)
{
    u64 pid = proc64_snap.rdi;
    u64 status_u = proc64_snap.rsi;
    u64 reaped = 0;
    if (!current) return (u64)-1;
    if (reap_one(current, pid, status_u, &reaped))
        return reaped;
    if (!has_child(current, pid))
        return (u64)-1;
    snap_to_ctx(current);
    current->wpid = pid;
    current->wstatus = status_u;
    current->state = ST_WAIT;
    current = 0;
    proc64_dispatch_next();
}

static void sys_exit(u64 code)
{
    if (!current) {
        ser_puts("\n [ring3] exit(");
        ser_put_dec(code);
        ser_puts(") - RING3-SYSCALL-OK\n");
        ser_puts(" returning to the shell...\n");
        sh64_run();
    }
    current->exit_code = (u32)code;
    current->state = ST_ZOMBIE;
    current = 0;
    proc64_dispatch_next();
}

static const char *state_name(int st)
{
    if (st == ST_RUN) return "RUN";
    if (st == ST_SLEEP) return "SLEEP";
    if (st == ST_WAIT) return "WAIT";
    if (st == ST_ZOMBIE) return "ZOMBIE";
    return "?";
}

void proc64_ps(void)
{
    int i, live = 0;
    for (i = 0; i < MAX_PROCS; i++) {
        struct proc *p = &procs[i];
        if (p->state == ST_FREE) continue;
        if (p->state == ST_RUN || p->state == ST_SLEEP || p->state == ST_WAIT)
            live = 1;
        ser_puts(" ps: pid ");
        ser_put_dec(p->pid);
        ser_puts(" ppid ");
        ser_put_dec(p->ppid);
        ser_puts(" ");
        ser_puts(state_name(p->state));
        if (p->background) ser_puts(" bg");
        ser_puts(" ");
        ser_puts(p->name);
        ser_puts("\n");
    }
    if (!live) ser_puts(" ps: (no live processes)\n");
    else ser_puts(" PS-OK-17\n");
}

int proc64_kill(u32 pid)
{
    struct proc *p = proc_by_pid(pid);
    if (!pid || !p || p->state == ST_ZOMBIE) return -1;
    p->exit_code = 9;
    p->state = ST_ZOMBIE;
    if (current == p) current = 0;
    return 0;
}

/* Reap a shell child (ppid 0). pid 0 means any. Returns the pid or -1. */
static int reap_ppid0(u32 pid, u32 *code)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++) {
        struct proc *p = &procs[i];
        u32 id;
        if (p->state != ST_ZOMBIE || p->ppid != 0) continue;
        if (pid && p->pid != pid) continue;
        id = p->pid;
        if (code) *code = p->exit_code;
        proc_release(p);
        return (int)id;
    }
    return -1;
}

static int shell_has_ppid0(u32 pid)
{
    int i;
    for (i = 0; i < MAX_PROCS; i++) {
        if (procs[i].state == ST_FREE || procs[i].ppid != 0) continue;
        if (pid && procs[i].pid != pid) continue;
        return 1;
    }
    return 0;
}

int proc64_shell_wait(u32 pid, u32 *code)
{
    for (;;) {
        int id = reap_ppid0(pid, code);
        if (id >= 0) return id;
        if (!shell_has_ppid0(pid)) return -1;
        focus_pid = pid ? pid : 0xffffffffu;
        shell_poll_mode = 0;
        kernel_armed = 1;
        if (proc_save_kernel() == 0)
            proc64_dispatch_next();
        kernel_armed = 0;
        focus_pid = 0;
        __asm__ volatile("sti" ::: "memory");
    }
}

int proc64_spawn(const u8 *img, u32 size, const char *name, int bg)
{
    struct proc *p;
    u32 code = 0;
    int id;
    if (!img || !size || size > PAGE) return -1;
    p = spawn_image(name ? name : "proc", img, size, 0);
    if (!p) return -1;
    p->background = bg ? 1 : 0;
    if (bg) return (int)p->pid;
    id = proc64_shell_wait(p->pid, &code);
    if (id < 0) return -1;
    return (int)code;
}

void proc64_shell_poll(void)
{
    wake_sleepers();
    if (!pick_next(0, 1)) return;
    shell_poll_mode = 1;
    focus_pid = 0;
    kernel_armed = 1;
    slice = QUANTUM - 1;         /* yield on the next timer tick */
    if (proc_save_kernel() == 0)
        proc64_dispatch_next();
    kernel_armed = 0;
    shell_poll_mode = 0;
    __asm__ volatile("sti" ::: "memory");
}

static u64 sys_sleep(u64 ms)
{
    u64 ticks;
    if (!current) {
        ticks = (ms + 9) / 10;
        if (!ticks) ticks = 1;
        timer64_wait(ticks);
        return 0;
    }
    ticks = (ms * 100ull + 999ull) / 1000ull;
    if (!ticks) ticks = 1;
    snap_to_ctx(current);
    current->ctx.rax = 0;
    current->wake = timer64_ticks() + ticks;
    current->state = ST_SLEEP;
    current = 0;
    proc64_dispatch_next();
}

u64 syscall_handler(u64 nr, u64 a1, u64 a2)
{
    (void)a1;
    (void)a2;
    switch ((u32)nr) {
    case 1: {                               /* write(rsi=buf, rdx=len) */
        u64 n = proc64_snap.rdx;
        u64 i;
        const char *p;
        if (n > PAGE) n = PAGE;
        p = (const char *)proc64_snap.rsi;
        if (current) {
            if (!n) return 0;
            if (!uvirt_to_phys(current, (u64)p) ||
                !uvirt_to_phys(current, (u64)p + n - 1))
                return 0;
        }
        for (i = 0; i < n; i++) ser_putc(p[i]);
        return n;
    }
    case 2:                                 /* exit (64-bit ABI) */
    case 5:                                 /* exit (32-bit number) */
        sys_exit(proc64_snap.rdi);
        return 0;
    case 3:
        return sys_sleep(proc64_snap.rdi);
    case 6:
        return current ? current->pid : 0;
    case 7:
        return current ? current->ppid : 0;
    case 8:
        return timer64_ticks();
    case 16:
        return sys_fork();
    case 17:
        return sys_execve();
    case 18:
        return sys_waitpid();
    case 19:
        proc64_ps();
        return 0;
    default:
        return (u64)-1;
    }
}

void proc64_boot_test(void)
{
    u32 size;
    struct proc *p;
    int i;

    size = (u32)(_binary_forkdemo64_bin_end - _binary_forkdemo64_bin_start);
    p = spawn_image("FORKDEMO", _binary_forkdemo64_bin_start, size, 0);
    if (!p) {
        ser_puts(" M16: spawn failed\n");
        return;
    }
    ser_puts(" proc64: spawned FORKDEMO pid ");
    ser_put_dec(p->pid);
    ser_puts(" (");
    ser_put_dec(size);
    ser_puts(" bytes)\n");

    kernel_armed = 1;
    preempt_noted = 0;
    slice = 0;
    if (proc_save_kernel() == 0)
        proc64_dispatch_next();
    kernel_armed = 0;
    current = 0;
    for (i = 0; i < MAX_PROCS; i++) {
        if (procs[i].state != ST_FREE)
            proc_release(&procs[i]);
    }
    __asm__ volatile("sti" ::: "memory");
    ser_puts(" M16-RETURN-OK\n");
}

void proc64_m17_test(void)
{
    u32 size;
    struct proc *p;
    int i;

    size = (u32)(_binary_m17demo_bin_end - _binary_m17demo_bin_start);
    p = spawn_image("JOB17", _binary_m17demo_bin_start, size, 0);
    if (!p) {
        ser_puts(" M17: spawn failed\n");
        return;
    }
    ser_puts(" M17: shell-job test (sleep, ps, wait)\n");
    kernel_armed = 1;
    shell_poll_mode = 0;
    focus_pid = 0;
    slice = 0;
    if (proc_save_kernel() == 0)
        proc64_dispatch_next();
    kernel_armed = 0;
    current = 0;
    for (i = 0; i < MAX_PROCS; i++) {
        if (procs[i].state != ST_FREE)
            proc_release(&procs[i]);
    }
    __asm__ volatile("sti" ::: "memory");
}
