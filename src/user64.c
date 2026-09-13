/* user64.c - ring 3 bring-up for the AJOS x86-64 port: TSS, user GDT
 * segments, syscall/sysret MSRs, user page mappings, and the embedded
 * first user program (asm/user64.asm, linked via objcopy). */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern void *kmalloc64(unsigned long long n);
extern int vm64_map_user(u64 vaddr, u64 paddr, int noexec);
extern u64 pmm64_alloc_frame(void);
extern void sh64_run(void) __attribute__((noreturn));
extern u64 syscall_entry(void);
extern void jump_to_user(u64 entry, u64 user_rsp) __attribute__((noreturn));

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
static void ser_put_hex(u64 v)
{
    static const char digits[] = "0123456789abcdef";
    int i;
    ser_puts("0x");
    for (i = 60; i >= 0; i -= 4)
        ser_putc(digits[(v >> i) & 0xF]);
}
static void ser_put_dec(u64 v)
{
    char buf[21];
    int i = 0;
    if (!v) { ser_putc('0'); return; }
    while (v) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i) ser_putc(buf[--i]);
}

#define USER_BASE   0x10000000000ull   /* 1TB: fresh PML4 entry 16 */
#define USER_STACK  0x10000100000ull

/* the embedded user program (build/user64.bin via objcopy) */
extern u8 _binary_user64_bin_start[];
extern u8 _binary_user64_bin_end[];

/* ---- GDT with ring3 + TSS descriptor ---- */
static u8 gdt_full[80];          /* 6 x 8-byte + 16-byte TSS desc */
static u16 gdt_lim = sizeof(gdt_full) - 1;
static u8  tss64[136] __attribute__((aligned(8)));

static void lgdt_and_tr(void)
{
    struct { u16 lim; u64 base; } __attribute__((packed)) idtr_gdtr;
    idtr_gdtr.lim = gdt_lim;
    idtr_gdtr.base = (u64)gdt_full;
    __asm__ __volatile__("lgdt %0" : : "m"(idtr_gdtr));
    __asm__ __volatile__("ltr %%ax" : : "a"((u16)0x30));
}

static void wrmsr64(u32 msr, u64 v)
{
    __asm__ __volatile__("wrmsr" : : "c"(msr), "a"((u32)v), "d"((u32)(v >> 32)));
}

static u64 rd_efer64(void)
{
    u32 lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));
    return ((u64)hi << 32) | lo;
}

void user64_init(void)
{
    u64 base;
    int i;
    for (i = 0; i < (int)sizeof(gdt_full); i++) gdt_full[i] = 0;
    /* 0x08: kernel code L=1 */
    {
        u64 d = 0x00AF9A000000FFFFull;
        for (i = 0; i < 8; i++) gdt_full[8 + i] = (u8)(d >> (8 * i));
    }
    /* 0x10: kernel data */
    {
        u64 d = 0x00CF92000000FFFFull;
        for (i = 0; i < 8; i++) gdt_full[16 + i] = (u8)(d >> (8 * i));
    }
    /* 0x18: filler (NULL) - left zero */
    /* 0x20: user data DPL3 */
    {
        u64 d = 0x00CFF2000000FFFFull;
        for (i = 0; i < 8; i++) gdt_full[32 + i] = (u8)(d >> (8 * i));
    }
    /* 0x28: user code L=1 DPL3 */
    {
        u64 d = 0x00AFFA000000FFFFull;
        for (i = 0; i < 8; i++) gdt_full[40 + i] = (u8)(d >> (8 * i));
    }
    /* 0x30: 64-bit TSS descriptor (16 bytes) */
    base = (u64)tss64;
    {
        u64 d0 = ((base & 0xFFFFFFull) << 16) | 0x67ull | (0x89ull << 40) |
                 (((base >> 24) & 0xFFull) << 32);
        u64 d1 = base >> 32;
        for (i = 0; i < 8; i++) gdt_full[48 + i] = (u8)(d0 >> (8 * i));
        for (i = 0; i < 8; i++) gdt_full[56 + i] = (u8)(d1 >> (8 * i));
    }
    /* TSS: RSP0 (the ring0 stack for the interrupts from ring 3) at the
     * offset 4. Use a dedicated stack below the kernel's 7MB stack. */
    tss64[4] = 0x00; tss64[5] = 0x00;
    tss64[6] = 0x6E; tss64[7] = 0x00;
    tss64[8] = 0x00; tss64[9] = 0x00;
    tss64[10] = 0x00; tss64[11] = 0x00;

    lgdt_and_tr();
    {
        struct { u16 lim; u64 base; } __attribute__((packed)) chk;
        __asm__ __volatile__("sgdt %0" : : "m"(chk) : "memory");
        ser_puts(" user-64: gdtr base=");
        {
            u64 v = chk.base, sh = 60;
            static const char hd[] = "0123456789abcdef";
            ser_putc('0'); ser_putc('x');
            for (; (long)sh >= 0; sh -= 4) ser_putc(hd[(v >> sh) & 0xF]);
        }
        ser_puts(" lim=");
        ser_put_dec(chk.lim);
        ser_puts("\n");
    }
    ser_puts(" user-64: GDT reloaded (ring3 segs + TSS), ltr 0x30\n");

    /* syscall/sysret MSRs: SCE, STAR, LSTAR, FMASK */
    wrmsr64(0xC0000080u, rd_efer64() | 1);            /* EFER.SCE */
    wrmsr64(0xC0000081u,
            ((u64)0x1B << 48) | ((u64)0x08 << 32));   /* STAR */
    wrmsr64(0xC0000082u, (u64)syscall_entry);         /* LSTAR */
    wrmsr64(0xC0000084u, 0x200);                      /* FMASK: clear IF */
    ser_puts(" user-64: syscall/sysret enabled (STAR/LSTAR/FMASK)\n");
}

/* the C syscall handler: called from syscall_entry with (nr, a1, a2) */
extern unsigned long long dbg_rcx;
extern unsigned long long user_rsp_save;

u64 syscall_handler(u64 nr, u64 a1, u64 a2)
{
    ser_puts(" [sys] nr=");
    ser_put_dec(nr);
    ser_puts(" rcx=");
    {
        u64 v = dbg_rcx, sh = 60;
        static const char hd[] = "0123456789abcdef";
        ser_putc('0'); ser_putc('x');
        for (; (long)sh >= 0; sh -= 4) ser_putc(hd[(v >> sh) & 0xF]);
    }
    ser_puts(" rsp_save=");
    ser_put_hex(user_rsp_save);
    ser_puts("\n");
    if (nr == 1) {                          /* write */
        const char *p = (const char *)a1;
        u64 n = a2, i;
        for (i = 0; i < n; i++) ser_putc(p[i]);
        return n;
    }
    if (nr == 2) {                          /* exit */
        ser_puts("\n [ring3] exit(");
        ser_put_dec(a1);
        ser_puts(") - RING3-SYSCALL-OK\n");
        ser_puts(" returning to the shell...\n");
        sh64_run();                         /* noreturn */
    }
    return (u64)-1;
}

/* Map fresh pages and jump into a user image (never returns: the exit
 * syscall continues in a fresh shell). Position-independent images only
 * (rip-relative), loaded at USER_BASE. */
void user64_exec(const u8 *img, u32 size)
{
    u64 code_frame = pmm64_alloc_frame();
    u64 stack_frame = pmm64_alloc_frame();
    u64 i;
    u8 *dst;

    if (size > 4096) size = 4096;
    vm64_map_user(USER_BASE, code_frame, 0);
    vm64_map_user(USER_STACK, stack_frame, 1);
    dst = (u8 *)USER_BASE;
    for (i = 0; i < size; i++) dst[i] = img[i];

    /* re-arm the descriptor tables: the GDT/TSS state must be intact for
     * the iretq into ring 3 on every exec (evidence: #GP(0x28) with a
     * stale GDTR/TR in the -d int dump) */
    lgdt_and_tr();
    ser_puts(" exec: ");
    ser_put_dec(size);
    ser_puts(" bytes at 0x100000000000 -> ring 3\n");
    jump_to_user(USER_BASE, USER_STACK + 4096);
}

void user64_start(void)
{
    u64 code_frame = pmm64_alloc_frame();
    u64 stack_frame = pmm64_alloc_frame();
    u64 size, i;
    u8 *dst;

    /* code page: P|W|U, executable */
    vm64_map_user(USER_BASE, code_frame, 0);
    /* stack page: P|W|U|NX */
    vm64_map_user(USER_STACK, stack_frame, 1);

    size = (u64)(_binary_user64_bin_end - _binary_user64_bin_start);
    dst = (u8 *)USER_BASE;
    for (i = 0; i < size; i++) dst[i] = _binary_user64_bin_start[i];

    ser_puts(" user-64: program (");
    ser_put_dec(size);
    ser_puts(" bytes) mapped at 0x100000000000, jumping to ring 3...\n");
    jump_to_user(USER_BASE, USER_STACK + 4096);
}
