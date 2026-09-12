/* kernel64.c - AJOS x86-64 long-mode milestone stub.
 *
 * Milestone 1 of the 64-bit port: prove the boot chain reaches IA-32e
 * (long mode) and that C code compiled -m64 runs identity-mapped at 1MB.
 * Output goes to the QEMU serial port (COM1) - no video drivers needed.
 *
 * Deliberately freestanding: no kernel.h include (the i386 headers are
 * 32-bit ABI assumptions), no libgcc calls (compile with -mno-red-zone,
 * -mno-sse and soft-float; avoid 128-bit and float ops).
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

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

static void io_wait(void)
{
    outb(0x80, 0);
}

#define COM1 0x3F8

static void serial_init(void)
{
    outb(COM1 + 1, 0x00);   /* disable interrupts */
    outb(COM1 + 3, 0x80);   /* DLAB on */
    outb(COM1 + 0, 0x01);   /* 115200 baud (divisor 1) */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);   /* 8N1 */
    outb(COM1 + 2, 0xC7);   /* FIFO on, clear */
    outb(COM1 + 4, 0x0B);   /* RTS/DSR */
    io_wait();
}

static void serial_putc(char c)
{
    int spins = 100000;
    while (!(inb(COM1 + 5) & 0x20)) {
        if (--spins <= 0) return;
    }
    outb(COM1, (u8)c);
}

static void serial_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') serial_putc('\r');
        serial_putc(*s++);
    }
}

static void serial_put_hex(u64 v)
{
    static const char digits[] = "0123456789abcdef";
    int i;
    serial_puts("0x");
    for (i = 60; i >= 0; i -= 4)
        serial_putc(digits[(v >> i) & 0xF]);
}

/* CPUID via inline asm (64-bit safe; we are already in long mode). */
static void cpuid(u32 leaf, u32 *a, u32 *b, u32 *c, u32 *d)
{
    u32 la = leaf, lc = 0;
    __asm__ __volatile__("cpuid"
                         : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                         : "a"(la), "c"(lc));
}

static u64 read_cr0(void)
{
    u64 v;
    __asm__ __volatile__("mov %%cr0, %0" : "=r"(v));
    return v;
}

static u64 read_cr4(void)
{
    u64 v;
    __asm__ __volatile__("mov %%cr4, %0" : "=r"(v));
    return v;
}

static u64 read_efer(void)
{
    u32 lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));
    return ((u64)hi << 32) | lo;
}

void kernel_main64(void)
{
    u32 a, b, c, d;
    char vendor[13];

    serial_init();

    serial_puts("\n");
    serial_puts("================================================\n");
    serial_puts(" AJOS x86-64 :: LONG MODE MILESTONE 1\n");
    serial_puts("================================================\n");

    /* If this code is running at all, CS.L=1 and paging are active: the
     * CPU is in IA-32e 64-bit mode. Print the proof registers anyway. */
    serial_puts(" cr0   = ");
    serial_put_hex(read_cr0());
    serial_puts("   (PG=1, PE=1)\n");
    serial_puts(" cr4   = ");
    serial_put_hex(read_cr4());
    serial_puts("   (PAE=1)\n");
    serial_puts(" efer  = ");
    serial_put_hex(read_efer());
    serial_puts("   (LME=1, LMA=1)\n");

    cpuid(0, &a, &b, &c, &d);
    vendor[0]  = (char)(b & 0xFF);  vendor[1]  = (char)((b >> 8) & 0xFF);
    vendor[2]  = (char)((b >> 16) & 0xFF); vendor[3]  = (char)((b >> 24) & 0xFF);
    vendor[4]  = (char)(d & 0xFF);  vendor[5]  = (char)((d >> 8) & 0xFF);
    vendor[6]  = (char)((d >> 16) & 0xFF); vendor[7]  = (char)((d >> 24) & 0xFF);
    vendor[8]  = (char)(c & 0xFF);  vendor[9]  = (char)((c >> 8) & 0xFF);
    vendor[10] = (char)((c >> 16) & 0xFF); vendor[11] = (char)((c >> 24) & 0xFF);
    vendor[12] = 0;
    serial_puts(" cpu   = ");
    serial_puts(vendor);
    serial_puts(" (max leaf ");
    serial_put_hex(a);
    serial_puts(")\n");

    cpuid(0x80000001u, &a, &b, &c, &d);
    serial_puts(" lm    = ");
    serial_puts((d >> 29) & 1 ? "yes (long mode capable)\n" : "no\n");

    serial_puts("\n 64-bit kernel stub alive. Port plan: memory -> interrupts\n");
    serial_puts(" -> drivers (e1000/ATA/FAT) -> network stack -> shell.\n");
    serial_puts("================================================\n");

    for (;;)
        __asm__ __volatile__("hlt");
}
