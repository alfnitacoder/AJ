/* kernel64.c - AJOS x86-64 long-mode kernel (milestone 2).
 *
 * M1: boot chain reaches IA-32e, C code runs identity-mapped at 1MB.
 * M2: 64-bit IDT + exception reporting, PIC remap, PIT timer at 100Hz,
 *     bitmap physical frame allocator with self-test, breakpoint demo.
 *
 * Freestanding: no kernel.h (32-bit ABI), -mno-red-zone -mno-sse soft-float.
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

/* ---- externs from intr64.c / pmm64.c ---- */
extern void net64_init(void);
extern int net64_arp_resolve(unsigned int ip);
extern int net64_ping(unsigned int dst, unsigned short seq);
extern void net64_poll(void);
extern void e1000_64_init(void);
extern void e1000_64_debug_dump(void);
extern int e1000_64_present(void);
extern void vm64_init(void);
extern void heap64_init(void);
extern void *kmalloc64(unsigned long long n);
extern void kfree64(void *p);
extern void idt64_init(void);
extern void timer64_init(void);
extern unsigned long long timer64_ticks(void);
extern void timer64_wait(unsigned long long ticks);
extern void pmm64_init(void);
extern unsigned long long pmm64_alloc_frame(void);
extern void pmm64_free_frame(unsigned long long phys);
extern unsigned int pmm64_used(void);
extern unsigned int pmm64_total(void);

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

#define COM1 0x3F8

static void serial_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);   /* 115200 */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);   /* 8N1 */
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
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

static void serial_put_dec(u64 v)
{
    char buf[21];
    int i = 0;
    if (!v) { serial_putc('0'); return; }
    while (v) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i) serial_putc(buf[--i]);
}

static void cpuid(u32 leaf, u32 *a, u32 *b, u32 *c, u32 *d)
{
    u32 la = leaf, lc = 0;
    __asm__ __volatile__("cpuid"
                         : "=a"(*a), "=b"(*b), "=c"(*c), "=d"(*d)
                         : "a"(la), "c"(lc));
}

void kernel_main64(void)
{
    u32 a, b, c, d;
    u64 f1, f2, f3;

    serial_init();

    serial_puts("\n");
    serial_puts("================================================\n");
    serial_puts(" AJOS x86-64 :: LONG MODE MILESTONE 4\n");
    serial_puts(" (e1000 polling NIC + ARP/IP4/ICMP ping)\n");
    serial_puts("================================================\n");

    /* CPU info (kept from M1) */
    cpuid(0, &a, &b, &c, &d);
    {
        char vendor[13];
        vendor[0]  = (char)(b & 0xFF);         vendor[1]  = (char)((b >> 8) & 0xFF);
        vendor[2]  = (char)((b >> 16) & 0xFF); vendor[3]  = (char)((b >> 24) & 0xFF);
        vendor[4]  = (char)(d & 0xFF);         vendor[5]  = (char)((d >> 8) & 0xFF);
        vendor[6]  = (char)((d >> 16) & 0xFF); vendor[7]  = (char)((d >> 24) & 0xFF);
        vendor[8]  = (char)(c & 0xFF);         vendor[9]  = (char)((c >> 8) & 0xFF);
        vendor[10] = (char)((c >> 16) & 0xFF); vendor[11] = (char)((c >> 24) & 0xFF);
        vendor[12] = 0;
        serial_puts(" cpu   = ");
        serial_puts(vendor);
        serial_puts("\n");
    }

    /* ---- M2: interrupts ---- */
    idt64_init();
    timer64_init();

    /* ---- M2: physical memory ---- */
    pmm64_init();

    f1 = pmm64_alloc_frame();
    f2 = pmm64_alloc_frame();
    f3 = pmm64_alloc_frame();
    serial_puts(" PMM alloc 3: ");
    serial_put_hex(f1); serial_puts(" ");
    serial_put_hex(f2); serial_puts(" ");
    serial_put_hex(f3);
    serial_puts(" (used=");
    serial_put_dec(pmm64_used());
    serial_puts(")\n");

    pmm64_free_frame(f2);
    {
        u64 f4 = pmm64_alloc_frame();
        serial_puts(" PMM free+realloc: f4=");
        serial_put_hex(f4);
        serial_puts(" (== freed frame: ");
        serial_puts(f4 == f2 ? "yes" : "NO");
        serial_puts(")\n");
    }
    serial_puts(" PMM used=");
    serial_put_dec(pmm64_used());
    serial_puts("/");
    serial_put_dec(pmm64_total());
    serial_puts(" frames\n");

    /* ---- M2: breakpoint exception demo (resumes) ---- */
    serial_puts(" triggering int3 breakpoint exception...\n");
    __asm__ __volatile__("int3");
    serial_puts(" resumed after breakpoint - exception handling works\n");

    /* ---- M2: timer ---- */
    serial_puts(" waiting 250 ticks (2.5s @ 100Hz)...\n");
    timer64_wait(250);
    serial_puts(" timer alive: ticks=");
    serial_put_dec(timer64_ticks());
    serial_puts("\n");

    /* ---- M3: virtual memory + kernel heap ---- */
    vm64_init();
    heap64_init();
    {
        u8 *p1 = (u8 *)kmalloc64(1000);
        u8 *p2 = (u8 *)kmalloc64(1048576u);   /* 1MB: spans multiple PDs */
        u8 *p3 = (u8 *)kmalloc64(65536);
        u64 i, bad = 0;
        void *p4;
        for (i = 0; i < 1000; i++) p1[i] = (u8)(i & 0xFF);
        for (i = 0; i < 1048576u; i++) p2[i] = (u8)((i * 7) & 0xFF);
        for (i = 0; i < 1000; i++) if (p1[i] != (u8)(i & 0xFF)) bad++;
        for (i = 0; i < 1048576u; i++) if (p2[i] != (u8)((i * 7) & 0xFF)) bad++;
        serial_puts(" kmalloc 1KB+1MB fill/verify: ");
        serial_puts(bad ? "FAIL" : "OK");
        serial_puts("\n");
        kfree64(p1);
        kfree64(p3);
        kfree64(p2);
        p4 = kmalloc64(2097152u);              /* needs the coalesced space */
        serial_puts(" kmalloc 2MB after free+coalesce: ");
        serial_puts(p4 ? "OK" : "FAIL");
        serial_puts(" at ");
        serial_put_hex((u64)p4);
        serial_puts("\n");
        kfree64(p4);
    }

    /* ---- M4: network - e1000 polling + ARP/IP/ICMP ---- */
    e1000_64_init();
    net64_init();
    if (e1000_64_present()) {
        int seq;
        int ok = 0;
        if (net64_arp_resolve(0x0202000Au) == 0) {
            serial_puts(" ARP: gateway 10.0.2.2 resolved\n");
        } else {
            serial_puts(" ARP: gateway resolve FAILED\n");
            e1000_64_debug_dump();
        }
        for (seq = 1; seq <= 4; seq++) {
            int r = net64_ping(0x0202000Au, (unsigned short)seq);
            if (r >= 0) {
                ok++;
                serial_puts(" ping seq=");
                serial_put_dec((u64)seq);
                serial_puts(": reply rtt=");
                serial_put_dec((u64)r * 10);
                serial_puts("ms\n");
            } else {
                serial_puts(" ping seq=");
                serial_put_dec((u64)seq);
                serial_puts(": TIMEOUT\n");
            }
        }
        serial_puts(" PONG count=");
        serial_put_dec((u64)ok);
        serial_puts("/4\n");
    }

    serial_puts("\n Milestone 4 complete. Next: TCP/UDP, then ATA/FAT.\n");
    serial_puts("================================================\n");

    for (;;)
        __asm__ __volatile__("sti; hlt");
}
