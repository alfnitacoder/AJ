/* intr64.c - 64-bit IDT, PIC remap and PIT timer for the AJOS x86-64 port. */

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

/* ---- serial (shared with kernel64.c; tiny duplicate to stay standalone) ---- */
#define COM1 0x3F8

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

/* ---- IDT ---- */

struct idt_entry {
    u16 offset_lo;
    u16 selector;
    u8  ist;        /* bits 0-2; 0 = no IST */
    u8  flags;      /* type/attr: 0x8E = present, ring0, 64-bit interrupt gate */
    u16 offset_mid;
    u32 offset_hi;
    u32 zero;
} __attribute__((packed));

struct idtr {
    u16 limit;
    u64 base;
} __attribute__((packed));

static struct idt_entry idt[256] __attribute__((aligned(16)));
static struct idtr idtr;

extern u64 isr64_stub_table[];   /* from asm/isr64.asm: 49 stub addresses */

static void idt_set(int vec, u64 handler)
{
    idt[vec].offset_lo  = (u16)(handler & 0xFFFF);
    idt[vec].selector   = 0x08;
    idt[vec].ist        = 0;
    idt[vec].flags      = 0x8E;
    idt[vec].offset_mid = (u16)((handler >> 16) & 0xFFFF);
    idt[vec].offset_hi  = (u32)((handler >> 32) & 0xFFFFFFFFu);
    idt[vec].zero       = 0;
}

static const char *exc_name(int v)
{
    static const char *names[32] = {
        "DE divide-error", "DB debug", "NMI", "BP breakpoint", "OF overflow",
        "BR bound", "UD invalid-opcode", "NM device-na", "DF double-fault",
        "9 reserved", "TS invalid-tss", "NP segment-not-present",
        "SS stack-fault", "GP general-protection", "PF page-fault",
        "15 reserved", "MF x87", "AC alignment", "MC machine-check",
        "XM simd", "VE virtualization", "CP control-protection",
        "22-31 reserved", "23-31 reserved", "24-31 reserved",
        "25-31 reserved", "26-31 reserved", "27-31 reserved",
        "28-31 reserved", "29-31 reserved", "30-31 reserved", "31 reserved"
    };
    return (v >= 0 && v < 32) ? names[v] : "?";
}

/* C exception dispatcher (called from the asm stubs). */
void isr64_dispatch(u64 vec, u64 err, u64 rip)
{
    if (vec == 3) {
        ser_puts(" [BP] breakpoint at rip=");
        ser_put_hex(rip);
        ser_puts(" (resuming)\n");
        return;                     /* int3 is resumable: iretq continues */
    }
    ser_puts("\n!!! EXCEPTION ");
    ser_put_dec(vec);
    ser_puts(" (");
    ser_puts(exc_name((int)vec));
    ser_puts(") err=");
    ser_put_hex(err);
    ser_puts(" rip=");
    ser_put_hex(rip);
    ser_puts(" - system halted\n");
    for (;;)
        __asm__ __volatile__("hlt");
}

/* ---- PIC 8259 + PIT ---- */

static volatile u64 timer_ticks;

void irq64_dispatch(u64 irq)
{
    if (irq == 0) {
        timer_ticks++;
        outb(0x20, 0x20);           /* EOI master */
    }
}

static void pic_remap(void)
{
    outb(0x20, 0x11); outb(0xA0, 0x11);   /* ICW1: cascade, ICW4 */
    outb(0x21, 0x20); outb(0xA1, 0x28);   /* ICW2: vectors 32/40 */
    outb(0x21, 0x04); outb(0xA1, 0x02);   /* ICW3 */
    outb(0x21, 0x01); outb(0xA1, 0x01);   /* ICW4: 8086 mode */
    outb(0x21, 0xFE);                     /* mask all but IRQ0 */
    outb(0xA1, 0xFF);                     /* mask slave entirely */
}

static void pit_init(u32 hz)
{
    u32 divisor = 1193182u / hz;
    outb(0x43, 0x36);                     /* ch0, lobyte/hibyte, square wave */
    outb(0x40, (u8)(divisor & 0xFF));
    outb(0x40, (u8)((divisor >> 8) & 0xFF));
}

void idt64_init(void)
{
    int i;
    for (i = 0; i < 256; i++)
        idt_set(i, 0);
    for (i = 0; i < 49; i++)
        idt_set(i, isr64_stub_table[i]);
    idtr.limit = sizeof(idt) - 1;
    idtr.base  = (u64)idt;
    __asm__ __volatile__("lidt %0" : : "m"(idtr));
    ser_puts(" IDT: 256 gates (32 exc + 16 irq + spurious) loaded\n");
}

void timer64_init(void)
{
    pic_remap();
    pit_init(100);
    __asm__ __volatile__("sti");
    ser_puts(" PIC remapped, PIT @100Hz, interrupts on\n");
}

u64 timer64_ticks(void)
{
    return timer_ticks;
}

void timer64_wait(u64 ticks)
{
    u64 start = timer_ticks;
    while (timer_ticks - start < ticks)
        __asm__ __volatile__("hlt");
}
