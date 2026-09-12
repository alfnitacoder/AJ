/* pmm64.c - bitmap physical frame allocator for the AJOS x86-64 port.
 * Manages frames from PMM64_START (8MB, matching the i386 PMM convention)
 * to the end of RAM. Frame size 4KB. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

#define PMM64_FRAME      4096u
#define PMM64_START      0x800000ull       /* 8MB */
#define PMM64_RAM_END    0x20000000ull     /* 512MB (QEMU -m 512M) */
#define PMM64_FRAMES     ((u32)((PMM64_RAM_END - PMM64_START) / PMM64_FRAME))

static u8  frame_bitmap[(PMM64_FRAMES + 7) / 8];   /* ~16KB in .bss */
static u32 frames_used;
static u32 lowest_free_hint;

static void ser_putc(char c);
static void ser_puts(const char *s);

static inline void bm_set(u32 idx) { frame_bitmap[idx >> 3] |=  (u8)(1u << (idx & 7)); }
static inline void bm_clr(u32 idx) { frame_bitmap[idx >> 3] &= (u8)~(1u << (idx & 7)); }
static inline int  bm_tst(u32 idx) { return (frame_bitmap[idx >> 3] >> (idx & 7)) & 1; }

void pmm64_init(void)
{
    frames_used = 0;
    lowest_free_hint = 0;
    ser_puts(" PMM: ");
    {
        char buf[11];
        u32 v = PMM64_FRAMES;
        int i = 0;
        if (!v) buf[i++] = '0';
        while (v) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
        while (i) ser_putc(buf[--i]);
    }
    ser_puts(" frames (");
    {
        u32 mb = (u32)((PMM64_RAM_END - PMM64_START) >> 20);
        char b[5]; int i = 0;
        while (mb) { b[i++] = (char)('0' + (mb % 10)); mb /= 10; }
        while (i) ser_putc(b[--i]);
    }
    ser_puts(" MB) from 0x800000, bitmap .bss\n");
}

u64 pmm64_alloc_frame(void)
{
    u32 i;
    for (i = lowest_free_hint; i < PMM64_FRAMES; i++) {
        if (!bm_tst(i)) {
            bm_set(i);
            frames_used++;
            lowest_free_hint = (i == PMM64_FRAMES - 1) ? 0 : i + 1;
            return PMM64_START + (u64)i * PMM64_FRAME;
        }
    }
    return 0;   /* out of frames */
}

void pmm64_free_frame(u64 phys)
{
    if (phys < PMM64_START || phys >= PMM64_RAM_END || (phys & (PMM64_FRAME - 1)))
        return;
    {
        u32 idx = (u32)((phys - PMM64_START) / PMM64_FRAME);
        if (bm_tst(idx)) {
            bm_clr(idx);
            frames_used--;
            if (idx < lowest_free_hint) lowest_free_hint = idx;
        }
    }
}

u32 pmm64_used(void)        { return frames_used; }
u32 pmm64_total(void)       { return PMM64_FRAMES; }

/* serial helpers used above (kept after to avoid forward decls in hot code) */
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
