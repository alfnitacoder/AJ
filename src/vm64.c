/* vm64.c - 64-bit virtual memory + kernel heap for the AJOS x86-64 port.
 *
 * The boot chain identity-maps 0..4GB with 1GB pages. This module adds:
 *   - EFER.NXE so data pages can be marked no-execute
 *   - vm64_map(): 4KB page mapping at a chosen VMA (tables from the PMM,
 *     written through the identity map)
 *   - an 8MB kernel heap at HEAP_VMA (0x20000000000, 2TB - canonical,
 *     far from the identity region) with first-fit kmalloc/kfree that
 *     coalesces adjacent free blocks.
 */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern u64 pmm64_alloc_frame(void);
extern void pmm64_free_frame(u64 phys);

#define PTE_P   1ull
#define PTE_W   2ull
#define PTE_NX  (1ull << 63)
#define ADDR_MASK 0x000FFFFFFFFFF000ull

#define HEAP_VMA    0x20000000000ull    /* 2TB, canonical, below 2^47 */
#define HEAP_FRAMES 2048ull             /* 8MB */
#define HEAP_SIZE   (HEAP_FRAMES * 4096ull)

/* ---- minimal serial + helpers (standalone) ---- */
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
static void kmemset64(void *dst, u8 val, u64 n)
{
    u8 *d = (u8 *)dst;
    while (n--) *d++ = val;
}

/* ---- MSR / CR helpers ---- */
static u64 rd_cr3(void)
{
    u64 v;
    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));
    return v & ADDR_MASK;
}
static u64 rd_efer(void)
{
    u32 lo, hi;
    __asm__ __volatile__("rdmsr" : "=a"(lo), "=d"(hi) : "c"(0xC0000080u));
    return ((u64)hi << 32) | lo;
}
static void wr_efer(u64 v)
{
    __asm__ __volatile__("wrmsr" : : "c"(0xC0000080u), "a"((u32)v), "d"((u32)(v >> 32)));
}

/* ---- page tables ---- */

/* Descend one level, allocating + zeroing the table if absent. */
static u64 *next_level(u64 *entry_ptr)
{
    u64 e = *entry_ptr;
    if (!(e & PTE_P)) {
        u64 t = pmm64_alloc_frame();
        kmemset64((void *)t, 0, 4096);
        e = t | PTE_P | PTE_W | PTE_NX;
        *entry_ptr = e;
    }
    return (u64 *)(e & ADDR_MASK);
}

static void vm64_map(u64 vaddr, u64 paddr)
{
    u64 *pml4 = (u64 *)rd_cr3();
    u64 *pdpt = next_level(&pml4[(vaddr >> 39) & 511]);
    u64 *pd   = next_level(&pdpt[(vaddr >> 30) & 511]);
    u64 *pt   = next_level(&pd[(vaddr >> 21) & 511]);
    pt[(vaddr >> 12) & 511] = paddr | PTE_P | PTE_W | PTE_NX;
}

void vm64_init(void)
{
    u64 off;
    wr_efer(rd_efer() | (1ull << 11));   /* EFER.NXE */
    for (off = 0; off < HEAP_SIZE; off += 4096)
        vm64_map(HEAP_VMA + off, pmm64_alloc_frame());
    ser_puts(" VM: 8MB heap mapped at ");
    ser_put_hex(HEAP_VMA);
    ser_puts(" (4KB pages, NX, tables from PMM)\n");
}

/* ---- kernel heap: first-fit with header + coalescing ---- */

struct kblock {
    u64 size;               /* payload bytes */
    u64 free;
    struct kblock *next;
    struct kblock *prev;
};

static struct kblock *heap_head;

void heap64_init(void)
{
    heap_head = (struct kblock *)HEAP_VMA;
    heap_head->size = HEAP_SIZE - sizeof(struct kblock);
    heap_head->free = 1;
    heap_head->next = 0;
    heap_head->prev = 0;
    ser_puts(" kmalloc: heap ready (8MB at 2TB VMA)\n");
}

void *kmalloc64(u64 n)
{
    struct kblock *b;
    n = (n + 15) & ~15ull;
    for (b = heap_head; b; b = b->next) {
        if (b->free && b->size >= n) {
            if (b->size >= n + sizeof(struct kblock) + 16) {
                struct kblock *nb =
                    (struct kblock *)((char *)b + sizeof(struct kblock) + n);
                nb->size = b->size - n - sizeof(struct kblock);
                nb->free = 1;
                nb->prev = b;
                nb->next = b->next;
                if (nb->next) nb->next->prev = nb;
                b->next = nb;
                b->size = n;
            }
            b->free = 0;
            return (char *)b + sizeof(struct kblock);
        }
    }
    return 0;
}

void kfree64(void *p)
{
    struct kblock *b = (struct kblock *)p;
    if (!p) return;
    b--;                     /* header precedes the payload */
    b->free = 1;
    if (b->next && b->next->free) {
        b->size += sizeof(struct kblock) + b->next->size;
        b->next = b->next->next;
        if (b->next) b->next->prev = b;
    }
    if (b->prev && b->prev->free) {
        b->prev->size += sizeof(struct kblock) + b->size;
        b->prev->next = b->next;
        if (b->next) b->next->prev = b->prev;
    }
}
