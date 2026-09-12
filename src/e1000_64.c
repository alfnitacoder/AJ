/* e1000_64.c - minimal polling e1000 driver for the AJOS x86-64 port.
 * Self-contained: PCI config-space scan for 8086:100E, rings + buffers
 * from the PMM (all < 4GB, covered by the boot identity map), TX send
 * and RX poll. No interrupts - net64 polls. Mirrors src/e1000.c init. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern u64 pmm64_alloc_frame(void);
extern void pmm64_free_frame(u64 phys);

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

/* ---- PCI config space ---- */
static void pci_write32(u8 bus, u8 dev, u8 func, u8 off, u32 val)
{
    u32 addr = 0x80000000u | ((u32)bus << 16) | ((u32)dev << 11) |
               ((u32)func << 8) | (off & 0xFC);
    __asm__ __volatile__("outl %%eax, %%dx" : : "a"(addr), "d"((u16)0xCF8));
    __asm__ __volatile__("outl %%eax, %%dx" : : "a"(val), "d"((u16)0xCFC));
}

static u32 pci_read32(u8 bus, u8 dev, u8 func, u8 off)
{
    u32 addr = 0x80000000u | ((u32)bus << 16) | ((u32)dev << 11) |
               ((u32)func << 8) | (off & 0xFC);
    __asm__ __volatile__("outl %%eax, %%dx" : : "a"(addr), "d"((u16)0xCF8));
    u32 r;
    __asm__ __volatile__("inl %%dx, %%eax" : "=a"(r) : "d"((u16)0xCFC));
    return r;
}

/* ---- e1000 ---- */
#define E1000_TX_RING 32
#define E1000_RX_RING 32
#define E1000_BUF_SZ  2048

typedef struct {
    u64 addr;
    u16 length;
    u8 cso;
    u8 cmd;
    u8 status;
    u8 css;
    u16 special;
} e1000_tx_desc_t;

typedef struct {
    u64 addr;
    u16 length;
    u16 checksum;
    u8 status;
    u8 errors;
    u16 special;
} e1000_rx_desc_t;

static volatile u32 *mmio;
static u64 tx_ring_phys, rx_ring_phys;
static e1000_tx_desc_t *tx_ring;
static e1000_rx_desc_t *rx_ring;
static u64 tx_buf_phys[E1000_TX_RING];
static u64 rx_buf_phys[E1000_RX_RING];
static u32 tx_tail;
static u32 rx_next;    /* software head: next descriptor to consume */
static u8  my_mac[6];
static int nic_present;

static void reg_write(u32 off, u32 val)
{
    mmio[off / 4] = val;
}
static u32 reg_read(u32 off)
{
    return mmio[off / 4];
}

static void kmem_zero(u64 phys, u32 n)
{
    u8 *p = (u8 *)phys;
    while (n--) *p++ = 0;
}

static void msleep64(u32 ticks10ms)
{
    extern void timer64_wait(unsigned long long);
    timer64_wait(ticks10ms);
}

int e1000_64_present(void) { return nic_present; }
const u8 *e1000_64_mac(void) { return my_mac; }

void e1000_64_init(void)
{
    u8 bus = 0xFF, slot = 0;
    u32 bar0 = 0;
    int d, f;

    nic_present = 0;
    for (d = 0; d < 32 && bus == 0xFF; d++) {
        for (f = 0; f < 8; f++) {
            u32 id = pci_read32(0, (u8)d, (u8)f, 0x00);
            if ((id & 0xFFFF) == 0x8086 && ((id >> 16) & 0xFFFF) == 0x100E) {
                bus = 0;
                slot = (u8)d;
                {
                    u32 cmd = pci_read32(0, (u8)d, (u8)f, 0x04) & 0xFFFF;
                    cmd |= 0x07;   /* IO | MEM | BUS MASTER */
                    pci_write32(0, (u8)d, (u8)f, 0x04, cmd);
                }
                bar0 = pci_read32(0, (u8)d, (u8)f, 0x10) & 0xFFFFFFF0u;
                ser_puts(" e1000-64: PCI cmd readback=");
                ser_put_hex(pci_read32(0, (u8)d, (u8)f, 0x04) & 0xFFFF);
                ser_puts("\n");
                break;
            }
        }
    }
    if (bus == 0xFF || !bar0) {
        ser_puts(" e1000-64: NO NIC FOUND (8086:100E not on bus 0)\n");
        return;
    }
    mmio = (volatile u32 *)(u64)bar0;
    ser_puts(" e1000-64: found 8086:100E slot ");
    ser_putc('0' + slot);
    ser_puts(" BAR0=");
    ser_put_hex(bar0);
    ser_puts("\n");

    /* Reset + link up */
    reg_write(0x0000, (1u << 26));            /* CTRL.RST */
    msleep64(2);
    reg_write(0x0000, (u32)(reg_read(0x0000) | (1u << 6)));   /* CTRL.SLU */
    reg_write(0x0410, 0x0060200Au);           /* TIPG */
    reg_write(0x00D8, 0xFFFFFFFFu);           /* IMC: mask all (polling) */

    /* MAC: read RAL0/RAH0 (QEMU presets from -net nic) */
    u32 ral = reg_read(0x5400);
    u32 rah = reg_read(0x5404);
    my_mac[0] = (u8)(ral & 0xFF);
    my_mac[1] = (u8)((ral >> 8) & 0xFF);
    my_mac[2] = (u8)((ral >> 16) & 0xFF);
    my_mac[3] = (u8)((ral >> 24) & 0xFF);
    my_mac[4] = (u8)(rah & 0xFF);
    my_mac[5] = (u8)((rah >> 8) & 0xFF);
    if (!(my_mac[0] | my_mac[1] | my_mac[2] | my_mac[3] | my_mac[4] | my_mac[5])) {
        my_mac[0] = 0x52; my_mac[1] = 0x54; my_mac[2] = 0x00;
        my_mac[3] = 0xAB; my_mac[4] = 0x64; my_mac[5] = 0x01;
        ral = (u32)my_mac[0] | ((u32)my_mac[1] << 8) | ((u32)my_mac[2] << 16) |
              ((u32)my_mac[3] << 24);
        rah = (u32)my_mac[4] | ((u32)my_mac[5] << 8) | (1u << 31);
        reg_write(0x5400, ral);
        reg_write(0x5404, rah);
    }
    /* Program RAR0 explicitly with the AV bit (QEMU filter needs it for
     * unicast unless RCTL.PROM; the i386 driver does the same). */
    ral = (u32)my_mac[0] | ((u32)my_mac[1] << 8) | ((u32)my_mac[2] << 16) |
          ((u32)my_mac[3] << 24);
    rah = (u32)my_mac[4] | ((u32)my_mac[5] << 8) | (1u << 31);
    reg_write(0x5400, ral);
    reg_write(0x5404, rah);
    ser_puts(" e1000-64: MAC ");
    {
        int i;
        for (i = 0; i < 6; i++) {
            static const char hd[] = "0123456789abcdef";
            ser_putc(hd[my_mac[i] >> 4]);
            ser_putc(hd[my_mac[i] & 0xF]);
            ser_putc(i < 5 ? ':' : '\n');
        }
    }

    /* TX ring (1 frame) + buffers */
    tx_ring_phys = pmm64_alloc_frame();
    kmem_zero(tx_ring_phys, 4096);
    tx_ring = (e1000_tx_desc_t *)tx_ring_phys;
    {
        int i;
        for (i = 0; i < E1000_TX_RING; i++) {
            tx_buf_phys[i] = pmm64_alloc_frame();
            tx_ring[i].addr = tx_buf_phys[i];
            tx_ring[i].length = 0;
            tx_ring[i].cmd = 0;
            tx_ring[i].status = 0x01;   /* DD: software-owned */
            tx_ring[i].cso = tx_ring[i].css = 0;
            tx_ring[i].special = 0;
        }
    }
    tx_tail = 0;
    reg_write(0x3800, (u32)tx_ring_phys);                       /* TDBAL */
    reg_write(0x3804, (u32)(tx_ring_phys >> 32));               /* TDBAH */
    reg_write(0x3808, sizeof(e1000_tx_desc_t) * E1000_TX_RING); /* TDLEN */
    reg_write(0x3810, 0);                                       /* TDH */
    reg_write(0x3818, 0);                                       /* TDT */
    reg_write(0x0400, (1u << 1) | (1u << 3) | (0x10u << 4) | (0x40u << 12)); /* TCTL EN|PSP|CT|COLD */

    /* RX ring + buffers */
    rx_ring_phys = pmm64_alloc_frame();
    kmem_zero(rx_ring_phys, 4096);
    rx_ring = (e1000_rx_desc_t *)rx_ring_phys;
    {
        int i;
        for (i = 0; i < E1000_RX_RING; i++) {
            rx_buf_phys[i] = pmm64_alloc_frame();
            rx_ring[i].addr = rx_buf_phys[i];
            rx_ring[i].status = 0;
            rx_ring[i].length = 0;
        }
    }
    rx_next = 0;
    reg_write(0x2800, (u32)rx_ring_phys);                       /* RDBAL */
    reg_write(0x2804, (u32)(rx_ring_phys >> 32));               /* RDBAH */
    reg_write(0x2808, sizeof(e1000_rx_desc_t) * E1000_RX_RING); /* RDLEN */
    reg_write(0x2810, 0);                                       /* RDH */
    reg_write(0x2818, E1000_RX_RING - 1);                       /* RDT: must differ from RDH */
    {
        int i;
        for (i = 0; i < 128; i++)
            reg_write(0x5200 + (u32)(i * 4), 0);                /* MTA */
    }
    reg_read(0x00C0);                                           /* ICR: clear */
    reg_write(0x2820, 0x80);                                    /* RDTR */
    reg_write(0x282C, 0x80);                                    /* RADV */
    reg_write(0x0100, (1u << 1) | (1u << 3) | (1u << 4) | (1u << 15)); /* RCTL EN|UPE|MPE|BAM */

    /* QEMU quirk: every RCTL write arms a 1s flush_queue_timer during
     * which all inbound packets are queued (can_receive=false). Wait it
     * out before any traffic (real hardware has no such gate). */
    msleep64(150);
    nic_present = 1;
    ser_puts(" e1000-64: TX/RX rings ready (polling, no IMS) status=");
    ser_put_hex(reg_read(0x0008));
    ser_puts(" link=");
    ser_put_dec((reg_read(0x0008) >> 1) & 1);
    ser_puts("\n");
}

void e1000_64_debug_dump(void)
{
    int i;
    ser_puts(" e1000-64 dbg: RDH=");
    ser_put_dec(reg_read(0x2810));
    ser_puts(" RDT=");
    ser_put_dec(reg_read(0x2818));
    ser_puts(" ICR=");
    ser_put_hex(reg_read(0x00C0));
    ser_puts(" RCTL=");
    ser_put_hex(reg_read(0x0100));
    ser_puts(" RDBAL=");
    ser_put_hex(reg_read(0x2800));
    ser_puts(" RDLEN=");
    ser_put_dec(reg_read(0x2808));
    ser_puts(" rxdesc_status:");
    for (i = 0; i < 6; i++) {
        ser_putc(' ');
        ser_put_dec(i);
        ser_putc('=');
        ser_put_dec(rx_ring[i].status);
        ser_putc('/');
        ser_put_dec(rx_ring[i].length);
    }
    ser_puts("\n");
}

/* Send one raw ethernet frame (len <= E1000_BUF_SZ). */
int e1000_64_send(const u8 *frame, u16 len)
{
    if (!nic_present || len > E1000_BUF_SZ) return -1;
    u32 i = tx_tail;
    u8 *buf = (u8 *)tx_buf_phys[i];
    {
        u16 j;
        for (j = 0; j < len; j++) buf[j] = frame[j];
    }
    tx_ring[i].addr = tx_buf_phys[i];
    tx_ring[i].length = len;
    tx_ring[i].cmd = 0x1B;      /* EOP | IFS | RS */
    tx_ring[i].status = 0;
    tx_tail = (tx_tail + 1) % E1000_TX_RING;
    reg_write(0x3818, tx_tail); /* TDT */
    /* wait for DD */
    {
        int spins = 500000;
        while (!(tx_ring[i].status & 0x01)) {
            if (--spins <= 0) return -2;
        }
    }
    return 0;
}

/* Poll one received frame into out (cap 2048). Returns the length or 0. */
u16 e1000_64_poll(u8 *out, u16 cap)
{
    if (!nic_present) return 0;
    if (!(rx_ring[rx_next].status & 0x01)) return 0;   /* not ready */
    u16 len = rx_ring[rx_next].length;
    u8 *buf = (u8 *)rx_buf_phys[rx_next];
    if (len > cap) len = cap;
    {
        u16 j;
        for (j = 0; j < len; j++) out[j] = buf[j];
    }
    rx_ring[rx_next].status = 0;
    rx_ring[rx_next].length = 0;
    reg_write(0x2818, rx_next);        /* RDT: give buffer back */
    rx_next = (rx_next + 1) % E1000_RX_RING;
    return len;
}
