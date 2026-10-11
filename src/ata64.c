/* ata64.c - primary-channel PIO ATA driver for the AJOS x86-64 port.
 * LBA28 sector reads from the primary master (QEMU -drive if=ide).
 * Pure port I/O, polling, no interrupts. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

#define ATA_DATA   0x1F0
#define ATA_ERR    0x1F1
#define ATA_SECCNT 0x1F2
#define ATA_LBA_LO 0x1F3
#define ATA_LBA_MID 0x1F4
#define ATA_LBA_HI 0x1F5
#define ATA_DRIVE  0x1F6
#define ATA_STATUS 0x1F7
#define ATA_CMD    0x1F7
#define ATA_CONTROL 0x3F6

#define ATA_STAT_BSY 0x80
#define ATA_STAT_DRQ 0x08
#define ATA_STAT_DF  0x20
#define ATA_STAT_ERR 0x01
#define ATA_NIEN     0x02          /* device-control bit 1: disable IRQ */

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
static inline void outw(u16 port, u16 val)
{
    __asm__ __volatile__("outw %0, %1" : : "a"(val), "Nd"(port));
}
static inline u16 inw(u16 port)
{
    u16 v;
    __asm__ __volatile__("inw %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}

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
static void ser_put_dec(u64 v)
{
    char buf[21];
    int i = 0;
    if (!v) { ser_putc('0'); return; }
    while (v) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i) ser_putc(buf[--i]);
}

static int ata_present;

/* ~400ns. Alternate status (0x3F6) does not ack the IRQ the way 0x1F7 does. */
static void ata_delay400(void)
{
    inb(ATA_CONTROL);
    inb(ATA_CONTROL);
    inb(ATA_CONTROL);
    inb(ATA_CONTROL);
}

/* Command block is only writable when BSY and DRQ are both clear.
 * Status 0xD0 (BSY|DRDY|DSC) is the in-progress PIO state QEMU leaves
 * set while a sector's aio has not finished. A command issued in that
 * window is ignored, so the guest polls 0xD0 until it gives up.
 * The 400ns pause lets the device raise BSY before the sample; rep outsw
 * can otherwise finish the sector and start the next command first. */
static int wait_idle(int spins)
{
    ata_delay400();
    while (spins--) {
        u8 st = inb(ATA_STATUS);
        if (st & ATA_STAT_BSY) continue;
        if (st & (ATA_STAT_ERR | ATA_STAT_DF)) return -3;
        if (!(st & ATA_STAT_DRQ)) return 0;
    }
    return -1;
}

static int wait_drq(int spins)
{
    ata_delay400();
    while (spins--) {
        u8 st = inb(ATA_STATUS);
        if (st & ATA_STAT_BSY) continue;
        if (st & (ATA_STAT_ERR | ATA_STAT_DF)) return -3;
        if (st & ATA_STAT_DRQ) return 0;
    }
    return -1;
}

static void ata_soft_reset(void)
{
    int i;
    /* SRST must stay asserted for several microseconds, not one 400ns beat. */
    outb(ATA_CONTROL, (u8)(0x04 | ATA_NIEN));
    for (i = 0; i < 2000; i++) inb(ATA_CONTROL);
    outb(ATA_CONTROL, ATA_NIEN);
    for (i = 0; i < 2000; i++) inb(ATA_CONTROL);
    wait_idle(2000000);
}

static int ata_prepare(void)
{
    if (wait_idle(200000) == 0) return 0;
    ata_soft_reset();
    return wait_idle(2000000) == 0 ? 0 : -1;
}

int ata64_init(void)
{
    u32 st;
    ata_present = 0;
    outb(ATA_CONTROL, ATA_NIEN);     /* polling driver: mask IRQ14 */
    /* select master, wait */
    outb(ATA_DRIVE, 0xA0);
    ata_delay400();
    if (wait_idle(200000) != 0) {
        ser_puts(" ATA-64: master stuck busy\\n");
        return -1;
    }
    /* IDENTIFY DEVICE */
    outb(ATA_SECCNT, 0);
    outb(ATA_LBA_LO, 0);
    outb(ATA_LBA_MID, 0);
    outb(ATA_LBA_HI, 0);
    outb(ATA_CMD, 0xEC);
    st = inb(ATA_STATUS);
    if (st == 0) {
        ser_puts(" ATA-64: no device\\n");
        return -1;
    }
    if (wait_drq(500000) != 0) {
        ser_puts(" ATA-64: identify timeout\\n");
        return -1;
    }
    {
        u16 id[256];
        int i;
        /* One inw per word. Two inb's consume two words on QEMU
         * (the data port is 16-bit) and the sector count comes back 0. */
        for (i = 0; i < 256; i++)
            id[i] = inw(ATA_DATA);
        /* words 60/61: user-addressable LBA sectors (LE words) */
        u32 sectors = (u32)id[61] << 16 | id[60];
        ata_present = 1;
        ser_puts(" ATA-64: master present, ");
        ser_put_dec(sectors / 2048);
        ser_puts(" MB (");
        ser_put_dec(sectors);
        ser_puts(" sectors)\\n");
    }
    return 0;
}

/* Read `count` sectors starting at `lba` into buf (count*512 bytes). */
/* Write `count` sectors from buf to `lba`. */
int ata64_write_lba(u32 lba, u16 count, const void *buf)
{
    if (!ata_present) return -1;
    if (count == 0) return 0;
    if (ata_prepare() != 0) return -2;
    outb(ATA_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
    ata_delay400();
    outb(ATA_SECCNT, (u8)count);
    outb(ATA_LBA_LO, (u8)(lba & 0xFF));
    outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
    outb(ATA_CMD, 0x30);             /* WRITE SECTORS with retry */
    {
        u16 s;
        const u16 *p = (const u16 *)buf;
        for (s = 0; s < count; s++) {
            u16 i;
            if (wait_drq(2000000) != 0) {
                ser_puts(" [ata] write timeout st=");
                ser_put_dec(inb(ATA_STATUS));
                ser_puts(" lba=");
                ser_put_dec(lba);
                ser_puts("\n");
                return -5;
            }
            /* Word at a time, IRQs off for the burst only. rep outsw can
             * retire the sector before BSY rises, and a timer tick in the
             * middle of the burst does the same. Restore IF afterwards:
             * this runs from the syscall path with interrupts already off. */
            __asm__ __volatile__("pushfq; cli" ::: "memory");
            for (i = 0; i < 256; i++)
                outw(ATA_DATA, p[s * 256 + i]);
            __asm__ __volatile__("popfq" ::: "memory");
        }
    }
    /* Device is idle only when BSY and DRQ are both clear. Then flush
     * the write cache (0xE7) so the next read is not served a busy drive. */
    if (wait_idle(2000000) != 0) return -6;
    outb(ATA_CMD, 0xE7);
    ata_delay400();
    if (wait_idle(2000000) != 0) return -7;
    return 0;
}

int ata64_read_lba(u32 lba, u16 count, void *buf)
{
    if (!ata_present) return -1;
    if (count == 0) return 0;
    if (ata_prepare() != 0) return -2;
    outb(ATA_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
    ata_delay400();
    outb(ATA_SECCNT, (u8)count);
    outb(ATA_LBA_LO, (u8)(lba & 0xFF));
    outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
    outb(ATA_CMD, 0x20);             /* READ SECTORS with retry */
    {
        u16 s;
        u16 *p = (u16 *)buf;
        for (s = 0; s < count; s++) {
            u16 i;
            if (wait_drq(2000000) != 0) {
                ser_puts(" [ata] timeout st=");
                ser_put_dec(inb(ATA_STATUS));
                ser_puts(" lba=");
                ser_put_dec(lba);
                ser_puts("\n");
                return -5;
            }
            __asm__ __volatile__("pushfq; cli" ::: "memory");
            for (i = 0; i < 256; i++)
                p[s * 256 + i] = inw(ATA_DATA);
            __asm__ __volatile__("popfq" ::: "memory");
        }
    }
    return 0;
}
