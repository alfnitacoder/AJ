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
#define ATA_STAT_ERR 0x01

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

static int wait_not_bsy(int spins)
{
    while (spins--) {
        if (!(inb(ATA_STATUS) & ATA_STAT_BSY)) return 0;
    }
    return -1;
}

int ata64_init(void)
{
    u32 st;
    ata_present = 0;
    outb(ATA_CONTROL, 0);            /* nIEN off */
    /* select master, wait */
    outb(ATA_DRIVE, 0xA0);
    {
        int i;
        for (i = 0; i < 4; i++) inb(ATA_STATUS);   /* 400ns settle */
    }
    if (wait_not_bsy(200000) != 0) {
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
    if (wait_not_bsy(200000) != 0) return -1;
    {
        int spins = 500000;
        while (!(inb(ATA_STATUS) & ATA_STAT_DRQ)) {
            if (inb(ATA_STATUS) & ATA_STAT_ERR) {
                ser_puts(" ATA-64: identify error\\n");
                return -1;
            }
            if (--spins <= 0) {
                ser_puts(" ATA-64: identify timeout\\n");
                return -1;
            }
        }
    }
    {
        u16 id[256];
        int i;
        for (i = 0; i < 256; i++) {
            u8 lo = inb(ATA_DATA);
            u8 hi = inb(ATA_DATA);
            id[i] = (u16)(lo | (u16)((u16)hi << 8));
        }
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
int ata64_read_lba(u32 lba, u16 count, void *buf)
{
    if (!ata_present) return -1;
    if (count == 0) return 0;
    if (wait_not_bsy(200000) != 0) return -2;
    outb(ATA_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
    outb(ATA_SECCNT, (u8)count);
    outb(ATA_LBA_LO, (u8)(lba & 0xFF));
    outb(ATA_LBA_MID, (u8)((lba >> 8) & 0xFF));
    outb(ATA_LBA_HI, (u8)((lba >> 16) & 0xFF));
    outb(ATA_CMD, 0x20);             /* READ SECTORS with retry */
    {
        u16 s;
        u16 *p = (u16 *)buf;
        for (s = 0; s < count; s++) {
            int spins = 2000000;
            for (;;) {
                u8 st = inb(ATA_STATUS);
                if (st & ATA_STAT_ERR) return -3;
                if (!(st & ATA_STAT_BSY) && (st & ATA_STAT_DRQ)) break;
                if (--spins <= 0) return -5;
            }
            __asm__ __volatile__("cld; rep insw"
                                 : "+D"(p)
                                 : "c"(256), "d"(ATA_DATA)
                                 : "memory");
        }
    }
    return 0;
}
