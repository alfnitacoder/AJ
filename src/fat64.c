/* fat64.c - minimal FAT12/FAT16 read-only filesystem for the AJOS x86-64
 * port. Reads from the primary-master IDE disk via ata64. Supports 8.3
 * names in the root directory (LFN entries skipped), cluster chains via
 * a cached FAT. Enough for the milestone 6 test: read a file, print it. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern int ata64_read_lba(u32 lba, u16 count, void *buf);

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

static u8  vbr[512];
static u16 f_bps, f_spc, f_reserved, f_nfats, f_rootent, f_spf;
static u32 f_root_lba, f_data_lba, f_root_secs;
static int f_fat16;                      /* 0 = FAT12, 1 = FAT16 */
static u16 f_type;                       /* 12/16 bits */
static u8  fat_cache[16384];
static u32 fat_cache_bytes;
static u8  root_cache[16384];
static u32 root_cache_bytes;

static u16 rd16(const u8 *p) { return (u16)(p[0] | (p[1] << 8)); }
static u32 rd32(const u8 *p)
{
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

int fat64_init(void)
{
    if (ata64_read_lba(0, 1, vbr) != 0) {
        ser_puts(" FAT-64: cannot read VBR\\n");
        return -1;
    }
    if (vbr[510] != 0x55 || vbr[511] != 0xAA) {
        ser_puts(" FAT-64: bad VBR signature\\n");
        return -1;
    }
    f_bps      = rd16(vbr + 11);
    f_spc      = vbr[13];
    f_reserved = rd16(vbr + 14);
    f_nfats    = vbr[16];
    f_rootent  = rd16(vbr + 17);
    f_spf      = rd16(vbr + 22);
    f_root_secs = (u32)(f_rootent * 32 + f_bps - 1) / f_bps;
    f_root_lba  = (u32)f_reserved + (u32)f_nfats * f_spf;
    f_data_lba  = f_root_lba + f_root_secs;
    /* FAT type from the cluster count */
    {
        u32 totsec = rd16(vbr + 19);
        if (!totsec) totsec = rd32(vbr + 32);
        {
            u32 clusters = (totsec - f_data_lba) / f_spc;
            f_type = (clusters >= 4085) ? 16 : 12;
        }
    }
    fat_cache_bytes = (u32)f_nfats * f_spf * f_bps;
    if (fat_cache_bytes > sizeof(fat_cache)) fat_cache_bytes = sizeof(fat_cache);
    ata64_read_lba(f_reserved, (u16)(fat_cache_bytes / f_bps), fat_cache);
    root_cache_bytes = (u32)f_root_secs * f_bps;
    if (root_cache_bytes > sizeof(root_cache)) root_cache_bytes = sizeof(root_cache);
    ata64_read_lba(f_root_lba, (u16)(root_cache_bytes / f_bps), root_cache);
    {
        u32 e;
        int shown;
        ser_puts(" FAT-64: root entries:");
        shown = 0;
        for (e = 0; e + 32 <= root_cache_bytes && shown < 24; e += 32) {
            u8 *d = root_cache + e;
            if (d[0] == 0x00) break;
            if (d[11] == 0x0F) { ser_puts(" [LFN]"); shown++; continue; }
            {
                int i;
                ser_puts(" '");
                for (i = 0; i < 11; i++) {
                    u8 ch = d[i];
                    ser_putc((ch >= 32 && ch < 127) ? ch : '?');
                }
                ser_putc('\'');
                ser_putc('(');
                ser_put_dec(d[11]);
                ser_putc(')');
            }
            shown++;
        }
        ser_puts("\n");
    }
    ser_puts(" FAT-64: FAT");
    ser_put_dec(f_type);
    ser_puts(" bps=");
    ser_put_dec(f_bps);
    ser_puts(" spc=");
    ser_put_dec(f_spc);
    ser_puts(" root=");
    ser_put_dec(f_rootent);
    ser_puts(" entries, fat=");
    ser_put_dec(fat_cache_bytes);
    ser_puts(" bytes cached\\n");
    return 0;
}

/* next cluster in the chain */
static u32 next_cluster(u32 cl)
{
    if (f_type == 12) {
        u32 off = cl + cl / 2;
        u16 v;
        if (off + 1 >= fat_cache_bytes) return 0;
        if (cl & 1)
            v = (u16)(((u16)fat_cache[off] >> 4) | ((u16)fat_cache[off + 1] << 4));
        else
            v = (u16)(fat_cache[off] | ((u16)fat_cache[off + 1] << 8));
        v &= 0xFFF;
        if (v >= 0xFF8) return 0;
        return v;
    }
    {
        u32 off = cl * 2;
        u16 v;
        if (off + 1 >= fat_cache_bytes) return 0;
        v = rd16(fat_cache + off);
        if (v >= 0xFFF8) return 0;
        return v;
    }
}

static int name_eq83(const u8 *entry, const char *name)
{
    /* name: up-to-8 chars, optional ".", up-to-3 ext; case-insensitive */
    char base[9], ext[4];
    int i, bi = 0, ei = -1;
    for (i = 0; i < 8; i++) {
        char c = name[i];
        if (!c || c == '.') { ei = (c == '.') ? i + 1 : i; break; }
        base[bi++] = c;
    }
    base[bi] = 0;
    if (ei >= 0) {
        int k = 0;
        while (name[ei + k] && k < 3) { ext[k] = name[ei + k]; k++; }
        ext[k] = 0;
    } else {
        ext[0] = 0;
    }
    for (i = 0; i < 8; i++) {
        char e = (char)entry[i];
        char w = (i < bi) ? base[i] : ' ';
        if (e >= 'a' && e <= 'z') e -= 32;
        if (w >= 'a' && w <= 'z') w -= 32;
        if (e != w) return 0;
    }
    for (i = 0; i < 3; i++) {
        char e = (char)entry[8 + i];
        char w = (i < 3) ? ext[i] : 0;
        if (e >= 'a' && e <= 'z') e -= 32;
        if (e != w) return 0;
    }
    return 1;
}

/* Find + read the first `cap` bytes of /NAME.EXT from the root dir.
 * Returns the byte count copied, or -1 if not found. */
int fat64_read_file(const char *name, void *out, u32 cap)
{
    u32 e;
    u8 *ent = 0;
    for (e = 0; e + 32 <= root_cache_bytes; e += 32) {
        u8 *d = root_cache + e;
        if (d[0] == 0x00) break;
        if (d[0] == 0xE5) continue;
        if (d[11] == 0x0F) continue;             /* LFN */
        if (d[11] & 0x18) continue;              /* volume label / dir */
        if (name_eq83(d, name)) { ent = d; break; }
    }
    if (!ent) return -1;
    {
        u32 cluster = rd16(ent + 26);
        u32 size = rd32(ent + 28);
        u8 *outp = (u8 *)out;
        u32 copied = 0;
        u32 guard = 0;
        while (cluster >= 2 && copied < size && cap > 0 && guard++ < 65536) {
            u32 lba = f_data_lba + (cluster - 2) * f_spc;
            u32 chunk = (u32)f_spc * f_bps;
            u8 sec[8192];
            u32 i;
            if (chunk > sizeof(sec)) chunk = sizeof(sec);
            if (ata64_read_lba(lba, (u16)(chunk / f_bps), sec) != 0) return -2;
            for (i = 0; i < chunk && copied < size && copied < cap; i++)
                outp[copied++] = sec[i];
            cluster = next_cluster(cluster);
            if (cluster == 0) break;
        }
        return (int)copied;
    }
}
