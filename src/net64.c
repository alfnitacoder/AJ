/* net64.c - minimal ARP/IP4/ICMP over e1000_64 for the AJOS x86-64 port.
 * Goal of milestone 4: answer "is the 64-bit kernel alive on the wire?"
 * with ICMP echo replies from the QEMU slirp gateway (10.0.2.2). */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern int  e1000_64_present(void);
extern const u8 *e1000_64_mac(void);
extern int  e1000_64_send(const u8 *frame, u16 len);
extern u16  e1000_64_poll(u8 *out, u16 cap);
extern unsigned long long timer64_ticks(void);
extern void timer64_wait(unsigned long long ticks);

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
static void ser_put_ip(u32 ip)
{
    ser_put_dec((ip) & 0xFF); ser_putc('.');
    ser_put_dec((ip >> 8) & 0xFF); ser_putc('.');
    ser_put_dec((ip >> 16) & 0xFF); ser_putc('.');
    ser_put_dec((ip >> 24) & 0xFF);
}

/* ---- config: QEMU slirp defaults ---- */
static u32 my_ip   = 0x0F02000Au;  /* 10.0.2.15 (LSB-first octets) */
static u32 gw_ip   = 0x0202000Au;  /* 10.0.2.2  */
static u8  my_mac[6];
static u8  bcast_mac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

/* ARP cache: one entry (the gateway) is all we need. */
static u32 arp_ip;
static u8  arp_mac[6];
static int arp_valid;

static u16 checksum(const u8 *data, u16 len)
{
    u32 sum = 0;
    u16 i;
    for (i = 0; i + 1 < len; i += 2)
        sum += ((u16)data[i] << 8) | data[i + 1];
    if (i < len)
        sum += ((u16)data[i] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)(~sum & 0xFFFF);
}

static void mac_copy(u8 *dst, const u8 *src)
{
    int i;
    for (i = 0; i < 6; i++) dst[i] = src[i];
}

/* ---- TX helpers ---- */

static int arp_tx(u16 op, const u8 *dst_mac, u32 tip)
{
    u8 f[42];
    int i;
    mac_copy(f, dst_mac);
    mac_copy(f + 6, my_mac);
    f[12] = 0x08; f[13] = 0x06;                       /* ARP */
    f[14] = 0x00; f[15] = 0x01;                       /* ethernet */
    f[16] = 0x08; f[17] = 0x00;                       /* IPv4 */
    f[18] = 6; f[19] = 4;
    f[20] = (u8)(op >> 8); f[21] = (u8)op;            /* 1 req, 2 reply */
    mac_copy(f + 22, my_mac);                         /* sha: frame 22..27 */
    f[28] = (u8)(my_ip); f[29] = (u8)(my_ip >> 8);    /* spa: frame 28..31 */
    f[30] = (u8)(my_ip >> 16); f[31] = (u8)(my_ip >> 24);
    mac_copy(f + 32, dst_mac);                        /* tha: frame 32..37 */
    f[38] = (u8)(tip); f[39] = (u8)(tip >> 8);        /* tpa: frame 38..41 */
    f[40] = (u8)(tip >> 16); f[41] = (u8)(tip >> 24);
    return e1000_64_send(f, 42);
}

static int ip_tx(u32 dst, u8 proto, const u8 *payload, u16 len, const u8 *dst_mac)
{
    u8 hdr[20];
    u16 total = (u16)(20 + len);
    hdr[0] = 0x45; hdr[1] = 0;
    hdr[2] = (u8)(total >> 8); hdr[3] = (u8)total;
    hdr[4] = hdr[5] = 0;                              /* id */
    hdr[6] = hdr[7] = 0;                              /* flags/frag */
    hdr[8] = 64;                                      /* ttl */
    hdr[9] = proto;
    hdr[10] = hdr[11] = 0;                            /* checksum placeholder */
    hdr[12] = (u8)(my_ip); hdr[13] = (u8)(my_ip >> 8);
    hdr[14] = (u8)(my_ip >> 16); hdr[15] = (u8)(my_ip >> 24);
    hdr[16] = (u8)(dst); hdr[17] = (u8)(dst >> 8);
    hdr[18] = (u8)(dst >> 16); hdr[19] = (u8)(dst >> 24);
    {
        u16 c = checksum(hdr, 20);
        hdr[10] = (u8)(c >> 8); hdr[11] = (u8)c;
    }
    {
        u8 frame[1500];
        int i;
        if (total > 1500) return -1;
        mac_copy(frame, dst_mac);
        mac_copy(frame + 6, my_mac);
        frame[12] = 0x08; frame[13] = 0x00;
        for (i = 0; i < 20; i++) frame[14 + i] = hdr[i];
        for (i = 0; i < len; i++) frame[34 + i] = payload[i];
        return e1000_64_send(frame, (u16)(34 + len));
    }
}

static int icmp_tx_echo(u32 dst, u16 id, u16 seq, const u8 *data, u16 dlen)
{
    u8 icmp[8 + 64];
    u16 i;
    if (dlen > 64) dlen = 64;
    icmp[0] = 8; icmp[1] = 0;                          /* echo request */
    icmp[2] = icmp[3] = 0;                             /* checksum */
    icmp[4] = (u8)(id >> 8); icmp[5] = (u8)id;
    icmp[6] = (u8)(seq >> 8); icmp[7] = (u8)seq;
    for (i = 0; i < dlen; i++) icmp[8 + i] = data[i];
    {
        u16 c = checksum(icmp, (u16)(8 + dlen));
        icmp[2] = (u8)(c >> 8); icmp[3] = (u8)c;
    }
    return ip_tx(dst, 1, icmp, (u16)(8 + dlen), arp_mac);
}

/* ---- RX dispatch ---- */

static volatile u64 pong_seq;      /* seq of the last echo reply */
static volatile u64 pong_at_tick;  /* when it arrived */

static void ip_rx(const u8 *frame, u16 len)
{
    const u8 *ip = frame + 14;
    u16 iplen;
    u32 src;
    if (len < 34) return;
    iplen = (u16)(((ip[2] << 8) | ip[3]));
    src = (u32)ip[12] | ((u32)ip[13] << 8) | ((u32)ip[14] << 16) | ((u32)ip[15] << 24);
    if (ip[9] == 1) {
        /* ICMP: the type lives AFTER the IP header (ihl), not at ip[0]. */
        u16 ihl = (u16)((ip[0] & 0xF) * 4);
        const u8 *icmp = ip + ihl;
        u16 icmplen = (u16)(iplen - ihl);
        if (icmplen >= 8 && icmp[0] == 8) {
            /* echo request: send reply straight back */
            u8 reply[84];
            u16 i;
            if (icmplen > 84) icmplen = 84;
            for (i = 0; i < icmplen; i++) reply[i] = icmp[i];
            reply[0] = 0;
            reply[2] = reply[3] = 0;
            {
                u16 c = checksum(reply, icmplen);
                reply[2] = (u8)(c >> 8); reply[3] = (u8)c;
            }
            ip_tx(src, 1, reply, icmplen, arp_valid ? arp_mac : bcast_mac);
        } else if (icmplen >= 8 && icmp[0] == 0) {
            /* echo reply: capture seq + arrival tick */
            pong_seq = ((u64)icmp[6] << 8) | icmp[7];
            pong_at_tick = timer64_ticks();
        }
    }
}

static void arp_rx(const u8 *frame, u16 len)
{
    /* ARP packet (after the 14-byte eth header):
     * 0-1 htype | 2-3 ptype | 4 hlen | 5 plen | 6-7 oper |
     * 8-13 sha | 14-17 spa | 18-23 tha | 24-27 tpa            */
    const u8 *arp = frame + 14;
    u16 op;
    if (len < 42) return;
    if (arp[0] != 0 || arp[1] != 1) return;            /* htype ethernet */
    if (arp[2] != 8 || arp[3] != 0) return;            /* ptype IPv4 */
    if (arp[4] != 6 || arp[5] != 4) return;            /* hlen/plen */
    op = (u16)((arp[6] << 8) | arp[7]);
    if (op == 2) {
        u32 spa = (u32)arp[14] | ((u32)arp[15] << 8) |
                  ((u32)arp[16] << 16) | ((u32)arp[17] << 24);
        if (spa == gw_ip) {
            mac_copy(arp_mac, arp + 8);                /* sender hw addr */
            arp_valid = 1;
        }
    } else if (op == 1) {
        u32 tpa = (u32)arp[24] | ((u32)arp[25] << 8) |
                  ((u32)arp[26] << 16) | ((u32)arp[27] << 24);
        if (tpa == my_ip) {
            u32 spa = (u32)arp[14] | ((u32)arp[15] << 8) |
                      ((u32)arp[16] << 16) | ((u32)arp[17] << 24);
            arp_tx(2, frame + 6, spa);                 /* unicast reply */
        }
    }
}

void net64_poll(void)
{
    u8 buf[1600];
    u16 len;
    while ((len = e1000_64_poll(buf, sizeof(buf))) != 0) {
        if (len < 14) continue;
        {
            u16 et = (u16)((buf[12] << 8) | buf[13]);
            if (et == 0x0806) arp_rx(buf, len);
            else if (et == 0x0800) ip_rx(buf, len);
        }
    }
}

int net64_arp_resolve(u32 ip)
{
    int tries;
    if (ip == gw_ip && arp_valid) return 0;
    for (tries = 0; tries < 5; tries++) {
        u64 deadline;
        arp_tx(1, bcast_mac, ip);
        deadline = timer64_ticks() + 10;   /* 100ms */
        while (timer64_ticks() < deadline) {
            net64_poll();
            if (arp_valid && ip == gw_ip) return 0;
        }
    }
    return arp_valid && ip == gw_ip ? 0 : -1;
}

int net64_ping(u32 dst, u16 seq)
{
    u64 start, deadline;
    static u16 ping_id;
    u8 payload[32];
    u16 i;
    for (i = 0; i < sizeof(payload); i++) payload[i] = (u8)('A' + (i & 0x0F));
    if (!arp_valid) {
        if (net64_arp_resolve(dst) != 0) return -1;
    }
    ping_id++;
    pong_seq = 0xFFFF;
    pong_at_tick = 0;
    start = timer64_ticks();
    icmp_tx_echo(dst, ping_id, seq, payload, 32);
    deadline = start + 30;                 /* 300ms */
    while (timer64_ticks() < deadline) {
        net64_poll();
        if (pong_at_tick && pong_seq == seq) {
            return (int)(pong_at_tick - start);   /* rtt in 10ms units */
        }
    }
    return -2;   /* timeout */
}

void net64_init(void)
{
    int i;
    for (i = 0; i < 6; i++) my_mac[i] = e1000_64_mac()[i];
    arp_valid = 0;
    ser_puts(" net-64: ip=");
    ser_put_ip(my_ip);
    ser_puts(" gw=");
    ser_put_ip(gw_ip);
    ser_puts(" (QEMU slirp defaults)\n");
}
