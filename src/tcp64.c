/* tcp64.c - minimal single-connection TCP for the AJOS x86-64 port.
 * Enough to do an HTTP GET over slirp: connect (SYN/SYN-ACK/ACK),
 * data send/recv with ACKs, retransmit of the last unacked segment,
 * graceful close (FIN), in-order receive only. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef long long s64;
typedef int s32;
typedef unsigned long long u64;

extern int  e1000_64_send(const u8 *frame, u16 len);
extern const u8 *e1000_64_mac(void);
extern u32  net64_my_ip(void);
extern u32  net64_gw_ip(void);
extern int  net64_arp_ready(void);
extern void net64_poll(void);
extern int  ip64_send_tcp(u32 dst, const u8 *seg, u16 seglen);
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

/* ---- TCP state ---- */
#define TS_CLOSED     0
#define TS_SYN_SENT   1
#define TS_ESTABLISHED 2
#define TS_FIN_SENT   3
#define TS_DONE       4

#define TCPF_FIN 0x01
#define TCPF_SYN 0x02
#define TCPF_RST 0x04
#define TCPF_PSH 0x08
#define TCPF_ACK 0x10

static u8  t_state = TS_CLOSED;
static u32 t_rip;            /* remote ip */
static u16 t_rport, t_lport;
static u32 t_seq;            /* my next seq to send */
static u32 t_snd_una;        /* oldest unacked */
static u32 t_rcv_nxt;        /* their next seq I expect */
static u16 t_window = 8192;

static u8  t_rxbuf[8192];
static u16 t_rxlen;
static u8  t_rx_fin;

/* retransmit: the last segment copy */
static u8  t_lastseg[600];
static u16 t_lastseg_len;
static u64 t_last_sent_tick;
static u8  t_last_retries;

static u16 checksum_tcp(const u8 *seg, u16 seglen, u32 src, u32 dst)
{
    /* pseudo-header: src, dst, zero, proto, len */
    u8 ph[12];
    u32 sum = 0;
    u16 i;
    ph[0] = (u8)(src); ph[1] = (u8)(src >> 8); ph[2] = (u8)(src >> 16); ph[3] = (u8)(src >> 24);
    ph[4] = (u8)(dst); ph[5] = (u8)(dst >> 8); ph[6] = (u8)(dst >> 16); ph[7] = (u8)(dst >> 24);
    ph[8] = 0; ph[9] = 6;
    ph[10] = (u8)(seglen >> 8); ph[11] = (u8)seglen;
    for (i = 0; i + 1 < 12; i += 2)
        sum += ((u16)ph[i] << 8) | ph[i + 1];
    for (i = 0; i + 1 < seglen; i += 2)
        sum += ((u16)seg[i] << 8) | seg[i + 1];
    if (i < seglen)
        sum += ((u16)seg[i] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (u16)(~sum & 0xFFFF);
}

static int seg_send(u8 flags, const u8 *payload, u16 len)
{
    u8 seg[600];
    u16 hdrlen = 20;
    u16 total = (u16)(20 + len);
    if (total > sizeof(seg)) return -1;
    seg[0] = (u8)(t_lport >> 8); seg[1] = (u8)t_lport;
    seg[2] = (u8)(t_rport >> 8); seg[3] = (u8)t_rport;
    seg[4] = (u8)(t_seq >> 24); seg[5] = (u8)(t_seq >> 16);
    seg[6] = (u8)(t_seq >> 8);  seg[7] = (u8)t_seq;
    seg[8] = (u8)(t_rcv_nxt >> 24); seg[9] = (u8)(t_rcv_nxt >> 16);
    seg[10] = (u8)(t_rcv_nxt >> 8); seg[11] = (u8)t_rcv_nxt;
    seg[12] = 0x50;                                  /* data offset 5 */
    seg[13] = flags;
    seg[14] = (u8)(t_window >> 8); seg[15] = (u8)t_window;
    seg[16] = seg[17] = 0;                           /* checksum placeholder */
    seg[18] = seg[19] = 0;
    {
        u16 i;
        for (i = 0; i < len; i++) seg[20 + i] = payload[i];
    }
    {
        u16 c = checksum_tcp(seg, total, net64_my_ip(), t_rip);
        seg[16] = (u8)(c >> 8); seg[17] = (u8)c;
    }
    /* remember for retransmit */
    {
        u16 i;
        if (total <= sizeof(t_lastseg)) {
            for (i = 0; i < total; i++) t_lastseg[i] = seg[i];
            t_lastseg_len = total;
        }
    }
    t_last_sent_tick = timer64_ticks();
    return ip64_send_tcp(t_rip, seg, total);
}

static void retransmit_check(u64 now)
{
    if (t_lastseg_len && t_state != TS_CLOSED && now - t_last_sent_tick >= 50 &&
        t_last_retries < 5) {
        u8 seg[600];
        u16 i;
        for (i = 0; i < t_lastseg_len; i++) seg[i] = t_lastseg[i];
        {
            u16 c = checksum_tcp(seg, t_lastseg_len, net64_my_ip(), t_rip);
            seg[16] = (u8)(c >> 8); seg[17] = (u8)c;
        }
        ip64_send_tcp(t_rip, seg, t_lastseg_len);
        t_last_sent_tick = now;
        t_last_retries++;
    }
}

static void seg_ack_from_peer(u32 ack)
{
    /* count the acked seq space (mod 2^32) */
    if ((s32)(ack - t_snd_una) > 0) {
        t_snd_una = ack;
        t_lastseg_len = 0;      /* everything up to ack confirmed */
        t_last_retries = 0;
    }
}

/* called from net64 for proto 6 (ip = the IP header, iplen = the total) */
void tcp64_rx(const u8 *ip, u16 iplen)
{
    u16 ihl = (u16)((ip[0] & 0xF) * 4);
    const u8 *t = ip + ihl;
    u16 tlen = (u16)(iplen - ihl);
    u16 sport, dport, hdrlen, flags, plen;
    u32 seq, ack;
    const u8 *payload;

    if (tlen < 20) return;
    sport = (u16)((t[0] << 8) | t[1]);
    dport = (u16)((t[2] << 8) | t[3]);
    if (t_state == TS_CLOSED || dport != t_lport || sport != t_rport)
        return;
    seq = ((u32)t[4] << 24) | ((u32)t[5] << 16) | ((u32)t[6] << 8) | t[7];
    ack = ((u32)t[8] << 24) | ((u32)t[9] << 16) | ((u32)t[10] << 8) | t[11];
    hdrlen = (u16)((t[12] >> 4) * 4);
    flags = t[13];
    if (hdrlen > tlen || hdrlen < 20) return;
    payload = t + hdrlen;
    plen = (u16)(tlen - hdrlen);

    if (flags & TCPF_RST) {
        t_state = TS_CLOSED;
        return;
    }

    if (t_state == TS_SYN_SENT) {
        if ((flags & TCPF_SYN) && (flags & TCPF_ACK) && ack == t_seq + 1) {
            t_seq = ack;                 /* SYN consumed */
            t_rcv_nxt = seq + 1;         /* their SYN consumed */
            t_state = TS_ESTABLISHED;
            seg_send(TCPF_ACK, 0, 0);
            t_lastseg_len = 0;           /* plain ACK: no retransmit */
        }
        return;
    }

    /* ESTABLISHED / FIN_SENT */
    if (flags & TCPF_ACK)
        seg_ack_from_peer(ack);

    if (plen && t_state == TS_ESTABLISHED && seq == t_rcv_nxt) {
        u16 i;
        if (t_rxlen + plen <= sizeof(t_rxbuf)) {
            for (i = 0; i < plen; i++) t_rxbuf[t_rxlen + i] = payload[i];
            t_rxlen += plen;
        }
        t_rcv_nxt += plen;
        seg_send(TCPF_ACK, 0, 0);
        t_lastseg_len = 0;
    }

    if ((flags & TCPF_FIN) && t_state == TS_ESTABLISHED) {
        t_rcv_nxt = seq + plen + 1;
        t_rx_fin = 1;
        seg_send(TCPF_ACK, 0, 0);
        t_lastseg_len = 0;
        t_state = TS_DONE;
    } else if ((flags & TCPF_FIN) && seq + plen + 1 == t_rcv_nxt + 1) {
        t_rcv_nxt = seq + plen + 1;
        t_rx_fin = 1;
        seg_send(TCPF_ACK, 0, 0);
        t_lastseg_len = 0;
        t_state = TS_DONE;
    }
}

static u32 isn(void)
{
    return 0x1A2B0000u + (u32)(timer64_ticks() * 7919u);
}

int tcp64_connect(u32 rip, u16 rport)
{
    u64 deadline;
    t_rip = rip;
    t_rport = rport;
    t_lport = (u16)(49152 + (timer64_ticks() & 0x7FF));
    t_seq = isn();
    t_snd_una = t_seq;
    t_rcv_nxt = 0;
    t_rxlen = 0;
    t_rx_fin = 0;
    t_lastseg_len = 0;
    t_last_retries = 0;
    t_state = TS_SYN_SENT;
    seg_send(TCPF_SYN, 0, 0);
    deadline = timer64_ticks() + 400;    /* 4s */
    while (timer64_ticks() < deadline && t_state == TS_SYN_SENT) {
        net64_poll();
        retransmit_check(timer64_ticks());
        timer64_wait(1);
    }
    return t_state == TS_ESTABLISHED ? 0 : -1;
}

int tcp64_send(const u8 *data, u16 len)
{
    u64 deadline;
    if (t_state != TS_ESTABLISHED) return -1;
    seg_send(TCPF_ACK | TCPF_PSH, data, len);
    t_seq += len;
    deadline = timer64_ticks() + 300;
    while (timer64_ticks() < deadline && t_state == TS_ESTABLISHED) {
        net64_poll();
        retransmit_check(timer64_ticks());
        if (t_lastseg_len == 0) return 0;    /* fully acked */
        timer64_wait(1);
    }
    return t_lastseg_len == 0 ? 0 : -2;
}

int tcp64_recv_wait(u64 max_ticks)
{
    u64 start = timer64_ticks();
    while (timer64_ticks() - start < max_ticks) {
        net64_poll();
        retransmit_check(timer64_ticks());
        if (t_rx_fin) return (int)t_rxlen;
        timer64_wait(1);
    }
    return (int)t_rxlen;    /* partial */
}

void tcp64_close(void)
{
    if (t_state == TS_ESTABLISHED || t_state == TS_DONE) {
        if (t_state == TS_ESTABLISHED) {
            seg_send(TCPF_ACK | TCPF_FIN, 0, 0);
            t_seq += 1;
            t_state = TS_FIN_SENT;
        }
        t_state = TS_DONE;
    }
    t_lastseg_len = 0;
    t_state = TS_CLOSED;
}

int tcp64_http_get(u32 ip, u16 port, const char *path, u16 *status_out, u16 *len_out)
{
    char req[256];
    u16 n = 0;
    const char *p;
    int r, total;
    if (tcp64_connect(ip, port) != 0) return -1;
    p = path;
    while (*p && n < sizeof(req) - 64) req[n++] = *p++;
    req[n] = 0;
    {
        char rq[320];
        u16 m = 0, i;
        const char *a = "GET ";
        const char *b = " HTTP/1.0\r\nHost: 10.0.2.2\r\nUser-Agent: AJOS64\r\n\r\n";
        for (i = 0; a[i]; i++) rq[m++] = a[i];
        for (i = 0; req[i]; i++) rq[m++] = req[i];
        for (i = 0; b[i]; i++) rq[m++] = b[i];
        r = tcp64_send((const u8 *)rq, m);
    }
    if (r != 0) { tcp64_close(); return -2; }
    total = tcp64_recv_wait(500);          /* 5s */
    tcp64_close();
    if (total < 12) return -3;
    /* parse "HTTP/1.x NNN" */
    {
        const u8 *h = t_rxbuf;
        u16 code = 0;
        if (h[0] == 'H' && h[1] == 'T' && h[2] == 'T' && h[3] == 'P') {
            u16 i = 9;                      /* skip "HTTP/1.x " */
            while (i < (u16)total && h[i] >= '0' && h[i] <= '9') {
                code = (u16)(code * 10 + (h[i] - '0'));
                i++;
            }
        }
        *status_out = code;
        *len_out = (u16)total;
        return code;
    }
}

/* Full GET returning the response BODY (after the blank line) in out.
 * Returns the HTTP status code, or a negative error. */
int tcp64_http_get_body(u32 ip, u16 port, const char *path, char *out, u16 cap)
{
    unsigned short code = 0, blen = 0;
    int total = tcp64_http_get(ip, port, path, &code, &blen);
    int i;
    if (total < 12) return total;
    for (i = 0; i + 3 < total; i++) {
        if (t_rxbuf[i] == '\r' && t_rxbuf[i + 1] == '\n' &&
            t_rxbuf[i + 2] == '\r' && t_rxbuf[i + 3] == '\n') {
            int body = total - (i + 4);
            int j;
            if (body > (int)cap - 1) body = cap - 1;
            for (j = 0; j < body; j++) out[j] = t_rxbuf[i + 4 + j];
            out[body > 0 ? body : 0] = 0;
            return (int)code;
        }
    }
    return (int)code;
}

void tcp64_init(void)
{
    ser_puts(" TCP-64: single-connection stack ready (retransmit on)\n");
}

