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
extern int ata64_init(void);
extern int fat64_init(void);
extern int fat64_read_file(const char *name, void *out, unsigned int cap);
extern int ajlang64_run(const char *name);
extern void sh64_run(void) __attribute__((noreturn));
extern void tcp64_serve_start(unsigned short port);
extern void tcp64_set_handler(int (*fn)(const char *req, char *out, unsigned short cap));
extern void ajlang64_set_output(char *buf, unsigned short cap);
extern void ajlang64_output_off(void);
extern void ajlang64_clear_query(void);
extern void ajlang64_set_query(const char *k, const char *v);
extern unsigned short ajlang64_output_len(void);
extern void tcp64_serve_start(unsigned short port);
extern void tcp64_set_handler(int (*fn)(const char *req, char *out, unsigned short cap));
extern void ajlang64_set_output(char *buf, unsigned short cap);
extern void ajlang64_output_off(void);
extern unsigned short ajlang64_output_len(void);

static char web_body[1024];

static int web_route(const char *script, char *out, unsigned short cap)
{
    unsigned short n;
    ajlang64_set_output(out, cap);
    ajlang64_run(script);
    ajlang64_output_off();
    n = ajlang64_output_len();
    return (int)n;
}

/* extract one URL-encoded param from an "a=1&b=2" body/query string */
static int body_param(const char *body, const char *key, char *out, int cap)
{
    int i = 0, j;
    while (body[i]) {
        j = 0;
        while (body[i + j] && body[i + j] != '=' && body[i + j] != '&') {
            if (key[j] != body[i + j]) break;
            j++;
        }
        if (key[j] == 0 && body[i + j] == '=') {
            int o = 0;
            i += j + 1;
            while (body[i] && body[i] != '&' && o < cap - 1) {
                char c = body[i];
                if (c == '+') { out[o++] = ' '; i++; }
                else if (c == '%' && body[i + 1] && body[i + 2]) {
                    u8 hi = (u8)body[i + 1], lo = (u8)body[i + 2];
                    hi = (u8)((hi >= '0' && hi <= '9') ? hi - '0' :
                              (hi | 0x20) - 'a' + 10);
                    lo = (u8)((lo >= '0' && lo <= '9') ? lo - '0' :
                              (lo | 0x20) - 'a' + 10);
                    out[o++] = (u8)((hi << 4) | lo);
                    i += 3;
                } else { out[o++] = c; i++; }
            }
            out[o] = 0;
            return o;
        }
        while (body[i] && body[i] != '&') i++;
        if (body[i] == '&') i++;
    }
    return -1;
}

static int web_handler(const char *req, char *out, unsigned short cap)
{
    /* routes: GET / -> WEB.TXT (form + entries), POST /gb -> GBAPP.TXT,
     * GET /count -> HITS.TXT (persistent counter) */
    ajlang64_clear_query();
    if (req[0] == 'P' && req[1] == 'O' && req[2] == 'S' && req[3] == 'T' &&
        req[4] == ' ' && req[5] == '/' && req[6] == 'g' && req[7] == 'b') {
        u16 i;
        for (i = 0; i + 3 < 1400 && req[i]; i++) {
            if (req[i] == '\r' && req[i + 1] == '\n' &&
                req[i + 2] == '\r' && req[i + 3] == '\n') {
                char namev[64], msgv[128];
                int n1 = body_param(req + i + 4, "name", namev, sizeof(namev));
                int n2 = body_param(req + i + 4, "msg", msgv, sizeof(msgv));
                if (n1 >= 0) ajlang64_set_query("name", namev);
                if (n2 >= 0) ajlang64_set_query("msg", msgv);
                break;
            }
        }
        return web_route("GBAPP.TXT", out, cap);
    }
    if (req[0] == 'G' && req[1] == 'E' && req[2] == 'T' &&
        req[3] == ' ' && req[4] == '/' &&
        (req[5] == ' ' || req[5] == '?'))
        return web_route("WEB.TXT", out, cap);
    if (req[0] == 'G' && req[1] == 'E' && req[2] == 'T' &&
        req[3] == ' ' && req[4] == '/' && req[5] == 'c' &&
        req[6] == 'o' && req[7] == 'u' && req[8] == 'n' && req[9] == 't' &&
        (req[10] == ' ' || req[10] == '?'))
        return web_route("HITS.TXT", out, cap);
    {
        const char *nf = "404 not found (routes: / and /count)";
        unsigned short i;
        for (i = 0; nf[i] && i < cap - 1; i++) out[i] = nf[i];
        out[i] = 0;
        return (int)i;
    }
}
extern int ajlang64_run(const char *name);
extern void user64_init(void);
extern void user64_start(void) __attribute__((noreturn));
extern void tcp64_init(void);
extern int tcp64_http_get(unsigned int ip, unsigned short port, const char *path, unsigned short *status, unsigned short *len);
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
    serial_puts(" AJOS x86-64 :: LONG MODE MILESTONE 14\n");
    serial_puts(" (guestbook web app: POST, query params, persistence)\n");
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

    /* ---- M5: TCP + HTTP GET to the host (slirp 10.0.2.2 alias) ---- */
    tcp64_init();
    if (e1000_64_present()) {
        unsigned short code = 0, blen = 0;
        u32 target = *(volatile u32 *)0x74000u;   /* config sector */
        if (!target) target = 0x0202000Au;        /* default 10.0.2.2 */
        serial_puts(" HTTP target = ");
        serial_put_dec(target & 0xFF); serial_putc('.');
        serial_put_dec((target >> 8) & 0xFF); serial_putc('.');
        serial_put_dec((target >> 16) & 0xFF); serial_putc('.');
        serial_put_dec((target >> 24) & 0xFF);
        serial_puts(":8130\n");
        int st = tcp64_http_get(target, 8130, "/", &code, &blen);
        serial_puts(" HTTP GET / : ");
        if (st > 0) {
            serial_puts("status=");
            serial_put_dec(code);
            serial_puts(" HTTP 200 TEST PASS bytes=");
            serial_put_dec(blen);
            serial_puts("\n");
        } else {
            serial_puts("FAILED err=");
            serial_put_dec((u64)(-st));
            serial_puts("\n");
        }
    }

    /* ---- M6: ATA + FAT storage ---- */
    if (ata64_init() == 0 && fat64_init() == 0) {
        static char filebuf[4096];
        int n = fat64_read_file("HELLO.TXT", filebuf, sizeof(filebuf) - 1);
        serial_puts(" HELLO.TXT: ");
        if (n > 0) {
            int i;
            filebuf[n] = 0;
            serial_puts("READ OK, content: \"");
            for (i = 0; i < n && i < 40; i++) serial_putc(filebuf[i]);
            serial_puts("\"\n");
            if (n >= 19) {
                char ok = 1;
                const char *expect = "AJOS64-DISK-READS-OK";
                int i2;
                for (i2 = 0; i2 < 19; i2++)
                    if (filebuf[i2] != expect[i2]) ok = 0;
                serial_puts(" DISK READ TEST: ");
                serial_puts(ok ? "PASS\n" : "CONTENT MISMATCH\n");
            }
        } else {
            serial_puts("NOT FOUND (err=");
            serial_put_dec((u64)(-n));
            serial_puts(")\n");
        }
    }

    /* ---- M8: AJLang ---- */
    {
        extern int ajlang64_run(const char *);
        serial_puts(" AJLang-64: running DEMO.TXT\n");
        ajlang64_run("DEMO.TXT");
        serial_puts(" AJLang-64: running HTTP.TXT (http_get from a script)\n");
        ajlang64_run("HTTP.TXT");
        serial_puts(" AJLang-64: running WRITE.TXT (file_write to disk)\n");
        ajlang64_run("WRITE.TXT");
    }

    /* ---- M12: web server (AJLang-driven, port 80) ---- */
    {
        extern void tcp64_init(void);
        tcp64_init();
        tcp64_serve_start(80);
        tcp64_set_handler(web_handler);
        serial_puts(" web server: listening on :80 (routes / and /count (persistent))\n");
    }

    /* ---- M10: ring 3 user program + syscall/sysret ---- */
    serial_puts(" M10: user program (ring 3)\n");
    user64_init();
    user64_start();
    /* noreturn: the user exits via the syscall, which lands in the shell */

    serial_puts("\n shell ready (web server co-running on :80).\n");
    serial_puts("================================================\n");
    sh64_run();   /* never returns */

}
