/* sh64.c - minimal serial shell for the AJOS x86-64 port.
 * Polls COM1 RX (no UART interrupts yet), line edit with echo and
 * backspace, dispatches a small command set over the milestone layers:
 * FAT (ls/cat), network (ping/http), memory (mem), misc. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern int ata64_init(void);
extern int fat64_init(void);
extern int fat64_read_file(const char *name, void *out, unsigned int cap);
extern int ajlang64_run(const char *name);
extern int proc64_spawn(const unsigned char *img, unsigned int size,
                       const char *name, int bg);
extern void proc64_ps(void);
extern int proc64_kill(unsigned int pid);
extern int proc64_shell_wait(unsigned int pid, unsigned int *code);
extern void proc64_shell_poll(void);
extern void sh64_switch_stack(void *top, void (*fn)(void));
extern void tcp64_server_pump(void);
extern void net64_poll(void);
extern void fat64_list(void);
extern int net64_arp_resolve(unsigned int ip);
extern int net64_ping(unsigned int dst, unsigned short seq);
extern void net64_poll(void);
extern int tcp64_http_get(unsigned int ip, unsigned short port, const char *path,
                          unsigned short *status, unsigned short *len);
extern unsigned long long timer64_ticks(void);

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

static int serial_getc_nb(void)
{
    if (inb(COM1 + 5) & 0x01) return inb(COM1);
    return -1;
}

static char line[160];
static int line_len;

static void sh_prompt(void)
{
    ser_puts("ajos64> ");
}

static void cmd_help(void)
{
    ser_puts(" commands: help ls cat FILE aj SCRIPT run BIN [&] ps kill PID wait [PID]\n");
    ser_puts("           mem ping http uptime echo clear\n");
    ser_puts(" ping/http target the slirp gateway 10.0.2.2\n");
}

static void cmd_mem(void)
{
    extern unsigned int pmm64_used(void);
    extern unsigned int pmm64_total(void);
    ser_puts(" pmm frames: ");
    ser_put_dec(pmm64_used());
    ser_puts("/");
    ser_put_dec(pmm64_total());
    ser_puts(" (4KB each, managed from 8MB)\n");
}

static void cmd_ping(void)
{
    int seq, ok = 0;
    if (net64_arp_resolve(0x0202000Au) != 0) {
        ser_puts(" arp: gateway resolve failed\n");
        return;
    }
    for (seq = 1; seq <= 4; seq++) {
        int r = net64_ping(0x0202000Au, (unsigned short)seq);
        if (r >= 0) {
            ok++;
            ser_puts(" seq ");
            ser_put_dec((u64)seq);
            ser_puts(": rtt ");
            ser_put_dec((u64)r * 10);
            ser_puts("ms\n");
        }
    }
    ser_puts(" ");
    ser_put_dec((u64)ok);
    ser_puts("/4 replies\n");
}

static void cmd_http(void)
{
    unsigned short code = 0, blen = 0;
    u32 target = *(volatile u32 *)0x74000u;   /* config sector (LSB-first) */
    if (!target) target = 0x0202000Au;
    {
        int st = tcp64_http_get(target, 8130, "/", &code, &blen);
        if (st > 0) {
            ser_puts(" HTTP ");
            ser_put_dec(code);
            ser_puts(", ");
            ser_put_dec(blen);
            ser_puts(" bytes\n");
        } else {
            ser_puts(" http get failed (err ");
            ser_put_dec((u64)(-st));
            ser_puts(") - is the test server running on the host?\n");
        }
    }
}

static void cmd_cat(const char *name)
{
    static char buf[2048];
    int n;
    if (!*name) { ser_puts(" usage: cat FILE\n"); return; }
    n = fat64_read_file(name, buf, sizeof(buf) - 1);
    if (n < 0) {
        ser_puts(" cat: not found\n");
        return;
    }
    buf[n] = 0;
    {
        int i;
        for (i = 0; i < n; i++) ser_putc(buf[i]);
        if (n && buf[n - 1] != '\n') ser_puts("\n");
    }
}

static void trim(char *s)
{
    char *e;
    while (*s == ' ') {
        char *p = s;
        while (*p) { p[0] = p[1]; p++; }
    }
    e = s;
    while (*e) e++;
    while (e > s && e[-1] == ' ') { e--; *e = 0; }
}

static int parse_u32(const char *s, u32 *out)
{
    u32 v = 0;
    if (!s || !*s) return 0;
    while (*s == ' ') s++;
    if (*s < '0' || *s > '9') return 0;
    while (*s >= '0' && *s <= '9') {
        v = v * 10u + (u32)(*s - '0');
        s++;
    }
    while (*s == ' ') s++;
    if (*s) return 0;
    *out = v;
    return 1;
}

static int starts(const char *s, const char *pfx)
{
    while (*pfx) {
        if (*s++ != *pfx++) return 0;
    }
    return 1;
}

static void cmd_run(char *arg)
{
    static unsigned char prog[4096];
    int bg = 0;
    int n, rc;
    char *end;
    trim(arg);
    end = arg;
    while (*end) end++;
    if (end > arg && end[-1] == '&') {
        bg = 1;
        end[-1] = 0;
        trim(arg);
    }
    if (!*arg) {
        ser_puts(" usage: run FILE [&]\n");
        return;
    }
    n = fat64_read_file(arg, prog, sizeof(prog));
    if (n <= 0) {
        ser_puts(" run: not found\n");
        return;
    }
    rc = proc64_spawn(prog, (unsigned int)n, arg, bg);
    if (rc < 0) {
        ser_puts(" run: failed\n");
        return;
    }
    if (bg) {
        ser_puts(" bg pid ");
        ser_put_dec((u64)rc);
        ser_puts("\n");
    } else {
        ser_puts(" exit ");
        ser_put_dec((u64)rc);
        ser_puts("\n");
    }
}

static void cmd_kill(char *arg)
{
    u32 pid = 0;
    trim(arg);
    if (!parse_u32(arg, &pid) || proc64_kill(pid) != 0) {
        ser_puts(" usage: kill PID\n");
        return;
    }
    ser_puts(" killed ");
    ser_put_dec(pid);
    ser_puts("\n");
}

static void cmd_wait(char *arg)
{
    u32 pid = 0;
    u32 code = 0;
    int id;
    trim(arg);
    if (*arg && !parse_u32(arg, &pid)) {
        ser_puts(" usage: wait [PID]\n");
        return;
    }
    id = proc64_shell_wait(pid, &code);
    if (id < 0) {
        ser_puts(" wait: no child\n");
        return;
    }
    ser_puts(" wait: reaped ");
    ser_put_dec((u64)id);
    ser_puts(" code ");
    ser_put_dec(code);
    ser_puts("\n");
}

static void exec_line(char *l)
{
    /* trim leading spaces */
    while (*l == ' ') l++;
    if (!*l) return;
    if (l[0] == 'h' && l[1] == 'e' && l[2] == 'l' && l[3] == 'p') { cmd_help(); return; }
    if (l[0] == 'l' && l[1] == 's') { fat64_list(); return; }
    if (l[0] == 'm' && l[1] == 'e' && l[2] == 'm') { cmd_mem(); return; }
    if (l[0] == 'p' && l[1] == 'i' && l[2] == 'n' && l[3] == 'g') { cmd_ping(); return; }
    if (l[0] == 'h' && l[1] == 't' && l[2] == 't' && l[3] == 'p') { cmd_http(); return; }
    if (l[0] == 'u' && l[1] == 'p') {
        ser_puts(" uptime: ");
        ser_put_dec(timer64_ticks() / 100);
        ser_puts("s\n");
        return;
    }
    if (l[0] == 'c' && l[1] == 'l' && l[2] == 'e' && l[3] == 'a' && l[4] == 'r') {
        int i;
        for (i = 0; i < 30; i++) ser_puts("\n");
        return;
    }
    if (l[0] == 'c' && l[1] == 'a' && l[2] == 't' && l[3] == ' ') { cmd_cat(l + 4); return; }
    if (l[0] == 'a' && l[1] == 'j' && l[2] == ' ') { ajlang64_run(l + 3); return; }
    if (starts(l, "run ") || (l[0] == 'r' && l[1] == 'u' && l[2] == 'n' && l[3] == 0)) {
        cmd_run(l + 3);
        return;
    }
    if (l[0] == 'p' && l[1] == 's' && (l[2] == 0 || l[2] == ' ')) { proc64_ps(); return; }
    if (starts(l, "kill")) { cmd_kill(l + 4); return; }
    if (starts(l, "wait")) { cmd_wait(l + 4); return; }
    if (l[0] == 'e' && l[1] == 'c' && l[2] == 'h' && l[3] == 'o') { ser_puts(l + 4); ser_puts("\n"); return; }
    ser_puts(" unknown: ");
    ser_puts(l);
    ser_puts(" (try help)\n");
}

static void shell_main(void)
{
    /* Disk program after ring-3 init. A scheduled foreground run returns
     * to this same loop; exit does not start a nested shell. */
    {
        static int autoran;
        if (!autoran) {
            char name[] = "HELLO64.UP";
            autoran = 1;
            ser_puts(" exec: running HELLO64.UP from disk\n");
            cmd_run(name);
        }
    }
    ser_puts("\n sh64 ready - type help\n");
    sh_prompt();
    for (;;) {
        int c = serial_getc_nb();
        if (c >= 0) {
            if (c == '\r' || c == '\n') {
                ser_puts("\n");
                line[line_len] = 0;
                exec_line(line);
                line_len = 0;
                sh_prompt();
            } else if (c == 0x7F || c == 0x08) {
                if (line_len > 0) {
                    line_len--;
                    ser_puts("\b \b");
                }
            } else if (c >= 32 && c < 127 && line_len < (int)sizeof(line) - 1) {
                line[line_len++] = (char)c;
                ser_putc((char)c);
            }
        } else {
            net64_poll();
            tcp64_server_pump();
            proc64_shell_poll();
            __asm__ __volatile__("sti; hlt");
        }
    }
}

void sh64_run(void)
{
    static u8 shell_stack[16384] __attribute__((aligned(16)));
    sh64_switch_stack(shell_stack + sizeof(shell_stack), shell_main);
}
