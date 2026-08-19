#include "kernel.h"
#include "ajlang.h"
#include "arp.h"
#include "ata.h"
#include "auth.h"
#include "debug_agent.h"
#include "dhcpd.h"
#include "disk.h"
#include "dnsd.h"
#include "e1000.h"
#include "fat.h"
#include "http.h"
#include "keyboard.h"
#include "minoca/mm.h"
#include "net.h" // eth_addr_t defined here
#include "netdev.h"
#include "pbuf.h"
#include "ramfs.h"
#include "ssh.h"
#include "user.h"
#include "vfs.h"
#include "video.h"
#include <stddef.h>
#include <stdint.h>

#define VIDEO_MEMORY 0xB8000
#define VGA_WIDTH 80
#define VGA_HEIGHT 25
#define VGA_GREEN 2
#define VGA_BLACK 0

// Reserve the last VGA row as a status bar.
#define STATUS_ROW (VGA_HEIGHT - 1)
#define TEXT_ROWS (VGA_HEIGHT - 1)

// Forward declarations used early in this file
void terminal_update_hw_cursor(void);
int input_getkey(void);
static void ps2_keyboard_init(void);
static void poweroff_now(void);

// Networking forward declarations (defined in net.h/arp.h)
void dns_lookup(const char *name);
void dns_set_server(uint32_t ip);
uint32_t arp_get_ajos_ip(void);
uint32_t ip4_get_netmask(void);
uint32_t ip4_get_gateway(void);
int arp_get_mac_for_ip(uint32_t ip, eth_addr_t *out_mac);
int arp_query(uint32_t ip);

// Datetime and other forward declarations are now in headers or handled by
// modules

// Utility functions (kstrcmp_n, skip_spaces, kstreq) are defined later in this
// file or in modules.

// System hostname storage
static char system_hostname[64] = "ajos";

static void cmd_uname(const char *args)
{
  const char *s = args;
  while (*s && (unsigned char)*s <= ' ')
    s++;

  if (*s == '\0')
  {
    // Default: show OS name
    log_writestring("AJOS\n");
  }
  else if (kstrcmp_n(s, "-a", 2) == 0)
  {
    // Show all information
    log_writestring("AJOS ");
    log_writestring("AJOS ");
    log_writestring("1.0.1 ");
    log_writestring("i386\n");
  }
  else if (kstrcmp_n(s, "-s", 2) == 0)
  {
    // Show OS name
    log_writestring("AJOS\n");
  }
  else if (kstrcmp_n(s, "-r", 2) == 0)
  {
    // Show release/version
    log_writestring("1.0.1\n");
  }
  else if (kstrcmp_n(s, "-m", 2) == 0)
  {
    // Show machine architecture
    log_writestring("i386\n");
  }
  else
  {
    log_writestring("Usage: uname [-a|-s|-r|-m]\n");
  }
}

// Current logged-in user
static char current_username[32] = {0};

static void login_prompt(void);

static void cmd_whoami(const char *args)
{
  (void)args;
  if (current_username[0] != '\0')
  {
    log_writestring(current_username);
    log_putchar('\n');
  }
  else
  {
    log_writestring("root\n");
  }
}

static void cmd_hostname(const char *args)
{
  const char *s = args;
  while (*s && (unsigned char)*s <= ' ')
    s++;

  if (*s == '\0')
  {
    // Show current hostname
    log_writestring(system_hostname);
    log_putchar('\n');
  }
  else
  {
    // Set new hostname
    int i = 0;
    while (s[i] && (unsigned char)s[i] > ' ' &&
           i < (int)sizeof(system_hostname) - 1)
    {
      system_hostname[i] = s[i];
      i++;
    }
    system_hostname[i] = '\0';
    log_writestring("Hostname set to: ");
    log_writestring(system_hostname);
    log_putchar('\n');
  }
}

// Paging moved to kernel/mm/paging.c
// Keep is_user_addr for sys_write validation
static int is_user_addr(uint32_t addr)
{
  // run3 program + stack region (must match cmd_run3 load/stack)
  return (addr >= 0x00300000u && addr < 0x00340000u);
}

#define DISK_CACHE_BASE ((uint8_t *)0x51000u)
#define DISK_BOUNCE_PHYS 0x7F000u

static void cmd_traceroute(const char *args);
static void cmd_nc(const char *args);
static void cmd_route(void);
static void cmd_showkeys(void);

// PCI functionality moved to pci.c
// E1000 driver and PCI listing moved to e1000.c and pci.c respectively.
// Heap allocator (kmalloc/kfree) moved to kernel/mm/heap.c

size_t terminal_row = 0;
size_t terminal_column = 0;
static uint8_t terminal_color = VGA_GREEN | (VGA_BLACK << 4);

// ---------------------------
// BIOS-backed sector reads (via real-mode thunk)
// ---------------------------

extern uint32_t bios_int13_read_chs(uint32_t drive, uint32_t cyl, uint32_t head,
                                    uint32_t sect, uint32_t seg, uint32_t off);
extern uint32_t bios_int13_write_chs(uint32_t drive, uint32_t cyl,
                                     uint32_t head, uint32_t sect, uint32_t seg,
                                     uint32_t off);
void mem_set(uint8_t *dst, uint8_t v, uint32_t n);

#define FLOPPY_SPT 18u
#define FLOPPY_HEADS 2u
#define SECTOR_SIZE 512u

// Verbose disk logging flag (set to 1 for debugging)
static int verbose_disk_log = 0;

static // BIOS-based disk functions moved to disk.c

    // Forward decls used by early helpers
    void
    terminal_putchar(char c);

// Interrupt/IDT entrypoints (defined in `asm/isr.asm`)
extern void idt_load(void *idt_ptr);

#define DECL_ISR(n) extern void isr##n(void)
DECL_ISR(0);
DECL_ISR(1);
DECL_ISR(2);
DECL_ISR(3);
DECL_ISR(4);
DECL_ISR(5);
DECL_ISR(6);
DECL_ISR(7);
DECL_ISR(8);
DECL_ISR(9);
DECL_ISR(10);
DECL_ISR(11);
DECL_ISR(12);
DECL_ISR(13);
DECL_ISR(14);
DECL_ISR(15);
DECL_ISR(16);
DECL_ISR(17);
DECL_ISR(18);
DECL_ISR(19);
DECL_ISR(20);
DECL_ISR(21);
DECL_ISR(22);
DECL_ISR(23);
DECL_ISR(24);
DECL_ISR(25);
DECL_ISR(26);
DECL_ISR(27);
DECL_ISR(28);
DECL_ISR(29);
DECL_ISR(30);
DECL_ISR(31);
DECL_ISR(32);
DECL_ISR(33);
DECL_ISR(34);
DECL_ISR(35);
DECL_ISR(36);
DECL_ISR(37);
DECL_ISR(38);
DECL_ISR(39);
DECL_ISR(40);
DECL_ISR(41);
DECL_ISR(42);
DECL_ISR(43);
DECL_ISR(44);
DECL_ISR(45);
DECL_ISR(46);
DECL_ISR(47);
DECL_ISR(128);
#undef DECL_ISR

// Basic COM1 (serial) output so `-nographic` runs show kernel logs.
#define COM1_PORT 0x3F8

void mem_copy(void *dest, const void *src, size_t n)
{
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (size_t i = 0; i < n; i++)
    d[i] = s[i];
}
void mem_set(uint8_t *dst, uint8_t v, uint32_t n)
{
  for (uint32_t i = 0; i < n; i++)
    dst[i] = v;
}

// memset wrapper for OpenSSH compatibility
void *memset(void *s, int c, size_t n)
{
  mem_set((uint8_t *)s, (uint8_t)c, (uint32_t)n);
  return s;
}

// memcpy wrapper for OpenSSH compatibility
void *memcpy(void *dest, const void *src, size_t n)
{
  mem_copy(dest, src, n);
  return dest;
}

// memcmp wrapper for OpenSSH compatibility
int memcmp(const void *s1, const void *s2, size_t n)
{
  const uint8_t *p1 = (const uint8_t *)s1;
  const uint8_t *p2 = (const uint8_t *)s2;
  for (size_t i = 0; i < n; i++)
  {
    if (p1[i] < p2[i])
      return -1;
    if (p1[i] > p2[i])
      return 1;
  }
    return 0;
  }

// memchr wrapper for OpenSSH compatibility
void *memchr(const void *s, int c, size_t n)
{
  const uint8_t *p = (const uint8_t *)s;
  for (size_t i = 0; i < n; i++)
  {
    if (p[i] == (uint8_t)c)
    {
      return (void *)(p + i);
    }
  }
  return NULL;
}

// strlen wrapper for OpenSSH compatibility
size_t strlen(const char *s)
{
  size_t len = 0;
  while (s[len] != '\0')
  {
    len++;
  }
  return len;
}

// memmove wrapper for OpenSSH compatibility
void *memmove(void *dest, const void *src, size_t n)
{
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  if (d < s)
  {
    // Copy forward
    for (size_t i = 0; i < n; i++)
    {
      d[i] = s[i];
    }
  }
  else if (d > s)
  {
    // Copy backward to handle overlapping regions
    for (size_t i = n; i > 0; i--)
    {
      d[i - 1] = s[i - 1];
    }
  }
  return dest;
}

// Interrupt handlers array (defined before register_interrupt_handler)
isr_t interrupt_handlers[256];

void register_interrupt_handler(uint8_t n, isr_t handler)
{
  interrupt_handlers[n] = handler;
}

void sleep_ms(uint32_t ms)
{
  // Simple busy-wait sleep (can be improved with PIT)
  // For now, just a placeholder
  volatile uint32_t count = ms * 1000;
  while (count-- > 0)
  {
    __asm__ volatile("pause");
  }
}

static void serial_initialize(void)
{
  // Match Linux kernel early_serial_init sequence (early_serial_console.c)
  // Linux does: LCR -> IER -> FCR -> MCR -> DLAB -> divisor -> clear DLAB
  outb(COM1_PORT + 3, 0x03); // LCR: 8n1 (8 bits, no parity, one stop bit)
  outb(COM1_PORT + 1, 0x00); // IER: no interrupt
  outb(COM1_PORT + 2, 0x00); // FCR: no fifo (Linux sets to 0, not 0xC7!)
  outb(COM1_PORT + 4, 0x03); // MCR: DTR + RTS

  // Now set baud rate (divisor = 115200 / 115200 = 1)
  unsigned char c = inb(COM1_PORT + 3);
  outb(COM1_PORT + 3, c | 0x80);  // Enable DLAB
  outb(COM1_PORT + 0, 0x01);      // Divisor lo = 1
  outb(COM1_PORT + 1, 0x00);      // Divisor hi = 0
  outb(COM1_PORT + 3, c & ~0x80); // Clear DLAB
}

static int serial_is_transmit_empty(void)
{
  return (inb(COM1_PORT + 5) & 0x20) != 0;
}

static int serial_received(void) { return (inb(COM1_PORT + 5) & 0x01) != 0; }

static void serial_putchar(char c)
{
  // Prefer CRLF on serial terminals.
  if (c == '\n')
  {
    serial_putchar('\r');
  }
  /* Wait for THRE; bound is large so bursty debug (JSON, ping traces) does not
   * drop characters — short timeouts caused truncated lines on COM1 under load. */
  uint32_t timeout = 50000000u;
  while (!serial_is_transmit_empty() && timeout > 0u)
  {
    timeout--;
    __asm__ volatile("pause");
  }
  if (timeout == 0u)
    return;
  outb(COM1_PORT, (uint8_t)c);
}

/* Exception path helpers: serial-only, no log subsystem usage. */
static void serial_write_cstr(const char *s)
{
  if (!s)
    return;
  while (*s)
    serial_putchar(*s++);
}

static void serial_write_u32_dec(uint32_t v)
{
  char buf[11];
  int idx = 0;
  if (v == 0)
  {
    serial_putchar('0');
    return;
  }
  while (v > 0 && idx < (int)sizeof(buf))
  {
    buf[idx++] = (char)('0' + (v % 10));
    v /= 10;
  }
  while (idx > 0)
    serial_putchar(buf[--idx]);
}

static void serial_write_hex32_local(uint32_t v)
{
  serial_putchar('0');
  serial_putchar('x');
  for (int i = 7; i >= 0; i--)
  {
    uint8_t nibble = (uint8_t)((v >> (i * 4)) & 0xF);
    serial_putchar((char)(nibble < 10 ? '0' + nibble : 'A' + (nibble - 10)));
  }
}

static char serial_getchar(void)
{
  while (!serial_received())
  {
  }
  return (char)inb(COM1_PORT);
}

void serial_writestring(const char *data)
{
  for (size_t i = 0; data[i] != '\0'; i++)
  {
    serial_putchar(data[i]);
  }
}

static void serial_erase_chars(size_t n)
{
  // Erase characters using backspace-space-backspace (works in many terminals).
  for (size_t i = 0; i < n; i++)
  {
    serial_putchar('\b');
    serial_putchar(' ');
    serial_putchar('\b');
  }
}

static void serial_clear(void)
{
  // Keep it portable: just push the prompt off-screen.
  for (size_t i = 0; i < 40; i++)
  {
    serial_putchar('\n');
  }
}

// Shell redirection / pipe state
static char shell_redirect_buf[16384];
static size_t shell_redirect_ptr = 0;
static int shell_redirect_active = 0;

/* GUI terminal capture (independent of file redirect / | more). */
static char *shell_gui_sink_buf = 0;
static size_t shell_gui_sink_cap = 0;
static size_t shell_gui_sink_len = 0;

void shell_gui_sink_begin(char *buf, size_t cap)
{
  shell_gui_sink_buf = buf;
  shell_gui_sink_cap = cap;
  shell_gui_sink_len = 0;
  if (buf && cap)
    buf[0] = '\0';
}

size_t shell_gui_sink_end(void)
{
  size_t n = shell_gui_sink_len;
  if (shell_gui_sink_buf && shell_gui_sink_cap && n < shell_gui_sink_cap)
    shell_gui_sink_buf[n] = '\0';
  shell_gui_sink_buf = 0;
  shell_gui_sink_cap = 0;
  shell_gui_sink_len = 0;
  return n;
}

static void flush_syslog(void);
static int shell_pipe_more = 0;

// HTTPD service state
static struct tcp_pcb *httpd_listen_pcb = 0;
static uint16_t httpd_service_port = 80;
static int httpd_service_active = 0;
static int background_logs_disabled = 0;
static uint32_t httpd_service_pid = 0;

void background_logs_set(int disabled) { background_logs_disabled = disabled; }

static void httpd_service_tick(void);

// Syslog globals
#define SYSLOG_BUF_SIZE 16384
static char syslog_buffer[SYSLOG_BUF_SIZE];
static uint32_t syslog_pos = 0;
static int syslog_enabled =
    0; /* off by default; use "syslog start" to enable */
static int syslog_flushing = 0;
static int syslog_flush_fail_count = 0;
/* When syslog is enabled, also echo log output to the console (default off:
 * logs go to /var/log/ajos only). Toggle with "syslog console". */
static int syslog_console_echo = 0;
/* Per-line classifier state for the syslog capture in log_putchar. */
static int syslog_line_new = 1;
static int syslog_line_tagged = 0;

// Timer globals
#define PIT_HZ 100u
volatile uint32_t pit_ticks = 0;

// System call numbers
#define SYSCALL_WRITE 1
#define SYSCALL_TICKS 2
#define SYSCALL_SLEEP 3
#define SYSCALL_GETKEY 4
#define SYSCALL_EXIT 5
#define SYSCALL_GETPID 6
#define SYSCALL_GETPPID 7
#define SYSCALL_SOCKET 8
#define SYSCALL_BIND 9
#define SYSCALL_LISTEN 10
#define SYSCALL_ACCEPT 11
#define SYSCALL_CONNECT 12
#define SYSCALL_SEND 13
#define SYSCALL_RECV 14
#define SYSCALL_CLOSE 15

// User mode globals
volatile int user_mode_exit_flag = 0;
uint32_t current_user_pid = 0;
volatile uint32_t user_mode_kernel_esp = 0;
volatile uint32_t user_mode_kernel_eip = 0;

// External declarations (forward declarations for types defined later in this
// file)
static void scheduler_tick(void);

// Forward declarations for types defined later in this file
// These structs are defined later in the file but used in syscall_handler
// We'll use incomplete types here and the full definitions later
#define MAX_PROCESSES 32
#define PROCESS_NAME_LEN 32
#define PROC_STATE_DEAD 0
#define PROC_STATE_RUNNING 1
#define PROC_STATE_SLEEPING 2
#define PROC_STATE_WAITING 3
#define PROC_STATE_ZOMBIE 4
struct process
{
  uint32_t pid;
  uint32_t ppid;
  uint32_t state;
  uint32_t in_use;
  char name[PROCESS_NAME_LEN];
  uint32_t start_ticks;
  uint32_t cpu_ticks;
  uint32_t page_dir;
  int is_background;
  uint32_t esp;          // Current stack pointer
  uint32_t kernel_stack; // Base of kernel stack
};

// Extern for assembly context switch
extern void switch_to(uint32_t *old_esp, uint32_t new_esp);
static void schedule(void);
struct tcp_pcb; // Forward declaration, defined in tcp.c

// Socket file descriptor management
#define MAX_SOCKETS 16
#define SOCKET_FD_BASE 3 // 0=stdin, 1=stdout, 2=stderr, 3+ are sockets

struct socket_fd
{
  uint8_t in_use;
  struct tcp_pcb *pcb; // NULL for non-TCP sockets (future)
  uint32_t pid;        // Owner process
};

static struct socket_fd socket_table[MAX_SOCKETS];
static uint32_t next_socket_fd = SOCKET_FD_BASE;

static struct process *process_get(uint32_t pid);
static uint32_t process_alloc(const char *name);
static void process_free(uint32_t pid);

int socket_alloc_fd(struct tcp_pcb *pcb, uint32_t pid)
{
  for (int i = 0; i < MAX_SOCKETS; i++)
  {
    if (!socket_table[i].in_use)
    {
      socket_table[i].in_use = 1;
      socket_table[i].pcb = pcb;
      socket_table[i].pid = pid;
      return SOCKET_FD_BASE + i;
    }
  }
  return -1; // No free slots
}

struct socket_fd *socket_get_fd(int fd)
{
  if (fd < SOCKET_FD_BASE || fd >= SOCKET_FD_BASE + MAX_SOCKETS)
  {
    return NULL;
  }
  int idx = fd - SOCKET_FD_BASE;
  if (!socket_table[idx].in_use)
  {
    return NULL;
  }
  return &socket_table[idx];
}

void socket_free_fd(int fd)
{
  struct socket_fd *sock = socket_get_fd(fd);
  if (sock)
  {
    sock->in_use = 0;
    sock->pcb = NULL;
    sock->pid = 0;
  }
}
extern int katoi(const char *s);
extern void socket_init(void);
extern void tsc_calibrate(void);
extern void e1000_print_info(void);
extern void pci_list_devices(void);
extern int a20_is_enabled(void);
extern void editor_open(const char *filename);
extern uint32_t read_cr2(void);
extern void pit_init(void);

// Keyboard buffer (interrupt-driven)
#define KBD_BUF_SIZE 256
volatile uint8_t kbd_buf[KBD_BUF_SIZE];
volatile uint8_t kbd_head = 0;
volatile uint8_t kbd_tail = 0;

void kbd_push_scancode(uint8_t sc)
{
  uint8_t next = (uint8_t)(kbd_head + 1);
  if (next == kbd_tail)
  {
    // Buffer full: drop scancode.
    return;
  }
  kbd_buf[kbd_head] = sc;
  kbd_head = next;
}

int kbd_pop_scancode(uint8_t *out)
{
  if (kbd_tail == kbd_head)
  {
    return 0;
  }
  *out = kbd_buf[kbd_tail];
  kbd_tail = (uint8_t)(kbd_tail + 1);
  return 1;
}

int kbd_has_scancode(void) { return kbd_tail != kbd_head; }

int kbd_has_data(void) { return kbd_tail != kbd_head; }
extern void kmemcpy(void *dest, const void *src, uint32_t n);
extern uint64_t get_time_us(void);
extern void sleep_ms(uint32_t ms);
extern int kstreq(const char *a, const char *b);
extern size_t kstrlen(const char *s);
extern void kstrncpy(char *dest, const char *src, size_t n);

extern int parse_u32(const char *s, uint32_t *out);

// Stub implementations for e1000 commands (defined later or in e1000.c)
static void cmd_e1000tx(void) { log_writestring("e1000tx: not implemented\n"); }
static void cmd_e1000rx(void) { log_writestring("e1000rx: not implemented\n"); }
static void cmd_e1000icr(void)
{
  log_writestring("e1000icr: not implemented\n");
}
static void cmd_e1000watch(void)
{
  log_writestring("e1000watch: not implemented\n");
}
static void cmd_e1000regs(void)
{
  log_writestring("e1000regs: not implemented\n");
}
static void cmd_e1000rxstat(void)
{
  log_writestring("e1000rxstat: not implemented\n");
}
static void cmd_e1000reinit(void)
{
  log_writestring("e1000reinit: not implemented\n");
}
static void cmd_e1000loop(const char *args)
{
  (void)args;
  log_writestring("e1000loop: not implemented\n");
}

// Missing utility functions
void log_write_hex32(uint32_t v)
{
  log_writestring("0x");
  for (int shift = 28; shift >= 0; shift -= 4)
  {
    /* Index the literal directly so a corrupted .data pointer cannot break hex
     * dumps (seen under QEMU as #PF at log_write_hex32 with CR2 ~0xffffea6c). */
    log_putchar("0123456789ABCDEF"[(v >> (uint32_t)shift) & 0xFu]);
  }
}

void log_write_hex8(uint8_t v)
{
  log_putchar("0123456789ABCDEF"[(v >> 4) & 0xF]);
  log_putchar("0123456789ABCDEF"[v & 0xF]);
}

void log_write_u32(uint32_t v)
{
  char buf[11];
  size_t i = 0;
  if (v == 0)
  {
    log_putchar('0');
    return;
  }
  while (v > 0 && i < sizeof(buf))
  {
    buf[i++] = (char)('0' + (v % 10u));
    v /= 10u;
  }
  while (i > 0)
  {
    log_putchar(buf[--i]);
  }
}

int kstrcmp_n(const char *a, const char *b, size_t n)
{
  for (size_t i = 0; i < n; i++)
  {
    if (a[i] != b[i])
    {
      return (int)((unsigned char)a[i] - (unsigned char)b[i]);
    }
    if (a[i] == '\0')
    {
      return 0;
    }
  }
  return 0;
}

// Missing utility functions
void kstrncpy(char *dest, const char *src, size_t n)
{
  size_t i;
  for (i = 0; i < n - 1 && src[i] != '\0'; i++)
    dest[i] = src[i];
  dest[i] = '\0';
}

int katoi(const char *s)
{
  int res = 0;
  while (*s >= '0' && *s <= '9')
  {
    res = res * 10 + (*s - '0');
    s++;
  }
  return res;
}

int a20_is_enabled(void)
{
  // Test whether address bit 20 is active by checking aliasing between
  // low memory and +1MiB. Use a safe scratch location.
  volatile uint32_t *low = (volatile uint32_t *)0x500;
  volatile uint32_t *high = (volatile uint32_t *)0x100500;
  uint32_t orig_low = *low;
  uint32_t orig_high = *high;
  *low = 0x12345678;
  if (*high == 0x12345678)
  {
    *low = orig_low;
    *high = orig_high;
    return 0; // A20 disabled (aliasing)
  }
  *low = orig_low;
  *high = orig_high;
  return 1; // A20 enabled
}

void pci_list_devices(void)
{
  extern uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func,
                                 uint8_t offset);
  log_writestring("PCI devices:\n");
  for (uint16_t bus = 0; bus < 256; bus++)
  {
    for (uint8_t dev = 0; dev < 32; dev++)
    {
      uint32_t id = pci_cfg_read32((uint8_t)bus, dev, 0, 0);
      if (id != 0xFFFFFFFF)
      {
        log_writestring("  ");
        log_write_hex32(bus);
        log_putchar(':');
        log_write_hex8(dev);
        log_writestring(": ");
        log_write_hex32(id);
  log_putchar('\n');
}
    }
  }
}

void e1000_print_info(void)
{
  if (e1000_device_count == 0)
  {
    log_writestring("e1000: no devices found\n");
    return;
  }
  log_writestring("e1000: ");
  log_write_u32((uint32_t)e1000_device_count);
  log_writestring(" device(s) found\n");
}

void tsc_calibrate(void)
{
  // Stub - TSC calibration would go here
  // For now, just a placeholder
}

uint64_t get_time_us(void)
{
  // Stub - return time in microseconds
  // For now, return ticks * approximate microseconds per tick
  extern volatile uint32_t pit_ticks;
  if (PIT_HZ == 0)
    return 0;
  return ((uint64_t)pit_ticks * 1000000ULL) / (uint64_t)PIT_HZ;
}

void socket_init(void)
{
  for (int i = 0; i < MAX_SOCKETS; i++)
  {
    socket_table[i].in_use = 0;
    socket_table[i].pcb = NULL;
    socket_table[i].pid = 0;
  }
  next_socket_fd = SOCKET_FD_BASE;
  extern void tcp_init(void);
  tcp_init();
}

uint32_t read_cr2(void)
{
  uint32_t v;
  __asm__ volatile("mov %%cr2, %0" : "=r"(v));
  return v;
}

void pit_init(void)
{
  // Program PIT channel 0 in mode 3 (square wave) with a chosen frequency.
  // Input clock: 1193182 Hz
  const uint32_t divisor = 1193182u / PIT_HZ;
  outb(0x43, 0x36);
  outb(0x40, (uint8_t)(divisor & 0xFF));
  outb(0x40, (uint8_t)((divisor >> 8) & 0xFF));
}

// 64-bit division/modulo runtime functions (compiler expects these)
uint64_t __udivdi3(uint64_t num, uint64_t den)
{
  uint64_t quot = 0;
  uint64_t rem = 0;
  for (int i = 63; i >= 0; i--)
  {
    rem = (rem << 1) | ((num >> (uint64_t)i) & 1);
    if (rem >= den)
    {
      rem -= den;
      quot |= (1ULL << (uint64_t)i);
    }
  }
  return quot;
}

uint64_t __umoddi3(uint64_t num, uint64_t den)
{
  uint64_t rem = 0;
  for (int i = 63; i >= 0; i--)
  {
    rem = (rem << 1) | ((num >> (uint64_t)i) & 1);
    if (rem >= den)
    {
      rem -= den;
    }
  }
  return rem;
}

/* Signed 64-bit div/mod for ajlang and other code */
int64_t __divdi3(int64_t num, int64_t den)
{
  int neg = 0;
  if (num < 0)
  {
    neg = 1;
    num = -num;
  }
  if (den < 0)
  {
    neg ^= 1;
    den = -den;
  }
  uint64_t q = __udivdi3((uint64_t)num, (uint64_t)den);
  return neg ? -(int64_t)q : (int64_t)q;
}

int64_t __moddi3(int64_t num, int64_t den)
{
  int neg = 0;
  if (num < 0)
  {
    neg = 1;
    num = -num;
  }
  if (den < 0)
    den = -den;
  uint64_t r = __umoddi3((uint64_t)num, (uint64_t)den);
  return neg ? -(int64_t)r : (int64_t)r;
}

size_t kstrlen(const char *s)
{
  size_t len = 0;
  while (s[len] != '\0')
  {
    len++;
  }
  return len;
}

const char *skip_spaces(const char *s)
{
  while (*s && (unsigned char)*s <= ' ')
  {
    s++;
  }
  return s;
}

int kstreq(const char *a, const char *b)
{
  while (*a && *b && *a == *b)
  {
    a++;
    b++;
  }
  return *a == '\0' && *b == '\0';
}

int parse_u32(const char *s, uint32_t *out)
{
  if (!s || !out)
    return 0;
  s = skip_spaces(s);
  if (*s == '\0')
    return 0;
  uint32_t v = 0;
  while (*s >= '0' && *s <= '9')
  {
    uint32_t d = (uint32_t)(*s - '0');
    if (v > (0xFFFFFFFFu / 10u))
      return 0; // Overflow
    v = v * 10u + d;
    s++;
  }
  if (*s != '\0' && (unsigned char)*s > ' ')
    return 0; // Invalid char
  *out = v;
  return 1;
}

void kmemcpy(void *dest, const void *src, uint32_t n)
{
  uint8_t *d = (uint8_t *)dest;
  const uint8_t *s = (const uint8_t *)src;
  for (uint32_t i = 0; i < n; i++)
  {
    d[i] = s[i];
  }
}

static void flush_syslog(void);

void log_putchar(char c)
{
  if (shell_gui_sink_buf && shell_gui_sink_cap)
  {
    if (shell_gui_sink_len + 1 < shell_gui_sink_cap)
    {
      shell_gui_sink_buf[shell_gui_sink_len++] = c;
      shell_gui_sink_buf[shell_gui_sink_len] = '\0';
    }
    return;
  }

  if (shell_redirect_active)
  {
    if (shell_redirect_ptr + 1 < sizeof(shell_redirect_buf))
    {
      shell_redirect_buf[shell_redirect_ptr++] = c;
    }
    return;
  }

  /* SSH shell: send command output to the remote PTY only (not VGA/serial).
   * Never mirror while handling inbound TCP/IP — that re-enters the SSH path
   * and spams the session with [TCP] logs (and can wedge the connection). */
  if (ssh_shell_log_sink_active() && ssh_log_mirror_depth == 0u &&
      ssh_suppress_log_mirror_to_session == 0u)
  {
    ssh_log_mirror_depth++;
    ssh_shell_mirror_putchar(c);
    ssh_log_mirror_depth--;
    return;
  }

  /* Syslog capture: when enabled, subsystem log lines — recognized by their
   * "[TAG] ..." prefix ([SSH], [TCP], [AUTH], ...) — are buffered for
   * /var/log/ajos and hidden from the console. Prompts and command output
   * (no tag) still print normally. */
  if (syslog_enabled && !syslog_flushing)
  {
    if (syslog_line_new && c == '[')
      syslog_line_tagged = 1;
    if (syslog_line_tagged)
    {
      if (syslog_pos < SYSLOG_BUF_SIZE)
      {
        syslog_buffer[syslog_pos++] = c;
      }
      if (syslog_pos > SYSLOG_BUF_SIZE - 512)
      {
        flush_syslog();
      }
      if (c == '\n')
      {
        syslog_line_new = 1;
        syslog_line_tagged = 0;
      }
      if (syslog_console_echo && c != '\r')
      {
        serial_putchar(c);
      }
      return;
    }
    if (c == '\n')
      syslog_line_new = 1;
    else if (c != '\r')
      syslog_line_new = 0;
    /* Untagged output falls through to the console below. */
  }

  // In serial-only builds (used by `make run-console`), avoid writing to VGA.
  // QEMU's -nographic multiplexes VGA text to stdio, which would otherwise
  // duplicate/garble output.
#ifndef AJOS_SERIAL_ONLY
  terminal_putchar(c);
#endif
  // Avoid double-CR when printing CRLF text files.
  if (c != '\r')
  {
    serial_putchar(c);
  }
}

void log_writestring(const char *data)
{
  for (size_t i = 0; data[i] != '\0'; i++)
  {
    log_putchar(data[i]);
  }
}

void shell_putchar(char c) { log_putchar(c); }

void shell_writestring(const char *s) { log_writestring(s); }

// ---------------------------
// VGA output + cursor control
// ---------------------------

#define VGA_CMD_PORT 0x3D4
#define VGA_DATA_PORT 0x3D5

// 1370 was terminal_update_hw_cursor, removed to use the global one below

// ---------------------------
// Interrupts: IDT + PIC + IRQ1
// ---------------------------

struct __attribute__((packed)) idt_entry
{
  uint16_t base_lo;
  uint16_t sel;
  uint8_t always0;
  uint8_t flags;
  uint16_t base_hi;
};

struct __attribute__((packed)) idt_ptr
{
  uint16_t limit;
  uint32_t base;
};

static struct idt_entry idt[256];
struct idt_ptr idtp;

static void idt_set_gate(uint8_t num, uint32_t base, uint16_t sel,
                         uint8_t flags)
{
  idt[num].base_lo = (uint16_t)(base & 0xFFFF);
  idt[num].base_hi = (uint16_t)((base >> 16) & 0xFFFF);
  idt[num].sel = sel;
  idt[num].always0 = 0;
  idt[num].flags = flags;
}

static void pic_remap_and_mask(void)
{
  // Remap PIC: IRQs 0..7 -> 0x20..0x27, IRQs 8..15 -> 0x28..0x2F
  const uint8_t ICW1_INIT = 0x10;
  const uint8_t ICW1_ICW4 = 0x01;
  const uint8_t ICW4_8086 = 0x01;

  outb(0x20, ICW1_INIT | ICW1_ICW4);
  outb(0xA0, ICW1_INIT | ICW1_ICW4);
  outb(0x21, 0x20);
  outb(0xA1, 0x28);
  outb(0x21, 0x04);
  outb(0xA1, 0x02);
  outb(0x21, ICW4_8086);
  outb(0xA1, ICW4_8086);

  // Mask everything except IRQ0 (timer) and IRQ1 (keyboard) on master; mask all
  // on slave.
  outb(0x21, 0xFC);
  outb(0xA1, 0xFF);
}

void pic_unmask_irq(uint8_t irq)
{
  if (irq < 8)
  {
    uint8_t mask = inb(0x21);
    mask &= (uint8_t)(~(1u << irq));
    outb(0x21, mask);
    // log_writestring("PIC1 mask="); log_write_hex32(mask); log_putchar('\n');
  }
  else if (irq < 16)
  {
    // Unmask on slave
    uint8_t maskval = inb(0xA1);
    maskval &= (uint8_t)(~(1u << (irq - 8)));
    outb(0xA1, maskval);

    // Also unmask cascade (IRQ 2) on master
    uint8_t master_mask = inb(0x21);
    master_mask &= (uint8_t)(~(1u << 2));
    outb(0x21, master_mask);

    log_writestring("[PIC] unmasked irq=");
    log_write_u32(irq);
    log_putchar('\n');
  }
}

void pic_mask_irq(uint8_t irq)
{
  if (irq < 8)
  {
    uint8_t mask = inb(0x21);
    mask |= (uint8_t)(1u << irq);
    outb(0x21, mask);
  }
  else if (irq < 16)
  {
    uint8_t maskval = inb(0xA1);
    maskval |= (uint8_t)(1u << (irq - 8));
    outb(0xA1, maskval);
  }
}

static void timer_handler(struct regs *r)
{
  (void)r;
  pit_ticks++;

  /* Must run always: SSH/HTTP retransmits and in-flight TCP state depend on it.
   * Placed before the early return that skips scheduler/RX polling during boot. */
  extern void tcp_tick(uint32_t now_ticks);
  tcp_tick(pit_ticks);

  /*
   * Without this, nothing drains the e1000 RX ring while the shell is idle.
   * SSH (and other TCP) then stalls until a command like `ping` busy-polls
   * net_pump_rx. IRQ/NAPI alone is not always enough in QEMU.
   */
  static uint32_t rx_poll_counter = 0;
  if (netdev_napi_any_scheduled())
  {
    netdev_napi_poll(32);
  }
  else
  {
    rx_poll_counter++;
    if (rx_poll_counter >= 2)
    {
      rx_poll_counter = 0;
      netdev_napi_poll(16);
    }
  }

  /* Skip heavy calls until we reach login prompt */
  return;

  // Scheduler tick (Roadmap v1.0.1 - Process Management)
  scheduler_tick();

  // (tcp_tick moved above early return)

  // Fallback RX polling: if E1000 RX interrupts are occasionally missed in
  // emulation, TCP/DNS can stall. Poll a few packets per tick to keep the
  // stack moving even without NIC IRQs.
  // Only poll every 10 ticks (100ms at 100Hz) to reduce CPU usage
  static uint32_t poll_counter = 0;
  poll_counter++;
  // If the NIC IRQ handler scheduled NAPI-style polling, drain RX promptly.
  if (netdev_napi_any_scheduled())
  {
    netdev_napi_poll(32);
  }
  else if (poll_counter >= 10)
  {
    poll_counter = 0;
    // Best-effort safety net even without IRQs: drain a small burst.
    netdev_napi_poll(4);
  }
}

static void keyboard_handler(struct regs *r)
{
  (void)r;
  uint8_t sc = inb(0x60);
  kbd_push_scancode(sc);
}

// Syscall implementations
uint32_t sys_write(uint32_t ptr, uint32_t len, int from_user)
{
  const uint8_t *p = (const uint8_t *)ptr;
  // If the syscall came from ring3, require the pointer range to be inside the
  // user window. (Basic range validation for now; later we'll also check
  // page-present bits.)
  if (from_user)
  {
    uint32_t end = ptr + len;
    if (end < ptr)
    {
      return 0;
    }
    if (len == 0)
    {
      return 0;
    }
    if (!is_user_addr(ptr) || !is_user_addr(end - 1u))
    {
      return 0;
    }
  }
  if (len > 4096u)
  {
    len = 4096u;
  }
  for (uint32_t i = 0; i < len; i++)
  {
    log_putchar((char)p[i]);
  }
  return len;
}

uint32_t sys_sleep(uint32_t ms)
{
  sleep_ms(ms);
  return 0;
}

uint32_t sys_getkey(void) { return (uint32_t)input_getkey(); }

static void syscall_handler(struct regs *r)
{
  // #region agent log - raw serial at very start
  {
    uint32_t esp_val;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp_val));
    const char *m = "[DBG] syscall_entry ESP=";
    for (const char *p = m; *p; p++)
      outb(0x3F8, (uint8_t)*p);
    // Log ESP
    for (int i = 28; i >= 0; i -= 4)
    {
      uint8_t nib = (esp_val >> i) & 0xF;
      outb(0x3F8, (uint8_t)(nib < 10 ? '0' + nib : 'A' + nib - 10));
    }
    const char *m2 = " r=";
    for (const char *p = m2; *p; p++)
      outb(0x3F8, (uint8_t)*p);
    // Log r pointer
    uint32_t r_val = (uint32_t)r;
    for (int i = 28; i >= 0; i -= 4)
    {
      uint8_t nib = (r_val >> i) & 0xF;
      outb(0x3F8, (uint8_t)(nib < 10 ? '0' + nib : 'A' + nib - 10));
    }
    outb(0x3F8, (uint8_t)'\n');
  }
  // #endregion
  // Validate r pointer before accessing it
  if ((uint32_t)r < 0x1000 || (uint32_t)r > 0x1000000)
  {
    const char *m = "[DBG] syscall_handler: invalid r pointer\n";
    for (const char *p = m; *p; p++)
      outb(0x3F8, (uint8_t)*p);
    return;
  }
  const int from_user = ((r->cs & 3u) == 3u);
  uint32_t ret = 0;
  switch (r->eax)
  {
  case SYSCALL_WRITE:
    ret = sys_write(r->ebx, r->ecx, from_user);
    break;
  case SYSCALL_TICKS:
    ret = pit_ticks;
    break;
  case SYSCALL_SLEEP:
    ret = sys_sleep(r->ebx);
    break;
  case SYSCALL_GETKEY:
    ret = sys_getkey();
    break;
  case SYSCALL_EXIT:
    // Request exit from user-mode program back to the kernel.
    // Keep it simple: set a flag that the ISR stub uses to jump back
    // to the saved kernel context (enter_user_mode).
    __asm__ volatile("cli");
    user_mode_exit_flag = 1;
    ret = 0;
    break;
  case SYSCALL_GETPID:
    // Return current process ID (only valid from user mode)
    if (from_user)
    {
      ret = current_user_pid;
    }
    else
    {
      ret = 0; // Kernel has PID 0
    }
    break;
  case SYSCALL_GETPPID:
    // Return parent process ID
    if (from_user && current_user_pid != 0)
    {
      struct process *proc = process_get(current_user_pid);
      if (proc)
      {
        ret = proc->ppid;
      }
      else
      {
        ret = 0;
      }
    }
    else
    {
      ret = 0; // Kernel or no current process
    }
    break;
  case SYSCALL_SOCKET:
    // socket(domain, type, protocol)
    // For now, only support AF_INET (2), SOCK_STREAM (1), IPPROTO_TCP (6)
    if (from_user && r->ebx == 2 && r->ecx == 1 && r->edx == 6)
    {
      extern struct tcp_pcb *tcp_get_free_pcb(void);
      struct tcp_pcb *pcb = tcp_get_free_pcb();
      if (pcb)
      {
        int fd = socket_alloc_fd(pcb, current_user_pid);
        if (fd >= 0)
        {
          ret = fd;
        }
        else
        {
          ret = 0xFFFFFFFFu; // -1
        }
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1 (unsupported)
    }
    break;
  case SYSCALL_BIND:
    // bind(fd, addr, addrlen)
    // addr is struct sockaddr_in { sin_family, sin_port, sin_addr }
    if (from_user && is_user_addr(r->ecx))
    {
      struct socket_fd *sock = socket_get_fd((int)r->ebx);
      if (sock && sock->pid == current_user_pid && sock->pcb)
      {
        // Read sockaddr_in from user memory
        uint8_t addr_buf[16];
        for (int i = 0; i < 16 && i < (int)r->edx; i++)
        {
          addr_buf[i] = *((volatile uint8_t *)(r->ecx + i));
        }
        // sin_family at offset 0, sin_port at offset 2, sin_addr at offset 4
        uint16_t sin_family =
            (uint16_t)addr_buf[0] | ((uint16_t)addr_buf[1] << 8);
        uint16_t sin_port =
            (uint16_t)addr_buf[2] | ((uint16_t)addr_buf[3] << 8);
        uint32_t sin_addr =
            (uint32_t)addr_buf[4] | ((uint32_t)addr_buf[5] << 8) |
            ((uint32_t)addr_buf[6] << 16) | ((uint32_t)addr_buf[7] << 24);

        if (sin_family == 2)
        { // AF_INET
          sock->pcb->local_port = ntohs(sin_port);
          sock->pcb->local_ip = ntohl(sin_addr);
          if (sock->pcb->local_ip == 0)
          {
            sock->pcb->local_ip = arp_get_ajos_ip();
          }
          ret = 0; // Success
        }
        else
        {
          ret = 0xFFFFFFFFu; // -1
        }
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  case SYSCALL_LISTEN:
    // listen(fd, backlog)
    if (from_user)
    {
      struct socket_fd *sock = socket_get_fd((int)r->ebx);
      if (sock && sock->pid == current_user_pid && sock->pcb)
      {
        sock->pcb->state = TCP_LISTEN;
        ret = 0; // Success
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  case SYSCALL_ACCEPT:
    // accept(fd, addr, addrlen_ptr)
    // For now, simple implementation: wait for connection on listening socket
    if (from_user)
    {
      struct socket_fd *listen_sock = socket_get_fd((int)r->ebx);
      if (listen_sock && listen_sock->pid == current_user_pid &&
          listen_sock->pcb)
      {
        // Wait for connection (poll until state changes from LISTEN)
        // In a real OS, this would block and be woken by TCP input
        uint32_t start_ticks = pit_ticks;
        while (listen_sock->pcb->state == TCP_LISTEN)
        {
          if ((pit_ticks - start_ticks) > (5 * PIT_HZ))
          {
            ret = 0xFFFFFFFFu; // -1 (timeout)
            break;
          }
          __asm__ volatile("hlt");
        }

        if (ret != 0xFFFFFFFFu && listen_sock->pcb->state != TCP_LISTEN)
        {
          // Create new socket for accepted connection
          extern struct tcp_pcb *tcp_get_free_pcb(void);
          struct tcp_pcb *new_pcb = tcp_get_free_pcb();
          if (new_pcb)
          {
            // Copy connection info to new PCB
            *new_pcb = *listen_sock->pcb;
            new_pcb->state = TCP_ESTABLISHED;
            // Reset listen socket to LISTEN state for next accept
            listen_sock->pcb->state = TCP_LISTEN;
            listen_sock->pcb->remote_ip = 0;
            listen_sock->pcb->remote_port = 0;

            int new_fd = socket_alloc_fd(new_pcb, current_user_pid);
            if (new_fd >= 0)
            {
              ret = new_fd;
              // Write address to user buffer if provided
              if (r->ecx != 0 && is_user_addr(r->ecx))
              {
                uint8_t addr_buf[16] = {0};
                addr_buf[0] = 2; // AF_INET
                addr_buf[1] = 0;
                uint16_t port = htons(new_pcb->remote_port);
                addr_buf[2] = (uint8_t)(port & 0xFF);
                addr_buf[3] = (uint8_t)((port >> 8) & 0xFF);
                uint32_t ip = htonl(new_pcb->remote_ip);
                addr_buf[4] = (uint8_t)(ip & 0xFF);
                addr_buf[5] = (uint8_t)((ip >> 8) & 0xFF);
                addr_buf[6] = (uint8_t)((ip >> 16) & 0xFF);
                addr_buf[7] = (uint8_t)((ip >> 24) & 0xFF);
                for (int i = 0; i < 16; i++)
                {
                  *((volatile uint8_t *)(r->ecx + i)) = addr_buf[i];
                }
              }
            }
            else
            {
              ret = 0xFFFFFFFFu; // -1
            }
          }
          else
          {
            ret = 0xFFFFFFFFu; // -1
          }
        }
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  case SYSCALL_CONNECT:
    // connect(fd, addr, addrlen)
    if (from_user && is_user_addr(r->ecx))
    {
      struct socket_fd *sock = socket_get_fd((int)r->ebx);
      if (sock && sock->pid == current_user_pid && sock->pcb)
      {
        // Read sockaddr_in from user memory
        uint8_t addr_buf[16];
        for (int i = 0; i < 16 && i < (int)r->edx; i++)
        {
          addr_buf[i] = *((volatile uint8_t *)(r->ecx + i));
        }
        uint16_t sin_family =
            (uint16_t)addr_buf[0] | ((uint16_t)addr_buf[1] << 8);
        uint16_t sin_port =
            (uint16_t)addr_buf[2] | ((uint16_t)addr_buf[3] << 8);
        uint32_t sin_addr =
            (uint32_t)addr_buf[4] | ((uint32_t)addr_buf[5] << 8) |
            ((uint32_t)addr_buf[6] << 16) | ((uint32_t)addr_buf[7] << 24);

        if (sin_family == 2)
        { // AF_INET
          extern int tcp_connect(struct tcp_pcb * pcb, ip_addr_t remote_ip,
                                 uint16_t remote_port);
          int result = tcp_connect(sock->pcb, ntohl(sin_addr), ntohs(sin_port));
          ret = (result == 0) ? 0 : 0xFFFFFFFFu;
        }
        else
        {
          ret = 0xFFFFFFFFu; // -1
        }
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  case SYSCALL_SEND:
    // send(fd, buf, len, flags)
    if (from_user && is_user_addr(r->ecx) && r->edx > 0)
    {
      struct socket_fd *sock = socket_get_fd((int)r->ebx);
      if (sock && sock->pid == current_user_pid && sock->pcb)
      {
        // Copy data from user memory
        uint32_t len = r->edx;
        if (len > 1024)
          len = 1024; // Limit
        uint8_t buf[1024];
        for (uint32_t i = 0; i < len; i++)
        {
          buf[i] = *((volatile uint8_t *)(r->ecx + i));
        }
        extern int tcp_send(struct tcp_pcb * pcb, const uint8_t *data,
                            uint16_t len);
        int result = tcp_send(sock->pcb, buf, (uint16_t)len);
        ret = (result == 0) ? len : 0xFFFFFFFFu;
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  case SYSCALL_RECV:
    // recv(fd, buf, len, flags)
    if (from_user && is_user_addr(r->ecx) && r->edx > 0)
    {
      struct socket_fd *sock = socket_get_fd((int)r->ebx);
      if (sock && sock->pid == current_user_pid && sock->pcb)
      {
        // Copy data from PCB RX buffer to user memory
        uint32_t len = r->edx;
        if (len > sock->pcb->app_rx_len)
        {
          len = sock->pcb->app_rx_len;
        }
        if (len > 0)
        {
          for (uint32_t i = 0; i < len; i++)
          {
            *((volatile uint8_t *)(r->ecx + i)) = sock->pcb->app_rx_buf[i];
          }
          // Remove consumed data (simple shift)
          for (uint32_t i = len; i < sock->pcb->app_rx_len; i++)
          {
            sock->pcb->app_rx_buf[i - len] = sock->pcb->app_rx_buf[i];
          }
          sock->pcb->app_rx_len -= (uint16_t)len;
        }
        ret = len;
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  case SYSCALL_CLOSE:
    // close(fd)
    if (from_user)
    {
      struct socket_fd *sock = socket_get_fd((int)r->ebx);
      if (sock && sock->pid == current_user_pid)
      {
        if (sock->pcb)
        {
          extern int tcp_close(struct tcp_pcb * pcb);
          tcp_close(sock->pcb);
        }
        socket_free_fd((int)r->ebx);
        ret = 0; // Success
      }
      else
      {
        ret = 0xFFFFFFFFu; // -1
      }
    }
    else
    {
      ret = 0xFFFFFFFFu; // -1
    }
    break;
  default:
    ret = 0xFFFFFFFFu;
    break;
  }
  // #region agent log
  log_writestring("[DBG] pre-ret r=0x");
  log_write_hex32((uint32_t)r);
  log_putchar('\n');
  // #endregion
  r->eax = ret;
}

void isr_handler(struct regs *r)
{
  // #region agent log - log ESP and TSS.esp0 at ISR entry
  if (r->int_no == 128)
  { // Only for syscalls
    uint32_t esp_val;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp_val));
    extern uint32_t tss_get_esp0(void);
    uint32_t esp0_val = tss_get_esp0();
    const char *m = "[DBG] isr_handler(syscall) ESP=";
    for (const char *p = m; *p; p++)
      outb(0x3F8, (uint8_t)*p);
    for (int i = 28; i >= 0; i -= 4)
    {
      uint8_t nib = (esp_val >> i) & 0xF;
      outb(0x3F8, (uint8_t)(nib < 10 ? '0' + nib : 'A' + nib - 10));
    }
    const char *m2 = " TSS.esp0=";
    for (const char *p = m2; *p; p++)
      outb(0x3F8, (uint8_t)*p);
    for (int i = 28; i >= 0; i -= 4)
    {
      uint8_t nib = (esp0_val >> i) & 0xF;
      outb(0x3F8, (uint8_t)(nib < 10 ? '0' + nib : 'A' + nib - 10));
    }
    const char *m3 = " r=";
    for (const char *p = m3; *p; p++)
      outb(0x3F8, (uint8_t)*p);
    uint32_t r_val = (uint32_t)r;
    for (int i = 28; i >= 0; i -= 4)
    {
      uint8_t nib = (r_val >> i) & 0xF;
      outb(0x3F8, (uint8_t)(nib < 10 ? '0' + nib : 'A' + nib - 10));
    }
    outb(0x3F8, (uint8_t)'\n');
  }
  // #endregion
  static const char *exception_messages[32] = {
      "Division By Zero",
      "Debug",
      "Non Maskable Interrupt",
      "Breakpoint",
      "Into Detected Overflow",
      "Out of Bounds",
      "Invalid Opcode",
      "No Coprocessor",
      "Double Fault",
      "Coprocessor Segment Overrun",
      "Bad TSS",
      "Segment Not Present",
      "Stack Fault",
      "General Protection Fault",
      "Page Fault",
      "Unknown Interrupt",
      "Coprocessor Fault",
      "Alignment Check",
      "Machine Check",
      "SIMD Floating-Point",
      "Virtualization",
      "Control Protection",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
      "Reserved",
  };

  if (interrupt_handlers[r->int_no] != 0)
  {
    interrupt_handlers[r->int_no](r);
  }
  else if (r->int_no < 32)
  {
    __asm__ volatile("cli");
    serial_putchar('\n');
    serial_putchar('\n');
    serial_write_cstr("*** EXCEPTION ");
    serial_write_u32_dec((uint32_t)r->int_no);
    serial_write_cstr(": ");
    serial_write_cstr(exception_messages[r->int_no]);
    serial_putchar('\n');

    serial_write_cstr("EIP=");
    serial_write_hex32_local(r->eip);
    serial_write_cstr(" ERR=");
    serial_write_hex32_local(r->err_code);

    if (r->int_no == 14)
    {
      serial_write_cstr(" CR2=");
      serial_write_hex32_local(read_cr2());
    }
    serial_putchar('\n');
    serial_write_cstr("System halted.\n");
    for (;;)
    {
      __asm__ volatile("hlt");
    }
  }
  else if (r->int_no > 47 && r->int_no != 128)
  {
    __asm__ volatile("cli");
    log_writestring("isr_handler: unhandled vector ");
    log_write_u32((uint32_t)r->int_no);
    log_writestring(" — halting\n");
    for (;;)
    {
      __asm__ volatile("hlt");
    }
  }

  // Send EOI for IRQs (32..47)
  if (r->int_no >= 32 && r->int_no <= 47)
  {
    if (r->int_no >= 40)
    {
      outb(0xA0, 0x20);
    }
    outb(0x20, 0x20);
  }
}

static void interrupts_init(void)
{
  // Set exception ISRs (0..31) and IRQ ISRs (32..47)
  idt_set_gate(0, (uint32_t)isr0, 0x08, 0x8E);
  idt_set_gate(1, (uint32_t)isr1, 0x08, 0x8E);
  idt_set_gate(2, (uint32_t)isr2, 0x08, 0x8E);
  idt_set_gate(3, (uint32_t)isr3, 0x08, 0x8E);
  idt_set_gate(4, (uint32_t)isr4, 0x08, 0x8E);
  idt_set_gate(5, (uint32_t)isr5, 0x08, 0x8E);
  idt_set_gate(6, (uint32_t)isr6, 0x08, 0x8E);
  idt_set_gate(7, (uint32_t)isr7, 0x08, 0x8E);
  idt_set_gate(8, (uint32_t)isr8, 0x08, 0x8E);
  idt_set_gate(9, (uint32_t)isr9, 0x08, 0x8E);
  idt_set_gate(10, (uint32_t)isr10, 0x08, 0x8E);
  idt_set_gate(11, (uint32_t)isr11, 0x08, 0x8E);
  idt_set_gate(12, (uint32_t)isr12, 0x08, 0x8E);
  idt_set_gate(13, (uint32_t)isr13, 0x08, 0x8E);
  idt_set_gate(14, (uint32_t)isr14, 0x08, 0x8E);
  idt_set_gate(15, (uint32_t)isr15, 0x08, 0x8E);
  idt_set_gate(16, (uint32_t)isr16, 0x08, 0x8E);
  idt_set_gate(17, (uint32_t)isr17, 0x08, 0x8E);
  idt_set_gate(18, (uint32_t)isr18, 0x08, 0x8E);
  idt_set_gate(19, (uint32_t)isr19, 0x08, 0x8E);
  idt_set_gate(20, (uint32_t)isr20, 0x08, 0x8E);
  idt_set_gate(21, (uint32_t)isr21, 0x08, 0x8E);
  idt_set_gate(22, (uint32_t)isr22, 0x08, 0x8E);
  idt_set_gate(23, (uint32_t)isr23, 0x08, 0x8E);
  idt_set_gate(24, (uint32_t)isr24, 0x08, 0x8E);
  idt_set_gate(25, (uint32_t)isr25, 0x08, 0x8E);
  idt_set_gate(26, (uint32_t)isr26, 0x08, 0x8E);
  idt_set_gate(27, (uint32_t)isr27, 0x08, 0x8E);
  idt_set_gate(28, (uint32_t)isr28, 0x08, 0x8E);
  idt_set_gate(29, (uint32_t)isr29, 0x08, 0x8E);
  idt_set_gate(30, (uint32_t)isr30, 0x08, 0x8E);
  idt_set_gate(31, (uint32_t)isr31, 0x08, 0x8E);

  idt_set_gate(32, (uint32_t)isr32, 0x08, 0x8E);
  idt_set_gate(33, (uint32_t)isr33, 0x08, 0x8E);
  idt_set_gate(34, (uint32_t)isr34, 0x08, 0x8E);
  idt_set_gate(35, (uint32_t)isr35, 0x08, 0x8E);
  idt_set_gate(36, (uint32_t)isr36, 0x08, 0x8E);
  idt_set_gate(37, (uint32_t)isr37, 0x08, 0x8E);
  idt_set_gate(38, (uint32_t)isr38, 0x08, 0x8E);
  idt_set_gate(39, (uint32_t)isr39, 0x08, 0x8E);
  idt_set_gate(40, (uint32_t)isr40, 0x08, 0x8E);
  idt_set_gate(41, (uint32_t)isr41, 0x08, 0x8E);
  idt_set_gate(42, (uint32_t)isr42, 0x08, 0x8E);
  idt_set_gate(43, (uint32_t)isr43, 0x08, 0x8E);
  idt_set_gate(44, (uint32_t)isr44, 0x08, 0x8E);
  idt_set_gate(45, (uint32_t)isr45, 0x08, 0x8E);
  idt_set_gate(46, (uint32_t)isr46, 0x08, 0x8E);
  idt_set_gate(47, (uint32_t)isr47, 0x08, 0x8E);

  // Syscalls: allow int 0x80 (DPL=3).
  // Use a TRAP gate (0xEF) so IF is not cleared on entry; this allows
  // keyboard IRQs to keep filling the input buffer while a syscall blocks.
  idt_set_gate(128, (uint32_t)isr128, 0x08, 0xEF);

  idtp.limit = (uint16_t)(sizeof(idt) - 1);
  idtp.base = (uint32_t)&idt;
  idt_load(&idtp);

  // Register default handlers
  register_interrupt_handler(32, timer_handler);
  register_interrupt_handler(33, keyboard_handler);
  register_interrupt_handler(128, syscall_handler);

  pic_remap_and_mask();
  ps2_keyboard_init();
  outb(0x3F8, (uint8_t)'q');
  pit_init();
  outb(0x3F8, (uint8_t)'i');
  __asm__ volatile("sti");
  outb(0x3F8, (uint8_t)'I');
}

extern void gdt_install_and_tss(void);
extern void tss_set_esp0(uint32_t esp0);
extern uint32_t tss_get_esp0(void);
extern void enter_user_mode(uint32_t user_eip, uint32_t user_esp);

static void terminal_scroll(void)
{
  // Move text rows 1..(TEXT_ROWS-1) up by 1; clear last text row.
  // Keep STATUS_ROW intact.
  uint8_t *video_memory = (uint8_t *)VIDEO_MEMORY;

  for (size_t y = 1; y < TEXT_ROWS; y++)
  {
    for (size_t x = 0; x < VGA_WIDTH; x++)
    {
      const size_t from = (y * VGA_WIDTH + x) * 2;
      const size_t to = ((y - 1) * VGA_WIDTH + x) * 2;
      video_memory[to] = video_memory[from];
      video_memory[to + 1] = video_memory[from + 1];
    }
  }

  for (size_t x = 0; x < VGA_WIDTH; x++)
  {
    const size_t index = ((TEXT_ROWS - 1) * VGA_WIDTH + x) * 2;
    video_memory[index] = ' ';
    video_memory[index + 1] = terminal_color;
  }

  terminal_row = TEXT_ROWS - 1;
  terminal_column = 0;
}

void terminal_clear(void)
{
  terminal_row = 0;
  terminal_column = 0;
  terminal_color = VGA_GREEN | (VGA_BLACK << 4);
  uint8_t *video_memory = (uint8_t *)VIDEO_MEMORY;
  for (size_t y = 0; y < VGA_HEIGHT; y++)
  {
    for (size_t x = 0; x < VGA_WIDTH; x++)
    {
      const size_t index = y * VGA_WIDTH + x;
      video_memory[index * 2] = ' ';
      video_memory[index * 2 + 1] = terminal_color;
    }
  }
  terminal_update_hw_cursor();
}

// Non-static so editor can use it
void terminal_update_hw_cursor(void)
{
  size_t r = terminal_row;
  size_t col = terminal_column;
  if (r >= VGA_HEIGHT)
    r = VGA_HEIGHT - 1u;
  if (col >= VGA_WIDTH)
    col = VGA_WIDTH - 1u;
  uint16_t pos = (uint16_t)(r * VGA_WIDTH + col);
  outb(0x3D4, 0x0F);
  outb(0x3D5, (uint8_t)(pos & 0xFF));
  outb(0x3D4, 0x0E);
  outb(0x3D5, (uint8_t)((pos >> 8) & 0xFF));
}

void terminal_initialize() { terminal_clear(); }

void terminal_putchar(char c)
{
  /* Defensive: bad cursor state would write past 0xB8000+4000 and trash RAM. */
  while (terminal_row >= TEXT_ROWS)
    terminal_scroll();
  if (terminal_column >= VGA_WIDTH)
  {
    terminal_column = 0;
    terminal_row++;
    while (terminal_row >= TEXT_ROWS)
      terminal_scroll();
  }

  if (c == '\n')
  {
    terminal_column = 0;
    terminal_row++;
    if (terminal_row >= TEXT_ROWS)
    {
      terminal_scroll();
    }
    terminal_update_hw_cursor();
    return;
  }
  if (c == '\r')
  {
    terminal_column = 0;
    terminal_update_hw_cursor();
    return;
  }
  if (c == '\b')
  {
    if (terminal_column > 0)
    {
      terminal_column--;
    }
    else if (terminal_row > 0)
    {
      terminal_row--;
      terminal_column = VGA_WIDTH - 1;
    }
    terminal_update_hw_cursor();
    return;
  }
  uint8_t *video_memory = (uint8_t *)VIDEO_MEMORY;
  const size_t index = terminal_row * VGA_WIDTH + terminal_column;
  video_memory[index * 2] = c;
  video_memory[index * 2 + 1] = terminal_color;
  if (++terminal_column == VGA_WIDTH)
  {
    terminal_column = 0;
    terminal_row++;
    if (terminal_row >= TEXT_ROWS)
    {
      terminal_scroll();
    }
  }
  terminal_update_hw_cursor();
}

void terminal_writestring(const char *data)
{
  for (size_t i = 0; data[i] != '\0'; i++)
  {
    terminal_putchar(data[i]);
  }
}

static void terminal_backspace(void)
{
  // Move cursor back one cell and erase it (wrap to previous line if needed).
  if (terminal_column == 0)
  {
    if (terminal_row == 0)
    {
      return;
    }
    terminal_row--;
    terminal_column = VGA_WIDTH - 1;
  }
  else
  {
    terminal_column--;
  }

  uint8_t *video_memory = (uint8_t *)VIDEO_MEMORY;
  const size_t index = terminal_row * VGA_WIDTH + terminal_column;
  video_memory[index * 2] = ' ';
  video_memory[index * 2 + 1] = terminal_color;
  terminal_update_hw_cursor();
}

// ---------------------------
// PS/2 keyboard (polling I/O)
// ---------------------------

#define PS2_STATUS_PORT 0x64
#define PS2_DATA_PORT 0x60

static uint8_t keyboard_shift_down = 0;
static uint8_t keyboard_ctrl_down = 0;

static void ps2_keyboard_init(void)
{
  // 1. Flush output buffer
  while (inb(PS2_STATUS_PORT) & 0x01)
  {
    (void)inb(PS2_DATA_PORT);
  }

  // 2. Send "Enable Scanning" (0xF4)
  // Wait for input buffer to be empty before writing
  int timeout = 100000;
  while ((inb(PS2_STATUS_PORT) & 0x02) && --timeout)
    ;
  outb(PS2_DATA_PORT, 0xF4);

  log_writestring("[KBD] PS/2 enabled\n");
  outb(0x3F8, (uint8_t)'Q');
}

static int keyboard_has_scancode(void)
{

  return (inb(PS2_STATUS_PORT) & 0x01) != 0;
}

static int keyboard_try_read_scancode(uint8_t *out)
{
  if (!keyboard_has_scancode())
  {
    return 0;
  }
  *out = inb(PS2_DATA_PORT);
  return 1;
}

static char scancode_to_ascii(uint8_t sc, uint8_t shifted)
{
  // If Control is held, map A-Z to 1-26
  if (keyboard_ctrl_down)
  {
    // Map standard QWERTY scancodes to 'a'-'z' first, then subtract 'a'-1
    // (A quick check: if the char is alpha, return char - 'a' + 1)
    // Re-using the lookup below is a bit verbose to duplicate logic.
    // Let's just do a normal lookup and then transform if it's alpha.
    // NOTE: This recursion/duplication is simpler if we just fall through
    // or use a temporary var.
  }

  char c = 0;
  // Set 1 scancodes (US layout)
  switch (sc)
  {
  case 0x01:
    c = 27; /* Esc */
    break;
  case 0x02:
    c = shifted ? '!' : '1';
    break;
  case 0x03:
    c = shifted ? '@' : '2';
    break;
  case 0x04:
    c = shifted ? '#' : '3';
    break;
  case 0x05:
    c = shifted ? '$' : '4';
    break;
  case 0x06:
    c = shifted ? '%' : '5';
    break;
  case 0x0F:
    c = '\t';
    break;
  case 0x07:
    c = shifted ? '^' : '6';
    break;
  case 0x08:
    c = shifted ? '&' : '7';
    break;
  case 0x09:
    c = shifted ? '*' : '8';
    break;
  case 0x0A:
    c = shifted ? '(' : '9';
    break;
  case 0x0B:
    c = shifted ? ')' : '0';
    break;
  case 0x0C:
    c = shifted ? '_' : '-';
    break;
  case 0x0D:
    c = shifted ? '+' : '=';
    break;
  case 0x10:
    c = shifted ? 'Q' : 'q';
    break;
  case 0x11:
    c = shifted ? 'W' : 'w';
    break;
  case 0x12:
    c = shifted ? 'E' : 'e';
    break;
  case 0x13:
    c = shifted ? 'R' : 'r';
    break;
  case 0x14:
    c = shifted ? 'T' : 't';
    break;
  case 0x15:
    c = shifted ? 'Y' : 'y';
    break;
  case 0x16:
    c = shifted ? 'U' : 'u';
    break;
  case 0x17:
    c = shifted ? 'I' : 'i';
    break;
  case 0x18:
    c = shifted ? 'O' : 'o';
    break;
  case 0x19:
    c = shifted ? 'P' : 'p';
    break;
  case 0x1A:
    c = shifted ? '{' : '[';
    break;
  case 0x1B:
    c = shifted ? '}' : ']';
    break;
  case 0x1E:
    c = shifted ? 'A' : 'a';
    break;
  case 0x1F:
    c = shifted ? 'S' : 's';
    break;
  case 0x20:
    c = shifted ? 'D' : 'd';
    break;
  case 0x21:
    c = shifted ? 'F' : 'f';
    break;
  case 0x22:
    c = shifted ? 'G' : 'g';
    break;
  case 0x23:
    c = shifted ? 'H' : 'h';
    break;
  case 0x24:
    c = shifted ? 'J' : 'j';
    break;
  case 0x25:
    c = shifted ? 'K' : 'k';
    break;
  case 0x26:
    c = shifted ? 'L' : 'l';
    break;
  case 0x27:
    c = shifted ? ':' : ';';
    break;
  case 0x28:
    c = shifted ? '"' : '\'';
    break;
  case 0x29:
    c = shifted ? '~' : '`';
    break;
  case 0x2B:
    c = shifted ? '|' : '\\';
    break;
  case 0x2C:
    c = shifted ? 'Z' : 'z';
    break;
  case 0x2D:
    c = shifted ? 'X' : 'x';
    break;
  case 0x2E:
    c = shifted ? 'C' : 'c';
    break;
  case 0x2F:
    c = shifted ? 'V' : 'v';
    break;
  case 0x30:
    c = shifted ? 'B' : 'b';
    break;
  case 0x31:
    c = shifted ? 'N' : 'n';
    break;
  case 0x32:
    c = shifted ? 'M' : 'm';
    break;
  case 0x33:
    c = shifted ? '<' : ',';
    break;
  case 0x34:
    c = shifted ? '>' : '.';
    break;
  case 0x35:
    c = shifted ? '?' : '/';
    break;
  case 0x39:
    c = ' ';
    break;
  }

  if (keyboard_ctrl_down && c >= 'a' && c <= 'z')
  {
    return c - 'a' + 1; // 1..26
  }
  return c;
}

int input_getkey_noblock(void)
{
  static int ext_prefix = 0;
#ifdef AJOS_SERIAL_ONLY
  if (serial_received())
    return (unsigned char)serial_getchar();
  uint8_t drop;
  while (kbd_pop_scancode(&drop))
  {
  }
  (void)drop;
  return -1;
#else
  uint8_t sc = 0;
  // Check keyboard first to drain queue
  while (kbd_pop_scancode(&sc))
  {
    // Handle extended prefix
    if (sc == 0xE0)
    {
      ext_prefix = 1;
      continue;
    }

    if (ext_prefix)
    {
      ext_prefix = 0; // Consumption of extended code
      // Ignore break codes for extended keys if needed, or handle them.
      // Usually we only care about make codes (presses).
      // Break codes for extended keys usually have 0x80 set as well (e.g. E0
      // B8).
      if (sc & 0x80)
      {
        continue;
      }
      switch (sc)
      {
      case 0x48:
        return KEY_UP;
      case 0x50:
        return KEY_DOWN;
      case 0x4B:
        return KEY_LEFT;
      case 0x4D:
        return KEY_RIGHT;
      case 0x47:
        return KEY_HOME;
      case 0x4F:
        return KEY_END;
      case 0x49:
        return KEY_PAGEUP;
      case 0x51:
        return KEY_PAGEDOWN;
      case 0x52:
        return KEY_INSERT;
      case 0x53:
        return KEY_DELETE;
      default:
        // Unknown extended key, return raw?
        return sc;
      }
    }

    // Ignore key releases (bit 7 set), but clear modifier state so a
    // Shift/Ctrl release seen here doesn't leave the flag stuck on for
    // whoever translates scancodes later.
    if (sc & 0x80)
    {
      uint8_t make = (uint8_t)(sc & 0x7F);
      if (make == 0x2A || make == 0x36)
        keyboard_shift_down = 0;
      if (make == 0x1D)
        keyboard_ctrl_down = 0;
      continue;
    }

    // Return valid press scancode
    return sc;
  }

  if (serial_received())
  {
    return (unsigned char)serial_getchar();
  }
  return -1;
#endif
}

/* Non-blocking input translated to ASCII (with shift/caps), for the GUI
 * desktop: input_getkey_noblock() returns raw scancodes in VGA builds. */
int input_getchar_noblock(void) {
  for (;;) {
    int k = input_getkey_noblock();
    if (k == -1)
      return -1;
    if (k >= 0x100)
      return k; /* KEY_UP/KEY_DOWN/... */
    uint8_t sc = (uint8_t)k;
    if (sc == 0x2A || sc == 0x36) {
      keyboard_shift_down = 1;
      continue;
    }
    if (sc == 0xAA || sc == 0xB6) {
      keyboard_shift_down = 0;
      continue;
    }
    if (sc == 0x1D) {
      keyboard_ctrl_down = 1;
      continue;
    }
    if (sc == 0x9D) {
      keyboard_ctrl_down = 0;
      continue;
    }
    char c = scancode_to_ascii(sc, keyboard_shift_down);
    if (c)
      return (unsigned char)c;
  }
}

int input_getkey(void)
{
  static int ext_prefix = 0;
  for (;;)
  {
    /* Prefer serial when bytes are waiting so Terminal (-serial stdio) works
     * even on GUI builds. Fall back to PS/2 for the QEMU window. */
    if (ssh_shell_log_sink_active())
    {
      ssh_flow_pump_from_shell();
      if (ssh_stdin_has_data())
      {
        int ci = ssh_stdin_getchar();
        if (ci < 0)
          continue;
        char c = (char)ci;
        if (c == 0x1b)
        {
          /* Wait briefly for CSI; arrow keys arrive as ESC [ A etc. */
          uint32_t start = pit_ticks;
          while (!ssh_stdin_has_data() &&
                 (uint32_t)(pit_ticks - start) < 20u)
          {
            ssh_flow_pump_from_shell();
            __asm__ volatile("pause");
          }
          if (!ssh_stdin_has_data())
            continue;
          char c2 = (char)ssh_stdin_getchar();
          if (c2 == '[')
          {
            start = pit_ticks;
            while (!ssh_stdin_has_data() &&
                   (uint32_t)(pit_ticks - start) < 20u)
            {
              ssh_flow_pump_from_shell();
              __asm__ volatile("pause");
            }
            if (!ssh_stdin_has_data())
              continue;
            char c3 = (char)ssh_stdin_getchar();
            if (c3 == 'A')
              return KEY_UP;
            if (c3 == 'B')
              return KEY_DOWN;
            if (c3 == 'C')
              return KEY_RIGHT;
            if (c3 == 'D')
              return KEY_LEFT;
            if (c3 == 'H')
              return KEY_HOME;
            if (c3 == 'F')
              return KEY_END;
            if (c3 >= '0' && c3 <= '9')
            {
              start = pit_ticks;
              while (!ssh_stdin_has_data() &&
                     (uint32_t)(pit_ticks - start) < 20u)
              {
                ssh_flow_pump_from_shell();
                __asm__ volatile("pause");
              }
              if (ssh_stdin_has_data())
              {
                char c4 = (char)ssh_stdin_getchar();
                if (c4 == '~')
                {
                  if (c3 == '2')
                    return KEY_INSERT;
                  if (c3 == '3')
                    return KEY_DELETE;
                  if (c3 == '1' || c3 == '7')
                    return KEY_HOME;
                  if (c3 == '4' || c3 == '8')
                    return KEY_END;
                }
              }
            }
          }
          continue;
        }
        if (c == '\r' || c == '\n')
          return '\n';
        if (c == 0x7f || c == '\b')
          return '\b';
        return (unsigned char)c;
      }
      /* Busy-poll NIC; hlt alone can miss back-to-back SSH keystrokes. */
      for (volatile int spin = 0; spin < 200; spin++)
        __asm__ volatile("pause");
      continue;
    }

    // If no input from either source, halt until next interrupt
    if (!kbd_has_data() && !serial_received())
    {
      __asm__ volatile("hlt");
      continue;
    }

    /* Prefer serial when bytes are waiting so Terminal (-serial stdio) works
     * even on GUI builds. Fall back to PS/2 for the QEMU window. */
    if (serial_received())
    {
      char c = serial_getchar();
      // Arrow keys via ANSI escape sequences: ESC [ A / ESC [ B
      if (c == 0x1b)
      {
        char c2 = serial_getchar();
        if (c2 == '[')
        {
          char c3 = serial_getchar();
          if (c3 == 'A')
          {
            return KEY_UP;
          }
          if (c3 == 'B')
          {
            return KEY_DOWN;
          }
          if (c3 == 'C')
          {
            return KEY_RIGHT;
          }
          if (c3 == 'D')
          {
            return KEY_LEFT;
          }
          if (c3 == 'H')
          {
            return KEY_HOME;
          }
          if (c3 == 'F')
          {
            return KEY_END;
          }

          // ESC [ <n> ~ sequences (insert/delete/home/end)
          if (c3 >= '0' && c3 <= '9')
          {
            char c4 = serial_getchar();
            if (c4 == '~')
            {
              if (c3 == '2')
              {
                return KEY_INSERT;
              }
              if (c3 == '3')
              {
                return KEY_DELETE;
              }
              if (c3 == '1' || c3 == '7')
              {
                return KEY_HOME;
              }
              if (c3 == '4' || c3 == '8')
              {
                return KEY_END;
              }
            }
          }
        }
        continue;
      }
      if (c == '\r' || c == '\n')
        return '\n';
      if (c == 0x7f || c == '\b')
        return '\b';
      return (unsigned char)c;
    }

#ifdef AJOS_SERIAL_ONLY
    /* Serial-only builds: ignore PS/2 so leftover scancodes never become text. */
    {
      uint8_t drop_sc;
      while (kbd_pop_scancode(&drop_sc))
      {
      }
    }
    continue;
#else
    if (kbd_has_data())
    {
      goto handle_keyboard;
    }
    continue;
#endif

  handle_keyboard:
    // Interrupt-driven keyboard scancode queue
    uint8_t sc = 0;
    if (!kbd_pop_scancode(&sc))
    {
      // Sleep until next interrupt (timer or keyboard), then re-check.
      __asm__ volatile("hlt");
      continue;
    }

    // Extended scancodes (0xE0 prefix)
    if (sc == 0xE0)
    {
      ext_prefix = 1;
        continue;
      }
    if (ext_prefix)
    {
      ext_prefix = 0;
      // Ignore key releases for extended keys
      if (sc & 0x80)
      {
        continue;
      }
      switch (sc)
      {
      case 0x48:
        return KEY_UP;
      case 0x50:
        return KEY_DOWN;
      case 0x4B:
        return KEY_LEFT;
      case 0x4D:
        return KEY_RIGHT;
      case 0x47:
        return KEY_HOME;
      case 0x4F:
        return KEY_END;
      case 0x49:
        return KEY_PAGEUP;
      case 0x51:
        return KEY_PAGEDOWN;
      case 0x52:
        return KEY_INSERT;
      case 0x53:
        return KEY_DELETE;
      case 0x1C:
        return '\n'; // Keypad Enter
      default:
        // Unknown extended key, ignore or return raw?
        // Fall through to normal processing or continue?
        // Better to act like it's a new key if it wasn't mapped?
        // But we consumed the prefix.
        break;
      }
      // If mapped, we returned.
      // If not mapped, fall through to treat as normal key?
      // But sc is 0xXX. e.g. Keypad / is E0 35. 35 is also 'h'.
      // We should probably just continue if handled, or return sc if we think
      // it's independent. But E0 means "extended". Map common ones.
      // If not mapped, safest to IGNORE to avoid phantom characters.
      continue;
    }

    // Key release (break code) has high bit set
    if (sc & 0x80)
    {
      uint8_t make = (uint8_t)(sc & 0x7F);
      if (make == 0x2A || make == 0x36)
      {
        keyboard_shift_down = 0;
      }
      if (make == 0x1D)
      {
        keyboard_ctrl_down = 0;
      }
      continue;
    }

    // Ctrl pressed (0x1D)
    if (sc == 0x1D)
    {
      keyboard_ctrl_down = 1;
      continue;
    }

    // Shift pressed
    if (sc == 0x2A || sc == 0x36)
    {
      keyboard_shift_down = 1;
      continue;
    }

    // Enter
    if (sc == 0x1C)
    {
      return '\n';
    }

    // Backspace
    if (sc == 0x0E)
    {
      return '\b';
    }

    char c = scancode_to_ascii(sc, keyboard_shift_down);
    if (c != 0)
    {
      return (uint8_t)c;
    }

    // Wait for next interrupt (timer/keyboard)
    if (!serial_received())
    {
      __asm__ volatile("hlt");
    }
  }
}

// ---------------------------
// Tiny shell utilities
// ---------------------------

static const char *shell_commands[] = {"service",
                                       "date",
                                       "uname",
                                       "whoami",
                                       "hostname",
                                       "help",
                                       "history",
                                       "more",
                                       "clear",
                                       "echo",
                                       "reboot",
                                       "test_pbuf",
                                       "eth_stat",
                                       "test_eth",
                                       "arp_stat",
                                       "arp_whois",
                                       "ip_stat",
                                       "ping",
                                       "ifconfig",
                                       "udp_send",
                                       "tcp_listen",
                                       "tcp_connect",
                                       "wget",
                                       "http_get",
                                       "tcp_stat",
                                       "policy_stat",
                                       "test_policy",
                                       "test_auth_add",
                                       "tcp_test_syn",
                                       "tcp_test_ack",
                                       "tcp_test_data",
                                       "dhcp",
                                       "dns",
                                       "whois",
                                       "netcfg",
                                       "hotspot",
                                       "sshd",
                                       "dhcpd_stat",
                                       "dnsd_stat",
                                       "auth_stat",
                                       "adduser",
                                       "deluser",
                                       "passwd",
                                       "users",
                                       "http_stat",
                                       "http_test",
                                       "edit",
                                       "ticks",
                                       "uptime",
                                       "ps",
                                       "kill",
                                       "wait",
                                       "sleep",
                                       "a20",
                                       "pci",
                                       "ps",
                                       "kill",
                                       "wait",
                                       "sleep",
                                       "a20",
                                       "pci",
                                       "traceroute",
                                       "logout",
                                       "nc",
                                       "route",
                                       "e1000",
                                       "e1000tx",
                                       "e1000rx",
                                       "e1000icr",
                                       "e1000watch",
                                       "e1000regs",
                                       "e1000info",
                                       "e1000rxstat",
                                       "e1000reinit",
                                       "e1000loop",
                                       "e100loop",
                                       "pwd",
                                       "cd",
                                       "ls",
                                       "cat",
                                       "create",
                                       "cp",
                                       "files",
                                       "freeram",
                                       "run",
                                       "run3",
                                       "jobs",
                                       "touch",
                                       "grep",
                                       "head",
                                       "tail",
                                       "wc",
                                       "hexdump",
                                       "strings",
                                       "heap",
                                       "mkdir",
                                       "httpd",
                                       "poweroff",
                                       "ajlang",
                                       "mem",
                                       "rm",
                                       "mv",
                                       "find",
                                       "showkeys",
                                       "syslog",
                                       NULL};

static void cmd_poweroff(void) { poweroff_now(); }

// Utility functions (kstrlen, kstrcmp_n, katoi, kstreq, kstrncpy, skip_spaces,
// parse_u32, kmemcpy, sleep_ms) are defined in kernel.h or handled by common
// includes.

// Simple allocation table so we can `alloc`/`free` from the shell.
#define ALLOC_SLOTS 32
static void *alloc_slots[ALLOC_SLOTS];

// struct file_slot and file_slots array are defined in fat.h

// ---------------------------
// Process Management (Roadmap v1.0.1 - Phase 1)
// ---------------------------
// (struct process and enums defined earlier for syscall handler)

static struct process process_table[MAX_PROCESSES];
static uint32_t next_pid = 1;               // Start PIDs at 1 (0 = kernel)
static struct process *current_process = 0; // Currently running process
static uint32_t scheduler_ticks = 0;        // Counter for scheduler decisions

// Forward declaration
static struct process *scheduler_next(void);

// Initialize process management
static void process_init(void)
{
  // Clear all process slots
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    process_table[i].in_use = 0;
    process_table[i].pid = 0;
    process_table[i].state = PROC_STATE_DEAD;
    process_table[i].name[0] = '\0';
  }

  // Create kernel process (PID 0)
  process_table[0].pid = 0;
  process_table[0].ppid = 0; // Kernel has no parent
  process_table[0].state = PROC_STATE_RUNNING;
  process_table[0].in_use = 1;
  process_table[0].start_ticks = pit_ticks;
  process_table[0].cpu_ticks = 0;
  process_table[0].page_dir = 0;
  const char *kernel_name = "kernel";
  for (int i = 0; i < PROCESS_NAME_LEN - 1 && kernel_name[i] != '\0'; i++)
  {
    process_table[0].name[i] = kernel_name[i];
  }
  process_table[0].name[PROCESS_NAME_LEN - 1] = '\0';

  // Create shell process (PID 1)
  process_table[1].pid = 1;
  process_table[1].ppid = 0; // Shell is created by kernel
  process_table[1].state = PROC_STATE_RUNNING;
  process_table[1].in_use = 1;
  process_table[1].start_ticks = pit_ticks;
  process_table[1].cpu_ticks = 0;
  process_table[1].page_dir = 0;
  process_table[1].is_background = 0;
  const char *shell_name = "shell";
  for (int i = 0; i < PROCESS_NAME_LEN - 1 && shell_name[i] != '\0'; i++)
  {
    process_table[1].name[i] = shell_name[i];
  }
  process_table[1].name[PROCESS_NAME_LEN - 1] = '\0';

  // Set shell as current process
  current_process = &process_table[1];

  // Initialize kernel and shell stacks (PID 0 and 1)
  // For now, they use the initial kernel stack boot provided.
  // We'll give them proper stacks when we first switch AWAY from them.
  process_table[0].kernel_stack = 0;
  process_table[0].esp = 0;
  process_table[1].kernel_stack = 0;
  process_table[1].esp = 0;

  next_pid = 2;
}

// Thread wrapper to handle return/exit
static void kthread_entry(void (*fn)(void *), void *arg)
{
  if (fn)
  {
    fn(arg);
  }
  log_writestring("[TASK] Thread exited\n");
  if (current_process)
  {
    current_process->state = PROC_STATE_ZOMBIE;
  }
  for (;;)
  {
    schedule();
  }
}

// Create a kernel thread
static uint32_t kthread_create(const char *name, void (*fn)(void *),
                               void *arg)
{
  uint32_t pid = process_alloc(name);
  if (pid == 0)
    return 0;

  struct process *p = process_get(pid);

  // Allocate kernel stack (4KB)
  void *stack_base = kmalloc(4096);
  if (!stack_base)
  {
    process_free(pid);
    return 0;
  }
  p->kernel_stack = (uint32_t)stack_base;

  uint32_t *stack = (uint32_t *)(p->kernel_stack + 4096);

  // Initial stack frame for switch_to
  *(--stack) = (uint32_t)arg;           // Argument for fn
  *(--stack) = (uint32_t)fn;            // Function to call
  *(--stack) = 0;                       // Dummy return address for kthread_entry
  *(--stack) = (uint32_t)kthread_entry; // Target for switch_to's ret

  // Registers switch_to pops: ebp, edi, esi, ebx
  *(--stack) = 0; // ebp
  *(--stack) = 0; // edi
  *(--stack) = 0; // esi
  *(--stack) = 0; // ebx

  p->esp = (uint32_t)stack;
  p->state = PROC_STATE_RUNNING;

  return pid;
}

// Allocate a new process slot and return PID, or 0 on failure
static uint32_t process_alloc(const char *name)
{
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    if (!process_table[i].in_use)
    {
      process_table[i].pid = next_pid++;
      process_table[i].ppid = current_user_pid; // Set parent to current user
                                                // process (or 0 if kernel)
      process_table[i].state = PROC_STATE_RUNNING;
      process_table[i].in_use = 1;
      process_table[i].start_ticks = pit_ticks;
      process_table[i].cpu_ticks = 0;
      process_table[i].page_dir = 0;
      process_table[i].is_background = 0;

      // Copy name
      int j = 0;
      for (; j < PROCESS_NAME_LEN - 1 && name[j] != '\0'; j++)
      {
        process_table[i].name[j] = name[j];
      }
      process_table[i].name[j] = '\0';

      return process_table[i].pid;
    }
  }
  return 0; // No free slots
}

static void test_thread(void *arg)
{
  uint32_t val = (uint32_t)arg;
  for (;;)
  {
    log_writestring("[THREAD ");
    log_write_u32(val);
    log_writestring("] PMM Free: ");
    log_write_u32(pmm_get_free_pages());
    log_writestring("\n");
    for (volatile int i = 0; i < 5000000; i++)
      ;
  }
}

static void cmd_thread_test(const char *arg)
{
  (void)arg;
  log_writestring("Starting test thread...\n");
  kthread_create("test_th", test_thread, (void *)123);
}

// Free a process slot
static void process_free(uint32_t pid)
{
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    if (process_table[i].pid == pid && process_table[i].in_use)
    {
      process_table[i].in_use = 0;
      process_table[i].state = PROC_STATE_DEAD;
      process_table[i].name[0] = '\0';
      return;
    }
  }
}

// Get process by PID
static struct process *process_get(uint32_t pid)
{
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    if (process_table[i].pid == pid && process_table[i].in_use)
    {
      return &process_table[i];
    }
  }
  return 0;
}

// Scheduler: select next runnable process (round-robin)
// Returns pointer to next process to run, or 0 if none
static struct process *scheduler_next(void)
{
  static int last_idx = 0;

  // Count runnable processes
  int runnable_count = 0;
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    if (process_table[i].in_use &&
        (process_table[i].state == PROC_STATE_RUNNING ||
         process_table[i].state == PROC_STATE_SLEEPING))
    {
      runnable_count++;
    }
  }

  if (runnable_count == 0)
  {
    return 0; // No runnable processes
  }

  // Round-robin: find next runnable process after last_idx
  for (int attempts = 0; attempts < MAX_PROCESSES; attempts++)
  {
    last_idx = (last_idx + 1) % MAX_PROCESSES;
    if (process_table[last_idx].in_use &&
        (process_table[last_idx].state == PROC_STATE_RUNNING ||
         process_table[last_idx].state == PROC_STATE_SLEEPING))
    {
      return &process_table[last_idx];
    }
  }

  return 0;
}

// Update current process pointer (called from scheduler)
static void schedule(void)
{
  if (!current_process)
    return;

  // Round-robin: find next running process
  struct process *next = (void *)0;
  // Calculate current index
  int current_idx = -1;
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    if (&process_table[i] == current_process)
    {
      current_idx = i;
      break;
    }
  }

  if (current_idx == -1)
    return;

  for (int i = 1; i <= MAX_PROCESSES; i++)
  {
    int idx = (current_idx + i) % MAX_PROCESSES;
    if (process_table[idx].in_use &&
        process_table[idx].state == PROC_STATE_RUNNING &&
        process_table[idx].esp != 0)
    {
      // Never switch to a process whose stack is outside identity-mapped RAM
      // (0..64MB). Faults at CR2=0x220F0000 were caused by switching to
      // a process with a bad esp (e.g. unmapped high address).
      uint32_t esp = process_table[idx].esp;
      if (esp >= 0x1000u && esp < 0x04000000u)
      {
        next = &process_table[idx];
        break;
      }
    }
  }

  if (next && next != current_process)
  {
    struct process *prev = current_process;
    current_process = next;
    switch_to(&prev->esp, next->esp);
  }
}

static void scheduler_tick(void)
{
  scheduler_ticks++;

  // Update current process CPU time
  if (current_process)
  {
    current_process->cpu_ticks++;

    // Preemption: yield every 10 ticks (approx 100ms)
    // Only preempt if we are not in an critical section (future)
    if (scheduler_ticks % 10 == 0)
    {
      schedule();
    }
  }
}

// wait command - wait for a background process to complete
static void cmd_wait(const char *arg)
{
  uint32_t pid = 0;
  if (arg && *arg != '\0')
  {
    if (!parse_u32(arg, &pid))
    {
      log_writestring("Usage: wait [pid]\n");
      return;
    }
  }

  if (pid == 0)
  {
    // Wait for any background process
    int found = 0;
    for (int i = 0; i < MAX_PROCESSES; i++)
    {
      if (process_table[i].in_use && process_table[i].is_background &&
          (process_table[i].state == PROC_STATE_RUNNING ||
           process_table[i].state == PROC_STATE_SLEEPING))
      {
        pid = process_table[i].pid;
        found = 1;
        break;
      }
    }
    if (!found)
    {
      log_writestring("wait: no background processes\n");
      return;
    }
  }

  struct process *proc = process_get(pid);
  if (!proc)
  {
    log_writestring("wait: process not found\n");
    return;
  }

  if (!proc->is_background)
  {
    log_writestring("wait: process is not a background job\n");
    return;
  }

  log_writestring("wait: waiting for process ");
  log_write_u32(pid);
  log_writestring("...\n");

  // Poll until process is dead (simple implementation)
  // In a real OS, this would block and be woken by the scheduler
  uint32_t start_ticks = pit_ticks;
  while (proc->in_use && (proc->state == PROC_STATE_RUNNING ||
                          proc->state == PROC_STATE_SLEEPING ||
                          proc->state == PROC_STATE_ZOMBIE))
  {
    // Timeout after 10 seconds
    if ((pit_ticks - start_ticks) > (10 * PIT_HZ))
    {
      log_writestring("wait: timeout\n");
      return;
    }
    __asm__ volatile("hlt"); // Wait for next interrupt
  }

  log_writestring("wait: process ");
  log_write_u32(pid);
  log_writestring(" completed\n");
}

// kill command - terminate a process
static void cmd_kill(const char *arg)
{
  uint32_t pid = 0;
  if (!parse_u32(arg, &pid))
  {
    log_writestring("Usage: kill <pid>\n");
    return;
  }

  // Can't kill kernel (PID 0) or shell (PID 1)
  if (pid == 0 || pid == 1)
  {
    log_writestring("kill: cannot kill system processes\n");
    return;
  }

  struct process *proc = process_get(pid);
  if (!proc)
  {
    log_writestring("kill: process not found\n");
    return;
  }

  if (proc->state == PROC_STATE_DEAD)
  {
    log_writestring("kill: process already dead\n");
    return;
  }

  // Mark process as zombie (will be cleaned up later)
  proc->state = PROC_STATE_ZOMBIE;
  log_writestring("kill: process ");
  log_write_u32(pid);
  log_writestring(" terminated\n");

  // For now, immediately free it (in a real OS, parent would wait for it)
  process_free(pid);
}

// ps command - list all processes
static void cmd_ps(void)
{
  log_writestring(
      "PID  PPID  STATE      CPU(ms)  NAME                    UPTIME\n");
  log_writestring(
      "---  ----  ---------  -------  --------------------    -------\n");

  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    if (process_table[i].in_use)
    {
      // Print PID
      log_write_u32(process_table[i].pid);
      log_writestring("  ");

      // Print PPID
      log_write_u32(process_table[i].ppid);
      log_writestring("  ");

      // Print state
      const char *state_str = "UNKNOWN";
      switch (process_table[i].state)
      {
      case PROC_STATE_RUNNING:
        state_str = "RUNNING  ";
        break;
      case PROC_STATE_SLEEPING:
        state_str = "SLEEPING ";
        break;
      case PROC_STATE_ZOMBIE:
        state_str = "ZOMBIE   ";
        break;
      case PROC_STATE_DEAD:
        state_str = "DEAD     ";
        break;
      }
      log_writestring(state_str);
      log_writestring("  ");

      // Print CPU time (in milliseconds)
      uint32_t cpu_ms = (process_table[i].cpu_ticks * 1000u) / PIT_HZ;
      log_write_u32(cpu_ms);
      log_writestring("  ");

      // Print name (pad to 20 chars)
      log_writestring(process_table[i].name);
      int name_len = 0;
      while (process_table[i].name[name_len] != '\0')
        name_len++;
      for (int j = name_len; j < 20; j++)
      {
        log_putchar(' ');
      }
      log_writestring("  ");

      // Print uptime (in ticks, converted to approximate seconds)
      uint32_t uptime_ticks = pit_ticks - process_table[i].start_ticks;
      uint32_t uptime_sec = uptime_ticks / PIT_HZ;
      log_write_u32(uptime_sec);
      log_writestring("s");

      // Show current process marker
      if (&process_table[i] == current_process)
      {
        log_writestring(" <--");
      }
      log_putchar('\n');
    }
  }
}

// FAT logic and associated shell commands have been moved to fat.c

void shell_format_prompt(char *out, size_t cap, const char *ssh_username_override)
{
  extern char fat12_cwd_path[];

  const char *user = ssh_username_override;
  if (!user || user[0] == '\0')
    user = current_username;

  // "AJOS [user]:/path> " or "AJOS:/path> " if no user
  size_t i = 0;
  const char *pfx = "AJOS";
  for (size_t k = 0; pfx[k] != '\0' && i + 1 < cap; k++)
  {
    out[i++] = pfx[k];
  }

  if (user[0] != '\0')
  {
    if (i + 1 < cap)
      out[i++] = ' ';
    if (i + 1 < cap)
      out[i++] = '[';
    for (size_t k = 0; user[k] != '\0' && i + 1 < cap; k++)
    {
      out[i++] = (char)user[k];
    }
    if (i + 1 < cap)
      out[i++] = ']';
  }

  if (i + 1 < cap)
    out[i++] = ':';
  for (size_t k = 0; fat12_cwd_path[k] != '\0' && i + 1 < cap; k++)
  {
    out[i++] = fat12_cwd_path[k];
  }
  if (i + 3 < cap)
  {
    out[i++] = '>';
    out[i++] = ' ';
  }
  out[i] = '\0';
}

static void build_prompt(char *out, size_t cap)
{
  shell_format_prompt(out, cap, NULL);
}
// FAT helper functions moved to fat.c

static void cmd_memdbg(void)
{
  extern uint8_t sbss[], ebss[];
  log_writestring("BSS Range: ");
  log_write_hex32((uint32_t)sbss);
  log_writestring(" - ");
  log_write_hex32((uint32_t)ebss);
      log_putchar('\n');

  log_writestring("file_slots: ");
  log_write_hex32((uint32_t)file_slots);
  log_writestring(" (size=");
  log_write_u32(sizeof(file_slots));
  log_writestring(")\n");

  log_writestring("idt:        ");
  log_write_hex32((uint32_t)idt);
  log_writestring(" (size=");
  log_write_u32(sizeof(idt));
  log_writestring(")\n");

  // heap_head is now internal to kernel/mm/heap.c
  log_writestring("heap_head: (internal to heap module)");
          log_putchar('\n');
}

static void cmd_heap(void)
{
  uint32_t ok, kf, fail;
  mm_kmalloc_stats(&ok, &kf, &fail);
  uint32_t free_p = pmm_get_free_pages();
  uint32_t total_p = pmm_get_total_pages();
  uint32_t used_p = (total_p >= free_p) ? (total_p - free_p) : 0u;

  log_writestring("Memory: slab caches (<=2048 B) + buddy PMM (larger)\n");
  log_writestring("  PMM pages: ");
  log_write_u32(used_p);
  log_writestring(" used, ");
  log_write_u32(free_p);
  log_writestring(" free, ");
  log_write_u32(total_p);
  log_writestring(" total (~");
  log_write_u32(used_p * 4u);
  log_writestring(" KiB mapped in use)\n");

  log_writestring("  kmalloc ok=");
  log_write_u32(ok);
  log_writestring("  kfree=");
  log_write_u32(kf);
  log_writestring("  kmalloc_fail=");
  log_write_u32(fail);
  log_writestring("\n");
  log_writestring(
      "  Leak hint: run twice at idle; if (ok-kfree) keeps growing, find\n");
  log_writestring(
      "  missing kfree. pbuf (~2KiB+) and SSH buffers use PMM pages.\n");
}

// Shell commands moved to fat.c and networking modules.

static void reboot_now(void)
{
  // Try PS/2 controller reset (works well in QEMU).
  // Wait for input buffer to be empty (bit 1 == 0), then send 0xFE.
  for (size_t i = 0; i < 100000; i++)
  {
    if ((inb(0x64) & 0x02) == 0)
    {
      break;
    }
  }
  outb(0x64, 0xFE);
  for (;;)
  {
    __asm__ volatile("hlt");
  }
}

static void poweroff_now(void)
{
  log_writestring("Shutdown requested...\n");

  // Method 1: QEMU ACPI shutdown (port 0x604)
  outw(0x604, 0x2000);

  // Method 2: Older QEMU/Bochs shutdown (port 0xB004)
  outw(0xB004, 0x2000);

  // Method 3: Bochs/QEMU debug exit (port 0x8900)
  // This is often configured for -device isa-debug-exit
  outw(0x8900, 0x0000); // Or some other code

  // If we're still here, halt.
  for (;;)
  {
    __asm__ volatile("cli; hlt");
  }
}

#define HISTORY_SIZE 16
#define LINE_MAX 256

static char history[HISTORY_SIZE][LINE_MAX];
static size_t history_count = 0;

static void history_add(const char *line)
{
  if (line[0] == '\0')
  {
    return;
  }

  // Avoid storing exact consecutive duplicates
  if (history_count > 0)
  {
    const char *prev = history[(history_count - 1) % HISTORY_SIZE];
    if (kstreq(prev, line))
    {
      return;
    }
  }

  size_t idx = history_count % HISTORY_SIZE;
  size_t i = 0;
  for (; i < (LINE_MAX - 1) && line[i] != '\0'; i++)
  {
    history[idx][i] = line[i];
  }
  history[idx][i] = '\0';
  history_count++;
}

static const char *history_get(size_t logical_index)
{
  // Index is absolute (0..history_count-1). Storage is a ring buffer.
  if (logical_index >= history_count)
  {
    return 0;
  }
  size_t idx = logical_index % HISTORY_SIZE;
  return history[idx];
}

static void terminal_put_at(size_t row, size_t col, char c)
{
  if (row >= VGA_HEIGHT || col >= VGA_WIDTH)
  {
    return;
  }
  uint8_t *video_memory = (uint8_t *)VIDEO_MEMORY;
  const size_t index = row * VGA_WIDTH + col;
  video_memory[index * 2] = (uint8_t)c;
  video_memory[index * 2 + 1] = terminal_color;
}

static void terminal_set_cursor(size_t row, size_t col)
{
  if (row >= TEXT_ROWS)
  {
    row = TEXT_ROWS - 1;
  }
  if (col >= VGA_WIDTH)
  {
    col = VGA_WIDTH - 1;
  }
  terminal_row = row;
  terminal_column = col;
  terminal_update_hw_cursor();
}

static void redraw_input_line(const char *prompt, size_t prompt_row,
                              size_t prompt_col, const char *buf, size_t len,
                              size_t cursor, size_t *io_prev_drawn)
{
  // VGA: update only the area after the prompt (single-line editor).
  size_t max = len;
  if (*io_prev_drawn > max)
  {
    max = *io_prev_drawn;
  }
  for (size_t i = 0; i < max; i++)
  {
    char c = (i < len) ? buf[i] : ' ';
    terminal_put_at(prompt_row, prompt_col + i, c);
  }
  terminal_set_cursor(prompt_row, prompt_col + cursor);

  // Serial: rewrite line from start using CR, then re-position by rewriting
  // only up to the cursor. Avoid ANSI escapes so it works in more terminals.
  serial_putchar('\r');
  serial_writestring(prompt);
  for (size_t i = 0; i < len; i++)
  {
    serial_putchar(buf[i]);
  }
  if (*io_prev_drawn > len)
  {
    for (size_t i = 0; i < (*io_prev_drawn - len); i++)
    {
      serial_putchar(' ');
    }
  }
  serial_putchar('\r');
  serial_writestring(prompt);
  for (size_t i = 0; i < cursor; i++)
  {
    serial_putchar(buf[i]);
  }

  *io_prev_drawn = len;
}

static void status_update(int insert_mode)
{
  // Basic status bar on VGA only.
  // Format: "TICKS: <n>  MODE: INS/OVR"
  char buf[16];
  size_t bi = 0;

  // Clear the whole status row first.
  for (size_t x = 0; x < VGA_WIDTH; x++)
  {
    terminal_put_at(STATUS_ROW, x, ' ');
  }

  const char *label1 = "TICKS: ";
  for (size_t i = 0; label1[i] != '\0' && bi < VGA_WIDTH; i++)
  {
    terminal_put_at(STATUS_ROW, bi++, label1[i]);
  }

  uint32_t v = pit_ticks;
  // u32 -> decimal into buf (reversed)
  if (v == 0)
  {
    buf[0] = '0';
    buf[1] = '\0';
  }
  else
  {
    size_t ti = 0;
    while (v > 0 && ti < (sizeof(buf) - 1))
    {
      buf[ti++] = (char)('0' + (v % 10u));
      v /= 10u;
    }
    // reverse in place
    for (size_t i = 0; i < ti / 2; i++)
    {
      char t = buf[i];
      buf[i] = buf[ti - 1 - i];
      buf[ti - 1 - i] = t;
    }
    buf[ti] = '\0';
  }

  for (size_t i = 0; buf[i] != '\0' && bi < VGA_WIDTH; i++)
  {
    terminal_put_at(STATUS_ROW, bi++, buf[i]);
  }

  const char *label2 = "  MODE: ";
  for (size_t i = 0; label2[i] != '\0' && bi < VGA_WIDTH; i++)
  {
    terminal_put_at(STATUS_ROW, bi++, label2[i]);
  }

  const char *mode = insert_mode ? "INS" : "OVR";
  for (size_t i = 0; mode[i] != '\0' && bi < VGA_WIDTH; i++)
  {
    terminal_put_at(STATUS_ROW, bi++, mode[i]);
  }

  // Keep hardware cursor where the editor put it (no call to
  // terminal_set_cursor here).
}

static void readline_serial_redraw(const char *prompt, const char *buf,
                                   size_t len)
{
  // Deprecated: use newline-based redraw to avoid CR overwrite issues
  // in some serial terminal captures.
  log_putchar('\n');
  log_writestring(prompt);
  for (size_t i = 0; i < len; i++)
    log_putchar(buf[i]);
}

// Read password with hidden input (shows * instead of characters)
static void readline_password(const char *prompt, char *out, size_t out_cap)
{
  log_writestring(prompt);

  size_t len = 0;
  out[0] = '\0';

  for (;;)
  {
    int key = input_getkey();
    if (key == '\n')
    {
      out[len] = '\0';
      log_putchar('\n');
      break;
    }

    if (key == '\b' || key == KEY_DELETE)
    {
      if (len > 0)
      {
        len--;
        out[len] = '\0';
        log_putchar('\b');
        log_putchar(' ');
        log_putchar('\b');
      }
      continue;
    }

    // Only accept printable ASCII characters
    if (key >= 32 && key < 127 && len < out_cap - 1)
    {
      out[len++] = (char)key;
      out[len] = '\0';
      log_putchar('*'); // Show * instead of actual character
    }
  }
}

static int shell_prefix_eq_ci(const char *s, const char *prefix, size_t plen)
{
  for (size_t k = 0; k < plen; k++)
  {
    char c1 = prefix[k];
    char c2 = s[k];
    if (c2 == '\0')
      return 0;
    if (c1 >= 'A' && c1 <= 'Z')
      c1 = (char)(c1 - 'A' + 'a');
    if (c2 >= 'A' && c2 <= 'Z')
      c2 = (char)(c2 - 'A' + 'a');
    if (c1 != c2)
      return 0;
  }
  return 1;
}

#define SHELL_TAB_MATCH_MAX 32

static void shell_apply_word(char *line, size_t *len, size_t cap,
                             size_t word_start, const char *word, int add_space)
{
  size_t mlen = kstrlen(word);
  size_t need = word_start + mlen + (add_space ? 1u : 0u);
  if (need >= cap)
    return;
  for (size_t i = 0; i < mlen; i++)
    line[word_start + i] = word[i];
  size_t n = word_start + mlen;
  if (add_space)
    line[n++] = ' ';
  line[n] = '\0';
  *len = n;
}

int shell_tab_complete(char *line, size_t *len, size_t cap,
                       char matches[][SHELL_TAB_MATCH_LEN], int max_matches)
{
  if (!line || !len || cap < 2)
    return 0;

  size_t pos = *len;
  if (pos >= cap)
    pos = cap - 1;
  line[pos] = '\0';

  size_t word_start = pos;
  while (word_start > 0 && line[word_start - 1] != ' ')
    word_start--;

  size_t first = 0;
  while (first < pos && line[first] == ' ')
    first++;
  int is_command = (word_start == first);

  size_t prefix_len = pos - word_start;
  char prefix[SHELL_TAB_MATCH_LEN];
  size_t copy_len = prefix_len;
  if (copy_len >= sizeof(prefix))
    copy_len = sizeof(prefix) - 1;
  for (size_t i = 0; i < copy_len; i++)
    prefix[i] = line[word_start + i];
  prefix[copy_len] = '\0';
  prefix_len = copy_len;

  int match_count = 0;
  char local_matches[SHELL_TAB_MATCH_MAX][SHELL_TAB_MATCH_LEN];
  char(*dest)[SHELL_TAB_MATCH_LEN] =
      matches ? matches : local_matches;
  int dest_max = matches ? max_matches : SHELL_TAB_MATCH_MAX;
  if (dest_max > SHELL_TAB_MATCH_MAX)
    dest_max = SHELL_TAB_MATCH_MAX;
  if (dest_max < 1)
    return 0;

  if (is_command)
  {
    for (size_t i = 0; shell_commands[i] != NULL; i++)
    {
      if (!shell_prefix_eq_ci(shell_commands[i], prefix, prefix_len))
        continue;
      if (match_count < dest_max)
      {
        kstrncpy(dest[match_count], shell_commands[i], SHELL_TAB_MATCH_LEN);
        match_count++;
      }
    }
  }
  else
  {
    fat12_ctx ctx;
    if (!fat12_init(&ctx))
      return 0;

    uint8_t *buf = 0;
    uint32_t bytes = 0;
    int ok = 0;
    if (fat12_cwd_cluster == 0)
      ok = fat12_read_root_dir(&ctx, &buf, &bytes);
    else
      ok = fat12_read_dir_cluster(&ctx, fat12_cwd_cluster, &buf, &bytes);

    if (!ok)
    {
      fat12_deinit(&ctx);
      return 0;
    }

    uint32_t entries = bytes / 32u;
    if (entries > 512)
      entries = 512;

    for (uint32_t i = 0; i < entries; i++)
    {
      struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
      if (e->name[0] == 0x00)
        break;
      if (e->name[0] == 0xE5 || (e->attr & 0x08))
        continue;

      char n[256];
      fat12_display_name(buf, i * 32u, n, sizeof(n));

      char lower[SHELL_TAB_MATCH_LEN];
      int j = 0;
      while (j < (int)sizeof(lower) - 1 && n[j] != '\0')
      {
        if (n[j] >= 'A' && n[j] <= 'Z')
          lower[j] = (char)(n[j] - 'A' + 'a');
        else
          lower[j] = n[j];
        j++;
      }
      lower[j] = '\0';

      if (!shell_prefix_eq_ci(lower, prefix, prefix_len))
        continue;
      if (match_count < dest_max)
      {
        kstrncpy(dest[match_count], lower, SHELL_TAB_MATCH_LEN);
        match_count++;
      }
    }

    if (buf)
      kfree(buf);
    fat12_deinit(&ctx);
  }

  if (match_count == 1)
  {
    shell_apply_word(line, len, cap, word_start, dest[0], is_command ? 1 : 0);
    return 1;
  }

  if (match_count > 1)
  {
    /* Extend to longest common prefix when it grows the current word. */
    size_t cp = kstrlen(dest[0]);
    for (int i = 1; i < match_count; i++)
    {
      size_t j = 0;
      while (j < cp && dest[0][j] && dest[i][j])
      {
        char a = dest[0][j];
        char b = dest[i][j];
        if (a >= 'A' && a <= 'Z')
          a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
          b = (char)(b - 'A' + 'a');
        if (a != b)
          break;
        j++;
      }
      cp = j;
    }
    if (cp > prefix_len)
    {
      char common[SHELL_TAB_MATCH_LEN];
      if (cp >= sizeof(common))
        cp = sizeof(common) - 1;
      for (size_t i = 0; i < cp; i++)
        common[i] = dest[0][i];
      common[cp] = '\0';
      shell_apply_word(line, len, cap, word_start, common, 0);
    }
  }

  return match_count;
}

static void readline(const char *prompt, char *out, size_t out_cap)
{
  log_writestring(prompt);

  size_t len = 0;
  size_t pos = 0; // Cursor position within the string
  out[0] = '\0';
  int browsing = 0;
  size_t browse_pos = 0;
  char saved_line[LINE_MAX];
  saved_line[0] = '\0';

  size_t prompt_row = terminal_row;
  size_t prompt_col = terminal_column;
  size_t prev_drawn = 0;

  for (;;)
  {
    int key = input_getkey();
    if (key == '\n')
    {
      out[len] = '\0';
      log_putchar('\n');
      break;
    }

    if (key == '\t')
    {
      /* Complete at end of line (commands or filenames). */
      if (pos == len)
      {
        char matches[SHELL_TAB_MATCH_MAX][SHELL_TAB_MATCH_LEN];
        size_t old_len = len;
        int n = shell_tab_complete(out, &len, out_cap, matches,
                                   SHELL_TAB_MATCH_MAX);
        pos = len;
        if (n == 1 || (n > 1 && len > old_len))
        {
          redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                            &prev_drawn);
        }
        if (n > 1)
        {
          log_putchar('\n');
          for (int i = 0; i < n; i++)
          {
            log_writestring(matches[i]);
            log_writestring("  ");
          }
          log_putchar('\n');
          log_writestring(prompt);
          prompt_row = terminal_row;
          prompt_col = terminal_column;
          prev_drawn = 0;
          redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                            &prev_drawn);
        }
      }
      continue;
    }

    if (key == '\b')
    {
      if (pos > 0)
      {
        // Shift characters left
        for (size_t i = pos; i <= len; i++)
        {
          out[i - 1] = out[i];
        }
        len--;
        pos--;
        redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                          &prev_drawn);
      }
      continue;
    }

    if (key == KEY_DELETE)
    {
      if (pos < len)
      {
        // Shift characters left
        for (size_t i = pos + 1; i <= len; i++)
        {
          out[i - 1] = out[i];
        }
        len--;
        redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                          &prev_drawn);
      }
      continue;
    }

    if (key == KEY_LEFT)
    {
      if (pos > 0)
      {
        pos--;
        redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                          &prev_drawn);
      }
      continue;
    }

    if (key == KEY_RIGHT)
    {
      if (pos < len)
      {
        pos++;
        redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                          &prev_drawn);
      }
      continue;
    }

    if (key == KEY_UP || key == KEY_DOWN)
    {
      if (history_count == 0)
        continue;

      if (!browsing)
      {
        size_t i = 0;
        for (; i < (out_cap - 1) && out[i] != '\0'; i++)
          saved_line[i] = out[i];
        saved_line[i] = '\0';
        browsing = 1;

        if (key == KEY_UP)
        {
        browse_pos = history_count - 1;
        }
        else
        {
          // KEY_DOWN when not browsing: doesn't do much, maybe ignore
          browsing = 0;
          continue;
        }
      }
      else
      {
        if (key == KEY_UP)
        {
          if (browse_pos > 0)
          {
            browse_pos--;
          }
        }
        else
        {
          if (browse_pos < (history_count - 1))
          {
            browse_pos++;
          }
          else
          {
            // Back to what was being typed
            size_t i = 0;
            for (; i < (out_cap - 1) && saved_line[i] != '\0'; i++)
              out[i] = saved_line[i];
            out[i] = '\0';
            len = i;
            pos = i;
            browsing = 0;
            redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                              &prev_drawn);
            continue;
          }
        }
      }

      const char *h = history_get(browse_pos);
      if (h)
      {
      size_t i = 0;
      for (; i < (out_cap - 1) && h[i] != '\0'; i++)
        out[i] = h[i];
      out[i] = '\0';
      len = i;
      pos = i;
        redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                          &prev_drawn);
      }
      continue;
    }

    if (key >= 0x20 && key <= 0x7E)
    {
      if (len + 1 < out_cap)
      {
        if (browsing)
          browsing = 0;
        // Shift characters right
        for (size_t i = len + 1; i > pos; i--)
        {
          out[i] = out[i - 1];
        }
        out[pos] = (char)key;
        len++;
        pos++;
        redraw_input_line(prompt, prompt_row, prompt_col, out, len, pos,
                          &prev_drawn);
      }
    }
  }
}

static void cmd_ip_stat(void)
{
  extern uint32_t ip4_get_rx_count(void);
  extern uint32_t ip4_get_tx_count(void);
  uint32_t my_ip = arp_get_ajos_ip();
  log_writestring("AJOS IP: ");
  log_write_u32((my_ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((my_ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((my_ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(my_ip & 0xFF);
  log_putchar('\n');
  log_writestring("IP RX Packets: ");
  log_write_u32(ip4_get_rx_count());
  log_putchar('\n');
  log_writestring("IP TX Packets: ");
  log_write_u32(ip4_get_tx_count());
  log_putchar('\n');
}

static void cmd_history(void)
{
  // Print the most recent HISTORY_SIZE commands (oldest -> newest)
  size_t start = 0;
  if (history_count > HISTORY_SIZE)
  {
    start = history_count - HISTORY_SIZE;
  }
  for (size_t i = start; i < history_count; i++)
  {
    const char *h = history_get(i);
    if (!h)
      continue;
    log_write_u32((uint32_t)i);
    log_writestring(": ");
    log_writestring(h);
    log_putchar('\n');
  }
}

static int parse_ip(const char **s_ptr, uint32_t *ip_out)
{
  const char *s = *s_ptr;
  uint32_t ip = 0;
  uint32_t part;
  for (int i = 0; i < 4; i++)
  {
    part = 0;
    if (*s < '0' || *s > '9')
      return 0;
    while (*s >= '0' && *s <= '9')
    {
      part = part * 10 + (*s - '0');
      s++;
    }
    if (part > 255)
      return 0;
    ip = (ip << 8) | part;
    if (i < 3)
    {
      if (*s != '.')
        return 0;
      s++;
    }
  }
  *s_ptr = s;
  *ip_out = ip;
  return 1;
}

static uint64_t isqrt(uint64_t n)
{
  if (n < 2)
    return n;
  uint64_t x = n / 2 + 1;
  uint64_t y = (x + n / x) / 2;
  while (y < x)
  {
    x = y;
    y = (x + n / x) / 2;
  }
  return x;
}

static void log_write_time_ms(uint64_t us)
{
  log_write_u32((uint32_t)(us / 1000));
  log_putchar('.');
  uint32_t frac = (uint32_t)(us % 1000);
  if (frac < 100)
    log_putchar('0');
  if (frac < 10)
    log_putchar('0');
  log_write_u32(frac);
}

static void net_pump_rx(int budget);

/* Wait until pit_ticks advances (~1/PIT_HZ s). `sleep_ms()` is a short busy-wait,
 * not real milliseconds; ping used it inside a spin-capped loop and could bail
 * before the PIT advanced → bogus ICMP timeouts and flaky SSH during ping. */
static void net_wait_pit_tick(uint32_t *prev_tick)
{
  uint32_t spins = 0;
  while (pit_ticks == *prev_tick && spins < 5000000u)
  {
    __asm__ volatile("sti");
    net_pump_rx(8);
    spins++;
  }
  *prev_tick = pit_ticks;
}

static void cmd_ping(const char *args)
{
  extern volatile uint32_t icmp_echo_reply_count;
  extern volatile uint32_t icmp_last_echo_reply_src;
  extern volatile uint16_t icmp_last_echo_reply_id;
  extern volatile uint16_t icmp_last_echo_reply_seq;
  extern volatile uint8_t icmp_last_echo_reply_ttl;
  extern int input_getkey_noblock(void);
  extern uint32_t eth_get_rx_count(void);
  extern uint32_t ip4_get_rx_count(void);

  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: ping <ip>\n");
    return;
  }

  uint32_t ip = 0;
  if (!parse_ip(&s, &ip))
  {
    extern volatile int dns_got_reply;
    extern volatile uint32_t dns_last_ip;
    const char *name = skip_spaces(args);
    if (!*name)
    {
      log_writestring("Invalid IP\n");
      return;
    }
    for (int attempt = 0; attempt < 2; attempt++)
    {
      dns_lookup(name);
      uint32_t start = pit_ticks;
      uint32_t dns_spins = 0;
      while ((pit_ticks - start) < (PIT_HZ * 3u) && dns_spins < 50000u)
      {
        net_pump_rx(8);
        ssh_flow_pump_from_shell();
        if (dns_got_reply)
        {
          ip = dns_last_ip;
          break;
        }
        sleep_ms(50);
        ssh_flow_pump_from_shell();
        dns_spins++;
      }
      if (ip != 0)
        break;
    }
    if (ip == 0)
    {
      log_writestring("ping: dns timeout\n");
      return;
    }
  }

  log_writestring("PING ");
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring(" (");
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring("): 56 data bytes\n");

  eth_addr_t tmp_mac;
  uint32_t my_ip = arp_get_ajos_ip();
  uint32_t mask = ip4_get_netmask();
  uint32_t gw = ip4_get_gateway();
  uint32_t next_hop = ip;
  if (my_ip != 0 && mask != 0 && gw != 0)
  {
    if ((ip & mask) != (my_ip & mask))
    {
      next_hop = gw;
    }
  }

  uint32_t start_ticks = pit_ticks;
  uint32_t arp_spins = 0;
  while (!arp_get_mac_for_ip(next_hop, &tmp_mac))
  {
    net_pump_rx(8);
    ssh_flow_pump_from_shell();
    arp_query(next_hop);
    if ((pit_ticks - start_ticks) > (PIT_HZ * 1u) || arp_spins++ > 20000u)
    {
      log_writestring("ping: ARP resolution timeout\n");
      return;
    }
    sleep_ms(50);
    ssh_flow_pump_from_shell();
  }

  uint16_t ping_id = 0x1234;
  static uint16_t ping_seq_gen = 0;

  uint32_t transmitted = 0;
  uint32_t received = 0;
  uint64_t min_us = 0xFFFFFFFFFFFFFFFF;
  uint64_t max_us = 0;
  uint64_t sum_us = 0;
  uint64_t sum_sq_us = 0;
  int ping_hw_logged = 0;

  for (int i = 0; i < 10; i++)
  {
    if (input_getkey_noblock() != -1)
    {
      break;
    }

    uint32_t before = icmp_echo_reply_count;
    uint16_t seq = ++ping_seq_gen;
    transmitted++;

  struct pbuf *p = pbuf_alloc();
  if (!p)
      break;

  pbuf_header(p, -(int)sizeof(struct icmp_hdr));
  struct icmp_hdr *hdr = (struct icmp_hdr *)p->payload;
  hdr->type = ICMP_TYPE_ECHO_REQUEST;
  hdr->code = 0;
  hdr->chksum = 0;
  hdr->id = htons(ping_id);
  hdr->seqno = htons(seq);
  p->len = sizeof(struct icmp_hdr);
  hdr->chksum = net_checksum(hdr, sizeof(struct icmp_hdr));

    uint64_t t_start = get_time_us();
  int send_ret = ip4_output(p, ip, IP_PROTO_ICMP);
    if (send_ret < 0)
    {
      // #region agent log
      agent_dbg_evt("E", "cmd_ping", "send_fail", (uint32_t)i,
                    (uint32_t)(int32_t)send_ret);
      // #endregion
      log_writestring("Request timeout for icmp_seq ");
      log_write_u32(i);
      log_putchar('\n');
      sleep_ms(1000);
      ssh_flow_pump_from_shell();
      continue;
    }

    int got_reply = 0;
    uint32_t wait_start = pit_ticks;
    uint32_t last_tick = pit_ticks;
    uint32_t eth_rx_wait0 = eth_get_rx_count();
    uint32_t ip4_rx_wait0 = ip4_get_rx_count();
    while ((pit_ticks - wait_start) < (PIT_HZ * 2u))
    {
      net_pump_rx(16);
      ssh_flow_pump_from_shell();
      if (icmp_echo_reply_count != before && icmp_last_echo_reply_src == ip &&
          icmp_last_echo_reply_id == ping_id &&
          icmp_last_echo_reply_seq == seq)
      {
        uint64_t t_end = get_time_us();
        uint64_t rtt = t_end - t_start;
        received++;
        if (rtt < min_us)
          min_us = rtt;
        if (rtt > max_us)
          max_us = rtt;
        sum_us += rtt;
        sum_sq_us += (rtt * rtt);

        log_writestring("64 bytes from ");
        log_write_u32((ip >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((ip >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((ip >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(ip & 0xFF);
        log_writestring(": icmp_seq=");
        log_write_u32(i);
        log_writestring(" ttl=");
        log_write_u32(icmp_last_echo_reply_ttl);
        log_writestring(" time=");
        log_write_time_ms(rtt);
        log_writestring(" ms\n");
        got_reply = 1;
        break;
      }
      net_wait_pit_tick(&last_tick);
    }

    if (!got_reply)
    {
      // #region agent log
      if (!ping_hw_logged)
      {
        ping_hw_logged = 1;
        uint32_t ring_pack = 0, flg_icr = 0;
        e1000_debug_snap(&ring_pack, &flg_icr);
        agent_dbg_ping_hw(ring_pack, flg_icr,
                          (uint32_t)netdev_napi_registry_count());
      }
      uint32_t eth_d = eth_get_rx_count() - eth_rx_wait0;
      uint32_t ip4_d = ip4_get_rx_count() - ip4_rx_wait0;
      agent_dbg_ping_to(before, (uint32_t)icmp_echo_reply_count, eth_d, ip4_d,
                        ip4_get_policy_drop_count(),
                        icmp_last_echo_reply_src);
      // #endregion
      log_writestring("Request timeout for icmp_seq ");
      log_write_u32(i);
    log_putchar('\n');
    }

    if (i < 9)
    {
      sleep_ms(1000);
      ssh_flow_pump_from_shell();
    }
  }

  log_writestring("\n--- ");
  log_write_u32((ip >> 24) & 0xFF);
    log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
    log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
    log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring(" ping statistics ---\n");

  log_write_u32(transmitted);
  log_writestring(" packets transmitted, ");
  log_write_u32(received);
  log_writestring(" packets received, ");
  if (transmitted > 0)
  {
    uint32_t loss = ((transmitted - received) * 100) / transmitted;
    log_write_u32(loss);
    log_writestring(".0% packet loss\n");
  }
  else
  {
    log_writestring("0.0% packet loss\n");
  }

  if (received == 0 && transmitted > 0)
  {
    /* Short ASCII lines: long UTF-8 text was truncated on serial under load. */
    int on_lan = (my_ip != 0 && mask != 0 &&
                  (ip & mask) == (my_ip & mask));
    if (ip == gw || on_lan)
    {
      log_writestring(
          "[PING] No replies on LAN/gateway: not a user-net Internet issue.\n");
      log_writestring("[PING] Check RX path (e1000), heap (pbuf), or post-SSH "
                      "state.\n");
    }
    else
    {
      log_writestring(
          "[PING] No replies: user-net often drops ICMP to the Internet.\n");
      log_writestring("[PING] In the AJOS shell (not macOS), try: ping "
                      "10.0.2.2\n");
    }
  }

  if (received > 0)
  {
    uint64_t avg_us = sum_us / received;
    // variance = (sum_sq / N) - (sum / N)^2
    uint64_t var_us2 = (sum_sq_us / received) - (avg_us * avg_us);
    uint64_t stddev_us = isqrt(var_us2);

    log_writestring("round-trip min/avg/max/stddev = ");
    log_write_time_ms(min_us);
    log_putchar('/');
    log_write_time_ms(avg_us);
    log_putchar('/');
    log_write_time_ms(max_us);
    log_putchar('/');
    log_write_time_ms(stddev_us);
    log_writestring(" ms\n");
  }
}

// cmd_ifconfig moved to e1000.c

static void cmd_udp_send(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: udp_send <ip> <src_port> <dst_port> <msg>\n");
    return;
  }

  // Parse IP
  uint32_t ip = 0;
  uint32_t part;
  for (int i = 0; i < 4; i++)
  {
    part = 0;
    while (*s >= '0' && *s <= '9')
    {
      part = part * 10 + (*s - '0');
      s++;
    }
    ip = (ip << 8) | (part & 0xFF);
    if (*s == '.')
      s++;
  }
  s = skip_spaces(s);

  // Parse src_port
  uint16_t src_port = 0;
  while (*s >= '0' && *s <= '9')
  {
    src_port = src_port * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  // Parse dst_port
  uint16_t dst_port = 0;
  while (*s >= '0' && *s <= '9')
  {
    dst_port = dst_port * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  // Remaining is message
  int msg_len = 0;
  while (s[msg_len])
    msg_len++;

  struct pbuf *p = pbuf_alloc();
  if (!p)
    return;

  // Reserve space for UDP header
  pbuf_header(p, -(int)sizeof(struct udp_hdr));
  uint8_t *data = (uint8_t *)p->payload + sizeof(struct udp_hdr);
  for (int i = 0; i < msg_len; i++)
  {
    data[i] = s[i];
  }
  p->len = sizeof(struct udp_hdr) + msg_len;

  udp_output(p, ip, src_port, dst_port);
}

extern void tcp_init(void);
extern struct tcp_pcb *tcp_find_pcb(ip_addr_t local_ip, uint16_t local_port,
                                    ip_addr_t remote_ip, uint16_t remote_port);
// Wait, tcp_pcb is in net.h, so we can use it if we include it correctly.

static void cmd_tcp_listen(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: tcp_listen <port>\n");
    return;
  }

  uint16_t port = 0;
  while (*s >= '0' && *s <= '9')
  {
    port = port * 10 + (*s - '0');
    s++;
  }

  // Find a free PCB
  extern struct tcp_pcb *tcp_get_free_pcb(void);
  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (pcb)
  {
    pcb->local_port = port;
    pcb->state = TCP_LISTEN;
    pcb->local_ip = arp_get_ajos_ip();
    log_writestring("TCP: Listening on port ");
    log_write_u32(port);
    log_putchar('\n');
  }
  else
  {
    log_writestring("TCP: No free PCBs\n");
  }
}

static void cmd_http_stat(const char *args);
static void cmd_http_test(const char *args);
static void cmd_dhcpd_stat(const char *args);
static void cmd_dnsd_stat(const char *args);
static void cmd_auth_stat(const char *args);
static void cmd_adduser(const char *args);
static void cmd_deluser(const char *args);
static void cmd_passwd(const char *args);
static void cmd_users(const char *args);
static void cmd_policy_stat(const char *args);
static void cmd_test_policy(const char *args);
static void cmd_test_auth_add(const char *args);
static void cmd_dhcpd_stat(const char *args);

static void cmd_dnsd_stat(const char *args);

static void cmd_tcp_stat(void)
{
  extern struct tcp_pcb *tcp_get_pcb_at(int idx);
  log_writestring("TCP active PCBs:\n");
  for (int i = 0; i < 16; i++)
  {
    struct tcp_pcb *pcb = tcp_get_pcb_at(i);
    if (!pcb || pcb->state == TCP_CLOSED)
      continue;

    log_writestring("  [");
    log_write_u32(i);
    log_writestring("] State: ");
    log_write_u32(pcb->state); // Simple for now
    log_writestring(" Local: ");
    log_write_u32((pcb->local_ip >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((pcb->local_ip >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((pcb->local_ip >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(pcb->local_ip & 0xFF);
    log_putchar(':');
    log_write_u32(pcb->local_port);
    log_writestring("\n");
  }
}

static void cmd_tcp_test_syn(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring(
        "Usage: tcp_test_syn <remote_ip> <remote_port> <local_port>\n");
    return;
  }

  // Parse remote IP
  uint32_t rip = 0;
  uint32_t part;
  for (int i = 0; i < 4; i++)
  {
    part = 0;
    while (*s >= '0' && *s <= '9')
    {
      part = part * 10 + (*s - '0');
      s++;
    }
    rip = (rip << 8) | (part & 0xFF);
    if (*s == '.')
      s++;
  }
  s = skip_spaces(s);

  // Parse remote port
  uint16_t rport = 0;
  while (*s >= '0' && *s <= '9')
  {
    rport = rport * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  // Parse local port
  uint16_t lport = 0;
  while (*s >= '0' && *s <= '9')
  {
    lport = lport * 10 + (*s - '0');
    s++;
  }

  // Create a synthetic pbuf
  struct pbuf *p = pbuf_alloc();
  if (!p)
    return;

  pbuf_header(p, -(int)sizeof(struct tcp_hdr));
  struct tcp_hdr *hdr = (struct tcp_hdr *)p->payload;
  hdr->src_port = htons(rport);
  hdr->dst_port = htons(lport);
  hdr->seqno = htonl(12345);
  hdr->ackno = 0;
  hdr->_offset_flags = htons((5 << 12) | TCP_SYN);
  hdr->window = htons(1024);
  hdr->chksum = 0;
  hdr->urgptr = 0;
  p->len = sizeof(struct tcp_hdr);

  tcp_input(p, rip, arp_get_ajos_ip());
  log_writestring("Simulated SYN sent to stack.\n");
}

static void net_dhcp_perform(void)
{
  extern volatile int dhcp_got_offer;
  extern volatile int dhcp_got_ack;

  log_writestring("dhcp: starting\n");

  // If DHCP fails, restore previous IP so the system doesn't end up at
  // 0.0.0.0.
  uint32_t prev_ip = arp_get_ajos_ip();
  // Always go to 0.0.0.0 while negotiating (DHCP servers may behave
  // differently if we already have an address configured).
  arp_set_ajos_ip(0);

  // Reset state before starting
  extern uint32_t dhcp_offered_ip;
  extern uint32_t dhcp_server_ip;
  dhcp_offered_ip = 0;
  dhcp_server_ip = 0;

  // Try a few times; some emulations drop the first REQUEST/ACK exchange.
  for (int attempt = 0; attempt < 3; attempt++)
  {
    dhcp_start();

    uint32_t start = pit_ticks;
    while ((pit_ticks - start) < (PIT_HZ * 5u))
    {
      // Proactively pump NIC RX while waiting for DHCP OFFER/ACK.
      // This makes DHCP reliable even if IRQ delivery is flaky in emulation.
      net_pump_rx(8);

      if (dhcp_got_ack)
      {
        uint32_t ip = arp_get_ajos_ip();
        uint32_t mask = ip4_get_netmask();
        uint32_t gw = ip4_get_gateway();
        uint32_t dns = dns_get_server();

        // Debug: check if IP is actually set
        if (ip == 0)
        {
          extern uint32_t dhcp_offered_ip;
          log_writestring("dhcp: WARNING - IP is 0 after ACK! offered_ip=");
          extern void log_write_hex32(uint32_t v);
          log_write_hex32(dhcp_offered_ip);
          log_putchar('\n');
          // Try to use offered_ip as fallback (should have been done in ACK
          // handler, but double-check)
          if (dhcp_offered_ip != 0)
          {
            log_writestring(
                "dhcp: attempting fallback to offered_ip in main loop\n");
            arp_set_ajos_ip(dhcp_offered_ip);
            ip = arp_get_ajos_ip();
            log_writestring("dhcp: after fallback, ip=");
            log_write_hex32(ip);
            log_putchar('\n');
          }
        }

        log_writestring("dhcp: lease acquired ip=");
        log_write_u32((ip >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((ip >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((ip >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(ip & 0xFF);
        log_writestring(" mask=");
        log_write_u32((mask >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((mask >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((mask >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(mask & 0xFF);
        log_writestring(" gw=");
        log_write_u32((gw >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((gw >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((gw >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(gw & 0xFF);
        log_writestring(" dns=");
        log_write_u32((dns >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((dns >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((dns >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(dns & 0xFF);
        log_putchar('\n');
        return;
      }
      sleep_ms(20);
    }
  }

  log_writestring("dhcp: failed\n");
  // Helpful diagnostics for debugging flaky emulation networking.
  extern uint32_t eth_get_rx_count(void);
  extern uint32_t eth_get_tx_count(void);
  extern uint32_t ip4_get_rx_count(void);
  extern uint32_t ip4_get_tx_count(void);
  extern uint32_t ip4_get_policy_drop_count(void);
  log_writestring("dhcp: stats eth_rx=");
  log_write_u32(eth_get_rx_count());
  log_writestring(" eth_tx=");
  log_write_u32(eth_get_tx_count());
  log_writestring(" ip_rx=");
  log_write_u32(ip4_get_rx_count());
  log_writestring(" ip_tx=");
  log_write_u32(ip4_get_tx_count());
  log_writestring(" ip_policy_drop=");
  log_write_u32(ip4_get_policy_drop_count());
  log_putchar('\n');
  if (prev_ip != 0)
  {
    arp_set_ajos_ip(prev_ip);
    log_writestring("dhcp: restored previous ip\n");
  }
}

static void cmd_dhcp(void) { net_dhcp_perform(); }

// Pump NIC RX in polling builds / flaky IRQ emulation.
static void net_pump_rx(int budget)
{
  if (budget <= 0)
    return;
  // Use the driver's NAPI-style budgeted poller.
  netdev_napi_poll(budget);
}

static void cmd_dns(const char *args)
{
  extern volatile int dns_got_reply;
  extern volatile uint32_t dns_last_ip;
  const char *name = skip_spaces(args);
  if (!*name)
  {
    log_writestring("Usage: dns <hostname>\n");
    return;
  }

  for (int attempt = 0; attempt < 2; attempt++)
  {
    dns_lookup(name);

    // Wait for reply (best-effort). DNS RX runs in IRQ context; we only print
    // here.
    uint32_t start = pit_ticks;
    uint32_t dns_cmd_spins = 0;
    while ((pit_ticks - start) < (PIT_HZ * 3u) && dns_cmd_spins < 50000u)
    {
      net_pump_rx(8);
      if (dns_got_reply)
      {
        uint32_t ip = dns_last_ip;
        log_writestring("dns: ");
        log_writestring(name);
        log_writestring(" -> ");
        log_write_u32((ip >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((ip >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((ip >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(ip & 0xFF);
        log_putchar('\n');
        ssh_shell_log_flush();
        return;
      }
      sleep_ms(50);
      dns_cmd_spins++;
    }
  }
  log_writestring("dns: timeout\n");
  ssh_shell_log_flush();
}

static int net_config_load(const char *filename)
{
  uint8_t *buf = NULL;
  uint32_t size = 0;
  int is_ram_slot = 0;

  // 1. Try RAM slots
  for (int i = 0; i < FILE_SLOTS; i++)
  {
    if (file_slots[i].ptr != (void *)0)
    {
      const char *n1 = filename;
      const char *n2 = file_slots[i].name;
      while (*n1 && (*n1 == *n2))
      {
        n1++;
        n2++;
      }
      if (*n1 == '\0' && *n2 == '\0')
      {
        buf = (uint8_t *)file_slots[i].ptr;
        size = file_slots[i].size;
        is_ram_slot = 1;
        break;
      }
    }
  }

  // 2. Try Disk
  if (!buf)
  {
    if (!fat12_read_file_to_ram(filename, &buf, &size))
    {
      return 0; // Not found
    }
  }

  log_writestring("[NetCfg] Loading from ");
  log_writestring(is_ram_slot ? "RAM: " : "Disk: ");
  log_writestring(filename);
  log_putchar('\n');

  int res = netcfg_load_from_buffer((const char *)buf, size);
  if (!is_ram_slot)
  {
    kfree(buf);
  }
  return res;
}

static void cmd_netcfg(const char *args)
{
  const char *filename = skip_spaces(args);
  if (!*filename)
  {
    // Try /etc/NETWORK.CFG first, fallback to root NETWORK.CFG
    if (fat12_read_file_to_ram("etc/NETWORK.CFG", 0, 0))
    {
      filename = "etc/NETWORK.CFG";
    }
    else
    {
    filename = "NETWORK.CFG";
    }
  }

  int res = net_config_load(filename);
  if (res == 0)
  {
    log_writestring("[NetCfg] File not found: ");
    log_writestring(filename);
    log_putchar('\n');
  }
  else if (res == 2)
  {
    log_writestring("[NetCfg] DHCP requested\n");
  }
  else if (res == 0)
  {
    log_writestring("[NetCfg] No static IP, use DHCP\n");
  }
}

static void network_auto_setup(void)
{
  // Hardcode IP for QEMU user-net (10.0.2.15) to bypass filesystem issues
  log_writestring("[NetCfg] Forcing static IP: 10.0.2.15\n");
  arp_set_ajos_ip(0x0A00020F); // 10.0.2.15 in hex
  ip4_set_netmask(0xFFFFFF00); // 255.255.255.0
  ip4_set_gateway(0x0A000202); // 10.0.2.2
  dns_set_server(0x08080808);  // 8.8.8.8

  // Start SSH and HTTP listener updates
  extern void sshd_update_listener_ip(uint32_t ip);
  sshd_update_listener_ip(0x0A00020F);
  return;

  // Try /etc/NETWORK.CFG first, fallback to root NETWORK.CFG
  int res = net_config_load("etc/NETWORK.CFG");
  if (res == 0)
  {
    res = net_config_load("NETWORK.CFG");
  }
  if (res == 1)
  {
    return; // Static IP set
  }
  // res == 2 (DHCP) or res == 0 (file not found/fallback)
  //
  // IMPORTANT: Don't block boot on DHCP. Start it in the background and let
  // `timer_handler()`'s RX polling + udp_input() drive dhcp_input().
  log_writestring("[NetCfg] Starting DHCP (background)\n");
  // Keep the current IP while negotiating so networking still works even if
  // DHCP is flaky in emulation. The interactive `dhcp` command will still
  // negotiate from 0.0.0.0 and restore the previous IP on failure.
  dhcp_start();
}

static void cmd_tcp_connect(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: tcp_connect <ip> <port>\n");
    return;
  }

  uint32_t ip = 0;
  if (!parse_ip(&s, &ip))
  {
    log_writestring("Invalid IP\n");
    return;
  }

  s = skip_spaces(s);
  uint32_t port = 0;
  if (!parse_u32(s, &port) || port > 65535)
  {
    log_writestring("Invalid port\n");
    return;
  }

  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb)
  {
    log_writestring("No free PCBs\n");
    return;
  }

  log_writestring("Connecting to ");
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring(":");
  log_write_u32(port);
  log_putchar('\n');

  tcp_connect(pcb, ip, (uint16_t)port);
}

// HTTP response parser helper
static int http_parse_response(const uint8_t *buf, uint16_t len,
                               uint16_t *status_code, uint16_t *header_end,
                               uint32_t *content_length)
{
  // Find status line (HTTP/1.x CODE ...)
  uint16_t i = 0;
  while (i + 8 < len)
  {
    if (buf[i] == 'H' && buf[i + 1] == 'T' && buf[i + 2] == 'T' &&
        buf[i + 3] == 'P' && buf[i + 4] == '/' && buf[i + 5] >= '0' &&
        buf[i + 5] <= '9')
    {
      // Found HTTP/ version, skip to status code
      i += 8; // Skip "HTTP/1.x "
      if (i + 3 < len && buf[i] >= '0' && buf[i] <= '9')
      {
        *status_code = (uint16_t)((buf[i] - '0') * 100 +
                                  (buf[i + 1] - '0') * 10 + (buf[i + 2] - '0'));
      }
      break;
    }
    i++;
  }

  // Find end of headers (\r\n\r\n)
  *header_end = 0;
  for (i = 0; i + 3 < len; i++)
  {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' &&
        buf[i + 3] == '\n')
    {
      *header_end = i + 4;
      break;
    }
  }

  // Try to find Content-Length header
  *content_length = 0;
  for (i = 0; i + 15 < len; i++)
  {
    if (buf[i] == 'C' && buf[i + 1] == 'o' && buf[i + 2] == 'n' &&
        buf[i + 3] == 't' && buf[i + 4] == 'e' && buf[i + 5] == 'n' &&
        buf[i + 6] == 't' && buf[i + 7] == '-' && buf[i + 8] == 'L' &&
        buf[i + 9] == 'e' && buf[i + 10] == 'n' && buf[i + 11] == 'g' &&
        buf[i + 12] == 't' && buf[i + 13] == 'h' && buf[i + 14] == ':')
    {
      i += 15;
      while (i < len && buf[i] == ' ')
        i++;
      uint32_t cl = 0;
      while (i < len && buf[i] >= '0' && buf[i] <= '9')
      {
        cl = cl * 10 + (buf[i] - '0');
        i++;
      }
      *content_length = cl;
      break;
    }
  }

  return (*header_end > 0);
}

// wget command - download file via HTTP
static void cmd_wget(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: wget <url> [output_file]\n");
    log_writestring(
        "  URL format: http://<host>/<path> or http://<ip>/<path>\n");
    return;
  }

  // Parse URL (simple: http://host/path)
  if (s[0] != 'h' || s[1] != 't' || s[2] != 't' || s[3] != 'p' || s[4] != ':' ||
      s[5] != '/' || s[6] != '/')
  {
    log_writestring("wget: URL must start with http://\n");
    return;
  }
  s += 7; // Skip "http://"

  char host[128];
  int hi = 0;
  while (*s && *s != '/' && hi < (int)sizeof(host) - 1)
  {
    host[hi++] = *s++;
  }
  host[hi] = '\0';

  const char *path = *s ? s : "/";

  // Parse output filename (optional - everything after URL)
  const char *orig_args = skip_spaces(args);
  const char *url_end = s; // s points to path now
  // Find end of URL (first space after path)
  while (*url_end && *url_end != ' ')
    url_end++;
  const char *outfile_arg = skip_spaces(url_end);

  char outfile[64] = "index.html";
  if (*outfile_arg)
  {
    int oi = 0;
    while (*outfile_arg && oi < (int)sizeof(outfile) - 1)
    {
      outfile[oi++] = *outfile_arg++;
    }
    outfile[oi] = '\0';
  }
  else
  {
    // Default: use last component of path as filename
    const char *last_slash = path;
    const char *p = path;
    while (*p)
    {
      if (*p == '/')
        last_slash = p + 1;
      p++;
    }
    if (*last_slash)
    {
      int oi = 0;
      while (*last_slash && *last_slash != '?' &&
             oi < (int)sizeof(outfile) - 1)
      {
        outfile[oi++] = *last_slash++;
      }
      outfile[oi] = '\0';
    }
  }

  // Resolve hostname to IP (try DNS first, then parse as IP)
  uint32_t ip = 0;
  extern volatile int dns_got_reply;
  extern volatile uint32_t dns_last_ip;
  dns_got_reply = 0;
  extern void dns_lookup(const char *name);
  dns_lookup(host);

  uint32_t start = pit_ticks;
  while ((pit_ticks - start) < (PIT_HZ * 3u))
  {
    net_pump_rx(8);
    if (dns_got_reply)
    {
      ip = dns_last_ip;
      break;
    }
    sleep_ms(50);
  }

  // If DNS failed, try parsing host as IP
  if (ip == 0)
  {
    const char *ip_str = host;
    if (!parse_ip(&ip_str, &ip))
    {
      log_writestring("wget: could not resolve hostname\n");
      return;
    }
  }

  // Connect and send HTTP request
  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb)
  {
    log_writestring("wget: no free pcb\n");
    return;
  }

  log_writestring("wget: connecting to ");
  log_writestring(host);
  log_writestring("...\n");

  int connected = 0;
  for (int attempt = 0; attempt < 2; attempt++)
  {
    tcp_connect(pcb, ip, 80);
    start = pit_ticks;
    while ((pit_ticks - start) < (PIT_HZ * 6u))
    {
      if (pcb->state == TCP_ESTABLISHED)
      {
        connected = 1;
        break;
      }
      if (pcb->state == TCP_CLOSED)
      {
        break;
      }
      sleep_ms(50);
    }
    if (connected)
      break;
    pcb->state = TCP_CLOSED;
    sleep_ms(100);
  }

  if (!connected)
  {
    log_writestring("wget: connect timeout\n");
    return;
  }

  pcb->app_rx_len = 0;

  // Build HTTP request
  char req[512];
  int n = 0;
  const char *pfx = "GET ";
  for (int i = 0; pfx[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = pfx[i];
  for (int i = 0; path[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = path[i];
  const char *mid = " HTTP/1.0\r\nHost: ";
  for (int i = 0; mid[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = mid[i];
  for (int i = 0; host[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = host[i];
  const char *end = "\r\n\r\n";
  for (int i = 0; end[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = end[i];
  req[n] = '\0';

  tcp_send(pcb, (const uint8_t *)req, (uint16_t)n);

  // Wait for response
  start = pit_ticks;
  int found_http = 0;
  while ((pit_ticks - start) < (PIT_HZ * 10u))
  {
    uint16_t max = pcb->app_rx_len;
    if (max > 512)
      max = 512;
    for (uint16_t i = 0; i + 4 < max; i++)
    {
      if (pcb->app_rx_buf[i] == 'H' && pcb->app_rx_buf[i + 1] == 'T' &&
          pcb->app_rx_buf[i + 2] == 'T' && pcb->app_rx_buf[i + 3] == 'P' &&
          pcb->app_rx_buf[i + 4] == '/')
      {
        found_http = 1;
        break;
      }
    }
    if (found_http)
      break;
    sleep_ms(50);
  }

  if (pcb->app_rx_len == 0)
  {
    log_writestring("wget: no response\n");
    tcp_close(pcb);
    return;
  }

  // Parse response
  uint16_t status_code = 0;
  uint16_t header_end = 0;
  uint32_t content_length = 0;
  if (!http_parse_response(pcb->app_rx_buf, pcb->app_rx_len, &status_code,
                           &header_end, &content_length))
  {
    log_writestring("wget: invalid HTTP response\n");
    tcp_close(pcb);
    return;
  }

  log_writestring("wget: HTTP ");
  log_write_u32(status_code);
  log_writestring(", ");
  log_write_u32((uint32_t)pcb->app_rx_len);
  log_writestring(" bytes received\n");

  if (status_code != 200)
  {
    log_writestring("wget: HTTP error ");
    log_write_u32(status_code);
    log_putchar('\n');
    tcp_close(pcb);
    return;
  }

  // Extract body (everything after headers)
  uint16_t body_start = header_end;
  uint16_t body_len = pcb->app_rx_len - body_start;

  // Save to file
  if (body_len > 0)
  {
    if (fat12_write_file(outfile, pcb->app_rx_buf + body_start, body_len))
    {
      log_writestring("wget: saved ");
      log_write_u32(body_len);
      log_writestring(" bytes to ");
      log_writestring(outfile);
      log_putchar('\n');
    }
    else
    {
      log_writestring("wget: failed to save file\n");
    }
  }
  else
  {
    log_writestring("wget: empty response body\n");
  }

  tcp_close(pcb);
}

// httpd service tick - handles one request cycle if ready
static void httpd_service_tick(void)
{
  if (!httpd_service_active || !httpd_listen_pcb)

    return;

  uint32_t start_tick = pit_ticks;
  struct process *proc = process_get(httpd_service_pid);

  // Poll for packets
  net_pump_rx(4);

  if (httpd_listen_pcb->state != TCP_LISTEN ||
      httpd_listen_pcb->app_rx_len > 0)
  {
    if (proc)
      proc->state = PROC_STATE_RUNNING;

    struct tcp_pcb *conn = httpd_listen_pcb;

    // Extremely brief wait for data (non-blocking)
    uint32_t wait_start = pit_ticks;
    while (conn->app_rx_len < 10 && (pit_ticks - wait_start) < (PIT_HZ / 50))
    {
      net_pump_rx(2);
      __asm__ volatile("pause");
    }

    if (conn->app_rx_len > 0)
    {
      if (!background_logs_disabled)
      {
        log_writestring("httpd: request detected\n");
      }

      char *req = (char *)conn->app_rx_buf;
      if (req[0] == 'G' && req[1] == 'E' && req[2] == 'T' && req[3] == ' ')
      {
        char path[64];
        int pi = 0;
        char *p = req + 4;
        while (*p && *p != ' ' && pi < (int)sizeof(path) - 1)
        {
          path[pi++] = *p++;
        }
        path[pi] = '\0';

        if (!background_logs_disabled)
        {
          log_writestring("httpd: GET ");
          log_writestring(path);
          log_putchar('\n');
        }

        const char *fn =
            (path[0] == '/' && path[1] == '\0') ? "INDEX.HTM" : (path + 1);
        uint8_t *file_buf = 0;
        uint32_t file_size = 0;

        if (fat12_read_file_to_ram(fn, &file_buf, &file_size))
        {
          const char *resp_hdr = "HTTP/1.0 200 OK\r\nContent-Type: "
                                 "text/html\r\nConnection: close\r\n\r\n";
          tcp_send(conn, (const uint8_t *)resp_hdr,
                   (uint16_t)kstrlen(resp_hdr));

          uint32_t sent = 0;
          while (sent < file_size)
          {
            uint16_t to_send = (uint16_t)(file_size - sent);
            if (to_send > 512)
              to_send = 512;
            tcp_send(conn, file_buf + sent, to_send);
            sent += to_send;
            // No long pause here, just a hint to the CPU
            __asm__ volatile("pause");
          }
          kfree(file_buf);
          if (!background_logs_disabled)
          {
            log_writestring("httpd: file sent\n");
          }
        }
        else
        {
          const char *not_found = "HTTP/1.0 404 Not Found\r\nContent-Type: "
                                  "text/plain\r\n\r\nFile Not Found";
          tcp_send(conn, (const uint8_t *)not_found,
                   (uint16_t)kstrlen(not_found));
          if (!background_logs_disabled)
          {
            log_writestring("httpd: 404\n");
          }
        }
      }
    }

    if (!background_logs_disabled)
    {
      log_writestring("httpd: closing\n");
    }
    tcp_close(conn);
    // Briefly wait for close
    uint32_t close_start = pit_ticks;
    while (conn->state != TCP_CLOSED &&
           (pit_ticks - close_start) < (PIT_HZ / 2))
    {
      net_pump_rx(2);
      __asm__ volatile("pause");
    }

    conn->state = TCP_LISTEN;
    conn->remote_ip = 0;
    conn->remote_port = 0;
    conn->app_rx_len = 0;

    if (proc)
      proc->state = PROC_STATE_SLEEPING;
  }

  if (proc)
  {
    proc->cpu_ticks += (pit_ticks - start_tick);
  }
}

// Update HTTP listener IP (called when IP changes)
void httpd_update_listener_ip(uint32_t ip)
{
  if (httpd_listen_pcb && httpd_service_active)
  {
    httpd_listen_pcb->local_ip = ip;
    log_writestring("[HTTP] Listener IP updated\n");
  }
}

// Auto-start HTTP service if not already running
void httpd_auto_start(void)
{
  if (!httpd_service_active)
  {
    httpd_listen_pcb = tcp_get_free_pcb();
    if (httpd_listen_pcb)
    {
      httpd_listen_pcb->local_port = httpd_service_port;
      httpd_listen_pcb->state = TCP_LISTEN;
      uint32_t current_ip = arp_get_ajos_ip();
      httpd_listen_pcb->local_ip =
          (current_ip != 0) ? current_ip : 0; // 0 = any interface
      httpd_service_active = 1;
      httpd_service_pid = process_alloc("httpd");
      if (httpd_service_pid)
      {
        struct process *p = process_get(httpd_service_pid);
        if (p)
        {
          p->is_background = 1;
          p->state = PROC_STATE_SLEEPING;
        }
      }
      log_writestring("[HTTP] Auto-started on port ");
      log_write_u32(httpd_service_port);
      log_putchar('\n');
    }
  }
}

// httpd command - simple HTTP server
static void cmd_httpd(const char *arg)
{
  const char *s = skip_spaces(arg);
  if (kstreq(s, "start"))
  {
    if (httpd_service_active)
    {
      log_writestring("httpd already running\n");
      return;
    }
    httpd_listen_pcb = tcp_get_free_pcb();
    if (!httpd_listen_pcb)
    {
      log_writestring("httpd: no free pcb\n");
      return;
    }
    httpd_listen_pcb->local_port = httpd_service_port;
    httpd_listen_pcb->state = TCP_LISTEN;
    // Listen on all interfaces (0.0.0.0) or current IP
    uint32_t current_ip = arp_get_ajos_ip();
    httpd_listen_pcb->local_ip =
        (current_ip != 0) ? current_ip : 0; // 0 = any interface
    httpd_service_active = 1;
    httpd_service_pid = process_alloc("httpd");
    if (httpd_service_pid)
    {
      struct process *p = process_get(httpd_service_pid);
      if (p)
      {
        p->is_background = 1;
        p->state = PROC_STATE_SLEEPING; // Initially sleeping
      }
    }
    log_writestring("httpd service started on port ");
    log_write_u32(httpd_service_port);
    log_putchar('\n');
  }
  else if (kstreq(s, "stop"))
  {
    if (!httpd_service_active)
    {
      log_writestring("httpd not running\n");
      return;
    }
    if (httpd_listen_pcb)
    {
      httpd_listen_pcb->state = TCP_CLOSED;
      httpd_listen_pcb = 0;
    }
    if (httpd_service_pid)
    {
      process_free(httpd_service_pid);
      httpd_service_pid = 0;
    }
    httpd_service_active = 0;
    log_writestring("httpd service stopped\n");
  }
  else if (kstreq(s, "reload") || kstreq(s, "restart"))
  {
    cmd_httpd("stop");
    cmd_httpd("start");
  }
  else if (kstreq(s, "status"))
  {
    log_writestring("httpd service: ");
    log_writestring(httpd_service_active ? "RUNNING" : "STOPPED");
    if (httpd_service_active)
    {
      log_writestring(" on port ");
      log_write_u32(httpd_service_port);
    }
    log_putchar('\n');
  }
  else
  {
    log_writestring("Usage: httpd [start|stop|restart|status]\n");
    log_writestring("Current state: ");
    log_writestring(httpd_service_active ? "RUNNING" : "STOPPED");
    log_putchar('\n');
  }
}

static void cmd_http_get(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: http_get <ip> <host> [path]\n");
    return;
  }

  uint32_t ip = 0;
  if (!parse_ip(&s, &ip))
  {
    log_writestring("Invalid IP\n");
    return;
  }
  s = skip_spaces(s);
  if (!*s)
  {
    log_writestring("Usage: http_get <ip> <host> [path]\n");
    return;
  }

  char host[64];
  int hi = 0;
  while (*s && (unsigned char)*s > ' ' && hi < (int)sizeof(host) - 1)
  {
    host[hi++] = *s++;
  }
  host[hi] = '\0';

  s = skip_spaces(s);
  const char *path = *s ? s : "/";

  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb)
  {
    log_writestring("http_get: no free pcb\n");
    return;
  }

  log_writestring("http_get: connecting...\n");
  int connected = 0;
  uint32_t start = 0;
  for (int attempt = 0; attempt < 2; attempt++)
  {
    tcp_connect(pcb, ip, 80);

    start = pit_ticks;
    while ((pit_ticks - start) < (PIT_HZ * 6u))
    {
      if (pcb->state == TCP_ESTABLISHED)
      {
        connected = 1;
        break;
      }
      // If SYN retransmits exhausted, pcb may go CLOSED.
      if (pcb->state == TCP_CLOSED)
      {
        break;
      }
      sleep_ms(50);
    }

    if (connected)
    {
      break;
    }

    // Ensure pcb is reusable for a retry
    pcb->state = TCP_CLOSED;
    sleep_ms(100);
  }

  if (!connected)
  {
    log_writestring("http_get: connect timeout\n");
    return;
  }

  // Clear any previous captured response bytes on this PCB.
  pcb->app_rx_len = 0;

  char req[256];
  int n = 0;
  const char *pfx = "GET ";
  for (int i = 0; pfx[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = pfx[i];
  for (int i = 0; path[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = path[i];
  const char *mid = " HTTP/1.0\r\nHost: ";
  for (int i = 0; mid[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = mid[i];
  for (int i = 0; host[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = host[i];
  const char *end = "\r\n\r\n";
  for (int i = 0; end[i] && n < (int)sizeof(req) - 1; i++)
    req[n++] = end[i];
  req[n] = '\0';

  tcp_send(pcb, (const uint8_t *)req, (uint16_t)n);

  // Wait for response bytes to arrive (captured by TCP into pcb->app_rx_buf).
  start = pit_ticks;
  int found_http = 0;
  while ((pit_ticks - start) < (PIT_HZ * 8u))
  {
    // Prefer waiting until we actually see an "HTTP/" status line
    uint16_t max = pcb->app_rx_len;
    if (max > 512)
      max = 512;
    for (uint16_t i = 0; i + 4 < max; i++)
    {
      if (pcb->app_rx_buf[i] == 'H' && pcb->app_rx_buf[i + 1] == 'T' &&
          pcb->app_rx_buf[i + 2] == 'T' && pcb->app_rx_buf[i + 3] == 'P' &&
          pcb->app_rx_buf[i + 4] == '/')
      {
        found_http = 1;
        break;
      }
    }
    if (found_http)
      break;
    sleep_ms(50);
  }
  if (pcb->app_rx_len == 0)
  {
    log_writestring("http_get: no response\n");
    return;
  }

  // Print status line (try to find "HTTP/" start; stop at first \n).
  uint16_t max = pcb->app_rx_len;
  if (max > 512)
    max = 512;

  // Find "HTTP/" marker inside the captured buffer
  uint16_t start_i = 0;
  int have_http = 0;
  for (uint16_t i = 0; i + 4 < max; i++)
  {
    if (pcb->app_rx_buf[i] == 'H' && pcb->app_rx_buf[i + 1] == 'T' &&
        pcb->app_rx_buf[i + 2] == 'T' && pcb->app_rx_buf[i + 3] == 'P' &&
        pcb->app_rx_buf[i + 4] == '/')
    {
      start_i = i;
      have_http = 1;
      break;
    }
  }

  if (!have_http)
  {
    log_writestring("http_get: non-http response\n");
    log_writestring("http_get: captured_bytes=");
    log_write_u32((uint32_t)pcb->app_rx_len);
    log_putchar('\n');
    // Show a tiny safe signature so we can tell what it is.
    // (ASCII + decimal bytes; avoids heavy hex dumps in serial capture.)
    uint16_t sig_n = pcb->app_rx_len;
    if (sig_n > 8)
      sig_n = 8;

    // TLS ClientHello/ServerHello often starts with 22,3,1 or 22,3,3.
    if (sig_n >= 3 && pcb->app_rx_buf[0] == 22 && pcb->app_rx_buf[1] == 3)
    {
      log_writestring("http_get: looks like TLS on this port\n");
    }
    // HTTP/2 cleartext preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    else if (sig_n >= 4 && pcb->app_rx_buf[0] == 'P' &&
             pcb->app_rx_buf[1] == 'R' && pcb->app_rx_buf[2] == 'I' &&
             pcb->app_rx_buf[3] == ' ')
    {
      log_writestring("http_get: looks like HTTP/2 preface\n");
    }

    log_writestring("http_get: first bytes ascii=\"");
    for (uint16_t i = 0; i < sig_n; i++)
    {
      char c = (char)pcb->app_rx_buf[i];
      if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E)
        c = '.';
      log_putchar(c);
    }
    log_writestring("\" bytes=");
    for (uint16_t i = 0; i < sig_n; i++)
    {
      if (i)
        log_putchar(',');
      log_write_u32((uint32_t)pcb->app_rx_buf[i]);
    }
    log_putchar('\n');

    // Best-effort close to free up the PCB for repeated http_get usage.
    if (pcb->state == TCP_ESTABLISHED)
    {
      tcp_close(pcb);
    }
    return;
  }
  else
  {
    log_writestring("http_get: ");
  }

  for (uint16_t i = start_i; i < max; i++)
  {
    char c = (char)pcb->app_rx_buf[i];
    if (c == '\r')
      continue;
    if (c == '\n')
      break;
    if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7E)
      c = '.';
    log_putchar(c);
  }
  log_putchar('\n');

  // Best-effort close to free up the PCB for repeated http_get usage.
  if (pcb->state == TCP_ESTABLISHED)
  {
    tcp_close(pcb);
  }
}

static void cmd_tcp_test_ack(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: tcp_test_ack <remote_ip> <remote_port> "
                    "<local_port> <seq> <ack>\n");
    return;
  }

  uint32_t rip = 0;
  for (int i = 0; i < 4; i++)
  {
    uint32_t part = 0;
    while (*s >= '0' && *s <= '9')
    {
      part = part * 10 + (*s - '0');
      s++;
    }
    rip = (rip << 8) | (part & 0xFF);
    if (*s == '.')
      s++;
  }
  s = skip_spaces(s);

  uint16_t rport = 0;
  while (*s >= '0' && *s <= '9')
  {
    rport = rport * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  uint16_t lport = 0;
  while (*s >= '0' && *s <= '9')
  {
    lport = lport * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  uint32_t seq = 0;
  while (*s >= '0' && *s <= '9')
  {
    seq = seq * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  uint32_t ack = 0;
  while (*s >= '0' && *s <= '9')
  {
    ack = ack * 10 + (*s - '0');
    s++;
  }

  struct pbuf *p = pbuf_alloc();
  if (!p)
    return;

  pbuf_header(p, -(int)sizeof(struct tcp_hdr));
  struct tcp_hdr *hdr = (struct tcp_hdr *)p->payload;
  hdr->src_port = htons(rport);
  hdr->dst_port = htons(lport);
  hdr->seqno = htonl(seq);
  hdr->ackno = htonl(ack);
  hdr->_offset_flags = htons((5 << 12) | TCP_ACK);
  hdr->window = htons(1024);
  hdr->chksum = 0;
  hdr->urgptr = 0;
  p->len = sizeof(struct tcp_hdr);

  tcp_input(p, rip, arp_get_ajos_ip());
  log_writestring("Simulated ACK sent to stack.\n");
}

static void cmd_tcp_test_data(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: tcp_test_data <remote_ip> <remote_port> "
                    "<local_port> <seq> <ack> <msg>\n");
    return;
  }

  uint32_t rip = 0;
  for (int i = 0; i < 4; i++)
  {
    uint32_t part = 0;
    while (*s >= '0' && *s <= '9')
    {
      part = part * 10 + (*s - '0');
      s++;
    }
    rip = (rip << 8) | (part & 0xFF);
    if (*s == '.')
      s++;
  }
  s = skip_spaces(s);

  uint16_t rport = 0;
  while (*s >= '0' && *s <= '9')
  {
    rport = rport * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  uint16_t lport = 0;
  while (*s >= '0' && *s <= '9')
  {
    lport = lport * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  uint32_t seq = 0;
  while (*s >= '0' && *s <= '9')
  {
    seq = seq * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  uint32_t ack = 0;
  while (*s >= '0' && *s <= '9')
  {
    ack = ack * 10 + (*s - '0');
    s++;
  }
  s = skip_spaces(s);

  int msg_len = 0;
  while (s[msg_len])
    msg_len++;

  struct pbuf *p = pbuf_alloc();
  if (!p)
    return;

  pbuf_header(p, -(int)sizeof(struct tcp_hdr));
  struct tcp_hdr *hdr = (struct tcp_hdr *)p->payload;
  hdr->src_port = htons(rport);
  hdr->dst_port = htons(lport);
  hdr->seqno = htonl(seq);
  hdr->ackno = htonl(ack);
  hdr->_offset_flags = htons((5 << 12) | TCP_ACK);
  hdr->window = htons(1024);
  hdr->chksum = 0;
  hdr->urgptr = 0;

  uint8_t *data = (uint8_t *)p->payload + sizeof(struct tcp_hdr);
  for (int i = 0; i < msg_len; i++)
  {
    data[i] = s[i];
  }
  p->len = sizeof(struct tcp_hdr) + msg_len;

  tcp_input(p, rip, arp_get_ajos_ip());
  log_writestring("Simulated DATA sent to stack.\n");
}

static void cmd_test_pbuf(void)
{
  log_writestring("Testing pbuf allocator...\n");
  struct pbuf *p = pbuf_alloc();
  if (p == NULL)
  {
    log_writestring("FAIL: pbuf_alloc returned NULL\n");
    return;
  }
  log_writestring("Allocated pbuf at: ");
  log_write_hex32((uint32_t)p);
  log_writestring("\n");

  if (p->len != 0)
  {
    log_writestring("WARN: p->len not 0\n");
  }

  // Test header reservation
  if (pbuf_header(p, 10) == 0)
  {
    log_writestring("pbuf_header(10) OK\n"); // 10 forward
  }
  else
  {
    log_writestring("pbuf_header(10) FAIL\n");
  }

  // Free
  pbuf_free(p);
  log_writestring("Freed pbuf.\n");
}

extern uint32_t eth_get_rx_count(void);
extern uint32_t eth_get_tx_count(void);
extern uint32_t eth_get_tx_attempt_count(void);
extern uint32_t eth_get_tx_fail_count(void);

static void cmd_eth_stat(void)
{
  log_writestring("Ethernet Stats:\n");
  log_writestring("  RX frames: ");
  log_write_u32(eth_get_rx_count());
  log_writestring("\n");
  log_writestring("  TX frames: ");
  log_write_u32(eth_get_tx_count());
  log_writestring("\n");
  log_writestring("  TX attempts: ");
  log_write_u32(eth_get_tx_attempt_count());
  log_writestring("\n");
  log_writestring("  TX fails: ");
  log_write_u32(eth_get_tx_fail_count());
  log_writestring("\n");
  log_writestring("  MAC: ");
  for (int i = 0; i < 6; i++)
  {
    log_write_hex32(e1000_mac[i]);
    if (i < 5)
      log_putchar(':');
  }
  log_putchar('\n');
}

static void cmd_test_eth(void)
{
  log_writestring("Sending test Ethernet frame...\n");
  struct pbuf *p = pbuf_alloc();
  if (!p)
  {
    log_writestring("Allocation failed\n");
    return;
  }
  // Reserve space for payload
  pbuf_header(p, 100);
  const char *msg = "Hello from AJOS Ethernet Layer!";
  for (int i = 0; msg[i]; i++)
  {
    p->payload[i] = (uint8_t)msg[i];
  }
  p->len = 32; // some fixed length for test

  eth_addr_t dst = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  ethernet_output(p, &dst, 0x1234);
  log_writestring("Sent.\n");
}

static void cmd_arp_stat(void)
{
  uint32_t my_ip = arp_get_ajos_ip();
  log_writestring("AJOS IP: ");
  log_write_u32((my_ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((my_ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((my_ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(my_ip & 0xFF);
  log_putchar('\n');

  log_writestring("ARP Cache:\n");
  for (int i = 0; i < 16; i++)
  {
    uint32_t ip = arp_get_ip_at(i);
    if (ip != 0)
    {
      log_writestring("  ");
      log_write_u32((ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(ip & 0xFF);
      log_writestring(" at ");
      uint8_t *mac = arp_get_mac_at(i);
      for (int b = 0; b < 6; b++)
      {
        log_write_hex32(mac[b]);
        if (b < 5)
          log_putchar(':');
      }
      log_putchar('\n');
    }
  }
}

static void cmd_arp_whois(const char *arg)
{
  if (!arg || *arg == '\0')
  {
    log_writestring("Usage: arp_whois <ip>\n");
    return;
  }
  // Very simple IP parser
  uint32_t ip = 0;
  uint32_t part = 0;
  uint8_t *b = (uint8_t *)&ip;
  const char *s = arg;
  for (int i = 0; i < 4; i++)
  {
    part = 0;
    while (*s >= '0' && *s <= '9')
    {
      part = part * 10 + (*s - '0');
      s++;
    }
    ip = (ip << 8) | (part & 0xFF);
    if (*s == '.')
      s++;
  }
  log_writestring("Querying ARP for IP...\n");
  arp_query(ip);

  // Wait briefly for a reply so this command is actually useful.
  eth_addr_t mac;
  uint32_t start = pit_ticks;
  while ((pit_ticks - start) < (PIT_HZ * 1u))
  {
    net_pump_rx(8);
    if (arp_get_mac_for_ip(ip, &mac))
    {
      log_writestring("ARP: ");
      log_write_u32((ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(ip & 0xFF);
      log_writestring(" is at ");
      for (int b = 0; b < 6; b++)
      {
        log_write_hex32(mac.addr[b]);
        if (b < 5)
          log_putchar(':');
      }
      log_putchar('\n');
      return;
    }
    sleep_ms(50);
  }
  log_writestring("ARP: timeout\n");
}

// WHOIS command - query WHOIS servers for domain or IP information
static void cmd_whois(const char *arg)
{
  if (!arg || *arg == '\0')
  {
    log_writestring("Usage: whois <domain|ip>\n");
    log_writestring("Example: whois example.com\n");
    log_writestring("Example: whois 8.8.8.8\n");
    return;
  }

  const char *query = skip_spaces(arg);
  int query_len = 0;
  while (query[query_len] && query[query_len] > ' ')
  {
    query_len++;
  }
  if (query_len == 0 || query_len > 255)
  {
    log_writestring("Invalid query\n");
    return;
  }

  // Determine if query is IP or domain
  uint32_t query_ip = 0;
  const char *ip_test = query;
  int is_ip = parse_ip(&ip_test, &query_ip);

  // Determine WHOIS server
  uint32_t whois_server_ip = 0;
  const char *whois_host = NULL;

  if (is_ip)
  {
    // For IP addresses, determine RIR based on IP range
    uint8_t first_octet = (query_ip >> 24) & 0xFF;
    if (first_octet == 0 || (first_octet >= 1 && first_octet <= 126))
    {
      // ARIN (North America) - but also try whois.arin.net
      whois_host = "whois.arin.net";
    }
    else if (first_octet >= 128 && first_octet <= 191)
    {
      // Could be ARIN or RIPE
      uint8_t second_octet = (query_ip >> 16) & 0xFF;
      if (first_octet == 128 || (first_octet == 192 && second_octet <= 95))
      {
        whois_host = "whois.arin.net";
      }
      else
      {
        whois_host = "whois.ripe.net";
      }
    }
    else if (first_octet >= 192 && first_octet <= 223)
    {
      // RIPE (Europe) or ARIN
      whois_host = "whois.ripe.net";
    }
    else
    {
      // APNIC (Asia-Pacific) or others
      whois_host = "whois.apnic.net";
    }
  }
  else
  {
    // For domains, use IANA or try to determine by TLD
    // Find TLD (last component after last dot)
    const char *tld_start = query + query_len - 1;
    while (tld_start > query && *tld_start != '.')
    {
      tld_start--;
    }
    if (*tld_start == '.')
    {
      tld_start++;
    }

    // Simple TLD-based server selection
    if (kstrcmp_n(tld_start, "com", 3) == 0 ||
        kstrcmp_n(tld_start, "net", 3) == 0)
    {
      whois_host = "whois.verisign-grs.com";
    }
    else if (kstrcmp_n(tld_start, "org", 3) == 0)
    {
      whois_host = "whois.pir.org";
    }
    else if (kstrcmp_n(tld_start, "edu", 3) == 0)
    {
      whois_host = "whois.educause.edu";
    }
    else
    {
      // Default to IANA
      whois_host = "whois.iana.org";
    }
  }

  if (!whois_host)
  {
    log_writestring("whois: could not determine server\n");
    return;
  }

  // Resolve WHOIS server hostname to IP
  extern volatile int dns_got_reply;
  extern volatile uint32_t dns_last_ip;
  dns_got_reply = 0;
  extern void dns_lookup(const char *name);
  dns_lookup(whois_host);

  uint32_t start = pit_ticks;
  while ((pit_ticks - start) < (PIT_HZ * 5u))
  {
    net_pump_rx(8);
    if (dns_got_reply)
    {
      whois_server_ip = dns_last_ip;
      break;
    }
    sleep_ms(50);
  }

  if (whois_server_ip == 0)
  {
    log_writestring("whois: could not resolve ");
    log_writestring(whois_host);
    log_writestring("\n");
    return;
  }

  // Connect to WHOIS server (port 43)
  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb)
  {
    log_writestring("whois: no free PCBs\n");
    return;
  }

  log_writestring("whois: connecting to ");
  log_writestring(whois_host);
  log_writestring("...\n");

  tcp_connect(pcb, whois_server_ip, 43);

  // Wait for connection
  start = pit_ticks;
  int connected = 0;
  while ((pit_ticks - start) < (PIT_HZ * 10u))
  {
    if (pcb->state == TCP_ESTABLISHED)
    {
      connected = 1;
      break;
    }
    if (pcb->state == TCP_CLOSED)
    {
      break;
    }
    sleep_ms(50);
  }

  if (!connected)
  {
    log_writestring("whois: connection timeout\n");
    pcb->state = TCP_CLOSED;
    return;
  }

  // Send WHOIS query (query string + \r\n)
  char query_buf[260];
  int i = 0;
  for (int j = 0; j < query_len && i < 255; j++)
  {
    query_buf[i++] = query[j];
  }
  query_buf[i++] = '\r';
  query_buf[i++] = '\n';

  log_writestring("whois: sending query...\n");
  tcp_send(pcb, (const uint8_t *)query_buf, (uint16_t)i);

  // Wait for response
  pcb->app_rx_len = 0;
  start = pit_ticks;
  int got_data = 0;
  while ((pit_ticks - start) < (PIT_HZ * 15u))
  {
    if (pcb->app_rx_len > 0)
    {
      got_data = 1;
      // Check if we have more data coming (wait a bit more)
      uint16_t prev_len = pcb->app_rx_len;
      sleep_ms(200);
      if (pcb->app_rx_len == prev_len)
      {
        // No more data, connection likely closed
        break;
      }
    }
    if (pcb->state == TCP_CLOSED)
    {
      break;
    }
    sleep_ms(50);
  }

  if (got_data && pcb->app_rx_len > 0)
  {
    log_writestring("\n--- WHOIS Response ---\n");
    // Print response (limit to reasonable size)
    uint16_t print_len = pcb->app_rx_len;
    if (print_len > 4096)
    {
      print_len = 4096;
    }
    for (uint16_t j = 0; j < print_len; j++)
    {
      char c = (char)pcb->app_rx_buf[j];
      if (c >= 32 && c < 127)
      {
        log_putchar(c);
      }
      else if (c == '\n' || c == '\r' || c == '\t')
      {
        log_putchar(c);
      }
      else
      {
        log_putchar('.');
      }
    }
    if (pcb->app_rx_len > 4096)
    {
      log_writestring("\n... (truncated)\n");
    }
    log_writestring("--- End of Response ---\n");
  }
  else
  {
    log_writestring("whois: no response received\n");
  }

  // Close connection
  tcp_close(pcb);
}

static void shell_help(void)
{
  log_writestring("Commands:\n");
  log_writestring("  Tab             Complete command or filename\n");
  log_writestring("  help            Show this help\n");
  log_writestring("  date            Show current system date/time\n");
  log_writestring("  uname [-a|-s|-r|-m]  Show system information\n");
  log_writestring("  whoami          Show current user\n");
  log_writestring("  hostname [name] Show or set hostname\n");
  log_writestring("  clear           Clear the screen\n");
  log_writestring("  echo <text>     Echo text\n");
  log_writestring("  ticks           Show PIT tick counter\n");
  log_writestring("  uptime          Show uptime in ms\n");
  log_writestring("  ps              List running processes\n");
  log_writestring("  kill <pid>      Terminate a process\n");
  log_writestring("  wait [pid]      Wait for background process\n");
  log_writestring("  jobs            List background jobs\n");
  log_writestring("  sleep <ms>      Sleep for ms\n");
  log_writestring("  a20             Show whether A20 is enabled\n");
  log_writestring("  pci             List PCI devices\n");
  log_writestring("  e1000           Show E1000 NIC info\n");
  log_writestring("  e1000tx         Send test Ethernet frame\n");
  log_writestring("  e1000rx         Poll and print one RX packet\n");
  log_writestring("  e1000rxstat     Dump RX ring/register state\n");
  log_writestring("  e1000reinit     Reinitialize E1000 RX/TX rings\n");
  log_writestring("  e1000loop mac|phy|off  Toggle NIC loopback\n");
  log_writestring("  pwd             Print current directory\n");
  log_writestring("  cd <DIR>        Change directory\n");
  log_writestring("  ls [DIR]        List files (current dir by default)\n");
  log_writestring("  cat <FILE.TXT>  Print a file from data floppy\n");
  log_writestring("  touch <file>    Create empty file or update timestamp\n");
  log_writestring("  grep <pat> <f>  Search pattern in file\n");
  log_writestring("  head [-n N] <f> Show first N lines (default 10)\n");
  log_writestring("  tail [-n N] <f> Show last N lines (default 10)\n");
  log_writestring("  wc <file>       Count lines, words, characters\n");
  log_writestring("  create <file> <text>  Create file with text\n");
  log_writestring("  mkdir <dir>     Create directory\n");
  log_writestring("  rm <file>       Delete file or directory\n");
  log_writestring("  mv <src> <dst>  Move/rename file or directory\n");
  log_writestring("  find <pattern>  Search for files matching pattern\n");
  log_writestring(
      "  cp <FILE>       Copy file into RAM (prints id/ptr/size)\n");
  log_writestring("  files           List copied RAM files\n");
  log_writestring("  freeram <id>    Free copied RAM file by id\n");
  log_writestring("  run <id>        Run AJOSBIN loaded by cp\n");
  log_writestring("  run3 <id>       Run AJOSBIN in user mode (ring3)\n");
  log_writestring(
      "  hexdump <FILE> [max_bytes]  Hex dump file (default 256)\n");
  log_writestring(
      "  strings <FILE> [min_len]    Extract strings (default 4)\n");
  log_writestring(
      "  mem             PMM pages + kmalloc/kfree counters (short)\n");
  log_writestring(
      "  heap            Slab/PMM usage + leak-hunting hints (see docs/MEMORY.md)\n");
  log_writestring("  alloc <bytes>   Allocate bytes (returns id)\n");
  log_writestring("  free <id>       Free allocation by id\n");
  log_writestring("  reboot          Reboot the machine\n");
  log_writestring("  poweroff        Poweroff the machine\n");
  log_writestring("  test_pbuf       Test packet buffer allocator\n");
  log_writestring("  eth_stat        Show Ethernet statistics\n");
  log_writestring("  test_eth        Send test Ethernet frame\n");
  log_writestring("  arp_stat        Show ARP cache\n");
  log_writestring("  arp_whois       Send ARP request for an IP\n");
  log_writestring("  ip_stat         Show IP statistics\n");
  log_writestring("  ping <ip>       Ping an IP address\n");
  log_writestring("  ifconfig [<interface>] [up|down|default]  Show/manage "
                  "network interfaces\n");
  log_writestring("  udp_send        Send UDP packet\n");
  log_writestring("  tcp_listen <port>  Listen on TCP port\n");
  log_writestring("  tcp_connect <ip> <port>  Connect to TCP port\n");
  log_writestring(
      "  httpd [port]       Start simple HTTP server (default 80)\n");
  log_writestring("  wget <url> [file]  Download file via HTTP\n");
  log_writestring(
      "  http_get <ip> <host> [path]  HTTP GET (prints first bytes)\n");
  log_writestring("  tcp_stat        Show TCP connection status\n");
  log_writestring(
      "  service <name> [op]  Manage services (httpd, hotspot, sshd)\n");
  log_writestring("  hotspot [cmd]   Manage hotspot (DHCP/DNS server)\n");
  log_writestring("  sshd [cmd]      Manage SSH server (port 22)\n");
  log_writestring("  adduser <user> <pass>  Add new user account\n");
  log_writestring("  deluser <user>  Delete user account\n");
  log_writestring("  passwd <user> <old> <new>  Change user password\n");
  log_writestring("  users           List all users\n");
  log_writestring("  dhcp            Start DHCP client\n");
  log_writestring("  dns <hostname>  Resolve hostname to IP\n");
  log_writestring("  whois <domain|ip>  Query WHOIS for domain or IP\n");
  log_writestring(
      "  netcfg [file]   Load network config (default: NETWORK.CFG)\n");
  log_writestring("  edit <file>     Open text AJOS editor\n");
  log_writestring("  gui             VGA Mode 13h desktop (make run)\n");
  log_writestring("\nShell features:\n");
  log_writestring("  cmd > file      Redirect output to file (overwrite)\n");
  log_writestring("  cmd >> file     Redirect output to file (append)\n");
  log_writestring("  cmd | more      Page long output (SPACE=page, ENTER=line, q=quit)\n");
  log_writestring("  cmd &           Run command in background (basic)\n");
}

static void cmd_hotspot(const char *arg)
{
  const char *s = skip_spaces(arg);
  if (kstreq(s, "start") || kstreq(s, ""))
  {
    // Hotspot services (DHCP and DNS) are always running
    // Reinitialize to ensure they're using current IP
    dhcpd_reinit();
    log_writestring("[HOTSPOT] DHCP and DNS servers active\n");
    log_writestring("[HOTSPOT] DHCP server: Port 67\n");
    log_writestring("[HOTSPOT] DNS server: Port 53\n");
    uint32_t my_ip = arp_get_ajos_ip();
    if (my_ip != 0)
    {
      log_writestring("[HOTSPOT] Gateway IP: ");
      log_write_u32((my_ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((my_ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((my_ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(my_ip & 0xFF);
      log_putchar('\n');
    }
  }
  else if (kstreq(s, "status"))
  {
    log_writestring("[HOTSPOT] Status:\n");
    log_writestring("  DHCP Server: ACTIVE (port 67)\n");
    log_writestring("  DNS Server: ACTIVE (port 53)\n");
    dhcpd_stat();
    dnsd_stat();
  }
  else if (kstreq(s, "restart"))
  {
    dhcpd_reinit();
    log_writestring("[HOTSPOT] Services reinitialized\n");
  }
  else
  {
    log_writestring("Usage: hotspot [start|status|restart]\n");
    log_writestring("Hotspot provides DHCP and DNS services\n");
  }
}

static void cmd_sshd(const char *arg)
{
  const char *s = skip_spaces(arg);
  extern void sshd_start(void);
  extern void sshd_stop(void);
  extern void sshd_stat(void);

  if (kstreq(s, "start") || kstreq(s, ""))
  {
    sshd_start();
  }
  else if (kstreq(s, "stop"))
  {
    sshd_stop();
  }
  else if (kstreq(s, "restart"))
  {
    sshd_stop();
    sshd_start();
  }
  else if (kstreq(s, "status"))
  {
    sshd_stat();
  }
  else
  {
    log_writestring("Usage: sshd [start|stop|restart|status]\n");
  }
}

static void cmd_service(const char *arg)
{
  const char *s = skip_spaces(arg);
  if (kstrcmp_n(s, "httpd", 5) == 0)
  {
    cmd_httpd(skip_spaces(s + 5));
  }
  else if (kstrcmp_n(s, "hotspot", 7) == 0)
  {
    cmd_hotspot(skip_spaces(s + 7));
  }
  else if (kstrcmp_n(s, "sshd", 4) == 0)
  {
    cmd_sshd(skip_spaces(s + 4));
  }
  else
  {
    log_writestring("Usage: service <name> [start|stop|restart|status]\n");
    log_writestring("Available services: httpd, hotspot, sshd\n");
  }
}

static void cmd_logout(const char *args)
{
  (void)args;
  current_username[0] = '\0';
  log_writestring("Logged out successfully.\n");
}

static void ensure_var_log_exists(void)
{
  // Try to create /var and /var/log. Ignore errors if they exist.
  fat12_mkdir("var");
  fat12_mkdir("var/log");
}

static int write_syslog_file(const char *logfile, const uint8_t *new_buf,
                             uint32_t new_size) {
  /* Root-level writes are the reliable path; subdirectory writes lose
   * their contents (see docs/MEMORY.md). Try /var/log first and verify,
   * falling back to a root-level ajos.log so logs are never lost. */
  if (fat12_write_file("var/log/ajos", new_buf, new_size)) {
    uint8_t *chk = 0;
    uint32_t chk_size = 0;
    if (fat12_read_file_to_ram("var/log/ajos", &chk, &chk_size) && chk &&
        chk_size == new_size) {
      kfree(chk);
      return 1;
    }
    if (chk)
      kfree(chk);
  }
  return fat12_write_file("ajos.log", new_buf, new_size) ? 2 : 0;
}

static void flush_syslog(void)
{
  if (syslog_flushing || syslog_pos == 0)
    return;
  syslog_flushing = 1;
  int was_enabled = syslog_enabled;
  syslog_enabled = 0; // Disable logging while writing to disk

  ensure_var_log_exists();

  const char *logfile = "var/log/ajos";
  uint8_t *old_buf = 0;
  uint32_t old_size = 0;

  // Try to read existing log
  if (fat12_read_file_to_ram(logfile, &old_buf, &old_size))
  {
    // old_buf allocated
  }
  else
  {
    old_size = 0;
    old_buf = 0;
  }

  uint32_t new_size = old_size + syslog_pos;
  uint8_t *new_buf = (uint8_t *)kmalloc(new_size);

  if (new_buf)
  {
    if (old_buf)
    {
      kmemcpy(new_buf, old_buf, old_size);
    }
    kmemcpy(new_buf + old_size, (uint8_t *)syslog_buffer, syslog_pos);

    if (write_syslog_file(logfile, new_buf, new_size))
    {
      syslog_pos = 0;
      syslog_flush_fail_count = 0;
    }
    else
    {
      syslog_pos = 0; // Discard to prevent repeated flush storm
      syslog_flush_fail_count++;
      if (syslog_flush_fail_count <= 2)
      {
        log_writestring("Syslog flush failed (disk full or read-only?)\n");
      }
      else if (syslog_flush_fail_count == 3)
      {
        syslog_enabled = 0;
        log_writestring("Syslog disabled after repeated flush failures.\n");
      }
    }
    kfree(new_buf);
  }
  else
  {
    for (const char *p = "Syslog flush OOM\n"; *p; p++)
      serial_putchar(*p);
  }

  if (old_buf)
    kfree(old_buf);

  if (syslog_flush_fail_count < 3)
    syslog_enabled = was_enabled;
  syslog_flushing = 0;
}

static void cmd_syslog(const char *arg)
{
  const char *s = skip_spaces(arg);
  if (kstrcmp_n(s, "start", 5) == 0)
  {
    syslog_enabled = 1;
    log_writestring("Syslog redirection enabled. Logs -> /var/log/ajos\n");
    flush_syslog();
  }
  else if (kstrcmp_n(s, "stop", 4) == 0)
  {
    syslog_enabled = 0;
    flush_syslog();
    log_writestring("Syslog redirection disabled.\n");
  }
  else if (kstrcmp_n(s, "flush", 5) == 0)
  {
    flush_syslog();
    log_writestring("Syslog flushed.\n");
  }
  else if (kstrcmp_n(s, "console", 7) == 0)
  {
    syslog_console_echo = !syslog_console_echo;
    log_writestring(syslog_console_echo
                        ? "Syslog console echo ENABLED (logs also shown here)\n"
                        : "Syslog console echo disabled (logs go to "
                          "/var/log/ajos only)\n");
  }
  else if (kstrcmp_n(s, "status", 6) == 0)
  {
    log_writestring("Syslog: ");
    log_writestring(syslog_enabled ? "ENABLED" : "DISABLED");
    log_writestring(" Buffer: ");
    log_write_u32(syslog_pos);
    log_writestring("/");
    log_write_u32(SYSLOG_BUF_SIZE);
    log_putchar('\n');
  }
  else
  {
    log_writestring("Usage: syslog [start|stop|flush|console|status]\n");
  }
}

static void vfs_cmd_ls(const char *args)
{
  uint32_t count = 0;
  char **names = 0;
  const char *path = skip_spaces(args);
  /* With no args always list root so we see full root dir (avoids cwd e.g.
   * /etc). */
  if (*path == '\0')
    path = "/";

  if (vfs_list(vfs_get_global(), path, &names, &count))
  {
    for (uint32_t i = 0; i < count; i++)
    {
      log_writestring(names[i]);
      log_putchar(' ');
    }
    if (count > 0)
      log_putchar('\n');
    if (count > 0 && names)
    {
      kfree(names[0]); /* single block for all names */
      kfree(names);
    }
  }
  else
  {
    log_writestring("ls: failed to list: ");
    log_writestring(path);
    log_putchar('\n');
  }
}

static void vfs_cmd_cat(const char *args)
{
  const char *path_arg = skip_spaces(args);
  if (*path_arg == '\0')
  {
    log_writestring("Usage: cat <path>\n");
    return;
  }

  /* Resolve relative path: prepend cwd if not absolute */
  char path_buf[128];
  if (path_arg[0] != '/')
  {
    size_t cwd_len = kstrlen(fat12_cwd_path);
    if (cwd_len >= sizeof(path_buf) - 1)
      cwd_len = sizeof(path_buf) - 2;
    mem_copy((uint8_t *)path_buf, (const uint8_t *)fat12_cwd_path,
             (uint32_t)cwd_len);
    path_buf[cwd_len] = '\0';
    if (cwd_len > 1 && path_buf[cwd_len - 1] != '/')
    {
      path_buf[cwd_len++] = '/';
      path_buf[cwd_len] = '\0';
    }
    size_t plen = kstrlen(path_arg);
    if (cwd_len + plen < sizeof(path_buf))
    {
      for (size_t i = 0; i <= plen; i++)
        path_buf[cwd_len + i] = path_arg[i];
    }
    else
    {
      path_buf[cwd_len] = '\0';
    }
  }
  else
  {
    size_t plen = kstrlen(path_arg);
    if (plen >= sizeof(path_buf))
      plen = sizeof(path_buf) - 1;
    for (size_t i = 0; i <= plen; i++)
      path_buf[i] = path_arg[i];
  }
  const char *path = path_buf;

  /* Try file slots first (e.g. from editor save), then VFS - same order as
   * ajlang/editor */
  uint8_t *buf = 0;
  uint32_t size = 0;
  int from_slot = 0;
  if (file_slot_read(path_arg, &buf, &size) == 1)
  {
    from_slot = 1;
  }
  else if (file_slot_read(path, &buf, &size) == 1)
  {
    from_slot = 1;
  }

  if (from_slot && buf)
  {
    for (uint32_t i = 0; i < size; i++)
      log_putchar((char)buf[i]);
    log_putchar('\n');
    kfree(buf);
    return;
  }

  if (!vfs_stat(vfs_get_global(), path, &size))
  {
    log_writestring("cat: file not found: ");
    log_writestring(path);
    log_putchar('\n');
    return;
  }

  int fd = vfs_open(vfs_get_global(), path, VFS_FD_READ);
  if (fd < 0)
  {
    log_writestring("cat: failed to open file\n");
    return;
  }

  buf = (uint8_t *)kmalloc(size + 1);
  if (buf)
  {
    int read = vfs_read(vfs_get_global(), fd, buf, size);
    if (read > 0)
    {
      buf[read] = '\0';
      log_writestring((const char *)buf);
      log_putchar('\n');
    }
    kfree(buf);
  }
  vfs_close(vfs_get_global(), fd);
}

static void vfs_cmd_ajlang(const char *args)
{
  const char *path_arg = skip_spaces(args);
  if (!path_arg || *path_arg == '\0')
  {
    log_writestring("Usage: ajlang <file.aj>\n");
    return;
  }

  /* Resolve relative path: prepend cwd if not absolute */
  char path_buf[128];
  if (path_arg[0] != '/')
  {
    size_t cwd_len = kstrlen(fat12_cwd_path);
    if (cwd_len >= sizeof(path_buf) - 1)
      cwd_len = sizeof(path_buf) - 2;
    mem_copy((uint8_t *)path_buf, (const uint8_t *)fat12_cwd_path,
             (uint32_t)cwd_len);
    path_buf[cwd_len] = '\0';
    if (cwd_len > 1 && path_buf[cwd_len - 1] != '/')
    {
      path_buf[cwd_len++] = '/';
      path_buf[cwd_len] = '\0';
    }
    size_t plen = kstrlen(path_arg);
    if (cwd_len + plen < sizeof(path_buf))
    {
      for (size_t i = 0; i <= plen; i++)
        path_buf[cwd_len + i] = path_arg[i];
    }
    else
    {
      path_buf[cwd_len] = '\0';
    }
  }
  else
  {
    size_t plen = kstrlen(path_arg);
    if (plen >= sizeof(path_buf))
      plen = sizeof(path_buf) - 1;
    for (size_t i = 0; i <= plen; i++)
      path_buf[i] = path_arg[i];
  }
  const char *path = path_buf;

  /* Try file slots first (e.g. from editor save), then disk - same order as
   * cat/editor */
  uint8_t *raw = 0;
  uint32_t size = 0;
  int loaded = 0;
  if (file_slot_read(path_arg, &raw, &size) == 1)
  {
    loaded = 1;
  }
  else if (file_slot_read(path, &raw, &size) == 1)
  {
    loaded = 1;
  }
  else if (fat12_read_file_to_ram(path, &raw, &size))
  {
    loaded = 1;
  }
  if (!loaded)
  {
    log_writestring("ajlang: file not found: ");
    log_writestring(path);
    log_putchar('\n');
    return;
  }

  /* Copy to null-terminated buffer for interpreter */
  uint8_t *buf = (uint8_t *)kmalloc(size + 1);
  if (!buf)
  {
    kfree(raw);
    log_writestring("ajlang: out of memory\n");
    return;
  }
  mem_copy(buf, raw, size);
  buf[size] = '\0';
  kfree(raw);

  if (size == 0)
  {
    log_writestring("ajlang: empty file\n");
    kfree(buf);
    return;
  }

  if (!ajlang_run((const char *)buf))
  {
    log_writestring("ajlang: run failed\n");
  }
  kfree(buf);
}

struct __attribute__((packed)) ajos_bin_hdr
{
  char magic[7]; // "AJOSBIN"
  uint8_t version;
  uint32_t entry_off;
  uint32_t data_off;
  uint32_t data_len;
};

static void cmd_jobs(void)
{
  log_writestring("JOB  PID  STATE      NAME\n");
  log_writestring("---  ---  ---------  --------------------\n");

  int job_num = 1;
  for (int i = 0; i < MAX_PROCESSES; i++)
  {
    extern struct process process_table[MAX_PROCESSES];
    if (process_table[i].in_use && process_table[i].is_background)
    {
      log_write_u32(job_num++);
      log_writestring("  ");
      log_write_u32(process_table[i].pid);
      log_writestring("  ");
      const char *state_str = "UNKNOWN";
      switch (process_table[i].state)
      {
      case PROC_STATE_RUNNING:
        state_str = "RUNNING  ";
        break;
      case PROC_STATE_SLEEPING:
        state_str = "SLEEPING ";
        break;
      case PROC_STATE_ZOMBIE:
        state_str = "ZOMBIE   ";
        break;
      case PROC_STATE_DEAD:
        state_str = "DEAD     ";
        break;
      }
      log_writestring(state_str);
      log_writestring("  ");
      log_writestring(process_table[i].name);
      log_putchar('\n');
    }
  }
}

static void cmd_loadbin(const char *arg)
{
  char fn[32];
  const char *s = skip_spaces(arg);
  int i = 0;
  while (*s && *s != ' ' && i < 31)
    fn[i++] = *s++;
  fn[i] = '\0';
  s = skip_spaces(s);
  uint32_t slot = 0;
  if (!*fn || !parse_u32(s, &slot) || slot >= FILE_SLOTS)
  {
    log_writestring("Usage: loadbin <file> <slot>\n");
    return;
  }
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(fn, &buf, &size))
  {
    log_writestring("loadbin: file not found\n");
    return;
  }
  if (file_slots[slot].ptr)
  {
    kfree(file_slots[slot].ptr);
  }
  file_slots[slot].ptr = buf;
  file_slots[slot].size = size;
  log_writestring("Loaded ");
  log_writestring(fn);
  log_writestring(" (");
  log_write_u32(size);
  log_writestring(" bytes) into slot ");
  log_write_u32(slot);
  log_putchar('\n');
}

static void cmd_ataread(const char *arg)
{
  uint32_t lba = 0;
  if (!parse_u32(arg, &lba))
  {
    log_writestring("Usage: ataread <lba>\n");
    return;
  }
  uint8_t buf[512];
  if (ata_read_sector(lba, buf))
  {
    log_writestring("ATA Read Successful. First 16 bytes:\n");
    for (int i = 0; i < 16; i++)
    {
      log_write_u32(buf[i]);
      log_putchar(' ');
    }
    log_putchar('\n');
  }
  else
  {
    log_writestring("ATA Read Failed\n");
  }
}

static void cmd_run(const char *arg, int bg)
{
  uint32_t id = 0;
  if (!parse_u32(arg, &id) || id >= FILE_SLOTS)
  {
    log_writestring("Usage: run <id>\n");
    return;
  }
  if (file_slots[id].ptr == (void *)0)
    return;
  const struct ajos_bin_hdr *hdr =
      (const struct ajos_bin_hdr *)file_slots[id].ptr;
  const uint32_t PROG_LOAD_ADDR = 0x00300000u;
  const uint32_t PROG_STACK_TOP = 0x00320000u;
  mem_copy((void *)PROG_LOAD_ADDR, file_slots[id].ptr, file_slots[id].size);
  uint32_t pid = process_alloc(file_slots[id].name);
  if (pid == 0)
    return;
  struct process *proc = process_get(pid);
  if (proc)
    proc->is_background = bg;
  void (*entry)(void) = (void (*)(void))(PROG_LOAD_ADDR + hdr->entry_off);
  volatile uint32_t saved_pid = pid;
  __asm__ volatile(
      "pushf\n pushal\n"
      "xor %%eax, %%eax\n mov %%ds, %%ax\n pushl %%eax\n"
      "xor %%eax, %%eax\n mov %%es, %%ax\n pushl %%eax\n"
      "xor %%eax, %%eax\n mov %%fs, %%ax\n pushl %%eax\n"
      "xor %%eax, %%eax\n mov %%gs, %%ax\n pushl %%eax\n"
      "mov %%esp, %%esi\n"
      "mov $0x10, %%ax\n mov %%ax, %%ds\n mov %%ax, %%es\n mov %%ax, %%fs\n "
      "mov %%ax, %%gs\n"
      "mov %1, %%esp\n mov %%esp, %%ebp\n"
      "call *%0\n"
      "mov %%esi, %%esp\n"
      "mov $0x10, %%ax\n mov %%ax, %%ds\n mov %%ax, %%es\n mov %%ax, %%fs\n "
      "mov %%ax, %%gs\n"
      "popl %%eax\n mov %%ax, %%gs\n popl %%eax\n mov %%ax, %%fs\n popl "
      "%%eax\n mov %%ax, %%es\n popl %%eax\n mov %%ax, %%ds\n"
      "popal\n popf\n" ::"r"(entry),
      "r"(PROG_STACK_TOP)
      : "memory", "eax", "esi", "cc");
  proc = process_get(saved_pid);
  if (proc)
  {
    proc->state = PROC_STATE_DEAD;
    process_free(saved_pid);
  }
}

static void cmd_run3(const char *arg, int bg)
{
  uint32_t id = 0;
  if (!parse_u32(arg, &id) || id >= FILE_SLOTS)
  {
    log_writestring("Usage: run3 <id>\n");
    return;
  }
  if (file_slots[id].ptr == (void *)0)
    return;
  const struct ajos_bin_hdr *hdr =
      (const struct ajos_bin_hdr *)file_slots[id].ptr;
  const uint32_t PROG_LOAD_ADDR = 0x00300000u;
  const uint32_t USER_STACK_TOP = 0x00330000u;
  mem_copy((void *)PROG_LOAD_ADDR, file_slots[id].ptr, file_slots[id].size);
  uint32_t pid = process_alloc(file_slots[id].name);
  if (pid == 0)
    return;
  struct process *proc = process_get(pid);
  if (proc)
    proc->is_background = bg;
  current_user_pid = pid;
  enter_user_mode((uint32_t)(PROG_LOAD_ADDR + hdr->entry_off), USER_STACK_TOP);
  current_user_pid = 0;
  proc = process_get(pid);
  if (proc)
  {
    proc->state = PROC_STATE_DEAD;
    process_free(pid);
  }
  __asm__ volatile("sti");
}

static void shell_dispatch(const char *line)
{
  const char *s = skip_spaces(line);
  if (*s == '\0')
  {
    return;
  }

  // Check for background job indicator (&) at the end
  int is_background = 0;
  const char *line_end = s;
  while (*line_end != '\0')
    line_end++;
  // Go backwards to find & before any trailing whitespace
  const char *p = line_end - 1;
  while (p >= s && ((unsigned char)*p <= (unsigned char)' ' ||
                    (unsigned char)*p == 0x7Fu))
  {
    p--;
  }
  if (p >= s && *p == '&')
  {
    is_background = 1;
    // Truncate line at & (we'll parse up to this point)
    line_end = p;
  }

  // Parse command token [s, s+cmd_len)
  const char *cmd = s;
  size_t cmd_len = 0;
  while (cmd + cmd_len < line_end &&
         (unsigned char)cmd[cmd_len] > (unsigned char)' ' &&
         (unsigned char)cmd[cmd_len] != 0x7Fu)
  {
    cmd_len++;
  }

  const char *rest = skip_spaces(cmd + cmd_len);
  // Also truncate rest at line_end
  if (rest >= line_end)
  {
    rest = line_end;
  }

  // Sanitize the token:
  // Some serial setups can inject invisible non-ASCII bytes into the command
  // token. We only keep a conservative ASCII subset for command matching.
  char cmd_clean[32];
  size_t cmd_clean_len = 0;
  for (size_t i = 0; i < cmd_len && cmd_clean_len + 1 < sizeof(cmd_clean);
       i++)
  {
    unsigned char ch = (unsigned char)cmd[i];
    if ((ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
        (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
        ch == (unsigned char)'_')
      cmd_clean[cmd_clean_len++] = (char)ch;
  }
  cmd_clean[cmd_clean_len] = '\0';

  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "service", 7) == 0)
  {
    cmd_service(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "date", 4) == 0)
  {
    // cmd_date() - show current date/time
    struct datetime dt;
    get_datetime(&dt);
    log_write_u32(dt.year);
    log_putchar('-');
    if (dt.month < 10)
      log_putchar('0');
    log_write_u32(dt.month);
    log_putchar('-');
    if (dt.day < 10)
      log_putchar('0');
    log_write_u32(dt.day);
    log_putchar(' ');
    if (dt.hour < 10)
      log_putchar('0');
    log_write_u32(dt.hour);
    log_putchar(':');
    if (dt.min < 10)
      log_putchar('0');
    log_write_u32(dt.min);
    log_putchar(':');
    if (dt.sec < 10)
      log_putchar('0');
    log_write_u32(dt.sec);
    log_putchar('\n');
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "uname", 5) == 0)
  {
    cmd_uname(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "whoami", 6) == 0)
  {
    cmd_whoami(rest);
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "showkeys", 8) == 0)
  {
    cmd_showkeys();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "hostname", 8) == 0)
  {
    cmd_hostname(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "ataread", 7) == 0)
  {
    cmd_ataread(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "atadump", 7) == 0)
  {
    cmd_ataread(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "help", 4) == 0)
  {
    shell_help();
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "more", 4) == 0)
  {
    log_writestring("Usage: <command> | more\n");
    log_writestring("  SPACE / f   next page\n");
    log_writestring("  ENTER       next line\n");
    log_writestring("  q           quit\n");
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "history", 7) == 0)
  {
    cmd_history();
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "clear", 5) == 0)
  {
    terminal_clear();
    serial_clear();
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "echo", 4) == 0)
  {
    log_writestring(rest);
    log_putchar('\n');
    return;
  }

  if (cmd_clean_len == 6 &&
      kstrcmp_n(cmd_clean, "time", 4) ==
          0)
  { // Keep time check if exists, otherwise append
    // ...
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "syslog", 6) == 0)
  {
    cmd_syslog(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "reboot", 6) == 0)
  {
    log_writestring("Rebooting...\n");
    reboot_now();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "poweroff", 8) == 0)
  {
    cmd_poweroff();
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "logout", 6) == 0)
  {
    cmd_logout(rest);
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "test_pbuf", 9) == 0)
  {
    cmd_test_pbuf();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "test_rsa", 8) == 0)
  {
    extern void test_simple_modexp(void);
    extern void test_rsa_modexp(void);
    extern void test_rsa_signature_direct(void);
    test_simple_modexp(); // Test with small numbers first
    test_rsa_modexp();
    test_rsa_signature_direct(); // Test signature computation and verification
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "eth_stat", 8) == 0)
  {
    cmd_eth_stat();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "test_eth", 8) == 0)
  {
    cmd_test_eth();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "arp_stat", 8) == 0)
  {
    cmd_arp_stat();
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "arp_whois", 9) == 0)
  {
    cmd_arp_whois(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "ip_stat", 7) == 0)
  {
    cmd_ip_stat();
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "ping", 4) == 0)
  {
    cmd_ping(rest);
    return;
  }
  if (cmd_clean_len == 10 && kstrcmp_n(cmd_clean, "traceroute", 10) == 0)
  {
    cmd_traceroute(rest);
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "nc", 2) == 0)
  {
    cmd_nc(rest);
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "route", 5) == 0)
  {
    cmd_route();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "ifconfig", 8) == 0)
  {
    cmd_ifconfig(rest);
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "udp_send", 8) == 0)
  {
    cmd_udp_send(rest);
    return;
  }
  if (cmd_clean_len == 10 && kstrcmp_n(cmd_clean, "tcp_listen", 10) == 0)
  {
    cmd_tcp_listen(rest);
    return;
  }
  if (cmd_clean_len == 11 && kstrcmp_n(cmd_clean, "tcp_connect", 11) == 0)
  {
    cmd_tcp_connect(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "wget", 4) == 0)
  {
    cmd_wget(rest);
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "httpd", 5) == 0)
  {
    cmd_httpd(rest);
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "http_get", 8) == 0)
  {
    cmd_http_get(rest);
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "tcp_stat", 8) == 0)
  {
    cmd_tcp_stat();
    return;
  }
  if (cmd_clean_len == 11 && kstrcmp_n(cmd_clean, "policy_stat", 11) == 0)
  {
    cmd_policy_stat(rest);
    return;
  }
  if (cmd_clean_len == 11 && kstrcmp_n(cmd_clean, "test_policy", 11) == 0)
  {
    cmd_test_policy(rest);
    return;
  }
  if (cmd_clean_len == 13 && kstrcmp_n(cmd_clean, "test_auth_add", 13) == 0)
  {
    cmd_test_auth_add(rest);
    return;
  }

  if (cmd_clean_len == 12 && kstrcmp_n(cmd_clean, "tcp_test_syn", 12) == 0)
  {
    cmd_tcp_test_syn(rest);
    return;
  }
  if (cmd_clean_len == 12 && kstrcmp_n(cmd_clean, "tcp_test_ack", 12) == 0)
  {
    cmd_tcp_test_ack(rest);
    return;
  }
  if (cmd_clean_len == 13 && kstrcmp_n(cmd_clean, "tcp_test_data", 13) == 0)
  {
    cmd_tcp_test_data(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "dhcp", 4) == 0)
  {
    cmd_dhcp();
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "dns", 3) == 0)
  {
    cmd_dns(rest);
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "whois", 5) == 0)
  {
    cmd_whois(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "netcfg", 6) == 0)
  {
    cmd_netcfg(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "hotspot", 7) == 0)
  {
    cmd_hotspot(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "sshd", 4) == 0)
  {
    cmd_sshd(rest);
    return;
  }
  if (cmd_clean_len == 10 && kstrcmp_n(cmd_clean, "dhcpd_stat", 10) == 0)
  {
    cmd_dhcpd_stat(rest);
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "dnsd_stat", 9) == 0)
  {
    cmd_dnsd_stat(rest);
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "auth_stat", 9) == 0)
  {
    cmd_auth_stat(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "adduser", 7) == 0)
  {
    cmd_adduser(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "deluser", 7) == 0)
  {
    cmd_deluser(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "passwd", 6) == 0)
  {
    cmd_passwd(rest);
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "users", 5) == 0)
  {
    cmd_users(rest);
    return;
  }

  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "http_stat", 9) == 0)
  {
    cmd_http_stat(rest);
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "http_test", 9) == 0)
  {
    cmd_http_test(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "edit", 4) == 0)
  {
    editor_open(rest);
    if (!ssh_shell_log_sink_active())
      terminal_clear(); // Clear local VGA after exit
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "gui", 3) == 0)
  {
    log_writestring(
        "gui: removed (recoverable from git history: src/desktop.c)\n");
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "ticks", 5) == 0)
  {
    log_writestring("ticks=");
    log_write_u32(pit_ticks);
    log_putchar('\n');
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "uptime", 6) == 0)
  {
    uint32_t ms = (pit_ticks * 1000u) / PIT_HZ;
    log_writestring("uptime_ms=");
    log_write_u32(ms);
    log_putchar('\n');
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "ps", 2) == 0)
  {
    cmd_ps();
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "kill", 4) == 0)
  {
    cmd_kill(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "wait", 4) == 0)
  {
    cmd_wait(rest);
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "sleep", 5) == 0)
  {
    uint32_t ms = 0;
    if (!parse_u32(rest, &ms))
    {
      log_writestring("Usage: sleep <ms>\n");
      return;
    }
    sleep_ms(ms);
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "a20", 3) == 0)
  {
    log_writestring("A20=");
    log_writestring(a20_is_enabled() ? "ON\n" : "OFF\n");
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "pci", 3) == 0)
  {
    pci_list_devices();
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "e1000", 5) == 0)
  {
    e1000_print_info();
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "e1000tx", 7) == 0)
  {
    cmd_e1000tx();
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "e1000rx", 7) == 0)
  {
    cmd_e1000rx();
    return;
  }
  if (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "e1000icr", 8) == 0)
  {
    cmd_e1000icr();
    return;
  }
  if (cmd_clean_len == 10 && kstrcmp_n(cmd_clean, "e1000watch", 10) == 0)
  {
    cmd_e1000watch();
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "e1000regs", 9) == 0)
  {
    cmd_e1000regs();
    return;
  }
  if (cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "e1000info", 9) == 0)
  {
    e1000_print_info();
    return;
  }
  if (cmd_clean_len == 11 && kstrcmp_n(cmd_clean, "e1000rxstat", 11) == 0)
  {
    cmd_e1000rxstat();
    return;
  }
  if (cmd_clean_len == 11 && kstrcmp_n(cmd_clean, "e1000reinit", 11) == 0)
  {
    cmd_e1000reinit();
    return;
  }
  if ((cmd_clean_len == 9 && kstrcmp_n(cmd_clean, "e1000loop", 9) == 0) ||
      (cmd_clean_len == 8 && kstrcmp_n(cmd_clean, "e100loop", 8) == 0))
  {
    cmd_e1000loop(rest);
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "pwd", 3) == 0)
  {
    cmd_pwd();
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "cd", 2) == 0)
  {
    const char *arg = skip_spaces(rest);
    cmd_cd(arg);
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "ls", 2) == 0)
  {
    vfs_cmd_ls(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "memdbg", 6) == 0)
  {
    cmd_memdbg();
      return;
    }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "mkdir", 5) == 0)
  {
    cmd_mkdir(rest);
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "cat", 3) == 0)
  {
    vfs_cmd_cat(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "ajlang", 6) == 0)
  {
    vfs_cmd_ajlang(rest);
    return;
  }
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "create", 6) == 0)
  {
    const char *args = skip_spaces(rest);
    // Find space between fn and data
    const char *space = args;
    while (*space && *space != ' ')
      space++;
    if (*space == ' ')
    {
      char fn[32];
      int fn_len = (int)(space - args);
      if (fn_len > 31)
        fn_len = 31;
      for (int i = 0; i < fn_len; i++)
        fn[i] = args[i];
      fn[fn_len] = 0;

      const char *data = skip_spaces(space);
      uint32_t data_len = 0;
      while (data[data_len])
        data_len++;
      fat12_write_file(fn, (const uint8_t *)data, data_len);
    }
    else
    {
      log_writestring("Usage: create <file> <text>\n");
    }
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "cp", 2) == 0)
  {
    const char *fn = skip_spaces(rest);
    if (*fn == '\0')
    {
      log_writestring("Usage: cp <FILE>\n");
      return;
    }
    cmd_cp(fn);
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "files", 5) == 0)
  {
    cmd_files();
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "freeram", 7) == 0)
  {
    cmd_freeram(rest);
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "run", 3) == 0)
  {
    cmd_run(rest, is_background);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "run3", 4) == 0)
  {
    cmd_run3(rest, is_background);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "loadbin", 7) == 0)
  {
    cmd_loadbin(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "ataread", 7) == 0)
  {
    cmd_ataread(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "jobs", 4) == 0)
  {
    cmd_jobs();
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "touch", 5) == 0)
  {
    cmd_touch(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "grep", 4) == 0)
  {
    cmd_grep(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "head", 4) == 0)
  {
    cmd_head(rest);
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "tail", 4) == 0)
  {
    cmd_tail(rest);
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "wc", 2) == 0)
  {
    cmd_wc(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "hexdump", 7) == 0)
  {
    cmd_hexdump(rest);
    return;
  }
  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "strings", 7) == 0)
  {
    cmd_strings(rest);
    return;
  }
  if (cmd_clean_len == 3 && kstrcmp_n(cmd_clean, "mem", 3) == 0)
  {
    uint32_t free_p = pmm_get_free_pages();
    uint32_t total_p = pmm_get_total_pages();
    uint32_t ok, kf, fail;
    mm_kmalloc_stats(&ok, &kf, &fail);
    log_writestring("PMM Free: ");
    log_write_u32(free_p);
    log_writestring(" pages (");
    log_write_u32(free_p * 4 / 1024);
    log_writestring(" MB), Total: ");
    log_write_u32(total_p);
    log_writestring(" pages\n");
    log_writestring("kmalloc ok=");
    log_write_u32(ok);
    log_writestring(" kfree=");
    log_write_u32(kf);
    log_writestring(" fail=");
    log_write_u32(fail);
    log_writestring("  (see also: heap)\n");
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "heap", 4) == 0)
  {
    cmd_heap();
    return;
  }
  if (cmd_clean_len == 5 && kstrcmp_n(cmd_clean, "alloc", 5) == 0)
  {
    uint32_t bytes = 0;
    if (!parse_u32(rest, &bytes))
    {
      log_writestring("Usage: alloc <bytes>\n");
      return;
    }
    void *p = kmalloc(bytes);
    if (!p)
    {
      log_writestring("alloc failed\n");
      return;
    }
    int id = -1;
    for (int i = 0; i < ALLOC_SLOTS; i++)
    {
      if (alloc_slots[i] == (void *)0)
      {
        alloc_slots[i] = p;
        id = i;
        break;
      }
    }
    log_writestring("id=");
    log_write_u32((uint32_t)id);
    log_writestring(" ptr=");
    log_write_hex32((uint32_t)p);
    log_putchar('\n');
    return;
  }
  if (cmd_clean_len == 11 && kstrcmp_n(cmd_clean, "thread_test", 11) == 0)
  {
    cmd_thread_test(rest);
    return;
  }
  if (cmd_clean_len == 2 && kstrcmp_n(cmd_clean, "ps", 2) == 0)
  {
    cmd_ps();
    return;
  }
  if (cmd_clean_len == 4 && kstrcmp_n(cmd_clean, "free", 4) == 0)
  {
    uint32_t id = 0;
    if (!parse_u32(rest, &id) || id >= ALLOC_SLOTS)
    {
      log_writestring("Usage: free <id>\n");
      return;
    }
    if (alloc_slots[id] == (void *)0)
    {
      log_writestring("free: empty slot\n");
      return;
    }
    kfree(alloc_slots[id]);
    alloc_slots[id] = (void *)0;
    log_writestring("freed\n");
    return;
  }

  if (cmd_clean_len == 7 && kstrcmp_n(cmd_clean, "ataread", 7) == 0)
  {
    cmd_ataread(rest);
      return;
    }
  log_writestring("Unknown command: ");
  // Print only the (sanitized) token
  for (size_t i = 0; i < cmd_clean_len; i++)
  {
    log_putchar(cmd_clean[i]);
  }
  log_putchar('\n');
}

/* Page captured command output (from `cmd | more`). SPACE/f = next page,
 * ENTER = one line, q = quit. Over SSH, print everything without pausing. */
static void shell_more_pager(const char *buf, size_t len)
{
  const size_t page =
      (TEXT_ROWS > 2) ? (size_t)(TEXT_ROWS - 2) : (size_t)20;
  size_t i = 0;
  size_t lines = 0;
  int can_pause = !ssh_shell_log_sink_active();

  while (i < len)
  {
    char c = buf[i++];
    log_putchar(c);
    if (c != '\n')
      continue;

    lines++;
    if (!can_pause || lines < page || i >= len)
      continue;

    log_writestring("--More--");
    int key = input_getkey();
    log_putchar('\n');

    if (key == 'q' || key == 'Q')
      break;
    if (key == '\n' || key == '\r')
      lines = page - 1; /* one more line then prompt again */
    else
      lines = 0; /* SPACE / other → full next page */
  }
}

void shell_execute(const char *line)
{
  const char *s = skip_spaces(line);
  if (*s == '\0')
  {
    return;
  }

  ssh_shell_log_sink_recover_stale();
  ssh_shell_log_sink_clear_for_local_shell();

  // Pre-parse for `| more` and `>` / `>>` redirection
  char redir_fn[64];
  int redir_append = 0;
  const char *redir_op = 0;
  const char *pipe_op = 0;
  shell_pipe_more = 0;

  const char *curr = s;
  while (*curr)
  {
    if (!pipe_op && *curr == '|')
      pipe_op = curr;
    if (!redir_op && *curr == '>')
    {
      redir_op = curr;
      if (curr[1] == '>')
        redir_append = 1;
    }
    curr++;
  }

  char line_buf[256];
  kstrncpy(line_buf, s, sizeof(line_buf));

  if (pipe_op)
  {
    const char *rhs = skip_spaces(pipe_op + 1);
    /* Accept "more" with optional trailing junk/spaces */
    if (rhs[0] == 'm' && rhs[1] == 'o' && rhs[2] == 'r' && rhs[3] == 'e' &&
        (rhs[4] == '\0' || (unsigned char)rhs[4] <= ' '))
    {
      shell_pipe_more = 1;
      size_t op_pos = (size_t)(pipe_op - s);
      if (op_pos < sizeof(line_buf))
        line_buf[op_pos] = '\0';
      /* Prefer pager over file redirect if both present */
      redir_op = 0;
    }
    else
    {
      log_writestring("sh: only '| more' is supported\n");
      return;
    }
  }

  if (redir_op)
  {
    // Truncate the line_buf at the redirection operator
    size_t op_pos = (size_t)(redir_op - s);
    if (op_pos < sizeof(line_buf))
    {
      line_buf[op_pos] = '\0';
    }

    // Extract filename
    const char *fn_start = skip_spaces(redir_op + (redir_append ? 2 : 1));
    int fi = 0;
    while (fn_start[fi] && (unsigned char)fn_start[fi] > ' ' &&
           fi < (int)sizeof(redir_fn) - 1)
    {
      redir_fn[fi] = fn_start[fi];
      fi++;
    }
    redir_fn[fi] = '\0';
  }
  else
  {
    redir_fn[0] = '\0';
  }

  // Capture output for file redirect or `| more`
  if ((redir_op && redir_fn[0]) || shell_pipe_more)
  {
    shell_redirect_ptr = 0;
    shell_redirect_active = 1;
    if (redir_op && redir_fn[0] && redir_append)
    {
      uint8_t *old_data = 0;
      uint32_t old_size = 0;
      if (fat12_read_file_to_ram(redir_fn, &old_data, &old_size))
      {
        size_t to_copy = (size_t)old_size;
        if (to_copy > sizeof(shell_redirect_buf))
          to_copy = sizeof(shell_redirect_buf);
        kmemcpy((uint8_t *)shell_redirect_buf, old_data, (uint32_t)to_copy);
        shell_redirect_ptr = to_copy;
        kfree(old_data);
      }
    }
  }

  shell_dispatch(line_buf);

  // After execution:
  if (shell_redirect_active)
  {
    shell_redirect_active = 0;
    if (shell_pipe_more)
    {
      shell_pipe_more = 0;
      shell_more_pager(shell_redirect_buf, shell_redirect_ptr);
    }
    else if (redir_fn[0])
    {
      fat12_write_file(redir_fn, (const uint8_t *)shell_redirect_buf,
                       (uint32_t)shell_redirect_ptr);
    }
  }
}

void kernel_main()
{
  /* Serial beacon: confirm we reached C code (no wait, so no hang on THRE). */
  outb(0x3F8, (uint8_t)'C');
  /* VGA beacon: so we see something on QEMU window even if serial never reaches
   * terminal. */
  {
    volatile uint16_t *vga = (volatile uint16_t *)0xB8000u;
    vga[0] =
        (uint16_t)('A' | 0x0200); /* green 'A' = AJOS kernel_main reached */
  }

  // Very early VGA write (before any init) - confirms kernel reached and VGA
  // works
#ifndef AJOS_SERIAL_ONLY
  {
    volatile uint16_t *vga = (volatile uint16_t *)VIDEO_MEMORY;
    vga[0] = (uint16_t)('K' | (VGA_GREEN | (VGA_BLACK << 4)) << 8);
    vga[1] = (uint16_t)('M' | (VGA_GREEN | (VGA_BLACK << 4)) << 8);
  }
#endif

  // Very early: use direct port I/O before any initialization
  // Match Linux kernel early_serial_init sequence
  // Linux does: LCR -> IER -> FCR -> MCR -> DLAB -> divisor -> clear DLAB
  outb(0x3F8 + 3, 0x03); // LCR: 8n1 (8 bits, no parity, one stop bit)
  outb(0x3F8 + 1, 0x00); // IER: no interrupt
  outb(0x3F8 + 2, 0x00); // FCR: no fifo (Linux sets to 0, not 0xC7!)
  outb(0x3F8 + 4, 0x03); // MCR: DTR + RTS (Linux uses 0x3, not 0x0B)

  // Now set baud rate (divisor = 115200 / 38400 = 3)
  unsigned char c = inb(0x3F8 + 3);
  outb(0x3F8 + 3, c | 0x80);  // Enable DLAB
  outb(0x3F8 + 0, 0x01);      // Divisor lo = 1 (115200 baud)
  outb(0x3F8 + 1, 0x00);      // Divisor hi = 0
  outb(0x3F8 + 3, c & ~0x80); // Clear DLAB

  serial_initialize(); // Must be first: all logs go to serial

  // Initialize FPU (x87)
  {
    uint32_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~(1 << 2); // Clear EM (Emulation)
    cr0 |= (1 << 1);  // Set MP (Monitor Coprocessor)
    cr0 |= (1 << 5);  // Set NE (Numeric Error)
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0));
    __asm__ volatile("finit");
    log_writestring("[INIT] FPU initialized.\n");
  }

  // Reliably clear BSS if not already cleared by kernel_entry (skip
  // 0x51000-0xA0000 = disk cache)
  extern uint8_t sbss[], ebss[];
#define DISK_CACHE_START ((uint8_t *)0x51000u)
#define DISK_CACHE_END ((uint8_t *)0xA0000u)
  for (uint8_t *p = sbss; p < ebss; p++)
  {
    if (p >= DISK_CACHE_START && p < DISK_CACHE_END)
      continue;
    *p = 0;
  }
#undef DISK_CACHE_START
#undef DISK_CACHE_END
  /* First log line: raw outb only (no serial_putchar wait) so we never hang on
   * THRE. */
  {
    const char *msg = "[DEBUG] BSS cleared\n";
    for (const char *p = msg; *p; p++)
      outb(0x3F8, (uint8_t)*p);
  }

  // Slab Allocator init
  slab_init();
  outb(0x3F8, (uint8_t)'S');
  // Small delay
  for (volatile int i = 0; i < 1000; i++)
    ;

  // Terminal init
  terminal_initialize();
  outb(0x3F8, (uint8_t)'T');
  // We need to reload GDT to add TSS and user segments. Use raw outb so we
  // don't crash in log_writestring.
  {
    const char *gdt_msg = "[INIT] Reloading GDT & TSS...\n";
    for (const char *p = gdt_msg; *p; p++)
      outb(0x3F8, (uint8_t)*p);
  }
  gdt_install_and_tss();
  /* Ensure syscall-from-user stack is valid: TSS.esp0 used on int 0x80 must be
   * mapped. */
  tss_set_esp0(0x1FF000u);
  /* Agent log: confirm TSS.esp0 set (for debug) */
  {
    uint32_t esp0_val = tss_get_esp0();
    {
      const char *m = "[DBG] tss readback=";
      for (const char *p = m; *p; p++)
        outb(0x3F8, (uint8_t)*p);
    }
    log_write_hex32(esp0_val);
    outb(0x3F8, (uint8_t)'\n');
  }
  outb(0x3F8, (uint8_t)'G');
  {
    const char *m = "[INIT] GDT reloaded.\n";
    for (const char *p = m; *p; p++)
      outb(0x3F8, (uint8_t)*p);
  }

  /* Bypass log_writestring right after GDT reload (log path can fault on some
   * hosts). */
  {
    const char *welcome =
        "Welkam lo AJOS (A Simple Operating System)!\nKernel loaded "
        "successfully.\n\nBuild: " __DATE__ " " __TIME__ "\n\n";
    for (const char *p = welcome; *p; p++)
      outb(0x3F8, (uint8_t)*p);
  }
  /* Log/redirect globals may live in BSS range we skip (disk cache
   * 0x51000-0xA0000); re-init so log_writestring is safe. */
  shell_redirect_ptr = 0;
  shell_redirect_active = 0;
  shell_pipe_more = 0;
  syslog_pos = 0;
  syslog_enabled = 0;
  syslog_flushing = 0;
  syslog_flush_fail_count = 0;

  // Boot drive passed by BIOS is stored by the bootloader at 0x0500.
  // Disk init
  uint8_t bd = *(volatile uint8_t *)0x0500;
  uint16_t rs = *(volatile uint16_t *)0x0501;
  disk_init(bd, rs);

  // Interrupts init
  interrupts_init();
  outb(0x3F8, (uint8_t)'C');
  // TSC calibrate
  tsc_calibrate();
  outb(0x3F8, (uint8_t)'M');
  pmm_init(512 * 1024 * 1024);

  outb(0x3F8, (uint8_t)'P');
  paging_init();
  outb(0x3F8, (uint8_t)'p');
  outb(0x3F8, (uint8_t)'R');
  process_init();
  outb(0x3F8, (uint8_t)'r');
  outb(0x3F8, (uint8_t)'O');
  socket_init();
  outb(0x3F8, (uint8_t)'o');

  log_writestring("Loading kernel modules...\n");
  // E1000 probe
  e1000_probe();
  // PBUF init
  pbuf_init();
  // ARP init
  arp_init();
  // IP4 init
  ip4_init();
  // DNS init
  dns_init();
  // TCP init
  tcp_init();

  log_writestring("Initializing services...\n");
  file_slot_init();
  log_writestring("[INIT] file_slot_init done\n");

  // user_init() moved to after filesystem_init() - it needs to read /etc/passwd
  http_init();
  log_writestring("[INIT] http_init done\n");
  log_writestring("[INIT] ssh_init deferred (boot stability mode)\n");
  dhcpd_init();
  log_writestring("[INIT] dhcpd_init done\n");
  dnsd_init();
  log_writestring("[INIT] dnsd_init done\n");
  auth_init();
  log_writestring("[INIT] auth_init done\n");

  // Initialize file system structure FIRST (before user_init which reads from
  // it)
  log_writestring("[INIT] About to call filesystem_init...\n");
  e1000_disable_interrupts();
  log_writestring("[DEBUG] FS Init...\n");
  filesystem_init();

  // VFS Initialization and Mounting
  log_writestring("[INIT] Initializing VFS...\n");
  struct vfs_ctx *vfs = vfs_get_global();

  // Mount FAT root
  extern fat12_ctx fat_global_ctx; // We need a global FAT context
  vfs_mount(vfs, "/", VFS_FSTYPE_FAT, &fat_global_ctx);

  // Mount RAMFS to /tmp
  static struct ramfs_ctx ramfs_global_ctx;
  ramfs_init(&ramfs_global_ctx);
  vfs_mount(vfs, "/tmp", VFS_FSTYPE_RAMFS, &ramfs_global_ctx);

  e1000_enable_interrupts();
  log_writestring("[INIT] filesystem_init and VFS mount done\n");

  /* Secondary FAT volume (IDE Drive 0x80), e.g. /mnt */
  static fat12_ctx fat_data_ctx;
  if (fat12_init_ex(&fat_data_ctx, 0x80))
  {
    vfs_mount(vfs, "/mnt", VFS_FSTYPE_FAT, &fat_data_ctx);
    log_writestring("[INIT] Mounted secondary storage at /mnt\n");
  }
  else
  {
    log_writestring("[INIT] Secondary storage (IDE) not found\n");
  }

  // Now initialize user system (needs filesystem to load /etc/passwd)
  outb(0x3F8, 'U'); // Debug: User init
  log_writestring("[INIT] About to call user_init...\n");
  user_init();
  log_writestring("[INIT] user_init done\n");

  log_writestring("Configuring network...\n");
  network_auto_setup();
  outb(0x3F8, (uint8_t)'N'); /* Network setup done */

  log_writestring(
      "[INIT] All initialization complete! About to show login prompt...\n");
  outb(0x3F8, 'L'); // Debug: Login prompt

  /* Linux-style system directories; baked into new images by mkfat12.py and
   * (re)created here for older images. fat12_mkdir is mkdir -p semantics. */
  fat12_mkdir("etc");
  fat12_mkdir("var/log");
  fat12_mkdir("bin");
  fat12_mkdir("tmp");

  /* Quiet the JSON debug event stream now that boot is done. */
  {
    extern int agent_dbg_enabled;
    agent_dbg_enabled = 0;
  }

  /* Runtime logs (SSH sessions, network activity, services) go to
   * /var/log/ajos instead of the console. Boot messages above stay on the
   * console. Use "syslog console" to mirror logs back, "syslog stop" to
   * disable. */
  syslog_enabled = 1;

#ifdef AJOS_NET_AUTOTEST
  log_writestring("[AUTOTEST] Network smoke test starting...\n");
  // Verify ARP to gateway, ping gateway, DNS, then ping a public IP.
  cmd_arp_whois("10.0.2.2");
  cmd_eth_stat();
  cmd_arp_stat();
  cmd_ping("10.0.2.2");
  cmd_eth_stat();
  cmd_dns("google.com");
  cmd_eth_stat();
  cmd_ping("1.1.1.1");
  cmd_eth_stat();
  log_writestring("[AUTOTEST] Done. Powering off.\n");
  poweroff_now();
#endif

  outb(0x3F8, (uint8_t)'P'); /* Prompt beacon */

  while (1)
  {
  // Login prompt before shell
  login_prompt();

    while (current_username[0] != '\0')
    {
    char line[LINE_MAX];
    char prompt[160];
    build_prompt(prompt, sizeof(prompt));
    readline(prompt, line, sizeof(line));
      if (line[0] == '\0')
        continue;
    history_add(line);
    shell_execute(line);
    }
  }
}

static void cmd_http_stat(const char *args)
{
  (void)args;
  if (httpd_service_active && httpd_listen_pcb)
  {
    log_writestring("[HTTP] Server RUNNING on port ");
    log_write_u32(httpd_service_port);
    log_writestring("\n[HTTP] Listener IP: ");
    uint32_t ip = httpd_listen_pcb->local_ip;
    if (ip == 0)
    {
      log_writestring("0.0.0.0 (all interfaces)\n");
    }
    else
    {
      log_write_u32((ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(ip & 0xFF);
      log_putchar('\n');
    }
    log_writestring("[HTTP] Ready to serve captive portal\n");
  }
  else
  {
    log_writestring("[HTTP] Server NOT RUNNING\n");
    log_writestring("[HTTP] Start with: service httpd start\n");
  }
}

static void cmd_http_test(const char *args)
{
  (void)args;
  log_writestring("[HTTP] Test: Send HTTP request to port 80\n");
  log_writestring("[HTTP] Example: curl http://10.0.2.15/\n");
}

static void cmd_dhcpd_stat(const char *args)
{
  (void)args;
  dhcpd_stat();
}

static void cmd_dnsd_stat(const char *args)
{
  (void)args;
  dnsd_stat();
}

static void cmd_auth_stat(const char *args)
{
  (void)args;
  auth_stat();
}

static void cmd_adduser(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: adduser <username> <password>\n");
    return;
  }

  // Parse username
  char username[32] = {0};
  int i = 0;
  while (*s && *s != ' ' && i < 31)
  {
    username[i++] = *s++;
  }
  if (i == 0)
  {
    log_writestring("Usage: adduser <username> <password>\n");
    return;
  }

  s = skip_spaces(s);
  if (!*s)
  {
    log_writestring("Usage: adduser <username> <password>\n");
    return;
  }

  // Parse password
  char password[64] = {0};
  i = 0;
  while (*s && i < 63)
  {
    password[i++] = *s++;
  }
  if (i == 0)
  {
    log_writestring("Usage: adduser <username> <password>\n");
    return;
  }

  extern int user_add(const char *username, const char *password);
  if (user_add(username, password))
  {
    log_writestring("User added successfully\n");
  }
  else
  {
    log_writestring("Failed to add user\n");
  }
}

static void cmd_deluser(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: deluser <username>\n");
    return;
  }

  char username[32] = {0};
  int i = 0;
  while (*s && *s != ' ' && i < 31)
  {
    username[i++] = *s++;
  }

  extern int user_del(const char *username);
  if (user_del(username))
  {
    log_writestring("User deleted successfully\n");
  }
  else
  {
    log_writestring("Failed to delete user\n");
  }
}

static void cmd_passwd(const char *args)
{
  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: passwd <username> <old_password> <new_password>\n");
    return;
  }

  // Parse username
  char username[32] = {0};
  int i = 0;
  while (*s && *s != ' ' && i < 31)
  {
    username[i++] = *s++;
  }
  if (i == 0)
  {
    log_writestring("Usage: passwd <username> <old_password> <new_password>\n");
    return;
  }

  s = skip_spaces(s);
  if (!*s)
  {
    log_writestring("Usage: passwd <username> <old_password> <new_password>\n");
    return;
  }

  // Parse old password
  char old_pass[64] = {0};
  i = 0;
  while (*s && *s != ' ' && i < 63)
  {
    old_pass[i++] = *s++;
  }
  if (i == 0)
  {
    log_writestring("Usage: passwd <username> <old_password> <new_password>\n");
    return;
  }

  s = skip_spaces(s);
  if (!*s)
  {
    log_writestring("Usage: passwd <username> <old_password> <new_password>\n");
    return;
  }

  // Parse new password
  char new_pass[64] = {0};
  i = 0;
  while (*s && i < 63)
  {
    new_pass[i++] = *s++;
  }
  if (i == 0)
  {
    log_writestring("Usage: passwd <username> <old_password> <new_password>\n");
    return;
  }

  extern int user_change_password(const char *username, const char *old_pass,
                                  const char *new_pass);
  if (user_change_password(username, old_pass, new_pass))
  {
    log_writestring("Password changed successfully\n");
  }
  else
  {
    log_writestring("Failed to change password\n");
  }
}

static void cmd_users(const char *args)
{
  (void)args;
  extern void user_list(void);
  user_list();
}

// Login prompt function
static void login_prompt(void)
{
  const int MAX_ATTEMPTS = 3;
  int attempts = 0;

  while (attempts < MAX_ATTEMPTS)
  {
    log_writestring("\n");
    log_writestring("Welkam AJOS Login\n");
    log_writestring("==========\n");

    char username[64] = {0};
    char password[64] = {0};

    readline("Username: ", username, sizeof(username));

    // Skip empty username
    if (username[0] == '\0')
    {
      continue;
    }

    readline_password("Password: ", password, sizeof(password));

    // Check credentials
    extern int user_check_password(const char *username, const char *password);
    if (user_check_password(username, password))
    {
      // Login successful
      int i = 0;
      while (i < 31 && username[i] != '\0')
      {
        current_username[i] = username[i];
        i++;
      }
      current_username[i] = '\0';

      log_writestring("\n");
      log_writestring("Welcome to AJOS, ");
      log_writestring(current_username);
      log_writestring("!\n");
      log_writestring("\n");
      return;
    }
    else
    {
      attempts++;
      log_writestring("\n");
      log_writestring("Login incorrect\n");
      if (attempts < MAX_ATTEMPTS)
      {
        log_writestring("Please try again.\n");
      }
      else
      {
        log_writestring("Maximum login attempts exceeded.\n");
        log_writestring("System will continue with limited access.\n");
        log_writestring("\n");
        // Continue anyway but mark as not logged in
        current_username[0] = '\0';
        return;
      }
    }
  }
}

static void cmd_policy_stat(const char *args)
{
  (void)args;
  log_writestring("[POLICY] Packets dropped: ");
  log_write_u32(ip4_get_policy_drop_count());
  log_putchar('\n');
}

static void cmd_test_policy(const char *args)
{
  if (!args || *args == '\0')
  {
    log_writestring("Usage: test_policy <src_ip_hex> <dst_port> <proto>\n");
    log_writestring(
        "Example: test_policy 0A000005 80 6 (TCP to 80 from 10.0.0.5)\n");
    return;
  }
  // Simplified parsing for hex IP, port, proto
  uint32_t src_ip = 0;
  for (int i = 0; i < 8 && args[i]; i++)
  {
    char c = args[i];
    uint32_t v = 0;
    if (c >= '0' && c <= '9')
      v = c - '0';
    else if (c >= 'A' && c <= 'F')
      v = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
      v = c - 'a' + 10;
    src_ip = (src_ip << 4) | v;
  }

  // Skip to next arg (naively)
  const char *p = args;
  while (*p && *p != ' ')
    p++;
  while (*p == ' ')
    p++;
  uint16_t port = (uint16_t)katoi(p);
  while (*p && *p != ' ')
    p++;
  while (*p == ' ')
    p++;
  uint8_t proto = (uint8_t)katoi(p);

  struct ip4_hdr hdr;
  hdr.src = htonl(src_ip);
  hdr.proto = proto;

  // We need a mock pbuf. Buffer size just enough for IP + Proto headers
  struct pbuf mock_p;
  uint8_t payload[64];
  mock_p.payload = payload;
  mock_p.len = 64;

  // Set the L4 port in payload
  if (proto == IP_PROTO_UDP)
  {
    struct udp_hdr *u = (struct udp_hdr *)(payload + 20);
    u->dst_port = htons(port);
  }
  else if (proto == IP_PROTO_TCP)
  {
    struct tcp_hdr *t = (struct tcp_hdr *)(payload + 20);
    t->dst_port = htons(port);
  }

  extern int ip4_policy_filter(struct pbuf * p, struct ip4_hdr * hdr,
                               uint8_t hl);
  int allowed = ip4_policy_filter(&mock_p, &hdr, 20);

  log_writestring("[POLICY] Result: ");
  log_writestring(allowed ? "ALLOWED" : "DROPPED");
  log_putchar('\n');
}

static void cmd_test_auth_add(const char *args)
{
  if (!args || *args == '\0')
  {
    log_writestring("Usage: test_auth_add <ip_hex>\n");
    return;
  }
  uint32_t ip = 0;
  for (int i = 0; i < 8 && args[i]; i++)
  {
    char c = args[i];
    uint32_t v = 0;
    if (c >= '0' && c <= '9')
      v = c - '0';
    else if (c >= 'A' && c <= 'F')
      v = c - 'A' + 10;
    else if (c >= 'a' && c <= 'f')
      v = c - 'a' + 10;
    ip = (ip << 4) | v;
  }
  auth_set_authenticated(ip);
  log_writestring("[AUTH] IP Added: ");
  log_write_hex32(ip);
  log_putchar('\n');
}

static void cmd_traceroute(const char *args)
{
  extern int input_getkey_noblock(void);
  extern volatile uint32_t icmp_last_time_exceeded_src;
  extern volatile uint32_t icmp_last_time_exceeded_tick;
  extern volatile uint16_t icmp_last_time_exceeded_id;
  extern volatile uint16_t icmp_last_time_exceeded_seq;
  extern volatile uint32_t icmp_last_echo_reply_src;
  extern volatile uint16_t icmp_last_echo_reply_id;
  extern volatile uint16_t icmp_last_echo_reply_seq;

  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: traceroute <ip>\n");
    return;
  }

  uint32_t ip = 0;
  if (!parse_ip(&s, &ip))
  {
    extern volatile int dns_got_reply;
    extern volatile uint32_t dns_last_ip;
    const char *name = skip_spaces(args);
    if (!*name)
    {
      log_writestring("Invalid IP\n");
      return;
    }
    for (int attempt = 0; attempt < 2; attempt++)
    {
      dns_lookup(name);
      uint32_t start = pit_ticks;
      while ((pit_ticks - start) < (PIT_HZ * 3u))
      {
        net_pump_rx(8);
        if (dns_got_reply)
        {
          ip = dns_last_ip;
          break;
        }
        sleep_ms(50);
      }
      if (ip != 0)
        break;
    }
    if (ip == 0)
    {
      log_writestring("traceroute: dns timeout\n");
      return;
    }
  }

  log_writestring("traceroute to ");
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring(", 30 hops max\n");

  uint16_t trace_id = 0x5678;
  int reached_dest = 0;

  for (int ttl = 1; ttl <= 30; ttl++)
  {
    log_write_u32(ttl);
    log_writestring("  ");

    uint32_t last_hop_ip = 0;

    for (int probe = 0; probe < 3; probe++)
    {
      if (input_getkey_noblock() != -1)
      {
        log_writestring("\nAborted.\n");
        return;
      }

      icmp_last_time_exceeded_tick = 0;
      icmp_last_echo_reply_id = 0;

      struct pbuf *p = pbuf_alloc();
      if (!p)
        break;

      pbuf_header(p, -(int)sizeof(struct icmp_hdr));
      struct icmp_hdr *hdr = (struct icmp_hdr *)p->payload;
      hdr->type = ICMP_TYPE_ECHO_REQUEST;
      hdr->code = 0;
      hdr->chksum = 0;
      hdr->id = htons(trace_id);
      uint16_t seq = (uint16_t)((ttl << 8) | probe);
      hdr->seqno = htons(seq);
      p->len = sizeof(struct icmp_hdr);
      hdr->chksum = net_checksum(hdr, sizeof(struct icmp_hdr));

      uint64_t t_start = get_time_us();

      ip4_output_ttl(p, ip, IP_PROTO_ICMP, (uint8_t)ttl);

      int got_response = 0;
      uint32_t wait_start = pit_ticks;
      while ((pit_ticks - wait_start) < (PIT_HZ * 1u))
      {

        if (icmp_last_time_exceeded_tick > wait_start &&
            icmp_last_time_exceeded_id == trace_id &&
            icmp_last_time_exceeded_seq == seq)
        {

          uint64_t t_end = get_time_us();
          log_write_time_ms(t_end - t_start);
          log_writestring(" ms  ");
          last_hop_ip = icmp_last_time_exceeded_src;
          got_response = 1;
          break;
        }

        if (icmp_last_echo_reply_id == trace_id &&
            icmp_last_echo_reply_seq == seq)
        {

          uint64_t t_end = get_time_us();
          log_write_time_ms(t_end - t_start);
          log_writestring(" ms  ");
          last_hop_ip = icmp_last_echo_reply_src;
          got_response = 1;
          reached_dest = 1;
          break;
        }
        sleep_ms(10);
      }

      if (!got_response)
      {
        log_writestring("*     ");
      }
    }

    if (last_hop_ip != 0)
    {
      log_write_u32((last_hop_ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((last_hop_ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((last_hop_ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(last_hop_ip & 0xFF);
    }

    log_putchar('\n');

    if (reached_dest)
    {
      break;
    }
  }
}

static void cmd_showkeys(void)
{
  log_writestring("Press keys to see raw scancodes (dec).\n");
  log_writestring("Press 'q' (16) to exit. Key releases are > 128.\n");

  while (1)
  {
    uint8_t sc = 0;
    if (kbd_pop_scancode(&sc))
    {
      log_writestring("Scancode: ");
      log_write_u32((uint32_t)sc);
      log_writestring("\n");

      if (sc == 0x10)
      { // 'q' press
        break;
      }
    }
    else
    {
      __asm__ volatile("hlt");
    }
  }
}

static void cmd_nc(const char *args)
{
  extern int input_getkey_noblock(void);

  const char *s = skip_spaces(args);
  if (!*s)
  {
    log_writestring("Usage: nc <host> <port>\n");
    return;
  }

  // Parse host
  char host[256];
  int i = 0;
  while (*s && *s != ' ' && i < 255)
  {
    host[i++] = *s++;
  }
  host[i] = 0;

  s = skip_spaces(s);
  uint32_t port = 0;
  if (!parse_u32(s, &port) || port > 65535)
  {
    log_writestring("Invalid port\n");
    return;
  }

  uint32_t ip = 0;
  const char *host_ptr = host;
  if (!parse_ip(&host_ptr, &ip))
  {
    extern volatile int dns_got_reply;
    extern volatile uint32_t dns_last_ip;

    log_writestring("Resolving ");
    log_writestring(host);
    log_writestring("...\n");

    for (int attempt = 0; attempt < 2; attempt++)
    {
      dns_lookup(host);
      uint32_t start = pit_ticks;
      while ((pit_ticks - start) < (PIT_HZ * 3u))
      {
        net_pump_rx(8);
        if (dns_got_reply)
        {
          ip = dns_last_ip;
          break;
        }
        sleep_ms(50);
      }
      if (ip != 0)
        break;
    }
    if (ip == 0)
    {
      log_writestring("nc: dns lookup failed\n");
      return;
    }
  }

  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb)
  {
    log_writestring("nc: no free PCBs\n");
    return;
  }

  log_writestring("Connecting to ");
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring(" port ");
  log_write_u32(port);
  log_writestring("...\n");

  tcp_connect(pcb, ip, (uint16_t)port);

  // Wait for connection
  uint32_t start = pit_ticks;
  while ((pit_ticks - start) < (PIT_HZ * 10u))
  {
    if (pcb->state == TCP_ESTABLISHED)
    {
      log_writestring("Connected!\n");
      break;
    }
    if (pcb->state == TCP_CLOSED)
    {
      log_writestring("Connection refused.\n");
      return;
    }
    sleep_ms(50);
  }

  if (pcb->state != TCP_ESTABLISHED)
  {
    log_writestring("Connection timeout.\n");
    tcp_close(pcb);
    return;
  }

  // Interactive loop
  log_writestring("Type to send. Press Ctrl+C to exit.\n");

  while (pcb->state == TCP_ESTABLISHED)
  {
    // 1. Handle Input
    int k = input_getkey_noblock();
    if (k != -1)
    {
      if (k == 3)
      { // Ctrl+C
        break;
      }
      char c = (char)k;
      // Echo locally? Maybe
      log_putchar(c);
      // Send to TCP
      uint8_t b = (uint8_t)c;
      tcp_send(pcb, &b, 1);
    }

    // 2. Handle Output (TCP -> Screen)
    if (pcb->app_rx_len > 0)
    {
      for (int j = 0; j < pcb->app_rx_len; j++)
      {
        log_putchar((char)pcb->app_rx_buf[j]);
      }
      pcb->app_rx_len = 0; // Consumed
    }

    // 3. Poll drivers
    // (This happens in background if IRQs work, otherwise we might need
    // explicit polling if implemented) For now assuming interrupts drive TCP
    // state.

    // Check if remote closed
    if (pcb->state == TCP_CLOSE_WAIT || pcb->state == TCP_CLOSED)
    {
      log_writestring("\nConnection closed by foreign host.\n");
      break;
    }

    // Small sleep to yield
    // sleep_ms(1); // Too slow for typing?
  }

  tcp_close(pcb);
}

static void cmd_route(void)
{
  uint32_t my_ip = arp_get_ajos_ip();
  uint32_t gw = ip4_get_gateway();
  uint32_t mask = ip4_get_netmask();

  log_writestring("Kernel IP routing table\n");
  log_writestring(
      "Destination     Gateway         Genmask         Flags Iface\n");

  // Default route
  log_writestring("0.0.0.0         ");
  if (gw == 0)
    log_writestring("*               ");
  else
  {
    log_write_u32((gw >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((gw >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((gw >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(gw & 0xFF);
    // Padding logic skipped for brevity, just spaces
    log_writestring("     ");
  }
  log_writestring("0.0.0.0         UG    eth0\n");

  // Local subnet
  if (my_ip != 0 && mask != 0)
  {
    uint32_t net = my_ip & mask;
    log_write_u32((net >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((net >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((net >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(net & 0xFF);
    log_writestring("     *               "); // No gateway

    log_write_u32((mask >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((mask >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((mask >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(mask & 0xFF);
    log_writestring("     U     eth0\n");
  }
}
