#ifndef KERNEL_H
#define KERNEL_H

#include <stddef.h>
#include <stdint.h>

#include "datetime.h"
#include "io.h"
#include "pmm.h"
#include "slab.h"

typedef struct regs {
  uint32_t gs, fs, es, ds;
  uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
  uint32_t int_no, err_code;
  uint32_t eip, cs, efl, useresp, ss;
} regs_t;

typedef void (*isr_t)(regs_t *);

void register_interrupt_handler(uint8_t n, isr_t handler);

extern isr_t interrupt_handlers[256];

/* Implemented in kernel.c; exposed for other .c files that only include
 * kernel.h */
void serial_writestring(const char *data);
void log_writestring(const char *data);
void log_write_u32(uint32_t v);
void log_write_hex32(uint32_t v);
void log_write_hex8(uint8_t v);
void log_putchar(char c);
void pic_unmask_irq(uint8_t irq);
void pic_mask_irq(uint8_t irq);
const char *skip_spaces(const char *s);
int kstreq(const char *a, const char *b);
int kstrcmp_n(const char *a, const char *b, size_t n);

void shell_format_prompt(char *out, size_t cap,
                         const char *ssh_username_override);

/* Capture shell command output into a buffer (for GUI terminal). */
void shell_gui_sink_begin(char *buf, size_t cap);
size_t shell_gui_sink_end(void);

/* Tab-complete command (first word) or filename (later words) at end of line.
 * Returns number of matches (0..max_matches). On a unique match, or when a
 * longer common prefix exists, updates line/len. Optional matches[] is filled
 * when max_matches > 0 for listing. */
#define SHELL_TAB_MATCH_LEN 32
int shell_tab_complete(char *line, size_t *len, size_t cap,
                       char matches[][SHELL_TAB_MATCH_LEN], int max_matches);

void mem_copy(void *dest, const void *src, size_t n);

#endif
