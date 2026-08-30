#include "../../include/kernel.h"
#include <stddef.h>
#include <stdint.h>

// Heap constants
// The heap must live ABOVE the kernel image+BSS: ebss has grown past the old
// fixed 4MiB start, and heap allocations were silently overwriting kernel
// globals (process table, buffers) -> "random" corruption. Start is computed
// at init from the linker's ebss, page-aligned, with a floor for safety.
// HEAP_SIZE must keep the heap below PMM_START (0x800000).
#define HEAP_FLOOR 0x00500000u
#define HEAP_SIZE (0x00100000u) // 1 MiB

/* Linker symbols (kernel/linker.ld) */
extern char sbss[], ebss[];

typedef struct heap_block {
  uint32_t size;           // bytes in payload
  uint32_t is_free;        // 1 = free, 0 = used
  struct heap_block *next; // next block in list
} heap_block_t;

// Use a non-static global to avoid BSS initialization issues
volatile heap_block_t *heap_head = (heap_block_t *)0;

static uint32_t align_up_u32(uint32_t x, uint32_t a) {
  return (x + (a - 1u)) & ~(a - 1u);
}

void heap_init(void) {
  outb(0x3F8, 'H'); // Debug: heap_init called
  uint32_t start = align_up_u32((uint32_t)ebss, 4096u);
  if (start < HEAP_FLOOR)
    start = HEAP_FLOOR;
  heap_block_t *new_head = (heap_block_t *)start;
  new_head->size = (uint32_t)(HEAP_SIZE - sizeof(heap_block_t));
  new_head->is_free = 1;
  new_head->next = (heap_block_t *)0;

  // Force assignment - use multiple methods to ensure it works
  heap_head = new_head;
  __asm__ volatile("" ::: "memory");

  // Also write directly to memory address
  *(volatile uint32_t *)((uint32_t)&heap_head) = (uint32_t)new_head;
  __asm__ volatile("" ::: "memory");

  // Verify assignment
  uint32_t hh = (uint32_t)heap_head;
  outb(0x3F8, '0' + ((hh >> 20) & 0xF));
  outb(0x3F8, '0' + ((hh >> 16) & 0xF));
  outb(0x3F8, '0' + ((hh >> 12) & 0xF));
  outb(0x3F8, '0' + ((hh >> 8) & 0xF));

  outb(0x3F8, 'I'); // Debug: heap_init complete
}

void heap_stats(uint32_t *out_total, uint32_t *out_used, uint32_t *out_free) {
  uint32_t total = 0;
  uint32_t used = 0;
  uint32_t freeb = 0;

  heap_block_t *current_head = (heap_block_t *)((volatile uint32_t)heap_head);
  if (current_head == (heap_block_t *)0) {
    if (out_total)
      *out_total = 0;
    if (out_used)
      *out_used = 0;
    if (out_free)
      *out_free = 0;
    return;
  }
  for (heap_block_t *b = current_head; b != (heap_block_t *)0; b = b->next) {
    total += b->size;
    if (b->is_free) {
      freeb += b->size;
    } else {
      used += b->size;
    }
  }

  if (out_total) {
    *out_total = total;
  }
  if (out_used) {
    *out_used = used;
  }
  if (out_free) {
    *out_free = freeb;
  }
}

static void heap_coalesce(void) {
  // Merge adjacent free blocks when they are physically contiguous.
  heap_block_t *current_head = (heap_block_t *)((volatile uint32_t)heap_head);
  for (heap_block_t *b = current_head;
       b != (heap_block_t *)0 && b->next != (heap_block_t *)0;) {
    heap_block_t *n = b->next;
    uint8_t *b_end = (uint8_t *)b + sizeof(heap_block_t) + b->size;
    if (b->is_free && n->is_free && (uint8_t *)n == b_end) {
      b->size += (uint32_t)sizeof(heap_block_t) + n->size;
      b->next = n->next;
      continue;
    }
    b = b->next;
  }
}

void *kmalloc(uint32_t size) {
  // Make heap operations IRQ-safe: networking RX runs in interrupt context,
  // and can allocate/free pbufs. Without this, kmalloc/kfree can be re-entered
  // and corrupt the heap, causing random network failures.
  uint32_t flags = 0;
  __asm__ volatile("pushf\npop %0\ncli" : "=r"(flags) : : "memory");

  // Read heap_head with volatile to ensure we get the actual value
  heap_block_t *current_head = (heap_block_t *)((volatile uint32_t)heap_head);
  if (current_head == (heap_block_t *)0) {
    heap_init();
    // Re-read after init
    current_head = (heap_block_t *)((volatile uint32_t)heap_head);
    if (current_head == (heap_block_t *)0) {
      // Still 0 after init - critical error
      extern void log_writestring(const char *s);
      extern void log_write_hex32(uint32_t v);
      log_writestring(
          "kmalloc: CRITICAL - heap_init failed, heap_head still 0x");
      log_write_hex32((uint32_t)heap_head);
      log_putchar('\n');
      if (flags & (1u << 9))
        __asm__ volatile("sti" : : : "memory");
      return (void *)0;
    }
  }

  if (size == 0) {
    if (flags & (1u << 9))
      __asm__ volatile("sti" : : : "memory");
    return (void *)0;
  }

  // Basic alignment for pointers/headers
  uint32_t orig_size = size;
  size = align_up_u32(size, 8u);

  for (volatile heap_block_t *b = heap_head; b != (heap_block_t *)0;
       b = b->next) {
    if (!b->is_free || b->size < size) {
      continue;
    }

    // Split if there's enough room for a new header + minimal payload
    uint32_t remaining = b->size - size;
    if (remaining > (uint32_t)(sizeof(heap_block_t) + 8u)) {
      heap_block_t *newb =
          (heap_block_t *)((uint8_t *)b + sizeof(heap_block_t) + size);
      newb->size = remaining - (uint32_t)sizeof(heap_block_t);
      newb->is_free = 1;
      newb->next = b->next;

      b->size = size;
      b->next = newb;
    }

    b->is_free = 0;
    void *ret = (void *)((uint8_t *)b + sizeof(heap_block_t));
    if (flags & (1u << 9))
      __asm__ volatile("sti" : : : "memory");
    return ret;
  }

  // Allocation failed - debug output
  if (orig_size > 4000) {
    extern void log_writestring(const char *s);
    extern void log_write_u32(uint32_t v);
    extern void log_write_hex32(uint32_t v);
    log_writestring("kmalloc: FAILED to allocate ");
    log_write_u32(orig_size);
    log_writestring(" bytes, heap_head=0x");
    log_write_hex32((uint32_t)current_head);
    if (current_head != (heap_block_t *)0) {
      log_writestring(" first_block.size=");
      log_write_u32(current_head->size);
      log_writestring(" first_block.is_free=");
      log_write_u32(current_head->is_free ? 1 : 0);
    }
    log_putchar('\n');
  }

  if (flags & (1u << 9))
    __asm__ volatile("sti" : : : "memory");
  return (void *)0;
}

void kfree(void *ptr) {
  uint32_t flags = 0;
  __asm__ volatile("pushf\npop %0\ncli" : "=r"(flags) : : "memory");

  if (ptr == (void *)0) {
    if (flags & (1u << 9))
      __asm__ volatile("sti" : : : "memory");
    return;
  }

  heap_block_t *b = (heap_block_t *)((uint8_t *)ptr - sizeof(heap_block_t));
  b->is_free = 1;
  heap_coalesce();

  if (flags & (1u << 9))
    __asm__ volatile("sti" : : : "memory");
}
