#include "pmm.h"
#include "kernel.h"
#include <stddef.h>
#include <stdint.h>

// Buddy system structures
typedef struct free_block {
  struct free_block *next;
} free_block_t;

static free_block_t *free_lists[PMM_MAX_ORDER + 1];
static uint32_t total_pages = 0;
static uint32_t free_pages = 0;

// Page metadata to track allocation order for kfree
// Range is 8MB to 480MB (472MB = 120832 pages)
#define PMM_METADATA_SIZE 131072
static uint8_t page_metadata[PMM_METADATA_SIZE];
#define PAGE_DIRTY 0x80
#define PAGE_ORDER_MASK 0x0F

// Memory range to manage
// Start after kernel/disk-cache area; end well below PCI MMIO (E1000 at
// 0xFEBC0000)
#define PMM_START_ADDR 0x00800000u // 8MB
#define PMM_END_ADDR 0x1E000000u   // 480MB

static void pmm_add_to_list(void *addr, int order) {
  free_block_t *block = (free_block_t *)addr;
  block->next = free_lists[order];
  free_lists[order] = block;
}

void pmm_init(uint32_t mem_size) {
  /* These may be in BSS range we skip (disk cache 0x51000-0x9C000); ensure
   * clean. */
  for (int i = 0; i <= PMM_MAX_ORDER; i++) {
    free_lists[i] = NULL;
  }
  total_pages = 0;
  free_pages = 0;
  for (int i = 0; i < PMM_METADATA_SIZE; i++) {
    page_metadata[i] = 0;
  }

  /* Never expose more physical RAM than the machine has (mem_size), and never
   * above PMM_END_ADDR. Passing 512M while QEMU defaults to ~128M was causing
   * allocations past guest RAM → random corruption (often visible as VGA junk).
   */
  uint32_t end_addr = PMM_END_ADDR;
  if (mem_size > 0) {
    uint32_t ms = mem_size & ~(PAGE_SIZE - 1u);
    if (ms < end_addr)
      end_addr = ms;
  }

  if (end_addr <= PMM_START_ADDR) {
    return; // No memory to manage
  }

  total_pages = (end_addr - PMM_START_ADDR) / PAGE_SIZE;
  free_pages = total_pages;

  // Split the large physical memory into max-order blocks
  uint32_t current = PMM_START_ADDR;
  uint32_t max_block_size = PAGE_SIZE * (1 << PMM_MAX_ORDER);

  while (current + max_block_size <= end_addr) {
    pmm_add_to_list((void *)current, PMM_MAX_ORDER);
    current += max_block_size;
  }

  // Handle remaining memory by using smaller orders
  for (int order = PMM_MAX_ORDER - 1; order >= 0; order--) {
    uint32_t block_size = PAGE_SIZE * (1 << order);
    if (current + block_size <= end_addr) {
      pmm_add_to_list((void *)current, order);
      current += block_size;
    }
  }

  log_writestring("[PMM] Initialized Buddy Allocator: ");
  log_write_u32(free_pages);
  log_writestring(" pages free (");
  log_write_u32(free_pages * 4 / 1024);
  log_writestring(" MB)\n");
}

void *pmm_alloc_page(int order) {
  if (order < 0 || order > PMM_MAX_ORDER)
    return NULL;

  // Find first list with a free block
  for (int j = order; j <= PMM_MAX_ORDER; j++) {
    if (free_lists[j]) {
      void *addr = (void *)free_lists[j];
      free_lists[j] = free_lists[j]->next;

      // Split the block if it's larger than needed
      while (j > order) {
        j--;
        uint32_t mid = (uint32_t)addr + (PAGE_SIZE * (1 << j));
        pmm_add_to_list((void *)mid, j);
      }

      // Mark the allocation order in metadata
      uint32_t pg_idx = ((uint32_t)addr - PMM_START_ADDR) / PAGE_SIZE;
      if (pg_idx < PMM_METADATA_SIZE) {
        page_metadata[pg_idx] = (uint8_t)order | PAGE_DIRTY;
      }

      free_pages -= (1 << order);
      // log_writestring("[PMM] Alloc: 0x");
      // log_write_hex32((uint32_t)addr);
      // log_putchar('\n');
      return addr;
    }
  }

  return NULL;
}

void pmm_free_page(void *ptr, int order) {
  if (!ptr || order < 0 || order > PMM_MAX_ORDER)
    return;

  // Clear metadata
  uint32_t pg_idx = ((uint32_t)ptr - PMM_START_ADDR) / PAGE_SIZE;
  if (pg_idx < PMM_METADATA_SIZE) {
    page_metadata[pg_idx] = 0;
  }

  // Simple implementation: just add back to list
  // TODO: Coalesce buddies (requires bitmap or page descriptors)
  pmm_add_to_list(ptr, order);
  free_pages += (1 << order);
}

int pmm_get_order(void *ptr) {
  uint32_t pg_idx = ((uint32_t)ptr - PMM_START_ADDR) / PAGE_SIZE;
  if (pg_idx < PMM_METADATA_SIZE && (page_metadata[pg_idx] & PAGE_DIRTY)) {
    return (int)(page_metadata[pg_idx] & PAGE_ORDER_MASK);
  }
  return -1;
}

uint32_t pmm_get_free_pages(void) { return free_pages; }
uint32_t pmm_get_total_pages(void) { return total_pages; }
