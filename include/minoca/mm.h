#ifndef MINOCA_MM_H
#define MINOCA_MM_H

#include <stdint.h>
#include <stddef.h>

// Memory Management API (Minoca OS style)

// Paging
void paging_init(void);
void paging_map_mmio_4mb(uint32_t virt_base, uint32_t phys_base);

/* Identity-map a physical framebuffer/MMIO range (cache-disabled). */
void paging_map_framebuffer(uint32_t phys, uint32_t size);

// Heap
void heap_init(void);
void *kmalloc(uint32_t size);
void kfree(void *ptr);
void heap_stats(uint32_t *out_total, uint32_t *out_used, uint32_t *out_free);

#endif // MINOCA_MM_H
