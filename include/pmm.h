#ifndef PMM_H
#define PMM_H

#include <stddef.h>
#include <stdint.h>

#define PAGE_SIZE 4096u
#define PMM_MAX_ORDER 10 // 4KB * 2^10 = 4MB

void pmm_init(uint32_t mem_size);
void *pmm_alloc_page(int order);
void pmm_free_page(void *ptr, int order);

// Memory usage tracking
uint32_t pmm_get_free_pages(void);
uint32_t pmm_get_total_pages(void);
int pmm_get_order(void *ptr);

#endif
