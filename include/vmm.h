#ifndef VMM_H
#define VMM_H

#include <stddef.h>
#include <stdint.h>

// Page Table/Directory Flags
#define VMM_PRESENT 0x01
#define VMM_WRITABLE 0x02
#define VMM_USER 0x04
#define VMM_PCD 0x10 // Page Cache Disable
#define VMM_PWT 0x08 // Page Write Through

void vmm_init(void);

// Map a single page
int vmm_map_page(uint32_t *pd, uint32_t virt, uint32_t phys, uint32_t flags);

// Unmap a single page
int vmm_unmap_page(uint32_t *pd, uint32_t virt);

// Create a new address space (returns physical address of PD)
uint32_t vmm_create_address_space(void);

// Identity map a range
void vmm_map_range(uint32_t *pd, uint32_t start, uint32_t end, uint32_t flags);

#endif
