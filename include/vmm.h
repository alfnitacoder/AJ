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

// User-process address spaces: kernel_pd clone + private PDE[0] table that
// only exposes the user window (win_virt..win_virt+nframes*4096) to ring 3.
uint32_t *vmm_get_kernel_pd(void);
uint32_t *vmm_current_pd(void);
void vmm_load_pd(uint32_t *pd);
uint32_t *vmm_create_user_pd(const uint32_t *frames, int nframes,
                             uint32_t win_virt);
void vmm_remap_window(uint32_t *pd, const uint32_t *frames, int nframes,
                      uint32_t win_virt);
void vmm_destroy_user_pd(uint32_t *pd);

// Unmap a single page
int vmm_unmap_page(uint32_t *pd, uint32_t virt);

// Create a new address space (returns physical address of PD)
uint32_t vmm_create_address_space(void);

// Identity map a range
void vmm_map_range(uint32_t *pd, uint32_t start, uint32_t end, uint32_t flags);

#endif
