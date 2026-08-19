#include "../../include/kernel.h"
#include "../../include/pmm.h"
#include "../../include/vmm.h"
#include <stddef.h>
#include <stdint.h>

static uint32_t *kernel_pd = NULL;

// Helper to get PT from PDE, allocating if necessary. Updated to handle flags.
static uint32_t *get_page_table(uint32_t *pd, uint32_t virt, int make,
                                uint32_t flags) {
  uint32_t pde_idx = virt >> 22;
  if (pd[pde_idx] & VMM_PRESENT) {
    if (flags & VMM_USER)
      pd[pde_idx] |= VMM_USER;
    return (uint32_t *)(pd[pde_idx] & 0xFFFFF000u);
  }

  if (!make)
    return NULL;

  // Allocate a new page table
  uint32_t *pt = (uint32_t *)pmm_alloc_page(0);
  if (!pt)
    return NULL;

  // Clear the new page table
  for (int i = 0; i < 1024; i++)
    pt[i] = 0;

  // Add to page directory. Ensure we propagate VMM_USER if requested.
  pd[pde_idx] =
      ((uint32_t)pt) | VMM_PRESENT | VMM_WRITABLE | (flags & VMM_USER);
  return pt;
}

int vmm_map_page(uint32_t *pd, uint32_t virt, uint32_t phys, uint32_t flags) {
  uint32_t *pt = get_page_table(pd, virt, 1, flags);
  if (!pt)
    return -1;

  uint32_t pte_idx = (virt >> 12) & 0x3FFu;
  pt[pte_idx] = (phys & 0xFFFFF000u) | flags | VMM_PRESENT;

  // Flush TLB for this page
  __asm__ volatile("invlpg %0" : : "m"(*(char *)virt) : "memory");
  return 0;
}

int vmm_unmap_page(uint32_t *pd, uint32_t virt) {
  uint32_t *pt = get_page_table(pd, virt, 0, 0);
  if (!pt)
    return -1;

  uint32_t pte_idx = (virt >> 12) & 0x3FFu;
  pt[pte_idx] = 0;

  __asm__ volatile("invlpg %0" : : "m"(*(char *)virt) : "memory");
  return 0;
}

void vmm_map_range(uint32_t *pd, uint32_t start, uint32_t end, uint32_t flags) {
  for (uint32_t addr = start; addr < end; addr += PAGE_SIZE) {
    vmm_map_page(pd, addr, addr, flags);
  }
}

void paging_init(void) {
  // Allocate kernel page directory
  kernel_pd = (uint32_t *)pmm_alloc_page(0);
  for (int i = 0; i < 1024; i++)
    kernel_pd[i] = 0;

  // Identity map first 480MB for kernel and PMM range. Set VMM_USER so
  // user-mode processes can access their code/stack in this region.
  // Must match PMM_END_ADDR (0x1E000000 = 480MB) in pmm.c.
  vmm_map_range(kernel_pd, 0, 0x1E000000u, VMM_WRITABLE | VMM_USER);

  // Map VGA text + Mode 13h framebuffer
  vmm_map_page(kernel_pd, 0xB8000, 0xB8000, VMM_WRITABLE);
  for (uint32_t a = 0xA0000u; a < 0xB0000u; a += PAGE_SIZE)
    vmm_map_page(kernel_pd, a, a, VMM_WRITABLE);

  // Load CR3
  __asm__ volatile("mov %0, %%cr3" : : "r"((uint32_t)kernel_pd) : "memory");

  // Enable paging if not already enabled
  uint32_t cr0;
  __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
  cr0 |= 0x80000000u;
  __asm__ volatile("mov %0, %%cr0" : : "r"(cr0) : "memory");

  log_writestring("[VMM] Dynamic paging enabled\n");
}

// Keep compatibility with existing MMIO mapping calls
void paging_map_mmio_4mb(uint32_t virt_base, uint32_t phys_base) {
  for (uint32_t i = 0; i < 1024; i++) {
    vmm_map_page(kernel_pd, virt_base + i * PAGE_SIZE,
                 phys_base + i * PAGE_SIZE, VMM_WRITABLE | VMM_PCD | VMM_PWT);
  }
}

void paging_map_framebuffer(uint32_t phys, uint32_t size) {
  if (!kernel_pd || !size)
    return;
  uint32_t start = phys & ~(PAGE_SIZE - 1u);
  uint32_t end = (phys + size + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
  for (uint32_t a = start; a < end; a += PAGE_SIZE) {
    vmm_map_page(kernel_pd, a, a, VMM_WRITABLE | VMM_PCD | VMM_PWT);
  }
}
