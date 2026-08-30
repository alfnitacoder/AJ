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

uint32_t *vmm_get_kernel_pd(void) { return kernel_pd; }

uint32_t *vmm_current_pd(void) {
  uint32_t cr3;
  __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
  return (uint32_t *)cr3;
}

void vmm_load_pd(uint32_t *pd) {
  if (pd && pd != vmm_current_pd())
    __asm__ volatile("mov %0, %%cr3" : : "r"((uint32_t)pd) : "memory");
}

/* Build the private PDE[0] page table for a user process: identity map of the
 * low 4MB as supervisor-only, except the user window pages, which map to the
 * process's own frames with user access. */
static uint32_t *vmm_build_window_pt(const uint32_t *frames, int nframes,
                                     uint32_t win_virt) {
  uint32_t *pt = (uint32_t *)pmm_alloc_page(0);
  if (!pt)
    return NULL;
  for (int i = 0; i < 1024; i++)
    pt[i] = ((uint32_t)i << 12) | VMM_PRESENT | VMM_WRITABLE;
  for (int i = 0; i < nframes; i++) {
    uint32_t v = win_virt + (uint32_t)i * PAGE_SIZE;
    if (frames[i])
      pt[(v >> 12) & 0x3FFu] =
          (frames[i] & 0xFFFFF000u) | VMM_PRESENT | VMM_WRITABLE | VMM_USER;
    else
      pt[(v >> 12) & 0x3FFu] = 0; /* no frame: keep unmapped */
  }
  return pt;
}

/* Create a user page directory: kernel_pd clone with the user bit stripped
 * everywhere (kernel keeps supervisor access via ring 0) and a private PDE[0]
 * table that only exposes the process window to ring 3. Returns NULL (and
 * frees partial allocations) on failure. */
uint32_t *vmm_create_user_pd(const uint32_t *frames, int nframes,
                             uint32_t win_virt) {
  if (!kernel_pd || !frames || nframes <= 0)
    return NULL;
  uint32_t *pt = vmm_build_window_pt(frames, nframes, win_virt);
  if (!pt)
    return NULL;
  uint32_t *pd = (uint32_t *)pmm_alloc_page(0);
  if (!pd) {
    pmm_free_page(pt, 0);
    return NULL;
  }
  for (int i = 0; i < 1024; i++) {
    if (i == (win_virt >> 22)) {
      /* User bit required here too: x86 checks U/S at BOTH the PDE and PTE,
       * so a supervisor-only PDE makes the whole 4MB region ring-3-proof. */
      pd[i] = ((uint32_t)pt) | VMM_PRESENT | VMM_WRITABLE | VMM_USER;
    } else if (kernel_pd[i] & VMM_PRESENT) {
      /* Share the kernel's page tables, but supervisor-only. */
      pd[i] = kernel_pd[i] & ~VMM_USER;
    } else {
      pd[i] = 0;
    }
  }
  return pd;
}

/* Rewrite the window PTEs of an existing user pd (execve: same process, new
 * frames). Reloads cr3 for a full flush when pd is live. */
void vmm_remap_window(uint32_t *pd, const uint32_t *frames, int nframes,
                      uint32_t win_virt) {
  if (!pd)
    return;
  uint32_t pde = pd[win_virt >> 22];
  uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
  for (int i = 0; i < nframes; i++) {
    uint32_t v = win_virt + (uint32_t)i * PAGE_SIZE;
    if (frames[i])
      pt[(v >> 12) & 0x3FFu] =
          (frames[i] & 0xFFFFF000u) | VMM_PRESENT | VMM_WRITABLE | VMM_USER;
    else
      pt[(v >> 12) & 0x3FFu] = 0; /* no frame: keep unmapped */
  }
  if (pd == vmm_current_pd())
    __asm__ volatile("mov %0, %%cr3" : : "r"((uint32_t)pd) : "memory");
}

/* Free a user pd created by vmm_create_user_pd. Caller must not be running on
 * it (switch to kernel_pd first). The user window (0x300000) lives in PDE[0],
 * so that is always the private table to free. */
void vmm_destroy_user_pd(uint32_t *pd) {
  if (!pd || pd == kernel_pd)
    return;
  uint32_t *pt = (uint32_t *)(pd[0] & 0xFFFFF000u);
  if (pt)
    pmm_free_page(pt, 0);
  pmm_free_page(pd, 0);
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
