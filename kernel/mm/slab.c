#include "../../include/slab.h"
#include "../../include/kernel.h"
#include "../../include/pmm.h"
#include <stddef.h>
#include <stdint.h>

/* Allocation telemetry (observable leak / churn indicator). */
volatile uint32_t mm_stat_kmalloc_ok;
volatile uint32_t mm_stat_kfree_calls;
volatile uint32_t mm_stat_kmalloc_fail;

void mm_kmalloc_stats(uint32_t *out_ok, uint32_t *out_kf, uint32_t *out_fail) {
  if (out_ok)
    *out_ok = mm_stat_kmalloc_ok;
  if (out_kf)
    *out_kf = mm_stat_kfree_calls;
  if (out_fail)
    *out_fail = mm_stat_kmalloc_fail;
}

#define SLAB_MAGIC 0x51AB51ABu

typedef struct slab {
  uint32_t magic;
  struct slab_cache *cache;
  struct slab *next;
  uint32_t free_count;
  void *free_list; // Head of free objects in this slab
} slab_t;

struct slab_cache {
  const char *name;
  uint32_t obj_size;
  slab_t *full_slabs;
  slab_t *partial_slabs;
  slab_t *empty_slabs;
};

// Common caches: 32, 64, 128, 256, 512, 1024, 2048
// NOTE: We deliberately do NOT provide a 4096-byte cache here because a slab
// header consumes space inside a 4KB page and would leave no room for even a
// single 4096-byte object.
#define GENERIC_CACHE_COUNT 7
static slab_cache_t generic_caches[GENERIC_CACHE_COUNT];

void slab_init(void) {
  uint32_t sizes[] = {32, 64, 128, 256, 512, 1024, 2048};
  for (int i = 0; i < GENERIC_CACHE_COUNT; i++) {
    generic_caches[i].name = "generic";
    generic_caches[i].obj_size = sizes[i];
    generic_caches[i].full_slabs = NULL;
    generic_caches[i].partial_slabs = NULL;
    generic_caches[i].empty_slabs = NULL;
  }
  log_writestring("[SLAB] Initialized common caches\n");
}

static slab_t *slab_create(slab_cache_t *cache) {
  void *page = pmm_alloc_page(0); // 4KB
  if (!page)
    return NULL;

  slab_t *slab = (slab_t *)page;
  slab->magic = SLAB_MAGIC;
  slab->cache = cache;
  slab->next = NULL;

  uint32_t header_size = (sizeof(slab_t) + 7) & ~7;
  uint32_t usable_space = PAGE_SIZE - header_size;
  slab->free_count = usable_space / cache->obj_size;

  if (slab->free_count == 0) {
    pmm_free_page(page, 0);
    return NULL;
  }

  // Build free list within the slab
  uint8_t *data = (uint8_t *)page + header_size;
  slab->free_list = data;
  for (uint32_t i = 0; i < slab->free_count - 1; i++) {
    *(void **)(data + i * cache->obj_size) = data + (i + 1) * cache->obj_size;
  }
  *(void **)(data + (slab->free_count - 1) * cache->obj_size) = NULL;

  return slab;
}

void *slab_cache_alloc(slab_cache_t *cache) {
  slab_t *slab = cache->partial_slabs;
  if (!slab) {
    slab = cache->empty_slabs;
    if (!slab) {
      slab = slab_create(cache);
      if (!slab)
        return NULL;
    } else {
      cache->empty_slabs = slab->next;
    }
    slab->next = cache->partial_slabs;
    cache->partial_slabs = slab;
  }

  void *obj = slab->free_list;
  slab->free_list = *(void **)obj;
  slab->free_count--;

  if (slab->free_count == 0) {
    // Move to full
    cache->partial_slabs = slab->next;
    slab->next = cache->full_slabs;
    cache->full_slabs = slab;
  }

  return obj;
}

void slab_cache_free(slab_cache_t *cache, void *obj) {
  // Find which slab this object belongs to (it's at the start of the 4KB page)
  slab_t *slab = (slab_t *)((uint32_t)obj & ~4095u);
  if (slab->magic != SLAB_MAGIC)
    return;

  *(void **)obj = slab->free_list;
  slab->free_list = obj;
  uint32_t old_count = slab->free_count;
  slab->free_count++;

  uint32_t header_size = (sizeof(slab_t) + 7) & ~7;
  uint32_t total_objs = (PAGE_SIZE - header_size) / cache->obj_size;

  if (old_count == 0) {
    // Move from full to partial
    slab_t **prev = &cache->full_slabs;
    while (*prev && *prev != slab)
      prev = &(*prev)->next;
    if (*prev) {
      *prev = slab->next;
      slab->next = cache->partial_slabs;
      cache->partial_slabs = slab;
    }
  } else if (slab->free_count == total_objs) {
    // Move from partial to empty
    slab_t **prev = &cache->partial_slabs;
    while (*prev && *prev != slab)
      prev = &(*prev)->next;
    if (*prev) {
      *prev = slab->next;
      slab->next = cache->empty_slabs;
      cache->empty_slabs = slab;
    }
    // For now, keep empty slabs in cache for reuse.
    // In a more advanced version, we could free the page to PMM if empty list
    // is too long.
  }
}

void *kmalloc(uint32_t size) {
  if (size == 0)
    return NULL;

  if (size > 2048) {
    // Direct PMM allocation for large blocks (one or more whole pages).
    int order = 0;
    while ((PAGE_SIZE << order) < size)
      order++;
    void *p = pmm_alloc_page(order);
    if (p)
      mm_stat_kmalloc_ok++;
    else
      mm_stat_kmalloc_fail++;
    return p;
  }

  for (int i = 0; i < GENERIC_CACHE_COUNT; i++) {
    if (generic_caches[i].obj_size >= size) {
      void *p = slab_cache_alloc(&generic_caches[i]);
      if (p)
        mm_stat_kmalloc_ok++;
      else
        mm_stat_kmalloc_fail++;
      return p;
    }
  }
  mm_stat_kmalloc_fail++;
  return NULL;
}

void kfree(void *ptr) {
  if (!ptr)
    return;
  mm_stat_kfree_calls++;
  slab_t *slab = (slab_t *)((uint32_t)ptr & ~4095u);
  if (slab->magic == SLAB_MAGIC) {
    slab_cache_free(slab->cache, ptr);
  } else {
    // Was it a direct PMM allocation?
    int order = pmm_get_order(ptr);
    if (order >= 0) {
      pmm_free_page(ptr, order);
    } else {
      // Fallback: assume order 0 if not tracked
      pmm_free_page(ptr, 0);
    }
  }
}
