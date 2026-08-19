#ifndef SLAB_H
#define SLAB_H

#include <stddef.h>
#include <stdint.h>

typedef struct slab_cache slab_cache_t;

void slab_init(void);

// Create a custom slab cache (for specific structures like struct process)
slab_cache_t *slab_cache_create(const char *name, uint32_t size,
                                uint32_t align);

// Allocate an object from a cache
void *slab_cache_alloc(slab_cache_t *cache);

// Free an object back to its cache
void slab_cache_free(slab_cache_t *cache, void *obj);

// Generic kmalloc/kfree using global slab caches
void *kmalloc(uint32_t size);
void kfree(void *ptr);

/* Counters since boot (IRQ-safe increments). ok/fail = kmalloc paths; kfree
 * excludes NULL. (ok - kfree) trends up if something leaks paired allocs. */
void mm_kmalloc_stats(uint32_t *out_kmalloc_ok, uint32_t *out_kfree_calls,
                      uint32_t *out_kmalloc_fail);

#endif
