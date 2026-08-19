#ifndef FATENT_OPS_H
#define FATENT_OPS_H

#include <stdint.h>

// FAT entry operations abstraction (Linux-like pattern)
// This allows supporting FAT12, FAT16, and FAT32 with a unified interface

typedef struct fatent_ops {
  // Get the next cluster in a chain
  uint32_t (*get_entry)(const void *fat_data, uint32_t cluster);
  
  // Set the next cluster in a chain
  void (*set_entry)(void *fat_data, uint32_t cluster, uint32_t value);
  
  // Find a free cluster
  uint32_t (*find_free)(const void *fat_data, uint32_t start_cluster);
  
  // Check if cluster is end of chain
  int (*is_eof)(uint32_t value);
  
  // Check if cluster is bad
  int (*is_bad)(uint32_t value);
  
  // Get the EOF marker
  uint32_t (*eof_marker)(void);
  
  // Get the bad cluster marker
  uint32_t (*bad_marker)(void);
  
  // Get the number of bytes per FAT entry (for cache calculations)
  uint32_t (*entry_size)(void);
  
  // Get the number of FAT entries (clusters)
  uint32_t (*entry_count)(const void *fs_ctx);
} fatent_ops_t;

// FAT12 operations
extern const fatent_ops_t fat12_ops;

// FAT16 operations (to be implemented)
extern const fatent_ops_t fat16_ops;

#endif // FATENT_OPS_H
