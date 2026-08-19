#ifndef RAMFS_H
#define RAMFS_H

#include <stddef.h>
#include <stdint.h>

// RAMFS - Simple in-memory filesystem
// Similar to Linux's ramfs, provides a filesystem interface backed by kernel
// memory

#define RAMFS_MAX_FILES 256
#define RAMFS_MAX_NAME_LEN 255
#define RAMFS_INITIAL_SIZE 4096 // Initial allocation size for files

// RAMFS file entry
struct ramfs_file {
  char name[RAMFS_MAX_NAME_LEN + 1];
  uint8_t *data;
  uint32_t size;
  uint32_t capacity; // Allocated capacity
  uint32_t mode;     // File permissions (simplified)
  uint32_t mtime;    // Modification time
  int in_use;        // 1 if entry is in use, 0 if free
};

// RAMFS context
struct ramfs_ctx {
  struct ramfs_file files[RAMFS_MAX_FILES];
  uint32_t file_count;
  uint32_t total_size; // Total bytes used
};

// RAMFS operations
int ramfs_init(struct ramfs_ctx *ctx);
void ramfs_deinit(struct ramfs_ctx *ctx);

// File operations
int ramfs_create_file(struct ramfs_ctx *ctx, const char *name,
                      const uint8_t *data, uint32_t size);
int ramfs_read_file(struct ramfs_ctx *ctx, const char *name, uint8_t **out_data,
                    uint32_t *out_size);
int ramfs_write_file(struct ramfs_ctx *ctx, const char *name,
                     const uint8_t *data, uint32_t size);
int ramfs_delete_file(struct ramfs_ctx *ctx, const char *name);
int ramfs_file_exists(struct ramfs_ctx *ctx, const char *name);
int ramfs_list_files(struct ramfs_ctx *ctx, char ***out_names,
                     uint32_t *out_count);

// File info
int ramfs_get_file_size(struct ramfs_ctx *ctx, const char *name,
                        uint32_t *out_size);

#endif // RAMFS_H
