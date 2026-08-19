#include "ramfs.h"
#include "kernel.h"

// Forward declarations
extern void *kmalloc(uint32_t size);
extern void kfree(void *ptr);
extern void mem_set(uint8_t *dst, uint8_t v, uint32_t n);
extern void mem_copy(void *dest, const void *src, uint32_t n);
extern size_t kstrlen(const char *s);
extern int kstreq(const char *a, const char *b);

int ramfs_init(struct ramfs_ctx *ctx) {
  if (!ctx)
    return 0;

  mem_set((uint8_t *)ctx, 0, sizeof(*ctx));
  ctx->file_count = 0;
  ctx->total_size = 0;

  // Initialize all file entries as free
  for (int i = 0; i < RAMFS_MAX_FILES; i++) {
    ctx->files[i].in_use = 0;
    ctx->files[i].data = 0;
    ctx->files[i].size = 0;
    ctx->files[i].capacity = 0;
  }

  return 1;
}

void ramfs_deinit(struct ramfs_ctx *ctx) {
  if (!ctx)
    return;

  // Free all file data
  for (int i = 0; i < RAMFS_MAX_FILES; i++) {
    if (ctx->files[i].in_use && ctx->files[i].data) {
      kfree(ctx->files[i].data);
      ctx->files[i].data = 0;
      ctx->files[i].in_use = 0;
    }
  }

  mem_set((uint8_t *)ctx, 0, sizeof(*ctx));
}

static struct ramfs_file *ramfs_find_file(struct ramfs_ctx *ctx,
                                          const char *name) {
  if (!ctx || !name)
    return 0;

  for (int i = 0; i < RAMFS_MAX_FILES; i++) {
    if (ctx->files[i].in_use && kstreq(ctx->files[i].name, name)) {
      return &ctx->files[i];
    }
  }
  return 0;
}

static struct ramfs_file *ramfs_find_free_slot(struct ramfs_ctx *ctx) {
  if (!ctx)
    return 0;

  for (int i = 0; i < RAMFS_MAX_FILES; i++) {
    if (!ctx->files[i].in_use) {
      return &ctx->files[i];
    }
  }
  return 0;
}

int ramfs_create_file(struct ramfs_ctx *ctx, const char *name,
                      const uint8_t *data, uint32_t size) {
  if (!ctx || !name)
    return 0;

  // Check if file already exists
  if (ramfs_find_file(ctx, name))
    return 0; // File exists

  // Find free slot
  struct ramfs_file *file = ramfs_find_free_slot(ctx);
  if (!file)
    return 0; // No free slots

  // Copy name
  size_t name_len = kstrlen(name);
  if (name_len > RAMFS_MAX_NAME_LEN)
    name_len = RAMFS_MAX_NAME_LEN;
  mem_copy((uint8_t *)file->name, (const uint8_t *)name, (uint32_t)name_len);
  file->name[name_len] = '\0';

  // Allocate data buffer
  uint32_t capacity = size > RAMFS_INITIAL_SIZE ? size : RAMFS_INITIAL_SIZE;
  file->data = (uint8_t *)kmalloc(capacity);
  if (!file->data)
    return 0;

  // Copy data
  if (data && size > 0) {
    mem_copy(file->data, data, size);
  }

  file->size = size;
  file->capacity = capacity;
  file->mode = 0644; // Default permissions
  file->mtime = 0;   // TODO: Get current time
  file->in_use = 1;

  ctx->file_count++;
  ctx->total_size += size;

  return 1;
}

int ramfs_read_file(struct ramfs_ctx *ctx, const char *name, uint8_t **out_data,
                    uint32_t *out_size) {
  if (!ctx || !name || !out_data || !out_size)
    return 0;

  struct ramfs_file *file = ramfs_find_file(ctx, name);
  if (!file)
    return 0;

  // Allocate buffer for caller
  uint8_t *buf = (uint8_t *)kmalloc(file->size ? file->size : 1);
  if (!buf)
    return 0;

  if (file->size > 0 && file->data) {
    mem_copy(buf, file->data, file->size);
  }

  *out_data = buf;
  *out_size = file->size;
  return 1;
}

int ramfs_write_file(struct ramfs_ctx *ctx, const char *name,
                     const uint8_t *data, uint32_t size) {
  if (!ctx || !name || !data)
    return 0;

  struct ramfs_file *file = ramfs_find_file(ctx, name);

  if (!file) {
    // Create new file
    return ramfs_create_file(ctx, name, data, size);
  }

  // Resize if needed
  if (size > file->capacity) {
    // Reallocate
    uint8_t *new_data = (uint8_t *)kmalloc(size);
    if (!new_data)
      return 0;

    if (file->data) {
      if (file->size > 0) {
        mem_copy(new_data, file->data, file->size < size ? file->size : size);
      }
      kfree(file->data);
    }

    file->data = new_data;
    file->capacity = size;
    ctx->total_size = ctx->total_size - file->size + size;
  } else {
    ctx->total_size = ctx->total_size - file->size + size;
  }

  // Write data
  mem_copy(file->data, data, size);
  file->size = size;
  file->mtime = 0; // TODO: Update modification time

  return 1;
}

int ramfs_delete_file(struct ramfs_ctx *ctx, const char *name) {
  if (!ctx || !name)
    return 0;

  struct ramfs_file *file = ramfs_find_file(ctx, name);
  if (!file)
    return 0;

  if (file->data) {
    kfree(file->data);
  }

  ctx->total_size -= file->size;
  ctx->file_count--;

  mem_set((uint8_t *)file, 0, sizeof(*file));
  file->in_use = 0;

  return 1;
}

int ramfs_file_exists(struct ramfs_ctx *ctx, const char *name) {
  if (!ctx || !name)
    return 0;

  return ramfs_find_file(ctx, name) != 0;
}

int ramfs_get_file_size(struct ramfs_ctx *ctx, const char *name,
                        uint32_t *out_size) {
  if (!ctx || !name || !out_size)
    return 0;

  struct ramfs_file *file = ramfs_find_file(ctx, name);
  if (!file)
    return 0;

  *out_size = file->size;
  return 1;
}

int ramfs_list_files(struct ramfs_ctx *ctx, char ***out_names,
                     uint32_t *out_count) {
  if (!ctx || !out_names || !out_count)
    return 0;

  uint32_t count = 0;
  uint32_t total_len = 0;
  for (int i = 0; i < RAMFS_MAX_FILES; i++) {
    if (ctx->files[i].in_use) {
      total_len += (uint32_t)(kstrlen(ctx->files[i].name) + 1);
      count++;
    }
  }

  if (count == 0) {
    *out_count = 0;
    *out_names = 0;
    return 1;
  }

  char **names = (char **)kmalloc(count * sizeof(char *));
  if (!names)
    return 0;
  uint8_t *str_block = (uint8_t *)kmalloc(total_len);
  if (!str_block) {
    kfree(names);
    return 0;
  }

  uint32_t idx = 0;
  uint32_t off = 0;
  for (int i = 0; i < RAMFS_MAX_FILES && idx < count; i++) {
    if (ctx->files[i].in_use) {
      size_t name_len = kstrlen(ctx->files[i].name) + 1;
      mem_copy(str_block + off, (const uint8_t *)ctx->files[i].name,
               (uint32_t)name_len);
      names[idx] = (char *)(str_block + off);
      off += (uint32_t)name_len;
      idx++;
    }
  }

  *out_names = names;
  *out_count = count;
  return 1;
}
