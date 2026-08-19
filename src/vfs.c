#include "vfs.h"
#include "fat.h"
#include "kernel.h"
#include "ramfs.h"

// Forward declarations
extern void *kmalloc(uint32_t size);
extern void kfree(void *ptr);
extern void mem_set(uint8_t *dst, uint8_t v, uint32_t n);
extern void mem_copy(void *dest, const void *src, uint32_t n);
extern size_t kstrlen(const char *s);
extern int kstreq(const char *a, const char *b);

// Global VFS context
static struct vfs_ctx vfs_global_ctx;
static int vfs_initialized = 0;

// FAT filesystem operations
static int vfs_fat_open(void *fs_ctx, const char *path, int flags,
                        void **out_handle) {
  fat12_ctx *ctx = (fat12_ctx *)fs_ctx;
  uint8_t *data = 0;
  uint32_t size = 0;

  if (!fat12_read_file_to_ram_ex(ctx, path, &data, &size)) {
    if (flags & VFS_FD_CREATE) {
      // Create empty file
      if (fat12_write_file_ex(ctx, path, 0, 0)) {
        *out_handle = (void *)0x1; // Simple handle
        return 1;
      }
    }
    return 0;
  }

  *out_handle = data; // Use data pointer as handle
  return 1;
}

static int vfs_fat_read(void *fs_ctx, void *handle, uint8_t *buf, uint32_t size,
                        uint32_t offset, uint32_t *out_read) {
  uint8_t *data = (uint8_t *)handle;
  if (!data || !buf || !out_read)
    return 0;

  if (handle == (void *)0x1) {
    *out_read = 0;
    return 1;
  }

  mem_copy(buf, data + offset, size);
  *out_read = size;
  return 1;
}

static int vfs_fat_write(void *fs_ctx, void *handle, const uint8_t *buf,
                         uint32_t size, uint32_t offset,
                         uint32_t *out_written) {
  (void)fs_ctx;
  (void)handle;
  (void)buf;
  (void)size;
  (void)offset;
  *out_written = 0;
  return 0;
}

static int vfs_fat_close(void *fs_ctx, void *handle) {
  fat12_ctx *ctx = (fat12_ctx *)fs_ctx;
  (void)ctx;
  if (handle && handle != (void *)0x1) {
    kfree(handle); // Free file data
  }
  return 1;
}

static int vfs_fat_stat(void *fs_ctx, const char *path, uint32_t *out_size) {
  fat12_ctx *ctx = (fat12_ctx *)fs_ctx;
  uint8_t *data = 0;
  uint32_t size = 0;

  if (!fat12_read_file_to_ram_ex(ctx, path, &data, &size)) {
    return 0;
  }

  kfree(data);
  *out_size = size;
  return 1;
}

static int vfs_fat_list(void *fs_ctx, const char *path, char ***out_names,
                        uint32_t *out_count) {
  fat12_ctx *ctx = (fat12_ctx *)fs_ctx;
  uint8_t *dir_buf = 0;
  uint32_t dir_bytes = 0;

  // For now only root or current dir
  int ok = 0;
  if (!path || path[0] == '\0' || kstreq(path, "/")) {
    ok = fat12_read_root_dir(ctx, &dir_buf, &dir_bytes);
  } else {
    // Resolve path to cluster
    int dok = 0;
    uint16_t cluster = fat12_resolve_dir(ctx, 0, path, &dok); // Start from root
    if (dok) {
      ok = fat12_read_dir_cluster(ctx, cluster, &dir_buf, &dir_bytes);
    }
  }

  if (!ok || !dir_buf) {
    if (dir_buf)
      kfree(dir_buf);
    return 0;
  }

  // Count valid entries and total string length
  uint32_t count = 0;
  uint32_t total_len = 0;
  uint32_t entries = dir_bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    char formatted[256];
    fat12_display_name(dir_buf, i * 32u, formatted, sizeof(formatted));
    total_len += (uint32_t)(kstrlen(formatted) + 1);
    count++;
  }

  if (count == 0) {
    kfree(dir_buf);
    *out_count = 0;
    *out_names = 0;
    return 1;
  }

  char **names = (char **)kmalloc(count * sizeof(char *));
  if (!names) {
    kfree(dir_buf);
    return 0;
  }
  uint8_t *str_block = (uint8_t *)kmalloc(total_len);
  if (!str_block) {
    kfree(names);
    kfree(dir_buf);
    return 0;
  }

  uint32_t idx = 0;
  uint32_t off = 0;
  for (uint32_t i = 0; i < entries && idx < count; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;

    char formatted[256];
    fat12_display_name(dir_buf, i * 32u, formatted, sizeof(formatted));
    size_t len = kstrlen(formatted) + 1;
    if (off + (uint32_t)len <= total_len) {
      mem_copy(str_block + off, (const uint8_t *)formatted, (uint32_t)len);
      names[idx] = (char *)(str_block + off);
      off += (uint32_t)len;
      idx++;
    }
  }

  kfree(dir_buf);
  *out_names = names;
  *out_count = idx;
  /* All names point into str_block; caller must kfree(names[0]) and
   * kfree(names) only. */
  return 1;
}

// RAMFS filesystem operations
static int vfs_ramfs_open(void *fs_ctx, const char *path, int flags,
                          void **out_handle) {
  struct ramfs_ctx *ctx = (struct ramfs_ctx *)fs_ctx;
  uint8_t *data = 0;
  uint32_t size = 0;

  if (ramfs_read_file(ctx, path, &data, &size)) {
    *out_handle = data;
    return 1;
  }

  if (flags & VFS_FD_CREATE) {
    if (ramfs_create_file(ctx, path, 0, 0)) {
      *out_handle = (void *)0x1;
      return 1;
    }
  }

  return 0;
}

static int vfs_ramfs_read(void *fs_ctx, void *handle, uint8_t *buf,
                          uint32_t size, uint32_t offset, uint32_t *out_read) {
  uint8_t *data = (uint8_t *)handle;
  if (!data || !buf || !out_read)
    return 0;
  if (handle == (void *)0x1) {
    *out_read = 0;
    return 1;
  }
  mem_copy(buf, data + offset, size);
  *out_read = size;
  return 1;
}

static int vfs_ramfs_write(void *fs_ctx, void *handle, const uint8_t *buf,
                           uint32_t size, uint32_t offset,
                           uint32_t *out_written) {
  (void)fs_ctx;
  (void)handle;
  (void)buf;
  (void)size;
  (void)offset;
  *out_written = 0;
  return 0;
}

static int vfs_ramfs_close(void *fs_ctx, void *handle) {
  struct ramfs_ctx *ctx = (struct ramfs_ctx *)fs_ctx;
  (void)ctx;
  if (handle && handle != (void *)0x1) {
    kfree(handle);
  }
  return 1;
}

static int vfs_ramfs_stat(void *fs_ctx, const char *path, uint32_t *out_size) {
  struct ramfs_ctx *ctx = (struct ramfs_ctx *)fs_ctx;
  return ramfs_get_file_size(ctx, path, out_size);
}

static int vfs_ramfs_list(void *fs_ctx, const char *path, char ***out_names,
                          uint32_t *out_count) {
  struct ramfs_ctx *ctx = (struct ramfs_ctx *)fs_ctx;
  return ramfs_list_files(ctx, out_names, out_count);
}

int vfs_init(struct vfs_ctx *ctx) {
  if (!ctx)
    return 0;

  mem_set((uint8_t *)ctx, 0, sizeof(*ctx));
  ctx->next_fd = 3; // Start after stdin(0), stdout(1), stderr(2)

  for (int i = 0; i < VFS_MAX_MOUNTS; i++) {
    ctx->mounts[i].in_use = 0;
  }

  for (int i = 0; i < VFS_MAX_FDS; i++) {
    ctx->fds[i].in_use = 0;
  }

  vfs_initialized = 1;
  return 1;
}

void vfs_deinit(struct vfs_ctx *ctx) {
  if (!ctx)
    return;

  // Unmount all filesystems
  for (int i = 0; i < VFS_MAX_MOUNTS; i++) {
    if (ctx->mounts[i].in_use) {
      vfs_umount(ctx, ctx->mounts[i].mount_point);
    }
  }

  // Close all file descriptors
  for (int i = 0; i < VFS_MAX_FDS; i++) {
    if (ctx->fds[i].in_use) {
      vfs_close(ctx, i);
    }
  }

  mem_set((uint8_t *)ctx, 0, sizeof(*ctx));
  vfs_initialized = 0;
}

int vfs_mount(struct vfs_ctx *ctx, const char *mount_point, int fstype,
              void *fs_ctx) {
  if (!ctx || !mount_point || !fs_ctx)
    return 0;

  // Find free mount slot
  int slot = -1;
  for (int i = 0; i < VFS_MAX_MOUNTS; i++) {
    if (!ctx->mounts[i].in_use) {
      slot = i;
      break;
    }
  }

  if (slot == -1)
    return 0;

  // Set up mount point
  size_t len = kstrlen(mount_point);
  if (len >= VFS_MAX_PATH_LEN)
    len = VFS_MAX_PATH_LEN - 1;
  mem_copy((uint8_t *)ctx->mounts[slot].mount_point,
           (const uint8_t *)mount_point, (uint32_t)len);
  ctx->mounts[slot].mount_point[len] = '\0';

  ctx->mounts[slot].in_use = 1;
  ctx->mounts[slot].fstype = fstype;
  ctx->mounts[slot].fs_ctx = fs_ctx;

  // Set filesystem operations based on type
  if (fstype == VFS_FSTYPE_FAT) {
    ctx->mounts[slot].open = vfs_fat_open;
    ctx->mounts[slot].read = vfs_fat_read;
    ctx->mounts[slot].write = vfs_fat_write;
    ctx->mounts[slot].close = vfs_fat_close;
    ctx->mounts[slot].stat = vfs_fat_stat;
    ctx->mounts[slot].list = vfs_fat_list;
  } else if (fstype == VFS_FSTYPE_RAMFS) {
    ctx->mounts[slot].open = vfs_ramfs_open;
    ctx->mounts[slot].read = vfs_ramfs_read;
    ctx->mounts[slot].write = vfs_ramfs_write;
    ctx->mounts[slot].close = vfs_ramfs_close;
    ctx->mounts[slot].stat = vfs_ramfs_stat;
    ctx->mounts[slot].list = vfs_ramfs_list;
  } else {
    ctx->mounts[slot].in_use = 0;
    return 0;
  }

  return 1;
}

int vfs_umount(struct vfs_ctx *ctx, const char *mount_point) {
  if (!ctx || !mount_point)
    return 0;

  for (int i = 0; i < VFS_MAX_MOUNTS; i++) {
    if (ctx->mounts[i].in_use &&
        kstreq(ctx->mounts[i].mount_point, mount_point)) {
      // Close all FDs using this mount
      for (int j = 0; j < VFS_MAX_FDS; j++) {
        if (ctx->fds[j].in_use && ctx->fds[j].mount_id == i) {
          vfs_close(ctx, j);
        }
      }

      ctx->mounts[i].in_use = 0;
      return 1;
    }
  }

  return 0;
}

struct vfs_mount *vfs_find_mount(struct vfs_ctx *ctx, const char *path) {
  if (!ctx || !path)
    return 0;

  // Find longest matching mount point
  struct vfs_mount *best = 0;
  size_t best_len = 0;

  size_t path_len = kstrlen(path);

  for (int i = 0; i < VFS_MAX_MOUNTS; i++) {
    if (!ctx->mounts[i].in_use)
      continue;

    size_t mount_len = kstrlen(ctx->mounts[i].mount_point);

    // Check if path starts with mount point
    if (path_len >= mount_len) {
      int match = 1;
      for (size_t j = 0; j < mount_len; j++) {
        if (path[j] != ctx->mounts[i].mount_point[j]) {
          match = 0;
          break;
        }
      }

      // Also check that next char is / or end of string, OR if mount point is
      // just /
      if (match &&
          (mount_len == 1 || path_len == mount_len || path[mount_len] == '/')) {
        if (mount_len > best_len) {
          best = &ctx->mounts[i];
          best_len = mount_len;
        }
      }
    }
  }

  return best;
}

int vfs_resolve_path(struct vfs_ctx *ctx, const char *path, int *out_mount_id,
                     char *out_fs_path) {
  if (!ctx || !path || !out_mount_id || !out_fs_path)
    return 0;

  struct vfs_mount *mount = vfs_find_mount(ctx, path);
  if (!mount)
    return 0;

  // Find mount ID
  *out_mount_id = -1;
  for (int i = 0; i < VFS_MAX_MOUNTS; i++) {
    if (&ctx->mounts[i] == mount) {
      *out_mount_id = i;
      break;
    }
  }

  if (*out_mount_id == -1)
    return 0;

  // Extract filesystem path (remove mount point prefix)
  size_t mount_len = kstrlen(mount->mount_point);
  size_t path_len = kstrlen(path);

  if (path_len <= mount_len) {
    // Path is just the mount point, use root
    out_fs_path[0] = '/';
    out_fs_path[1] = '\0';
  } else {
    // Copy remaining path
    size_t fs_path_len = path_len - mount_len;
    if (fs_path_len >= VFS_MAX_PATH_LEN)
      fs_path_len = VFS_MAX_PATH_LEN - 1;

    mem_copy((uint8_t *)out_fs_path, (const uint8_t *)(path + mount_len),
             (uint32_t)fs_path_len);
    out_fs_path[fs_path_len] = '\0';

    // Ensure starts with /
    if (out_fs_path[0] != '/') {
      // Prepend /
      for (int i = (int)fs_path_len; i >= 0; i--) {
        out_fs_path[i + 1] = out_fs_path[i];
      }
      out_fs_path[0] = '/';
    }
  }

  return 1;
}

int vfs_open(struct vfs_ctx *ctx, const char *path, int flags) {
  if (!ctx || !path)
    return -1;

  int mount_id;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(ctx, path, &mount_id, fs_path))
    return -1;

  struct vfs_mount *mount = &ctx->mounts[mount_id];

  // Find free FD
  int fd = -1;
  for (int i = 0; i < VFS_MAX_FDS; i++) {
    if (!ctx->fds[i].in_use) {
      fd = i;
      break;
    }
  }

  if (fd == -1)
    return -1;

  // Open file in filesystem
  void *handle = 0;
  if (!mount->open(mount->fs_ctx, fs_path, flags, &handle)) {
    return -1;
  }

  // Set up FD
  ctx->fds[fd].in_use = 1;
  ctx->fds[fd].mount_id = mount_id;
  ctx->fds[fd].offset = 0;
  ctx->fds[fd].flags = flags;
  ctx->fds[fd].fs_private = handle;
  ctx->fds[fd].fstype = mount->fstype;

  return fd;
}

int vfs_read(struct vfs_ctx *ctx, int fd, uint8_t *buf, uint32_t size) {
  if (!ctx || fd < 0 || fd >= VFS_MAX_FDS || !buf)
    return -1;

  if (!ctx->fds[fd].in_use)
    return -1;

  struct vfs_mount *mount = &ctx->mounts[ctx->fds[fd].mount_id];
  uint32_t read = 0;

  if (!mount->read(mount->fs_ctx, ctx->fds[fd].fs_private, buf, size,
                   ctx->fds[fd].offset, &read)) {
    return -1;
  }

  ctx->fds[fd].offset += read;
  return (int)read;
}

int vfs_write(struct vfs_ctx *ctx, int fd, const uint8_t *buf, uint32_t size) {
  if (!ctx || fd < 0 || fd >= VFS_MAX_FDS || !buf)
    return -1;

  if (!ctx->fds[fd].in_use)
    return -1;

  struct vfs_mount *mount = &ctx->mounts[ctx->fds[fd].mount_id];
  uint32_t written = 0;

  if (!mount->write(mount->fs_ctx, ctx->fds[fd].fs_private, buf, size,
                    ctx->fds[fd].offset, &written)) {
    return -1;
  }

  ctx->fds[fd].offset += written;
  return (int)written;
}

int vfs_close(struct vfs_ctx *ctx, int fd) {
  if (!ctx || fd < 0 || fd >= VFS_MAX_FDS)
    return -1;

  if (!ctx->fds[fd].in_use)
    return -1;

  struct vfs_mount *mount = &ctx->mounts[ctx->fds[fd].mount_id];
  mount->close(mount->fs_ctx, ctx->fds[fd].fs_private);

  ctx->fds[fd].in_use = 0;
  return 0;
}

int vfs_seek(struct vfs_ctx *ctx, int fd, uint32_t offset) {
  if (!ctx || fd < 0 || fd >= VFS_MAX_FDS)
    return -1;

  if (!ctx->fds[fd].in_use)
    return -1;

  ctx->fds[fd].offset = offset;
  return 0;
}

int vfs_stat(struct vfs_ctx *ctx, const char *path, uint32_t *out_size) {
  if (!ctx || !path || !out_size)
    return -1;

  int mount_id;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(ctx, path, &mount_id, fs_path))
    return -1;

  struct vfs_mount *mount = &ctx->mounts[mount_id];
  return mount->stat(mount->fs_ctx, fs_path, out_size);
}

int vfs_list(struct vfs_ctx *ctx, const char *path, char ***out_names,
             uint32_t *out_count) {
  if (!ctx || !path || !out_names || !out_count)
    return -1;

  int mount_id;
  char fs_path[VFS_MAX_PATH_LEN];
  if (!vfs_resolve_path(ctx, path, &mount_id, fs_path))
    return -1;

  struct vfs_mount *mount = &ctx->mounts[mount_id];
  return mount->list(mount->fs_ctx, fs_path, out_names, out_count);
}

// Global VFS functions
struct vfs_ctx *vfs_get_global(void) {
  if (!vfs_initialized) {
    vfs_init(&vfs_global_ctx);
  }
  return &vfs_global_ctx;
}
