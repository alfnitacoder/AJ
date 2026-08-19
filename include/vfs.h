#ifndef VFS_H
#define VFS_H

#include <stddef.h>
#include <stdint.h>

// VFS - Virtual Filesystem Layer
// Provides unified interface for different filesystem types (FAT, RAMFS, etc.)

#define VFS_MAX_MOUNTS 8
#define VFS_MAX_FDS 64
#define VFS_MAX_PATH_LEN 256

// File descriptor flags
#define VFS_FD_READ 0x01
#define VFS_FD_WRITE 0x02
#define VFS_FD_APPEND 0x04
#define VFS_FD_CREATE 0x08

// Filesystem types
#define VFS_FSTYPE_FAT 1
#define VFS_FSTYPE_RAMFS 2

// File descriptor structure
struct vfs_fd {
  int in_use;       // 1 if in use, 0 if free
  int mount_id;     // Mount point ID
  uint32_t offset;  // Current file offset
  uint32_t flags;   // Open flags (read, write, etc.)
  void *fs_private; // Filesystem-specific data (e.g., file handle)
  int fstype;       // Filesystem type (VFS_FSTYPE_FAT, VFS_FSTYPE_RAMFS)
};

// Mount point structure
struct vfs_mount {
  int in_use;                         // 1 if mounted, 0 if free
  char mount_point[VFS_MAX_PATH_LEN]; // Mount point path (e.g., "/", "/ram")
  int fstype;                         // Filesystem type
  void *fs_ctx; // Filesystem context (fat_ctx*, ramfs_ctx*, etc.)

  // Filesystem operations
  int (*open)(void *fs_ctx, const char *path, int flags, void **out_handle);
  int (*read)(void *fs_ctx, void *handle, uint8_t *buf, uint32_t size,
              uint32_t offset, uint32_t *out_read);
  int (*write)(void *fs_ctx, void *handle, const uint8_t *buf, uint32_t size,
               uint32_t offset, uint32_t *out_written);
  int (*close)(void *fs_ctx, void *handle);
  int (*stat)(void *fs_ctx, const char *path, uint32_t *out_size);
  int (*list)(void *fs_ctx, const char *path, char ***out_names,
              uint32_t *out_count);
};

// VFS context
struct vfs_ctx {
  struct vfs_mount mounts[VFS_MAX_MOUNTS];
  struct vfs_fd fds[VFS_MAX_FDS];
  uint32_t next_fd; // Next available FD number
};

// VFS operations
int vfs_init(struct vfs_ctx *ctx);
void vfs_deinit(struct vfs_ctx *ctx);

// Mount operations
int vfs_mount(struct vfs_ctx *ctx, const char *mount_point, int fstype,
              void *fs_ctx);
int vfs_umount(struct vfs_ctx *ctx, const char *mount_point);

// File operations
int vfs_open(struct vfs_ctx *ctx, const char *path, int flags);
int vfs_read(struct vfs_ctx *ctx, int fd, uint8_t *buf, uint32_t size);
int vfs_write(struct vfs_ctx *ctx, int fd, const uint8_t *buf, uint32_t size);
int vfs_close(struct vfs_ctx *ctx, int fd);
int vfs_seek(struct vfs_ctx *ctx, int fd, uint32_t offset);
int vfs_stat(struct vfs_ctx *ctx, const char *path, uint32_t *out_size);
int vfs_list(struct vfs_ctx *ctx, const char *path, char ***out_names,
             uint32_t *out_count);

// Global VFS access
struct vfs_ctx *vfs_get_global(void);

// Helper functions
int vfs_resolve_path(struct vfs_ctx *ctx, const char *path, int *out_mount_id,
                     char *out_fs_path);
struct vfs_mount *vfs_find_mount(struct vfs_ctx *ctx, const char *path);

#endif // VFS_H
