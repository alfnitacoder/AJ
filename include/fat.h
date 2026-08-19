#ifndef FAT_H
#define FAT_H

#include <stddef.h>
#include <stdint.h>

// File slot management
#define FILE_SLOTS 16
struct file_slot {
  void *ptr;
  uint32_t size;
  char name[40];
};

int file_slot_save(const char *name, const uint8_t *data, uint32_t size);
int file_slot_read(const char *name, uint8_t **out_buf, uint32_t *out_size);
/** Peek at slot without copying; caller must not free *out_buf. Returns 1 if
 * found. */
int file_slot_peek(const char *name, uint8_t **out_buf, uint32_t *out_size);
void file_slot_init(void);

// Common BPB structure (shared by FAT12, FAT16, FAT32)
// FAT12 and FAT16 use the same BPB format
struct __attribute__((packed)) fat_bpb {
  uint8_t jmp[3];
  char oem[8];
  uint16_t bytes_per_sector;
  uint8_t sectors_per_cluster;
  uint16_t reserved_sectors;
  uint8_t fat_count;
  uint16_t root_dir_entries;
  uint16_t total_sectors_short;
  uint8_t media_type;
  uint16_t fat_size_sectors;
  uint16_t sectors_per_track;
  uint16_t heads_count;
  uint32_t hidden_sectors;
  uint32_t total_sectors_long;
  uint8_t drive_num;
  uint8_t reserved;
  uint8_t boot_sig;
  uint32_t volume_id;
  char volume_label[11];
  char fs_type[8];
};

// Legacy typedefs for backward compatibility
typedef struct fat_bpb fat12_bpb;

struct __attribute__((packed)) fat12_dirent {
  uint8_t name[11];
  uint8_t attr;
  uint8_t nt_res;
  uint8_t crt_time_tenth;
  uint16_t crt_time;
  uint16_t crt_date;
  uint16_t lst_acc_date;
  uint16_t first_cluster_hi;
  uint16_t wrt_time;
  uint16_t wrt_date;
  uint16_t first_cluster_lo;
  uint32_t size;
};

// VFAT Long File Name (LFN) directory entry
// LFN entries have attribute 0x0F and appear before the 8.3 entry
struct __attribute__((packed)) fat_lfn_dirent {
  uint8_t
      sequence; // Sequence number (bit 6 = last entry, bits 0-5 = entry number)
  uint16_t name1[5];      // First 5 characters of filename (UTF-16)
  uint8_t attr;           // Always 0x0F for LFN
  uint8_t type;           // Always 0x00 for LFN
  uint8_t checksum;       // Checksum of 8.3 name
  uint16_t name2[6];      // Next 6 characters (UTF-16)
  uint16_t first_cluster; // Always 0x0000 for LFN
  uint16_t name3[2];      // Last 2 characters (UTF-16)
};

#define FAT_ATTR_LFN 0x0F
#define FAT_LFN_LAST 0x40     // Bit 6 indicates last LFN entry
#define FAT_LFN_SEQ_MASK 0x3F // Bits 0-5 are sequence number

// FAT sector cache entry
#define FAT_CACHE_SIZE                                                         \
  32 // Cache up to 32 FAT sectors (16KB for FAT12, 16KB for FAT16)
struct fat_cache_entry {
  uint32_t sector;      // FAT sector number (relative to fat_lba)
  uint8_t data[512];    // Sector data
  int dirty;            // 1 if modified, 0 if clean
  uint32_t access_time; // Simple counter for LRU
};

// Unified FAT context (supports FAT12 and FAT16)
struct fat_ctx {
  struct fat_bpb bpb;
  uint8_t
      *fat; // Full FAT buffer (kept for compatibility, can be NULL with cache)
  uint32_t fat_lba; // Starting LBA of FAT
  uint32_t root_lba;
  uint16_t root_sectors;
  uint32_t data_lba;
  const void *ops; // FAT entry operations (fatent_ops_t*) - using void* to
                   // avoid circular dependency
  int fat_type;    // 12 for FAT12, 16 for FAT16
  int use_cache;   // 1 to use sector cache, 0 for full FAT in memory
  struct fat_cache_entry cache[FAT_CACHE_SIZE];
  uint32_t cache_access_counter; // For LRU eviction
  uint8_t drive;                 // Drive ID (0=floppy, 0x80=first IDE)
};

// Legacy typedef for compatibility
typedef struct fat_ctx fat12_ctx;

int fat12_init(fat12_ctx *ctx);
int fat12_init_ex(fat12_ctx *ctx, uint8_t drive);
void fat12_deinit(fat12_ctx *ctx);
/* Refresh a long-lived ctx (VFS mount) to see FAT/dir changes made through
 * other contexts. */
void fat12_reload(fat12_ctx *ctx);
uint32_t fat12_cluster_lba(const fat12_ctx *ctx, uint16_t cluster);
uint16_t fat12_resolve_dir(const fat12_ctx *ctx, uint16_t start_dir,
                           const char *path, int *out_is_ok);
void fat12_format_name(const uint8_t name[11], char out[13]);
/* Display name (LFN if present, else 8.3) for entry at dir_buf + byte_idx. */
void fat12_display_name(const uint8_t *dir_buf, uint32_t byte_idx,
                        char *out_name, size_t max_len);

int fat12_read_root_dir(const fat12_ctx *ctx, uint8_t **out_buf,
                        uint32_t *out_bytes);
int fat12_read_dir_cluster(const fat12_ctx *ctx, uint16_t start_cluster,
                           uint8_t **out_buf, uint32_t *out_bytes);
int fat12_write_dir_cluster(const fat12_ctx *ctx, uint16_t cluster,
                            const uint8_t *buf, uint32_t bytes);

int fat12_write_file(const char *fn, const uint8_t *data, uint32_t size);
int fat12_write_file_ex(fat12_ctx *ctx, const char *fn, const uint8_t *data,
                        uint32_t size);
int fat12_mkdir(const char *fn);
int fat12_read_file_to_ram(const char *path, uint8_t **out_buf,
                           uint32_t *out_size);
int fat12_read_file_to_ram_ex(fat12_ctx *ctx, const char *path,
                              uint8_t **out_buf, uint32_t *out_size);

void fat12_cwd_set_root(void);
void fat12_cwd_push(const char *seg);
void fat12_cwd_pop(void);

// Shell commands implemented in fat.c
void cmd_ls(void);
void cmd_ls_path(const char *path);
void cmd_cd(const char *path);
void cmd_pwd(void);
void cmd_mkdir(const char *args);
void cmd_cat_path(const char *path);
void cmd_cp(const char *path);
void cmd_touch(const char *arg);
void cmd_grep(const char *arg);
void cmd_head(const char *arg);
void cmd_tail(const char *arg);
void cmd_wc(const char *arg);
void cmd_hexdump(const char *args);
void cmd_strings(const char *args);
void cmd_files(void);
void cmd_freeram(const char *arg);

void filesystem_init(void);

extern uint16_t fat12_cwd_cluster;
extern struct file_slot file_slots[FILE_SLOTS];
extern char fat12_cwd_path[128];
extern fat12_ctx fat_global_ctx;

#endif
