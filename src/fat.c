#include "fat.h"
#include "datetime.h"
#include "disk.h"
#include "fatent_ops.h"
#include "debug_agent.h"
#include "kernel.h"

/* Per-call FAT trace logs (init geometry, write probes). Set to 1 to
 * re-enable FAT-level debugging on the console. */
#define FAT_TRACE_LOG 0

// Forward declarations
extern int parse_u32(const char *s, uint32_t *out);
extern void mem_set(uint8_t *dst, uint8_t v, uint32_t n);
extern void kmemcpy(void *dest, const void *src, uint32_t n);
extern size_t kstrlen(const char *s);

struct file_slot file_slots[FILE_SLOTS];
uint16_t fat12_cwd_cluster = 0;
char fat12_cwd_path[128] = "/";
fat12_ctx fat_global_ctx;

void fat12_cwd_set_root(void) {
  fat12_cwd_cluster = 0;
  fat12_cwd_path[0] = '/';
  fat12_cwd_path[1] = '\0';
}

void fat12_cwd_push(const char *seg) {
  size_t len = kstrlen(fat12_cwd_path);
  if (len == 0) {
    fat12_cwd_path[0] = '/';
    fat12_cwd_path[1] = '\0';
    len = 1;
  }
  if (seg[0] == '\0')
    return;
  if (len + 1 >= sizeof(fat12_cwd_path))
    return;

  if (len > 1 && fat12_cwd_path[len - 1] == '/') {
    fat12_cwd_path[--len] = '\0';
  }
  if (len + 1 >= sizeof(fat12_cwd_path))
    return;
  if (len > 1) {
    fat12_cwd_path[len++] = '/';
  }
  for (size_t i = 0; seg[i] != '\0' && len + 1 < sizeof(fat12_cwd_path); i++) {
    fat12_cwd_path[len++] = seg[i];
  }
  fat12_cwd_path[len] = '\0';
}

void fat12_cwd_pop(void) {
  size_t len = kstrlen(fat12_cwd_path);
  if (len <= 1) {
    fat12_cwd_set_root();
    return;
  }
  if (len > 1 && fat12_cwd_path[len - 1] == '/') {
    fat12_cwd_path[--len] = '\0';
  }
  while (len > 1 && fat12_cwd_path[len - 1] != '/') {
    fat12_cwd_path[--len] = '\0';
  }
  if (len > 1) {
    fat12_cwd_path[len - 1] = '\0';
  }
  if (fat12_cwd_path[0] == '\0' || fat12_cwd_path[0] != '/') {
    fat12_cwd_set_root();
  }
}

void file_slot_init(void) {
  for (int i = 0; i < FILE_SLOTS; i++) {
    file_slots[i].ptr = (void *)0;
    file_slots[i].size = 0;
    file_slots[i].name[0] = '\0';
  }
}

/* Drop a cached slot so reads fall through to disk (e.g. after rm). */
int file_slot_drop(const char *name) {
  int dropped = 0;
  for (int i = 0; i < FILE_SLOTS; i++) {
    if (file_slots[i].ptr != (void *)0 && kstreq(name, file_slots[i].name)) {
      kfree(file_slots[i].ptr);
      file_slots[i].ptr = (void *)0;
      file_slots[i].size = 0;
      file_slots[i].name[0] = '\0';
      dropped = 1;
    }
  }
  return dropped;
}

int file_slot_save(const char *name, const uint8_t *data, uint32_t size) {
  int id = -1;
  for (int i = 0; i < FILE_SLOTS; i++) {
    if (file_slots[i].ptr != (void *)0) {
      if (kstreq(name, file_slots[i].name)) {
        id = i;
        break;
      }
    }
  }
  if (id == -1) {
    for (int i = 0; i < FILE_SLOTS; i++) {
      if (file_slots[i].ptr == (void *)0) {
        id = i;
        break;
      }
    }
  }
  if (id == -1)
    return -1;

  void *new_buf = kmalloc(size ? size : 1);
  if (!new_buf)
    return -2;

  if (file_slots[id].ptr)
    kfree(file_slots[id].ptr);

  kmemcpy(new_buf, data, size);
  file_slots[id].ptr = new_buf;
  file_slots[id].size = size;

  size_t ni = 0;
  for (; name[ni] != '\0' && ni + 1 < sizeof(file_slots[id].name); ni++) {
    file_slots[id].name[ni] = name[ni];
  }
  file_slots[id].name[ni] = '\0';

  return id;
}

int file_slot_read(const char *name, uint8_t **out_buf, uint32_t *out_size) {
  for (int i = 0; i < FILE_SLOTS; i++) {
    if (file_slots[i].ptr != (void *)0) {
      if (kstreq(name, file_slots[i].name)) {
        uint32_t s = file_slots[i].size;
        void *cpy = kmalloc(s ? s : 1);
        if (!cpy)
          return -1;
        kmemcpy(cpy, file_slots[i].ptr, s);
        *out_buf = (uint8_t *)cpy;
        *out_size = s;
        return 1;
      }
    }
  }
  return 0;
}

int file_slot_peek(const char *name, uint8_t **out_buf, uint32_t *out_size) {
  for (int i = 0; i < FILE_SLOTS; i++) {
    if (file_slots[i].ptr != (void *)0 && kstreq(name, file_slots[i].name)) {
      *out_buf = (uint8_t *)file_slots[i].ptr;
      *out_size = file_slots[i].size;
      return 1;
    }
  }
  return 0;
}

// FAT12 implementation details
static uint16_t fat12_get_entry(const uint8_t *fat, uint16_t cluster) {
  uint32_t offset = (uint32_t)cluster + ((uint32_t)cluster / 2u);
  uint16_t v;
  if (cluster & 1u)
    v = (uint16_t)(((uint16_t)fat[offset] >> 4) |
                   ((uint16_t)fat[offset + 1] << 4));
  else
    v = (uint16_t)((uint16_t)fat[offset] |
                   (((uint16_t)fat[offset + 1] & 0x0F) << 8));
  return (uint16_t)(v & 0x0FFF);
}

// FAT16 implementation
static uint16_t fat16_get_entry(const uint8_t *fat, uint16_t cluster) {
  uint32_t offset = (uint32_t)cluster * 2u;
  return (uint16_t)((uint16_t)fat[offset] | ((uint16_t)fat[offset + 1] << 8));
}

/* Type-aware cluster accessor using ctx->fat_type and cache mode */
static uint16_t fat_get_entry(const fat12_ctx *ctx, uint16_t cluster);
static uint16_t fat16_get_entry_cached(fat12_ctx *ctx, uint16_t cluster);

/* Check if cluster is end-of-chain for the given FAT type */
static int fat_is_eoc(const fat12_ctx *ctx, uint16_t cluster) {
  if (ctx->fat_type == 16)
    return cluster >= 0xFFF8u;
  return cluster >= 0xFF8u;
}

static void fat12_set_entry(uint8_t *fat, uint16_t cluster, uint16_t value) {
  uint32_t offset = (uint32_t)cluster + ((uint32_t)cluster / 2u);
  if (cluster & 1u) {
    fat[offset] = (uint8_t)((fat[offset] & 0x0F) | ((value & 0x0F) << 4));
    fat[offset + 1] = (uint8_t)(((value >> 4) & 0xFF));
  } else {
    fat[offset] = (uint8_t)(value & 0xFF);
    fat[offset + 1] =
        (uint8_t)((fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F));
  }
}

/* Number of data clusters on the volume (BPB); cluster numbers are 2..n+1. */
static uint32_t fat_volume_cluster_count(const fat12_ctx *ctx) {
  const struct fat_bpb *bpb = &ctx->bpb;
  uint32_t total_sectors = bpb->total_sectors_short;
  if (total_sectors == 0)
    total_sectors = bpb->total_sectors_long;
  uint32_t root_sectors =
      ((uint32_t)bpb->root_dir_entries * 32u + 511u) / 512u;
  uint32_t data_sectors =
      total_sectors - (uint32_t)bpb->reserved_sectors -
      ((uint32_t)bpb->fat_count * (uint32_t)bpb->fat_size_sectors) -
      root_sectors;
  uint32_t spc = (uint32_t)bpb->sectors_per_cluster;
  if (spc == 0)
    return 0;
  return data_sectors / spc;
}

static void fat12_to_83(const char *in, uint8_t out11[11]) {
  for (int i = 0; i < 11; i++)
    out11[i] = ' ';
  int o = 0, in_ext = 0;
  for (int i = 0; in[i] != '\0'; i++) {
    char c = in[i];
    if (c == '.') {
      in_ext = 1;
      o = 8;
      continue;
    }
    if (c >= 'a' && c <= 'z')
      c = (char)(c - 'a' + 'A');
    if (!in_ext) {
      if (o < 8)
        out11[o++] = (uint8_t)c;
    } else {
      if (o < 11)
        out11[o++] = (uint8_t)c;
    }
  }
}

static int fat12_name_eq(const uint8_t name11[11], const uint8_t target11[11]) {
  for (int i = 0; i < 11; i++)
    if (name11[i] != target11[i])
      return 0;
  return 1;
}

// Read BPB and detect FAT type (FAT12 or FAT16)
static int fat_read_bpb(uint8_t drive, struct fat_bpb *bpb, int *fat_type) {
  uint8_t sector[SECTOR_SIZE];
  if (!disk_read_sector(drive, 0, sector))
    return 0;
  mem_copy((uint8_t *)bpb, sector, (uint32_t)sizeof(*bpb));

  if (bpb->bytes_per_sector != 512)
    return 0;

  // Detect FAT type based on cluster count
  // Formula: total_clusters = (total_sectors - reserved - root_sectors) /
  // sectors_per_cluster
  uint32_t total_sectors = bpb->total_sectors_short;
  if (total_sectors == 0)
    total_sectors = bpb->total_sectors_long;

  uint32_t root_sectors = ((uint32_t)bpb->root_dir_entries * 32u + 511u) / 512u;
  uint32_t data_sectors =
      total_sectors - (uint32_t)bpb->reserved_sectors -
      ((uint32_t)bpb->fat_count * (uint32_t)bpb->fat_size_sectors) -
      root_sectors;
  uint32_t total_clusters = data_sectors / (uint32_t)bpb->sectors_per_cluster;

  // FAT12: up to 4085 clusters (0xFF5)
  // FAT16: 4086 to 65525 clusters
  if (total_clusters < 4085) {
    *fat_type = 12;
  } else {
    *fat_type = 16;
  }

  return 1;
}

// Legacy function for compatibility
static int fat12_read_bpb(struct fat_bpb *bpb) {
  int fat_type;
  return fat_read_bpb(ramdisk_drive, bpb, &fat_type);
}

int fat12_init_ex(struct fat_ctx *ctx, uint8_t drive) {
  ctx->drive = drive;
  // log_writestring("[FAT] Reading BPB...\\n");
  if (!fat_read_bpb(drive, &ctx->bpb, &ctx->fat_type))
    return 0;

  // Set FAT entry operations based on detected type
  if (ctx->fat_type == 16) {
    ctx->ops = (const void *)&fat16_ops;
  } else {
    ctx->ops = (const void *)&fat12_ops;
  }

  uint16_t spf = ctx->bpb.fat_size_sectors;
  ctx->fat_lba = (uint32_t)ctx->bpb.reserved_sectors;
  ctx->root_lba = (uint32_t)ctx->bpb.reserved_sectors +
                  (uint32_t)ctx->bpb.fat_count * (uint32_t)spf;
  ctx->root_sectors =
      (uint16_t)((ctx->bpb.root_dir_entries * 32u + 511u) / 512u);
  ctx->data_lba = ctx->root_lba + (uint32_t)ctx->root_sectors;
#if FAT_TRACE_LOG
  log_writestring("[FAT] root_lba=");
  log_write_u32(ctx->root_lba);
  log_writestring(" root_sectors=");
  log_write_u32((uint32_t)ctx->root_sectors);
  log_writestring("\n");
#endif

  // Initialize cache
  ctx->use_cache = 1; // Enable sector-based cache
  ctx->cache_access_counter = 0;
  for (int i = 0; i < FAT_CACHE_SIZE; i++) {
    ctx->cache[i].sector = 0xFFFFFFFF; // Invalid sector marker
    ctx->cache[i].dirty = 0;
    ctx->cache[i].access_time = 0;
  }

  // For small FATs (< 16 sectors), still load fully for performance
  // For larger FATs, use sector cache
  if (spf <= 16) {
    ctx->use_cache = 0;
    uint32_t fat_bytes = (uint32_t)spf * 512u;
    ctx->fat = (uint8_t *)kmalloc(fat_bytes);
    if (!ctx->fat)
      return 0;
    for (uint16_t i = 0; i < spf; i++) {
      if (!disk_read_sector(ctx->drive, ctx->fat_lba + i,
                            ctx->fat + (uint32_t)i * 512u)) {
        kfree(ctx->fat);
        ctx->fat = 0;
        return 0;
      }
    }
  } else {
    // Use sector cache - don't allocate full FAT
    ctx->fat = 0;
  }
  return 1;
}

void fat12_deinit(fat12_ctx *ctx) {
  // Flush dirty cache entries
  if (ctx->use_cache) {
    for (int i = 0; i < FAT_CACHE_SIZE; i++) {
      if (ctx->cache[i].dirty && ctx->cache[i].sector != 0xFFFFFFFF) {
        disk_write_sector(ctx->drive, ctx->fat_lba + ctx->cache[i].sector,
                          ctx->cache[i].data);
      }
    }
  }
  if (ctx->fat)
    kfree(ctx->fat);
}

/* Refresh a long-lived context (e.g. the VFS mount) so it sees FAT and
 * directory changes made through other contexts since it was created. */
void fat12_reload(fat12_ctx *ctx) {
  uint16_t spf = ctx->bpb.fat_size_sectors;
  if (ctx->fat) {
    for (uint16_t i = 0; i < spf; i++) {
      if (!disk_read_sector(ctx->drive, ctx->fat_lba + i,
                            ctx->fat + (uint32_t)i * 512u))
        return;
    }
  }
  for (int i = 0; i < FAT_CACHE_SIZE; i++) {
    ctx->cache[i].sector = 0xFFFFFFFF;
    ctx->cache[i].dirty = 0;
    ctx->cache[i].access_time = 0;
  }
}

uint32_t fat12_cluster_lba(const fat12_ctx *ctx, uint16_t cluster) {
  uint32_t root_lba =
      (uint32_t)ctx->bpb.reserved_sectors +
      (uint32_t)ctx->bpb.fat_count * (uint32_t)ctx->bpb.fat_size_sectors;
  uint32_t root_sectors =
      (uint32_t)((ctx->bpb.root_dir_entries * 32u + 511u) / 512u);
  uint32_t data_lba = root_lba + root_sectors;
  return data_lba +
         (uint32_t)(cluster - 2u) * (uint32_t)ctx->bpb.sectors_per_cluster;
}

void fat12_format_name(const uint8_t name[11], char out[13]) {
  int oi = 0, has_ext = 0;
  for (int i = 0; i < 8; i++) {
    if (name[i] == ' ')
      break;
    out[oi++] = (char)name[i];
  }
  for (int i = 8; i < 11; i++) {
    if (name[i] != ' ') {
      has_ext = 1;
      break;
    }
  }
  if (has_ext) {
    out[oi++] = '.';
    for (int i = 8; i < 11; i++) {
      if (name[i] == ' ')
        break;
      out[oi++] = (char)name[i];
    }
  }
  out[oi] = '\0';
}

// FAT cache helper functions
static struct fat_cache_entry *fat_cache_find(fat12_ctx *ctx, uint32_t sector) {
  for (int i = 0; i < FAT_CACHE_SIZE; i++) {
    if (ctx->cache[i].sector == sector) {
      ctx->cache[i].access_time = ++ctx->cache_access_counter;
      return &ctx->cache[i];
    }
  }
  return 0;
}

static struct fat_cache_entry *fat_cache_evict(fat12_ctx *ctx) {
  // Find LRU entry (lowest access_time)
  int lru_idx = 0;
  uint32_t lru_time = ctx->cache[0].access_time;
  for (int i = 1; i < FAT_CACHE_SIZE; i++) {
    if (ctx->cache[i].access_time < lru_time) {
      lru_time = ctx->cache[i].access_time;
      lru_idx = i;
    }
  }

  // Write back if dirty
  if (ctx->cache[lru_idx].dirty && ctx->cache[lru_idx].sector != 0xFFFFFFFF) {
    disk_write_sector(ctx->drive, ctx->fat_lba + ctx->cache[lru_idx].sector,
                      ctx->cache[lru_idx].data);
    ctx->cache[lru_idx].dirty = 0;
  }

  return &ctx->cache[lru_idx];
}

static uint8_t *fat_get_sector(fat12_ctx *ctx, uint32_t sector, int for_write) {
  if (!ctx->use_cache) {
    // Full FAT in memory
    if (ctx->fat && sector < ctx->bpb.fat_size_sectors) {
      return ctx->fat + sector * 512;
    }
    return 0;
  }

  // Sector cache mode
  struct fat_cache_entry *entry = fat_cache_find(ctx, sector);
  if (entry) {
    if (for_write)
      entry->dirty = 1;
    return entry->data;
  }

  // Cache miss - load sector
  entry = fat_cache_evict(ctx);
  if (!disk_read_sector(ctx->drive, ctx->fat_lba + sector, entry->data)) {
    return 0;
  }
  entry->sector = sector;
  entry->dirty = for_write ? 1 : 0;
  entry->access_time = ++ctx->cache_access_counter;
  return entry->data;
}

// FAT12 entry access with cache support (byte-accurate; entries can span
// sector boundaries; must not pass a single-sector buffer to fat12_get_entry).
static int fat12_get_fat_byte(fat12_ctx *ctx, uint32_t abs, uint8_t *out) {
  uint32_t sec = abs / 512u;
  uint32_t rel = abs % 512u;
  uint8_t *s = fat_get_sector(ctx, sec, 0);
  if (!s)
    return 0;
  *out = s[rel];
  return 1;
}

static void fat12_put_fat_byte(fat12_ctx *ctx, uint32_t abs, uint8_t v) {
  uint32_t sec = abs / 512u;
  uint32_t rel = abs % 512u;
  uint8_t *s = fat_get_sector(ctx, sec, 1);
  if (s)
    s[rel] = v;
}

static uint16_t fat12_get_entry_cached(fat12_ctx *ctx, uint16_t cluster) {
  uint32_t o = (uint32_t)cluster + (uint32_t)cluster / 2u;
  uint8_t b0, b1;
  if (!fat12_get_fat_byte(ctx, o, &b0) || !fat12_get_fat_byte(ctx, o + 1u, &b1))
    return 0xFFFF;
  uint16_t v;
  if (cluster & 1u)
    v = (uint16_t)(((uint16_t)b0 >> 4) | ((uint16_t)b1 << 4));
  else
    v = (uint16_t)((uint16_t)b0 | (((uint16_t)b1 & 0x0F) << 8));
  return (uint16_t)(v & 0x0FFFu);
}

static void fat12_set_entry_cached(fat12_ctx *ctx, uint16_t cluster,
                                   uint16_t value) {
  uint32_t o = (uint32_t)cluster + (uint32_t)cluster / 2u;
  uint8_t b0, b1;
  if (!fat12_get_fat_byte(ctx, o, &b0) || !fat12_get_fat_byte(ctx, o + 1u, &b1))
    return;
  if (cluster & 1u) {
    b0 = (uint8_t)((b0 & 0x0Fu) | (uint8_t)((value << 4) & 0xF0u));
    b1 = (uint8_t)((value >> 4) & 0xFFu);
  } else {
    b0 = (uint8_t)(value & 0xFFu);
    b1 = (uint8_t)((b1 & 0xF0u) | (uint8_t)((value >> 8) & 0x0Fu));
  }
  fat12_put_fat_byte(ctx, o, b0);
  fat12_put_fat_byte(ctx, o + 1u, b1);
}

/* FAT16 cached entry access */
static uint16_t fat16_get_entry_cached(fat12_ctx *ctx, uint16_t cluster) {
  /* FAT16: 2 bytes per entry, sector = (cluster * 2) / 512 = cluster / 256 */
  uint32_t sector = (uint32_t)cluster / 256u;
  uint8_t *fat_sector = fat_get_sector(ctx, sector, 0);
  if (!fat_sector)
    return 0xFFFF;
  /* offset within the sector */
  uint32_t off = ((uint32_t)cluster % 256u) * 2u;
  return (uint16_t)((uint16_t)fat_sector[off] |
                    ((uint16_t)fat_sector[off + 1] << 8));
}

static void fat16_set_entry(uint8_t *fat, uint16_t cluster, uint16_t value) {
  uint32_t off = (uint32_t)cluster * 2u;
  fat[off] = (uint8_t)(value & 0xFFu);
  fat[off + 1u] = (uint8_t)(value >> 8);
}

static void fat16_set_entry_cached(fat12_ctx *ctx, uint16_t cluster,
                                   uint16_t value) {
  uint32_t sector = (uint32_t)cluster / 256u;
  uint8_t *fat_sector = fat_get_sector(ctx, sector, 1);
  if (!fat_sector)
    return;
  uint32_t off = ((uint32_t)cluster % 256u) * 2u;
  fat_sector[off] = (uint8_t)(value & 0xFFu);
  fat_sector[off + 1u] = (uint8_t)(value >> 8);
}

/* Type-aware cluster accessor - handles both cached and non-cached modes */
static uint16_t fat_get_entry(const fat12_ctx *ctx, uint16_t cluster) {
  if (ctx->use_cache) {
    if (ctx->fat_type == 16)
      return fat16_get_entry_cached((fat12_ctx *)ctx, cluster);
    return fat12_get_entry_cached((fat12_ctx *)ctx, cluster);
  }
  if (!ctx->fat)
    return 0xFFFF;
  if (ctx->fat_type == 16)
    return fat16_get_entry(ctx->fat, cluster);
  return fat12_get_entry(ctx->fat, cluster);
}

static void fat_ctx_set_entry(fat12_ctx *ctx, uint16_t cluster, uint16_t value) {
  if (ctx->use_cache) {
    if (ctx->fat_type == 16)
      fat16_set_entry_cached(ctx, cluster, value);
    else
      fat12_set_entry_cached(ctx, cluster, value);
    return;
  }
  if (!ctx->fat)
    return;
  if (ctx->fat_type == 16)
    fat16_set_entry(ctx->fat, cluster, value);
  else
    fat12_set_entry(ctx->fat, cluster, value);
}

static uint16_t fat_find_free_cluster(const fat12_ctx *ctx) {
  uint32_t n = fat_volume_cluster_count(ctx);
  if (n == 0)
    return 0xFFFF;
  uint32_t last = n + 1u;
  if (last > 0xFFFFu)
    last = 0xFFFFu;
  if (last < 2u)
    return 0xFFFF;
  for (uint32_t c = 2u; c <= last; c++) {
    if (fat_get_entry(ctx, (uint16_t)c) == 0u)
      return (uint16_t)c;
  }
  return 0xFFFF;
}

static uint16_t fat12_chain_count_cached(fat12_ctx *ctx, uint16_t start) {
  uint16_t count = 0, c = start;
  while (c >= 2 && !fat_is_eoc(ctx, c) && count < 65535u) {
    count++;
    c = fat_get_entry(ctx, c);
  }
  return count;
}

static uint16_t fat12_chain_count(const fat12_ctx *ctx, uint16_t start) {
  uint16_t count = 0, c = start;
  while (c >= 2 && !fat_is_eoc(ctx, c) && count < 65535u) {
    count++;
    c = fat_get_entry(ctx, c);
  }
  return count;
}

int fat12_read_root_dir(const fat12_ctx *ctx, uint8_t **out_buf,
                        uint32_t *out_bytes) {
  uint32_t root_lba;
  uint16_t root_sectors;
  uint32_t bytes;

  /* Always use BPB root from ctx and live disk_read_sector. Floppy cache is
   * updated on write; the old boot-time snapshot path returned a frozen copy
   * so touch/mkdir wrote to disk but cat/cd still saw the empty snapshot. */
  root_lba = (uint32_t)ctx->root_lba;
  root_sectors = ctx->root_sectors;
  bytes = (uint32_t)root_sectors * 512u;
  // #region agent log
  {
    static uint8_t fat_root_read_logged;
    if (!fat_root_read_logged) {
      fat_root_read_logged = 1;
      agent_dbg_evt("B", "fat.c:fat12_read_root_dir", "root_live_ctx",
                    root_lba, (uint32_t)root_sectors);
    }
  }
  // #endregion
  /* Do not scan alternate LBAs: writes always use ctx->root_lba; reading a
   * different root would desync metadata updates from directory data. */
  uint8_t *buf = (uint8_t *)kmalloc(bytes);
  if (!buf)
    return 0;
  for (uint32_t i = 0; i < bytes; i++)
    buf[i] = 0;
  for (uint16_t i = 0; i < root_sectors; i++) {
    if (!disk_read_sector(ctx->drive, root_lba + i, buf + (uint32_t)i * 512u)) {
      kfree(buf);
      return 0;
    }
  }
  *out_buf = buf;
  *out_bytes = bytes;
  return 1;
}

int fat12_read_dir_cluster(const fat12_ctx *ctx, uint16_t start_cluster,
                           uint8_t **out_buf, uint32_t *out_bytes) {
  uint16_t clusters;
  if (ctx->use_cache) {
    clusters = fat12_chain_count_cached((fat12_ctx *)ctx, start_cluster);
  } else {
    clusters = fat12_chain_count(ctx, start_cluster);
  }
  if (clusters == 0)
    return 0;
  uint32_t bytes =
      (uint32_t)clusters * (uint32_t)ctx->bpb.sectors_per_cluster * 512u;
  uint8_t *buf = (uint8_t *)kmalloc(bytes);
  if (!buf)
    return 0;
  uint16_t c = start_cluster;
  uint32_t off = 0;
  while (c >= 2 && !fat_is_eoc(ctx, c) && off < bytes) {
    uint32_t lba = fat12_cluster_lba(ctx, c);
    for (uint8_t s = 0; s < ctx->bpb.sectors_per_cluster; s++) {
      if (!disk_read_sector(ctx->drive, lba + s, buf + off)) {
        kfree(buf);
        return 0;
      }
      off += 512u;
    }
    c = fat_get_entry(ctx, c);
  }
  *out_buf = buf;
  *out_bytes = bytes;
  return 1;
}

// Calculate checksum for 8.3 filename (used for LFN entries)
static uint8_t fat_lfn_checksum(const uint8_t name83[11]) {
  uint8_t sum = 0;
  for (int i = 0; i < 11; i++) {
    sum = ((sum & 1) ? 0x80 : 0) + (sum >> 1) + name83[i];
  }
  return sum;
}

// String equality check helper (if kstreq doesn't exist)
static int kstreq_local(const char *a, const char *b) {
  if (!a || !b)
    return 0;
  while (*a && *b) {
    if (*a != *b)
      return 0;
    a++;
    b++;
  }
  return (*a == *b);
}

static int to_upper(int c) {
  return (c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c;
}

static int kstreq_local_nocase(const char *a, const char *b) {
  if (!a || !b)
    return 0;
  while (*a && *b) {
    if (to_upper((unsigned char)*a) != to_upper((unsigned char)*b))
      return 0;
    a++;
    b++;
  }
  return (*a == *b);
}

// Extract long filename from LFN entries
static int fat_extract_lfn(const uint8_t *dir_buf, uint32_t start_idx,
                           char *out_name, size_t max_len) {
  // Count LFN entries
  int lfn_count = 0;
  uint32_t idx = start_idx;
  uint8_t expected_checksum = 0;

  // First, get checksum from the 8.3 entry itself (at start_idx; the entry
  // before it is the last LFN entry, not the short name)
  {
    struct fat12_dirent *sfn = (struct fat12_dirent *)(dir_buf + start_idx);
    if (sfn->attr != FAT_ATTR_LFN) {
      expected_checksum = fat_lfn_checksum(sfn->name);
    }
  }

  // Count backwards to find all LFN entries
  while (idx >= 32) {
    struct fat_lfn_dirent *lfn =
        (struct fat_lfn_dirent *)(dir_buf + (idx - 32));
    if (lfn->attr != FAT_ATTR_LFN)
      break;
    if (lfn->checksum != expected_checksum)
      break;
    lfn_count++;
    if (lfn->sequence & FAT_LFN_LAST)
      break;
    idx -= 32;
  }

  if (lfn_count == 0)
    return 0;

  // Extract characters from LFN entries (in reverse order)
  int out_pos = 0;
  for (int entry = lfn_count - 1; entry >= 0; entry--) {
    struct fat_lfn_dirent *lfn =
        (struct fat_lfn_dirent *)(dir_buf + (start_idx - 32 - entry * 32));

    // Extract name1 (5 chars)
    for (int i = 0; i < 5 && out_pos < (int)max_len - 1; i++) {
      uint16_t wchar = lfn->name1[i];
      if (wchar == 0x0000 || wchar == 0xFFFF)
        goto done;
      if (wchar < 0x80) {
        out_name[out_pos++] = (char)wchar;
      } else {
        // Simple UTF-16 to ASCII conversion (drop high byte)
        out_name[out_pos++] = (char)(wchar & 0xFF);
      }
    }

    // Extract name2 (6 chars)
    for (int i = 0; i < 6 && out_pos < (int)max_len - 1; i++) {
      uint16_t wchar = lfn->name2[i];
      if (wchar == 0x0000 || wchar == 0xFFFF)
        goto done;
      if (wchar < 0x80) {
        out_name[out_pos++] = (char)wchar;
      } else {
        out_name[out_pos++] = (char)(wchar & 0xFF);
      }
    }

    // Extract name3 (2 chars)
    for (int i = 0; i < 2 && out_pos < (int)max_len - 1; i++) {
      uint16_t wchar = lfn->name3[i];
      if (wchar == 0x0000 || wchar == 0xFFFF)
        goto done;
      if (wchar < 0x80) {
        out_name[out_pos++] = (char)wchar;
      } else {
        out_name[out_pos++] = (char)(wchar & 0xFF);
      }
    }
  }

done:
  out_name[out_pos] = '\0';
  return 1;
}

/* Display name for the 8.3 entry at dir_buf + byte_idx: the long filename
 * if valid LFN entries precede it, otherwise the 8.3 name itself. */
void fat12_display_name(const uint8_t *dir_buf, uint32_t byte_idx,
                        char *out_name, size_t max_len) {
  if (byte_idx >= 32 && fat_extract_lfn(dir_buf, byte_idx, out_name, max_len))
    return;
  struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + byte_idx);
  if (max_len < 13) {
    if (max_len)
      out_name[0] = '\0';
    return;
  }
  fat12_format_name(e->name, out_name);
}

// Create LFN entries for a long filename
static int fat_create_lfn_entries(uint8_t *dir_buf, uint32_t *out_slots,
                                  const char *long_name,
                                  const uint8_t name83[11]) {
  size_t name_len = kstrlen(long_name);
  if (name_len == 0)
    return 0;

  // Calculate number of LFN entries needed (13 chars per entry)
  int lfn_entries = (int)((name_len + 12) / 13);
  if (lfn_entries > 20) // Limit to 20 LFN entries (260 chars max)
    lfn_entries = 20;

  uint8_t checksum = fat_lfn_checksum(name83);

  // Convert filename to UTF-16 (simplified - just use ASCII values)
  uint16_t *utf16_name = (uint16_t *)kmalloc((uint32_t)(name_len + 1) * 2);
  if (!utf16_name)
    return 0;

  for (size_t i = 0; i < name_len; i++) {
    utf16_name[i] = (uint16_t)(unsigned char)long_name[i];
  }
  utf16_name[name_len] = 0;

  // Create LFN entries (in reverse order, last entry first)
  int utf16_pos = 0;
  for (int entry = lfn_entries - 1; entry >= 0; entry--) {
    struct fat_lfn_dirent *lfn =
        (struct fat_lfn_dirent *)(dir_buf + entry * 32);

    // Clear entry
    mem_set((uint8_t *)lfn, 0, 32);

    // Set sequence number
    lfn->sequence = (uint8_t)(entry + 1);
    if (entry == lfn_entries - 1) {
      lfn->sequence |= FAT_LFN_LAST; // Mark last entry
    }

    lfn->attr = FAT_ATTR_LFN;
    lfn->type = 0x00;
    lfn->checksum = checksum;
    lfn->first_cluster = 0x0000;

    // Fill name1 (5 chars)
    for (int i = 0; i < 5; i++) {
      if (utf16_pos < (int)name_len) {
        lfn->name1[i] = utf16_name[utf16_pos++];
      } else {
        lfn->name1[i] = 0xFFFF; // Padding
      }
    }

    // Fill name2 (6 chars)
    for (int i = 0; i < 6; i++) {
      if (utf16_pos < (int)name_len) {
        lfn->name2[i] = utf16_name[utf16_pos++];
      } else {
        lfn->name2[i] = 0xFFFF; // Padding
      }
    }

    // Fill name3 (2 chars)
    for (int i = 0; i < 2; i++) {
      if (utf16_pos < (int)name_len) {
        lfn->name3[i] = utf16_name[utf16_pos++];
      } else {
        lfn->name3[i] = 0xFFFF; // Padding
      }
    }
  }

  kfree(utf16_name);
  *out_slots = (uint32_t)lfn_entries;
  return 1;
}

// Find file in directory (supports both 8.3 and LFN)
static int fat12_find_in_dir(const fat12_ctx *ctx, uint16_t dir_cluster,
                             const uint8_t name83[11],
                             struct fat12_dirent *out_ent) {
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  int ok = (dir_cluster == 0)
               ? fat12_read_root_dir(ctx, &buf, &bytes)
               : fat12_read_dir_cluster(ctx, dir_cluster, &buf, &bytes);
  if (!ok)
    return 0;
  uint32_t entries = bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;

    // Check for LFN entry
    if (e->attr == FAT_ATTR_LFN) {
      continue; // Skip LFN entries, we'll handle them when we find the 8.3
                // entry
    }

    // Check if this 8.3 entry matches
    if (fat12_name_eq(e->name, name83)) {
      *out_ent = *e;
      kfree(buf);
      return 1;
    }
  }
  kfree(buf);
  return 0;
}

// Find file by long filename (supports LFN)
static int fat12_find_in_dir_lfn(const fat12_ctx *ctx, uint16_t dir_cluster,
                                 const char *long_name,
                                 struct fat12_dirent *out_ent) {
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  int ok = (dir_cluster == 0)
               ? fat12_read_root_dir(ctx, &buf, &bytes)
               : fat12_read_dir_cluster(ctx, dir_cluster, &buf, &bytes);
  if (!ok)
    return 0;

  uint32_t entries = bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;

    // Skip LFN entries themselves
    if (e->attr == FAT_ATTR_LFN)
      continue;

    // Check if there's an LFN before this entry
    if (i > 0) {
      // Extract LFN and compare
      char extracted_name[256];
      if (fat_extract_lfn(buf, i * 32, extracted_name,
                          sizeof(extracted_name))) {
        if (kstreq_local(extracted_name, long_name)) {
          *out_ent = *e;
          kfree(buf);
          return 1;
        }
      }
    }

    // Also check 8.3 name (case-insensitive for user convenience)
    char name83_str[13];
    fat12_format_name(e->name, name83_str);
    if (kstreq_local_nocase(name83_str, long_name)) {
      *out_ent = *e;
      kfree(buf);
      return 1;
    }
  }
  kfree(buf);
  return 0;
}

uint16_t fat12_resolve_dir(const fat12_ctx *ctx, uint16_t start_dir,
                           const char *path, int *out_is_ok) {
  *out_is_ok = 0;
  if (!path || path[0] == '\0') {
    *out_is_ok = 1;
    return start_dir;
  }
  uint16_t dir = start_dir;
  const char *p = path;
  if (*p == '/') {
    dir = 0;
    p++;
  }
  char seg[32];
  while (*p != '\0') {
    while (*p == '/')
      p++;
    if (*p == '\0')
      break;
    int si = 0;
    while (*p != '\0' && *p != '/' && si < 31)
      seg[si++] = *p++;
    seg[si] = '\0';
    if (seg[0] == '\0' || (seg[0] == '.' && seg[1] == '\0'))
      continue;
    if (seg[0] == '.' && seg[1] == '.' && seg[2] == '\0') {
      if (dir == 0)
        continue;
      uint8_t dotdot[11] = {'.', '.', ' ', ' ', ' ', ' ',
                            ' ', ' ', ' ', ' ', ' '};
      struct fat12_dirent ent;
      dir =
          fat12_find_in_dir(ctx, dir, dotdot, &ent) ? ent.first_cluster_lo : 0;
      continue;
    }
    uint8_t n83[11];
    fat12_to_83(seg, n83);
    struct fat12_dirent ent;
    if (!fat12_find_in_dir(ctx, dir, n83, &ent) || (ent.attr & 0x10) == 0)
      return 0;
    dir = ent.first_cluster_lo;
    if (*p == '/')
      p++;
  }
  *out_is_ok = 1;
  return dir;
}

static void fat12_flush_fat(fat12_ctx *ctx) {
  uint16_t spf = ctx->bpb.fat_size_sectors;
  for (uint16_t i = 0; i < spf; i++) {
    uint32_t lba = ctx->fat_lba + i;
    uint8_t *src = ctx->fat + (uint32_t)i * 512u;
    disk_write_sector(ctx->drive, lba, src);
    if (ctx->bpb.fat_count > 1) {
      uint32_t lba2 = lba + spf;
      disk_write_sector(ctx->drive, lba2, src);
    }
  }
}

int fat12_write_dir_cluster(const fat12_ctx *ctx, uint16_t cluster,
                            const uint8_t *buf, uint32_t bytes) {
  uint16_t c = cluster;
  uint32_t off = 0;
  uint32_t bytes_per_cluster = (uint32_t)ctx->bpb.sectors_per_cluster * 512u;
  while (c >= 2 && !fat_is_eoc(ctx, c) && off < bytes) {
    uint32_t lba = fat12_cluster_lba(ctx, c);
    for (uint8_t s = 0; s < ctx->bpb.sectors_per_cluster && off < bytes; s++) {
      uint32_t sector_off = off + (uint32_t)s * 512u;
      uint32_t to_write =
          (bytes - sector_off) > 512 ? 512 : (bytes - sector_off);
      uint8_t sector[512];
      mem_set(sector, 0, 512);
      mem_copy(sector, buf + sector_off, to_write);
      if (!disk_write_sector(ctx->drive, lba + s, sector))
        return 0;
    }
    off += bytes_per_cluster;
    c = fat_get_entry(ctx, c);
  }
  return 1;
}

static void fat12_free_chain(fat12_ctx *ctx, uint16_t start_cluster) {
  uint16_t c = start_cluster;
  while (c >= 2 && !fat_is_eoc(ctx, c)) {
    uint16_t next;
    if (ctx->use_cache) {
      next = fat12_get_entry_cached(ctx, c);
      fat12_set_entry_cached(ctx, c, 0x000);
    } else {
      next = fat_get_entry(ctx, c);
      fat_ctx_set_entry(ctx, c, 0x000);
    }
    c = next;
  }
}

static struct fat12_dirent *fat12_find_free_slot(fat12_ctx *ctx,
                                                 uint16_t dir_cluster,
                                                 uint8_t *dir_buf,
                                                 uint32_t dir_bytes) {
  uint32_t entries = dir_bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    if (e->name[0] == 0x00 || e->name[0] == 0xE5) {
      mem_set((uint8_t *)e, 0, 32);
      return e;
    }
  }
  return 0;
}

static int fat12_create_dir(fat12_ctx *ctx, uint16_t parent_dir,
                            const char *name) {
  uint8_t name83[11];
  fat12_to_83(name, name83);
  struct fat12_dirent existing;
  if (fat12_find_in_dir(ctx, parent_dir, name83, &existing))
    return 0;
  uint16_t new_cluster = fat_find_free_cluster(ctx);
  if (new_cluster == 0xFFFF)
    return 0;
  uint16_t new_eoc = ctx->fat_type == 16 ? 0xFFFFu : 0x0FFFu;
  fat_ctx_set_entry(ctx, new_cluster, new_eoc);
  uint8_t *parent_buf = 0;
  uint32_t parent_bytes = 0;
  if (parent_dir == 0) {
    if (!fat12_read_root_dir(ctx, &parent_buf, &parent_bytes)) {
      fat_ctx_set_entry(ctx, new_cluster, 0x000);
      return 0;
    }
  } else {
    if (!fat12_read_dir_cluster(ctx, parent_dir, &parent_buf, &parent_bytes)) {
      fat_ctx_set_entry(ctx, new_cluster, 0x000);
      return 0;
    }
  }
  struct fat12_dirent *slot =
      fat12_find_free_slot(ctx, parent_dir, parent_buf, parent_bytes);
  if (!slot) {
    kfree(parent_buf);
    fat_ctx_set_entry(ctx, new_cluster, 0x000);
    return 0;
  }
  mem_copy(slot->name, name83, 11);
  slot->attr = 0x10;
  slot->first_cluster_lo = new_cluster;
  slot->size = 0;
  if (parent_dir == 0) {
    for (uint16_t i = 0; i < ctx->root_sectors; i++)
      disk_write_sector(ctx->drive, ctx->root_lba + i,
                        parent_buf + (uint32_t)i * 512u);
  } else {
    fat12_write_dir_cluster(ctx, parent_dir, parent_buf, parent_bytes);
  }
  kfree(parent_buf);
  uint8_t dir_sector[512];
  mem_set(dir_sector, 0, 512);
  struct fat12_dirent *dot = (struct fat12_dirent *)dir_sector;
  mem_copy(dot->name, ".          ", 11);
  dot->attr = 0x10;
  dot->first_cluster_lo = new_cluster;
  struct fat12_dirent *dotdot = (struct fat12_dirent *)(dir_sector + 32);
  mem_copy(dotdot->name, "..         ", 11);
  dotdot->attr = 0x10;
  dotdot->first_cluster_lo = parent_dir;
  disk_write_sector(ctx->drive, fat12_cluster_lba(ctx, new_cluster),
                    dir_sector);
  return 1;
}

int fat12_write_file_ex(fat12_ctx *ctx, const char *fn, const uint8_t *data,
                        uint32_t size) {
  if (!ctx)
    return 0;

  // #region agent log
  agent_dbg_evt("A", "fat.c:fat12_write_file_ex", "write_begin",
                (uint32_t)fat12_cwd_cluster, (uint32_t)size);
  // #endregion

#if FAT_TRACE_LOG
  log_writestring("[FAT] write drive=");
  log_write_hex8((uint8_t)ctx->drive);
  log_writestring(" root_lba=");
  log_write_u32((uint32_t)ctx->root_lba);
  log_putchar('\n');
#endif

  // Extract filename and parent path from full path
  const char *filename = fn;
  size_t fn_len = kstrlen(fn);
  for (size_t i = fn_len; i > 0; i--) {
    if (fn[i - 1] == '/') {
      filename = fn + i;
      break;
    }
  }

  uint8_t name83[11];
  fat12_to_83(filename, name83);
  /* Absolute paths (leading '/') are rooted at the volume root, not cwd.
   * Without this, SFTP put of /FILE.TXT followed a serial-console `cd`. */
  uint16_t target_dir = (*fn == '/') ? 0 : fat12_cwd_cluster;
  if (filename != fn && filename > fn + 1) {
    /* Path has directory - resolve it (e.g. "etc/PASSWD" -> write to etc) */
    const char *dir_start = (*fn == '/') ? fn + 1 : fn;
    size_t dir_len = (size_t)((filename - 1) - dir_start);
    if (dir_len > 0 && dir_len < 64) {
      char dir_part[64];
      kmemcpy(dir_part, dir_start, dir_len);
      dir_part[dir_len] = '\0';
      int dok = 0;
      uint16_t resolved = fat12_resolve_dir(ctx, 0, dir_part, &dok);
      if (!dok) {
        log_writestring("[FAT] write: directory not found: ");
        log_writestring(dir_part);
        log_putchar('\n');
        return 0;
      }
      target_dir = resolved;
    }
  }

  // #region agent log
  agent_dbg_evt("A", "fat.c:fat12_write_file_ex", "write_target_dir",
                (uint32_t)target_dir, (uint32_t)(unsigned char)filename[0]);
  // #endregion

  uint8_t *dir_buf = 0;
  uint32_t dir_bytes = 0;
  int ok = (target_dir == 0)
               ? fat12_read_root_dir(ctx, &dir_buf, &dir_bytes)
               : fat12_read_dir_cluster(ctx, target_dir, &dir_buf, &dir_bytes);
  if (!ok) {
    return 0;
  }

  // Check if filename needs LFN (longer than 8.3 or contains special chars)
  int needs_lfn = 0;
  size_t filename_len = kstrlen(filename);
  if (filename_len > 12) { // 8.3 + dot = 12 max
    needs_lfn = 1;
  } else {
    // Check for lowercase or special chars
    for (size_t i = 0; i < filename_len; i++) {
      if (filename[i] >= 'a' && filename[i] <= 'z') {
        needs_lfn = 1;
        break;
      }
      if (filename[i] == ' ' || filename[i] == '+' || filename[i] == ',') {
        needs_lfn = 1;
        break;
      }
    }
  }

  struct fat12_dirent *ent = 0;
  uint32_t entries = dir_bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5)
      continue;
    // Skip LFN entries
    if (e->attr == FAT_ATTR_LFN)
      continue;
    if (fat12_name_eq(e->name, name83)) {
      ent = e;
      fat12_free_chain(ctx, ent->first_cluster_lo);
      // Also free any LFN entries before this entry
      if (i > 0) {
        struct fat_lfn_dirent *prev =
            (struct fat_lfn_dirent *)(dir_buf + (i - 1) * 32u);
        if (prev->attr == FAT_ATTR_LFN) {
          // Mark LFN entries as deleted
          uint32_t lfn_idx = i - 1;
          while (lfn_idx > 0 && lfn_idx < entries) {
            struct fat_lfn_dirent *lfn =
                (struct fat_lfn_dirent *)(dir_buf + lfn_idx * 32u);
            if (lfn->attr == FAT_ATTR_LFN &&
                lfn->checksum == fat_lfn_checksum(name83)) {
              ((struct fat12_dirent *)lfn)->name[0] = 0xE5; // Mark as deleted
              if (lfn->sequence & FAT_LFN_LAST)
                break;
              lfn_idx--;
            } else {
              break;
            }
          }
        }
      }
      break;
    }
  }

  // Find free slot(s) for LFN + 8.3 entry
  uint32_t lfn_slots = 0;
  if (needs_lfn) {
    // Calculate LFN slots needed
    lfn_slots = (uint32_t)((filename_len + 12) / 13);
    if (lfn_slots > 20)
      lfn_slots = 20;
  }

  if (!ent) {
    // Find enough free slots for LFN + 8.3 entry
    uint32_t needed_slots = lfn_slots + 1;
    uint32_t free_start = 0;
    uint32_t free_count = 0;

    for (uint32_t i = 0; i < entries; i++) {
      struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
      if (e->name[0] == 0x00 || e->name[0] == 0xE5) {
        if (free_count == 0)
          free_start = i;
        free_count++;
        if (free_count >= needed_slots) {
          ent = (struct fat12_dirent *)(dir_buf + free_start * 32u +
                                        lfn_slots * 32u);
          break;
        }
      } else {
        free_count = 0;
      }
    }

    if (!ent) {
      kfree(dir_buf);
      return 0;
    }
  }

  // Capture the 32-byte directory slot index of the chosen 8.3 entry so we
  // can verify it after writing the directory sectors.
  uint32_t ent_slot_idx = 0xFFFFFFFFu;
  if (ent)
    ent_slot_idx = (uint32_t)(((uint8_t *)ent - dir_buf) / 32u);

  // Create LFN entries if needed
  if (needs_lfn && ent) {
    uint32_t ent_idx = (uint32_t)((uint8_t *)ent - dir_buf) / 32u;
    if (ent_idx >= lfn_slots) {
      uint8_t *lfn_start = dir_buf + (ent_idx - lfn_slots) * 32u;
      if (!fat_create_lfn_entries(lfn_start, &lfn_slots, filename, name83)) {
        kfree(dir_buf);
        return 0;
      }
    }
  }

  // Set up 8.3 entry
  if (ent) {
    // #region agent log
    agent_dbg_evt("F", "fat.c:fat12_write_file_ex", "attr",
                  (uint32_t)ent->attr, (uint32_t)ent->name[0]);
    // #endregion
#if FAT_TRACE_LOG
    log_writestring("[FAT] ent attr before=");
    log_write_hex8(ent->attr);
    log_writestring(" name0=");
    log_write_hex8(ent->name[0]);
    log_putchar('\n');
#endif
    kmemcpy(ent->name, name83, 11);
    // File entries must not keep stale attribute bits (e.g. volume-label
    // 0x08) from the previous occupant of this slot, or fat12_find_in_dir
    // and cmd_ls will skip it.
    ent->attr = 0x00;
    // #region agent log + robust write
    // Avoid relying solely on the `ent` struct cast: write name+attr
    // directly into dir_buf at the computed entry offset.
    if (ent_slot_idx != 0xFFFFFFFFu) {
      uint32_t ent_off = ent_slot_idx * 32u;
      kmemcpy(dir_buf + ent_off, name83, 11);
      dir_buf[ent_off + 11] = 0x00; // attr
    }
    // #endregion
#if FAT_TRACE_LOG
    log_writestring("[FAT] sfn_post name0=");
    log_write_hex8(ent->name[0]);
    log_writestring(" attr=");
    log_write_hex8(ent->attr);
    log_writestring(" slot=");
    log_write_u32(ent_slot_idx);
    log_putchar('\n');
#endif
  } else {
    kfree(dir_buf);
    return 0;
  }
  struct datetime dt;
  get_datetime(&dt);
  ent->wrt_time = datetime_to_fat_time(&dt);
  ent->wrt_date = datetime_to_fat_date(&dt);
  uint32_t clusters_needed =
      (size + (ctx->bpb.sectors_per_cluster * 512u) - 1) /
      (ctx->bpb.sectors_per_cluster * 512u);
  if (size == 0)
    clusters_needed = 1;
  uint16_t prev = 0, first = 0;
  uint16_t fat_eoc = ctx->fat_type == 16 ? 0xFFFFu : 0x0FFFu;
  for (uint32_t i = 0; i < clusters_needed; i++) {
    uint16_t c = fat_find_free_cluster(ctx);
    if (c < 2 || c == 0xFFFF) {
      fat12_free_chain(ctx, first);
      kfree(dir_buf);
      return 0;
    }
    fat_ctx_set_entry(ctx, c, fat_eoc);
    if (prev != 0)
      fat_ctx_set_entry(ctx, prev, c);
    else
      first = c;
    prev = c;
    uint32_t lba = fat12_cluster_lba(ctx, c);
    uint32_t to_write = (size - i * 512u * ctx->bpb.sectors_per_cluster);
    if (to_write > 512u * ctx->bpb.sectors_per_cluster)
      to_write = 512u * ctx->bpb.sectors_per_cluster;
    for (uint8_t s = 0; s < ctx->bpb.sectors_per_cluster; s++) {
      uint8_t sec[512];
      mem_set(sec, 0, 512);
      uint32_t sec_offset = i * 512u * ctx->bpb.sectors_per_cluster + s * 512u;
      if (sec_offset < size) {
        uint32_t copy = (size - sec_offset) > 512 ? 512 : (size - sec_offset);
        mem_copy(sec, data + sec_offset, copy);
      }
      disk_write_sector(ctx->drive, lba + s, sec);
    }
  }
  ent->first_cluster_lo = first;
  ent->size = size;
  if (target_dir == 0) {
    uint32_t dir_byte_off = (ent_slot_idx * 32u);
    uint32_t sector_idx = ent_slot_idx / 16u;
    uint32_t slot_in_sec = ent_slot_idx % 16u;
    uint32_t byte_off = slot_in_sec * 32u;
    for (uint16_t i = 0; i < ctx->root_sectors; i++) {
#if FAT_TRACE_LOG
      if (i == sector_idx) {
        log_writestring("[FAT] root_write src_check lba=");
        log_write_u32(ctx->root_lba + i);
        log_writestring(" ent_off=");
        log_write_u32(dir_byte_off);
        log_writestring(" entname0=");
        log_write_hex8(ent->name[0]);
        log_writestring(" dir_buf_byte_off=");
        log_write_hex8(dir_buf[dir_byte_off]);
        log_writestring(" src_sector_b288=");
        log_write_hex8(dir_buf[(uint32_t)i * 512u + byte_off]);
        log_putchar('\n');
      }
#endif
      disk_write_sector(ctx->drive, ctx->root_lba + i,
                        dir_buf + (uint32_t)i * 512u);
    }
  } else {
    fat12_write_dir_cluster(ctx, target_dir, dir_buf, dir_bytes);
  }

#if FAT_TRACE_LOG
  // Verify the just-written root directory entry before flushing FAT.
  if (target_dir == 0 && ent_slot_idx != 0xFFFFFFFFu) {
    uint32_t sector_idx = ent_slot_idx / 16u;      // 512/32 = 16 dir entries/sector
    uint32_t slot_in_sec = ent_slot_idx % 16u;
    uint32_t byte_off = slot_in_sec * 32u;
    uint8_t sec512[512];
    if (disk_read_sector(ctx->drive, ctx->root_lba + sector_idx, sec512)) {
      log_writestring("[FAT] direct_pre lba=");
      log_write_u32(ctx->root_lba + sector_idx);
      log_writestring(" sector=");
      log_write_u32(sector_idx);
      log_writestring(" name0=");
      log_write_hex8(sec512[byte_off + 0]);
      log_writestring(" attr=");
      log_write_hex8(sec512[byte_off + 11]);
      log_putchar('\n');
    }
    uint8_t *vbuf = 0;
    uint32_t vbytes = 0;
    if (fat12_read_root_dir(ctx, &vbuf, &vbytes)) {
      struct fat12_dirent *ve =
          (struct fat12_dirent *)(vbuf + ent_slot_idx * 32u);
      log_writestring("[FAT] verify_sfn_pre slot=");
      log_write_u32(ent_slot_idx);
      log_writestring(" name0=");
      log_write_hex8(ve->name[0]);
      log_writestring(" attr=");
      log_write_hex8(ve->attr);
      log_putchar('\n');

      if (needs_lfn && lfn_slots > 0 && ent_slot_idx >= lfn_slots) {
        uint32_t lfn_slot = ent_slot_idx - lfn_slots;
        struct fat12_dirent *lv =
            (struct fat12_dirent *)(vbuf + lfn_slot * 32u);
        log_writestring("[FAT] verify_lfn_pre slot=");
        log_write_u32(lfn_slot);
        log_writestring(" name0=");
        log_write_hex8(lv->name[0]);
        log_writestring(" attr=");
        log_write_hex8(lv->attr);
        log_putchar('\n');
      }
      kfree(vbuf);
    }
  }
#endif

  fat12_flush_fat(ctx);
#if FAT_TRACE_LOG
  if (target_dir == 0 && ent_slot_idx != 0xFFFFFFFFu) {
    uint32_t sector_idx = ent_slot_idx / 16u;
    uint32_t slot_in_sec = ent_slot_idx % 16u;
    uint32_t byte_off = slot_in_sec * 32u;
    uint8_t sec512[512];
    if (disk_read_sector(ctx->drive, ctx->root_lba + sector_idx, sec512)) {
      log_writestring("[FAT] direct_post lba=");
      log_write_u32(ctx->root_lba + sector_idx);
      log_writestring(" sector=");
      log_write_u32(sector_idx);
      log_writestring(" name0=");
      log_write_hex8(sec512[byte_off + 0]);
      log_writestring(" attr=");
      log_write_hex8(sec512[byte_off + 11]);
      log_putchar('\n');
    }
    uint8_t *vbuf = 0;
    uint32_t vbytes = 0;
    if (fat12_read_root_dir(ctx, &vbuf, &vbytes)) {
      struct fat12_dirent *ve =
          (struct fat12_dirent *)(vbuf + ent_slot_idx * 32u);
      log_writestring("[FAT] verify_sfn_post slot=");
      log_write_u32(ent_slot_idx);
      log_writestring(" name0=");
      log_write_hex8(ve->name[0]);
      log_writestring(" attr=");
      log_write_hex8(ve->attr);
      log_putchar('\n');

      if (needs_lfn && lfn_slots > 0 && ent_slot_idx >= lfn_slots) {
        uint32_t lfn_slot = ent_slot_idx - lfn_slots;
        struct fat12_dirent *lv =
            (struct fat12_dirent *)(vbuf + lfn_slot * 32u);
        log_writestring("[FAT] verify_lfn_post slot=");
        log_write_u32(lfn_slot);
        log_writestring(" name0=");
        log_write_hex8(lv->name[0]);
        log_writestring(" attr=");
        log_write_hex8(lv->attr);
        log_putchar('\n');
      }
      kfree(vbuf);
    }
  }
#endif
  // #region agent log
  agent_dbg_evt("A", "fat.c:fat12_write_file_ex", "write_done",
                (uint32_t)target_dir, (uint32_t)size);
  // #endregion
  kfree(dir_buf);
  return 1;
}

int fat12_write_file(const char *fn, const uint8_t *data, uint32_t size) {
  /* Static to avoid ~16KB stack use (prevents Page Fault in editor save path)
   */
  static fat12_ctx ctx;
  if (!fat12_init(&ctx))
    return 0;
  int ok = fat12_write_file_ex(&ctx, fn, data, size);
  fat12_deinit(&ctx);
  return ok;
}

int fat12_mkdir(const char *fn) {
  fat12_ctx ctx;
  if (!fat12_init(&ctx))
    return 0;
  // #region agent log
  agent_dbg_evt("A", "fat.c:fat12_mkdir", "mkdir_begin",
                (uint32_t)fat12_cwd_cluster, 0);
  // #endregion
  /* Support nested paths ("var/log"): create each component under the
   * previous one, starting from root for absolute paths. */
  uint16_t dir = (*fn == '/') ? 0 : fat12_cwd_cluster;
  const char *p = fn;
  int ok = 1;
  int created = 0;
  while (*p != '\0') {
    while (*p == '/')
      p++;
    if (*p == '\0')
      break;
    char seg[32];
    int si = 0;
    while (*p != '\0' && *p != '/' && si < 31)
      seg[si++] = *p++;
    seg[si] = '\0';
    if (seg[0] == '\0')
      continue;

    uint8_t n83[11];
    fat12_to_83(seg, n83);
    struct fat12_dirent ent;
    if (fat12_find_in_dir(&ctx, dir, n83, &ent)) {
      if (ent.attr & 0x10) {
        dir = ent.first_cluster_lo; // exists as directory: descend
        continue;
      }
      ok = 0; // exists as a file
      break;
    }
    if (!fat12_create_dir(&ctx, dir, seg)) {
      ok = 0;
      break;
    }
    created = 1;
    if (!fat12_find_in_dir(&ctx, dir, n83, &ent)) {
      ok = 0;
      break;
    }
    dir = ent.first_cluster_lo;
  }
  if (created && ok)
    fat12_flush_fat(&ctx);
  fat12_deinit(&ctx);
  return ok;
}

int fat12_read_file_to_ram_ex_max(fat12_ctx *ctx, const char *path,
                                  uint8_t **out_buf, uint32_t *out_size,
                                  uint32_t max_size) {
  if (!ctx)
    return 0;
  const char *p = skip_spaces(path);
  uint16_t dir = fat12_cwd_cluster;
  if (*p == '/') {
    dir = 0;
    p++;
  }
  const char *last = p;
  for (const char *q = p; *q != '\0'; q++)
    if (*q == '/')
      last = q + 1;
  if (last != p) {
    char dir_part[64];
    size_t dl = (size_t)(last - 1 - p);
    if (dl > 63)
      dl = 63;
    kmemcpy(dir_part, p, dl);
    dir_part[dl] = '\0';
    int dok = 0;
    dir = fat12_resolve_dir(ctx, dir, dir_part, &dok);
    if (!dok) {
      return 0;
    }
  }
  uint8_t target[11];
  fat12_to_83(last, target);
  struct fat12_dirent ent;
  if (!fat12_find_in_dir(ctx, dir, target, &ent) || (ent.attr & 0x10)) {
    /* Fallback: try LFN lookup (handles both LFN and 8.3) */
    if (!fat12_find_in_dir_lfn(ctx, dir, last, &ent) || (ent.attr & 0x10)) {
      return 0;
    }
  }
  /* Cap size to avoid huge allocations from corrupt directory entries */
  const uint32_t default_max = 256u * 1024u * 1024u; // 256MB for large models
  if (max_size == 0 || max_size > default_max)
    max_size = default_max;
  uint32_t read_size = ent.size ? ent.size : 1u;
  if (read_size > max_size)
    read_size = max_size;
  uint8_t *buf = (uint8_t *)kmalloc(read_size);
  if (!buf) {
    return 0;
  }
  uint32_t written = 0;
  uint16_t cluster = ent.first_cluster_lo;
  uint8_t sec[512];
  uint8_t spc = ctx->bpb.sectors_per_cluster;
  if (spc == 0)
    spc = 1;
  uint32_t hops = 0;
  uint32_t hop_max = (max_size / 256u) + 32u;
  if (hop_max < 32u)
    hop_max = 32u;
  if (hop_max > 1048576u)
    hop_max = 1048576u;
  while (cluster >= 2 && !fat_is_eoc(ctx, cluster) && written < read_size) {
    /* Cyclic or corrupt FAT must not wedge SSH/SFTP inside CHANNEL_DATA. */
    if (++hops > hop_max)
      break;
    uint32_t lba = fat12_cluster_lba(ctx, cluster);
    for (uint8_t s = 0; s < spc && written < read_size; s++) {
      if (!disk_read_sector(ctx->drive, lba + s, sec)) {
        kfree(buf);
        return 0;
      }
      uint32_t to_copy =
          (read_size - written) > 512 ? 512 : (read_size - written);
      mem_copy(buf + written, sec, to_copy);
      written += to_copy;
    }
    uint16_t next = fat_get_entry(ctx, cluster);
    if (next == cluster)
      break;
    cluster = next;
  }
  *out_buf = buf;
  *out_size = written;
  return 1;
}

int fat12_read_file_to_ram_ex(fat12_ctx *ctx, const char *path,
                              uint8_t **out_buf, uint32_t *out_size) {
  return fat12_read_file_to_ram_ex_max(ctx, path, out_buf, out_size,
                                       256u * 1024u * 1024u);
}

int fat12_read_file_to_ram(const char *path, uint8_t **out_buf,
                           uint32_t *out_size) {
  extern uint32_t ssh_suppress_log_mirror_to_session;
  /* Don't mirror FAT/disk debug into SSH mid-read.
   * Static ctx: fat12_ctx is ~17KB (FAT sector cache). Putting it on the
   * stack from SSH/SFTP CHANNEL_DATA has overflowed the kernel stack. */
  ssh_suppress_log_mirror_to_session++;
  static fat12_ctx ctx;
  if (!fat12_init(&ctx))
  {
    ssh_suppress_log_mirror_to_session--;
    return 0;
  }
  int ok = fat12_read_file_to_ram_ex(&ctx, path, out_buf, out_size);
  fat12_deinit(&ctx);
  ssh_suppress_log_mirror_to_session--;
  return ok;
}

static void filesystem_organize_file(fat12_ctx *ctx, const char *filename,
                                     const char *dest_dir) {
  uint8_t name83[11];
  fat12_to_83(filename, name83);
  struct fat12_dirent root_entry;
  if (!fat12_find_in_dir(ctx, 0, name83, &root_entry)) {
    return;
  }
  int ok = 0;
  uint16_t dest_cluster = fat12_resolve_dir(ctx, 0, dest_dir, &ok);
  if (!ok)
    return;
  struct fat12_dirent dest_entry;
  if (fat12_find_in_dir(ctx, dest_cluster, name83, &dest_entry))
    return;
  uint8_t *file_buf = 0;
  uint32_t file_size = 0;
  if (!fat12_read_file_to_ram(filename, &file_buf, &file_size))
    return;
  char dest_path[128];
  int len = 0;
  const char *p = dest_dir;
  while (*p && len < 120)
    dest_path[len++] = *p++;
  if (len > 0 && dest_path[len - 1] != '/')
    dest_path[len++] = '/';
  p = filename;
  while (*p && len < 127)
    dest_path[len++] = *p++;
  dest_path[len] = '\0';
  if (fat12_write_file(dest_path, file_buf, file_size)) {
    uint8_t *root_buf = 0;
    uint32_t root_bytes = 0;
    if (fat12_read_root_dir(ctx, &root_buf, &root_bytes)) {
      uint32_t entries = root_bytes / 32u;
      for (uint32_t i = 0; i < entries; i++) {
        struct fat12_dirent *e = (struct fat12_dirent *)(root_buf + i * 32u);
        if (e->name[0] == 0x00)
          break;
        if (fat12_name_eq(e->name, name83)) {
          e->name[0] = 0xE5;
          for (uint16_t j = 0; j < ctx->root_sectors; j++)
            disk_write_sector(ctx->drive, ctx->root_lba + j,
                              root_buf + (uint32_t)j * 512u);
          break;
        }
      }
      kfree(root_buf);
    }
  }
  kfree(file_buf);
}

int fat12_init(struct fat_ctx *ctx) {
  return fat12_init_ex(ctx, ramdisk_drive);
}

void filesystem_init(void) {
  log_writestring("[FS] Setting up filesystem...\n");
  file_slot_init();
  if (!fat12_init(&fat_global_ctx)) {
    log_writestring("[FS] Failed to initialize filesystem\n");
    return;
  }
  /* Boot stability mode: avoid mutating FAT metadata during early init.
   * Root-dir writes can fault on some current disk backends; defer all
   * mkdir/organize work to explicit user commands. */
  log_writestring("[FS] Boot-time filesystem writes deferred\n");
  log_writestring("[FS] Filesystem ready\n");
  return;

  const char *dirs[] = {"etc", "var", "home", "tmp", "bin", "usr", "root"};
  int created = 0;
  for (int i = 0; i < 7; i++) {
    struct fat12_dirent existing;
    uint8_t name83[11];
    fat12_to_83(dirs[i], name83);
    if (!fat12_find_in_dir(&fat_global_ctx, 0, name83, &existing)) {
      if (fat12_create_dir(&fat_global_ctx, 0, dirs[i]))
        created++;
    }
  }
  if (created > 0)
    fat12_flush_fat(&fat_global_ctx);
  filesystem_organize_file(&fat_global_ctx, "PASSWD", "etc");
  filesystem_organize_file(&fat_global_ctx, "NETWORK.CFG", "etc");

  /* Pre-load STORIES.BIN into a file slot while FS is known-good (avoids
   * heavy disk I/O late) */
  if (0) {
    uint8_t *model_buf = 0;
    uint32_t model_size = 0;
    int model_loaded = 0;
    const char *paths[] = {"STORIES.BIN", "/STORIES.BIN", 0};
    for (int i = 0; paths[i]; i++) {
      if (fat12_read_file_to_ram(paths[i], &model_buf, &model_size)) {
        if (file_slot_save("_llm_model", model_buf, model_size) >= 0)
          log_writestring("[FS] Pre-loaded STORIES.BIN for LLM\n");
        kfree(model_buf);
        model_loaded = 1;
        break;
      }
    }
    if (!model_loaded) {
      log_writestring(
          "[FS] STORIES.BIN not on boot disk; run: make run-console (rebuilds "
          "image with model)\n");
    }
  }

  fat12_flush_fat(&fat_global_ctx);
  log_writestring("[FS] Filesystem ready\n");
}

static void fat12_find_recursive(const fat12_ctx *ctx, uint16_t dir,
                                 const char *pattern, const char *prefix) {
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  int ok = (dir == 0) ? fat12_read_root_dir(ctx, &buf, &bytes)
                      : fat12_read_dir_cluster(ctx, dir, &buf, &bytes);
  if (!ok)
    return;
  uint32_t entries = bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    char name[13];
    fat12_format_name(e->name, name);
    int matches = 0;
    for (int j = 0; name[j] != '\0'; j++) {
      int k = 0;
      while (pattern[k] != '\0' && name[j + k] == pattern[k])
        k++;
      if (pattern[k] == '\0') {
        matches = 1;
        break;
      }
    }
    if (matches) {
      log_writestring(prefix);
      log_writestring(name);
      if (e->attr & 0x10)
        log_writestring("  <DIR>\n");
      else {
        log_writestring("  ");
        log_write_u32(e->size);
        log_putchar('\n');
      }
    }
    if ((e->attr & 0x10) && e->first_cluster_lo >= 2 &&
        !fat_is_eoc(ctx, e->first_cluster_lo)) {
      char new_prefix[128];
      size_t plen = kstrlen(prefix);
      if (plen >= sizeof(new_prefix) - 1)
        continue;
      kmemcpy(new_prefix, prefix, plen);
      new_prefix[plen] = '/';
      size_t nlen = kstrlen(name);
      if (plen + 1 + nlen >= sizeof(new_prefix))
        nlen = sizeof(new_prefix) - plen - 2;
      kmemcpy(new_prefix + plen + 1, name, nlen);
      new_prefix[plen + 1 + nlen] = '\0';
      fat12_find_recursive(ctx, e->first_cluster_lo, pattern, new_prefix);
    }
  }
  kfree(buf);
}

static int fat12_delete_entry(fat12_ctx *ctx, uint16_t parent_dir,
                              const uint8_t name83[11]) {
  uint8_t *parent_buf = 0;
  uint32_t parent_bytes = 0;
  int is_root = (parent_dir == 0);
  int ok = is_root ? fat12_read_root_dir(ctx, &parent_buf, &parent_bytes)
                   : fat12_read_dir_cluster(ctx, parent_dir, &parent_buf,
                                            &parent_bytes);
  if (!ok)
    return 0;
  uint32_t entries = parent_bytes / 32u;
  struct fat12_dirent *ent = 0;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(parent_buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5)
      continue;
    if (fat12_name_eq(e->name, name83)) {
      ent = e;
      break;
    }
  }
  if (!ent) {
    kfree(parent_buf);
    return 0;
  }
  uint16_t cluster = ent->first_cluster_lo;
  if (cluster >= 2 && !fat_is_eoc(ctx, cluster))
    fat12_free_chain(ctx, cluster);
  ent->name[0] = 0xE5;
  if (is_root) {
    for (uint16_t i = 0; i < ctx->root_sectors; i++)
      disk_write_sector(ctx->drive, ctx->root_lba + i,
                        parent_buf + (uint32_t)i * 512u);
  } else {
    fat12_write_dir_cluster(ctx, parent_dir, parent_buf, parent_bytes);
  }
  kfree(parent_buf);
  return 1;
}

void cmd_ls(void) {
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  fat12_ctx ctx;
  if (!fat12_init(&ctx))
    return;
  int ok = (fat12_cwd_cluster == 0)
               ? fat12_read_root_dir(&ctx, &buf, &bytes)
               : fat12_read_dir_cluster(&ctx, fat12_cwd_cluster, &buf, &bytes);
  if (!ok) {
    fat12_deinit(&ctx);
    return;
  }
  uint32_t entries = bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    char name[256];
    fat12_display_name(buf, i * 32u, name, sizeof(name));
    log_writestring(name);
    if (e->attr & 0x10)
      log_writestring("  <DIR>\n");
    else {
      log_writestring("  ");
      log_write_u32(e->size);
      log_putchar('\n');
    }
  }
  kfree(buf);
  fat12_deinit(&ctx);
}

void cmd_ls_path(const char *path) {
  fat12_ctx ctx;
  if (!fat12_init(&ctx))
    return;
  const char *p = skip_spaces(path);
  if (*p == '\0') {
    cmd_ls();
    fat12_deinit(&ctx);
    return;
  }
  int dok = 0;
  uint16_t cluster = fat12_resolve_dir(&ctx, fat12_cwd_cluster, p, &dok);
  if (!dok) {
    log_writestring("ls: directory not found: ");
    log_writestring(p);
    log_putchar('\n');
    fat12_deinit(&ctx);
    return;
  }
  uint8_t *buf = 0;
  uint32_t bytes = 0;
  int ok = (cluster == 0) ? fat12_read_root_dir(&ctx, &buf, &bytes)
                          : fat12_read_dir_cluster(&ctx, cluster, &buf, &bytes);
  if (!ok) {
    fat12_deinit(&ctx);
    return;
  }
  uint32_t entries = bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    char name[256];
    fat12_display_name(buf, i * 32u, name, sizeof(name));
    log_writestring(name);
    if (e->attr & 0x10)
      log_writestring("  <DIR>\n");
    else {
      log_writestring("  ");
      log_write_u32(e->size);
      log_putchar('\n');
    }
  }
  kfree(buf);
  fat12_deinit(&ctx);
}

void cmd_cd(const char *path) {
  const char *p = skip_spaces(path);
  if (*p == '\0') {
    fat12_cwd_set_root();
    return;
  }
  fat12_ctx ctx;
  if (!fat12_init(&ctx))
    return;
  int dok = 0;
  uint16_t cluster = fat12_resolve_dir(&ctx, fat12_cwd_cluster, p, &dok);
  if (!dok) {
    log_writestring("cd: directory not found: ");
    log_writestring(p);
    log_putchar('\n');
    fat12_deinit(&ctx);
    return;
  }
  if (*p == '/') {
    fat12_cwd_set_root();
    p++;
  }
  char seg[32];
  while (*p != '\0') {
    while (*p == '/')
      p++;
    if (*p == '\0')
      break;
    int si = 0;
    while (*p != '\0' && *p != '/' && si < 31)
      seg[si++] = *p++;
    seg[si] = '\0';
    if (kstreq(seg, ".")) {
    } else if (kstreq(seg, "..")) {
      fat12_cwd_pop();
    } else {
      fat12_cwd_push(seg);
    }
    if (*p == '/')
      p++;
  }
  fat12_cwd_cluster = cluster;
  fat12_deinit(&ctx);
}

void cmd_pwd(void) {
  log_writestring(fat12_cwd_path);
  log_putchar('\n');
}

void cmd_cat_path(const char *path) {
  const char *p = skip_spaces(path);
  if (*p == '\0') {
    log_writestring("Usage: cat <FILE>\n");
    return;
  }
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(p, &buf, &size)) {
    log_writestring("cat: file not found: ");
    log_writestring(p);
    log_putchar('\n');
    return;
  }
  for (uint32_t i = 0; i < size; i++)
    log_putchar((char)buf[i]);
  kfree(buf);
}

void cmd_cp(const char *path) {
  const char *s = skip_spaces(path);
  if (*s == '\0') {
    log_writestring("Usage: cp <SRC> <DEST>\n");
    return;
  }
  char src[64], dest[64];
  int i = 0;
  while (*s && *s != ' ' && i < 63)
    src[i++] = *s++;
  src[i] = '\0';
  s = skip_spaces(s);
  if (*s == '\0') {
    log_writestring("Usage: cp <SRC> <DEST>\n");
    return;
  }
  i = 0;
  while (*s && *s != ' ' && i < 63)
    dest[i++] = *s++;
  dest[i] = '\0';
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(src, &buf, &size)) {
    log_writestring("cp: source not found\n");
    return;
  }
  if (!fat12_write_file(dest, buf, size))
    log_writestring("cp: failed\n");
  kfree(buf);
}

void cmd_touch(const char *arg) {
  const char *s = skip_spaces(arg);
  if (*s == '\0') {
    log_writestring("Usage: touch <FILE>\n");
    return;
  }
  uint8_t dummy = 0;
  if (!fat12_write_file(s, &dummy, 0))
    log_writestring("touch: failed\n");
}

int fat12_delete_file(const char *path) {
  fat12_ctx ctx;
  if (!fat12_init(&ctx))
    return 0;

  /* Split into parent directory + file name (same scheme as write_file_ex) */
  const char *filename = path;
  size_t fn_len = kstrlen(path);
  for (size_t i = fn_len; i > 0; i--) {
    if (path[i - 1] == '/') {
      filename = path + i;
      break;
    }
  }
  uint16_t target_dir = (*path == '/') ? 0 : fat12_cwd_cluster;
  if (filename != path && filename > path + 1) {
    const char *dir_start = (*path == '/') ? path + 1 : path;
    size_t dir_len = (size_t)((filename - 1) - dir_start);
    if (dir_len > 0 && dir_len < 64) {
      char dir_part[64];
      kmemcpy(dir_part, dir_start, dir_len);
      dir_part[dir_len] = '\0';
      int dok = 0;
      uint16_t resolved = fat12_resolve_dir(&ctx, 0, dir_part, &dok);
      if (!dok) {
        fat12_deinit(&ctx);
        return 0;
      }
      target_dir = resolved;
    }
  }

  uint8_t *dir_buf = 0;
  uint32_t dir_bytes = 0;
  int ok = (target_dir == 0)
               ? fat12_read_root_dir(&ctx, &dir_buf, &dir_bytes)
               : fat12_read_dir_cluster(&ctx, target_dir, &dir_buf, &dir_bytes);
  if (!ok) {
    fat12_deinit(&ctx);
    return 0;
  }

  uint32_t entries = dir_bytes / 32u;
  for (uint32_t i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08))
      continue;
    if (e->attr == FAT_ATTR_LFN)
      continue;

    int match = 0;
    if (i > 0) {
      char extracted[256];
      if (fat_extract_lfn(dir_buf, i * 32u, extracted, sizeof(extracted)) &&
          kstreq_local(extracted, filename))
        match = 1;
    }
    if (!match) {
      char n83[13];
      fat12_format_name(e->name, n83);
      if (kstreq_local_nocase(n83, filename))
        match = 1;
    }
    if (!match)
      continue;

    if (e->attr & 0x10) { /* directories need rmdir, not rm */
      kfree(dir_buf);
      fat12_deinit(&ctx);
      return 0;
    }

    uint16_t first = e->first_cluster_lo;
    /* Mark any LFN entries ahead of the 8.3 entry as deleted too. */
    uint32_t j = i;
    while (j > 0) {
      struct fat_lfn_dirent *lfn =
          (struct fat_lfn_dirent *)(dir_buf + (j - 1) * 32u);
      if (lfn->attr != FAT_ATTR_LFN)
        break;
      ((struct fat12_dirent *)lfn)->name[0] = 0xE5;
      j--;
    }
    e->name[0] = 0xE5;
    fat12_free_chain(&ctx, first);
    if (target_dir == 0) {
      for (uint16_t s = 0; s < ctx.root_sectors; s++)
        disk_write_sector(ctx.drive, ctx.root_lba + s,
                          dir_buf + (uint32_t)s * 512u);
    } else {
      fat12_write_dir_cluster(&ctx, target_dir, dir_buf, dir_bytes);
    }
    fat12_flush_fat(&ctx);
    kfree(dir_buf);
    fat12_deinit(&ctx);
    return 1;
  }

  kfree(dir_buf);
  fat12_deinit(&ctx);
  return 0;
}

int fat12_rmdir(const char *path) {
  fat12_ctx ctx;
  const char *p;
  const char *filename;
  size_t fn_len;
  uint16_t target_dir;
  uint8_t *dir_buf = 0;
  uint32_t dir_bytes = 0;
  uint32_t entries;
  uint32_t i;

  if (!path)
    return 0;
  p = skip_spaces(path);
  if (*p == '\0' || (*p == '/' && p[1] == '\0') || kstreq(p, ".") ||
      kstreq(p, ".."))
    return 0;

  if (!fat12_init(&ctx))
    return 0;

  filename = p;
  fn_len = kstrlen(p);
  for (size_t n = fn_len; n > 0; n--) {
    if (p[n - 1] == '/') {
      filename = p + n;
      break;
    }
  }
  if (filename[0] == '\0' || kstreq(filename, ".") || kstreq(filename, "..")) {
    fat12_deinit(&ctx);
    return 0;
  }

  target_dir = (*p == '/') ? 0 : fat12_cwd_cluster;
  if (filename != p && filename > p + 1) {
    const char *dir_start = (*p == '/') ? p + 1 : p;
    size_t dir_len = (size_t)((filename - 1) - dir_start);
    if (dir_len > 0 && dir_len < 64) {
      char dir_part[64];
      int dok = 0;
      uint16_t resolved;
      kmemcpy(dir_part, dir_start, dir_len);
      dir_part[dir_len] = '\0';
      resolved = fat12_resolve_dir(&ctx, 0, dir_part, &dok);
      if (!dok) {
        fat12_deinit(&ctx);
        return 0;
      }
      target_dir = resolved;
    }
  }

  if ((target_dir == 0)
          ? !fat12_read_root_dir(&ctx, &dir_buf, &dir_bytes)
          : !fat12_read_dir_cluster(&ctx, target_dir, &dir_buf, &dir_bytes)) {
    fat12_deinit(&ctx);
    return 0;
  }

  entries = dir_bytes / 32u;
  for (i = 0; i < entries; i++) {
    struct fat12_dirent *e = (struct fat12_dirent *)(dir_buf + i * 32u);
    uint16_t first;
    uint8_t *child = 0;
    uint32_t child_bytes = 0;
    uint32_t centries;
    uint32_t ci;
    int empty = 1;
    int match = 0;
    if (e->name[0] == 0x00)
      break;
    if (e->name[0] == 0xE5 || (e->attr & 0x08) || e->attr == FAT_ATTR_LFN)
      continue;
    if (i > 0) {
      char extracted[256];
      if (fat_extract_lfn(dir_buf, i * 32u, extracted, sizeof(extracted)) &&
          kstreq_local(extracted, filename))
        match = 1;
    }
    if (!match) {
      char n83[13];
      fat12_format_name(e->name, n83);
      if (kstreq_local_nocase(n83, filename))
        match = 1;
    }
    if (!match)
      continue;
    if ((e->attr & 0x10) == 0) {
      kfree(dir_buf);
      fat12_deinit(&ctx);
      return 0;
    }

    first = e->first_cluster_lo;
    if (first >= 2) {
      if (!fat12_read_dir_cluster(&ctx, first, &child, &child_bytes)) {
        kfree(dir_buf);
        fat12_deinit(&ctx);
        return 0;
      }
      centries = child_bytes / 32u;
      for (ci = 0; ci < centries; ci++) {
        struct fat12_dirent *ce =
            (struct fat12_dirent *)(child + ci * 32u);
        char n83[13];
        if (ce->name[0] == 0x00)
          break;
        if (ce->name[0] == 0xE5 || (ce->attr & 0x08) ||
            ce->attr == FAT_ATTR_LFN)
          continue;
        fat12_format_name(ce->name, n83);
        if (n83[0] == '.' && n83[1] == '\0')
          continue;
        if (n83[0] == '.' && n83[1] == '.' && n83[2] == '\0')
          continue;
        empty = 0;
        break;
      }
      kfree(child);
    }
    if (!empty) {
      kfree(dir_buf);
      fat12_deinit(&ctx);
      return 0;
    }

    {
      uint32_t j = i;
      while (j > 0) {
        struct fat_lfn_dirent *lfn =
            (struct fat_lfn_dirent *)(dir_buf + (j - 1) * 32u);
        if (lfn->attr != FAT_ATTR_LFN)
          break;
        ((struct fat12_dirent *)lfn)->name[0] = 0xE5;
        j--;
      }
    }
    e->name[0] = 0xE5;
    if (first >= 2)
      fat12_free_chain(&ctx, first);
    if (target_dir == 0) {
      for (uint16_t s = 0; s < ctx.root_sectors; s++)
        disk_write_sector(ctx.drive, ctx.root_lba + s,
                          dir_buf + (uint32_t)s * 512u);
    } else {
      fat12_write_dir_cluster(&ctx, target_dir, dir_buf, dir_bytes);
    }
    fat12_flush_fat(&ctx);
    kfree(dir_buf);
    fat12_deinit(&ctx);
    return 1;
  }

  kfree(dir_buf);
  fat12_deinit(&ctx);
  return 0;
}

void cmd_rm(const char *arg) {
  const char *s = skip_spaces(arg);
  if (*s == '\0') {
    log_writestring("Usage: rm <FILE>\n");
    return;
  }
  if (fat12_delete_file(s)) {
    /* Invalidate any RAM file-slot copy so cat stops serving it. */
    file_slot_drop(s);
    log_writestring("removed: ");
    log_writestring(s);
    log_putchar('\n');
  } else {
    log_writestring("rm: cannot remove '");
    log_writestring(s);
    log_writestring("'\n");
  }
}

void cmd_grep(const char *arg) {
  const char *s = skip_spaces(arg);
  if (*s == '\0') {
    log_writestring("Usage: grep <PATTERN> <FILE>\n");
    return;
  }
  char pat[64];
  int i = 0;
  while (*s && *s != ' ' && i < 63)
    pat[i++] = *s++;
  pat[i] = '\0';
  s = skip_spaces(s);
  if (*s == '\0') {
    log_writestring("Usage: grep <PATTERN> <FILE>\n");
    return;
  }
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(s, &buf, &size)) {
    log_writestring("grep: file not found\n");
    return;
  }
  uint32_t line_start = 0;
  for (uint32_t j = 0; j < size; j++) {
    if (buf[j] == '\n' || j == size - 1) {
      uint32_t line_end = (buf[j] == '\n') ? j : size;
      int match = 0;
      for (uint32_t k = line_start; k < line_end; k++) {
        int m = 1;
        for (int l = 0; pat[l] != '\0'; l++) {
          if ((k + l) >= line_end || (char)buf[k + l] != pat[l]) {
            m = 0;
            break;
          }
        }
        if (m) {
          match = 1;
          break;
        }
      }
      if (match) {
        for (uint32_t k = line_start; k < line_end; k++)
          log_putchar((char)buf[k]);
        log_putchar('\n');
      }
      line_start = j + 1;
    }
  }
  kfree(buf);
}

void cmd_head(const char *arg) {
  const char *s = skip_spaces(arg);
  int num_lines = 10;
  if (kstrcmp_n(s, "-n", 2) == 0) {
    s = skip_spaces(s + 2);
    uint32_t n = 0;
    if (!parse_u32(s, &n) || n == 0) {
      log_writestring("Usage: head [-n <num>] <file>\n");
      return;
    }
    num_lines = (int)n;
    while (*s && *s >= '0' && *s <= '9')
      s++;
    s = skip_spaces(s);
  }
  if (*s == '\0') {
    log_writestring("Usage: head [-n <num>] <file>\n");
    return;
  }
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(s, &buf, &size)) {
    log_writestring("head: file not found\n");
    return;
  }
  int printed = 0;
  for (uint32_t i = 0; i < size && printed < num_lines; i++) {
    log_putchar((char)buf[i]);
    if (buf[i] == '\n')
      printed++;
  }
  kfree(buf);
}

void cmd_tail(const char *arg) {
  const char *s = skip_spaces(arg);
  int num_lines = 10;
  if (kstrcmp_n(s, "-n", 2) == 0) {
    s = skip_spaces(s + 2);
    uint32_t n = 0;
    if (!parse_u32(s, &n) || n == 0) {
      log_writestring("Usage: tail [-n <num>] <file>\n");
      return;
    }
    num_lines = (int)n;
    while (*s && *s >= '0' && *s <= '9')
      s++;
    s = skip_spaces(s);
  }
  if (*s == '\0') {
    log_writestring("Usage: tail [-n <num>] <file>\n");
    return;
  }
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(s, &buf, &size)) {
    log_writestring("tail: file not found\n");
    return;
  }
  int total = 0;
  for (uint32_t i = 0; i < size; i++)
    if (buf[i] == '\n')
      total++;
  if (size > 0 && buf[size - 1] != '\n')
    total++;
  int skip = total - num_lines;
  if (skip < 0)
    skip = 0;
  int skipped = 0;
  uint32_t start = 0;
  if (skip > 0) {
    for (uint32_t i = 0; i < size; i++) {
      if (buf[i] == '\n') {
        skipped++;
        if (skipped == skip) {
          start = i + 1;
          break;
        }
      }
    }
  }
  for (uint32_t i = start; i < size; i++)
    log_putchar((char)buf[i]);
  kfree(buf);
}

void cmd_wc(const char *arg) {
  const char *s = skip_spaces(arg);
  if (*s == '\0') {
    log_writestring("Usage: wc <file>\n");
    return;
  }
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(s, &buf, &size)) {
    log_writestring("wc: file not found\n");
    return;
  }
  uint32_t lines = 0, words = 0, chars = size;
  int in_word = 0;
  for (uint32_t i = 0; i < size; i++) {
    char c = (char)buf[i];
    if (c == '\n')
      lines++;
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      if (in_word) {
        words++;
        in_word = 0;
      }
    } else
      in_word = 1;
  }
  if (in_word)
    words++;
  log_write_u32(lines);
  log_putchar(' ');
  log_write_u32(words);
  log_putchar(' ');
  log_write_u32(chars);
  log_putchar(' ');
  log_writestring(s);
  log_putchar('\n');
  kfree(buf);
}

void cmd_hexdump(const char *args) {
  const char *p = skip_spaces(args);
  if (*p == '\0') {
    log_writestring("Usage: hexdump <FILE> [max_bytes]\n");
    return;
  }
  char file[64];
  int fi = 0;
  while (*p && *p != ' ' && fi < 63)
    file[fi++] = *p++;
  file[fi] = '\0';
  uint32_t max_bytes = 256, v = 0;
  if (parse_u32(p, &v) && v > 0)
    max_bytes = v;
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(file, &buf, &size)) {
    log_writestring("hexdump: not found\n");
    return;
  }
  uint32_t n = size < max_bytes ? size : max_bytes;
  for (uint32_t off = 0; off < n; off += 16u) {
    log_write_hex32(off);
    log_writestring(": ");
    for (uint32_t i = 0; i < 16u; i++) {
      if (off + i < n)
        log_write_hex8(buf[off + i]);
      else
        log_writestring("  ");
      log_putchar(' ');
    }
    log_writestring(" |");
    for (uint32_t i = 0; i < 16u; i++) {
      if (off + i < n) {
        uint8_t c = buf[off + i];
        log_putchar((c >= 0x20 && c <= 0x7E) ? (char)c : '.');
      } else
        log_putchar(' ');
    }
    log_writestring("|\n");
  }
  kfree(buf);
}

void cmd_strings(const char *args) {
  const char *p = skip_spaces(args);
  if (*p == '\0') {
    log_writestring("Usage: strings <FILE> [min_len]\n");
    return;
  }
  char file[64];
  int fi = 0;
  while (*p && *p != ' ' && fi < 63)
    file[fi++] = *p++;
  file[fi] = '\0';
  uint32_t min_len = 4, v = 0;
  if (parse_u32(p, &v) && v >= 1 && v <= 64)
    min_len = v;
  uint8_t *buf = 0;
  uint32_t size = 0;
  if (!fat12_read_file_to_ram(file, &buf, &size)) {
    log_writestring("strings: not found\n");
    return;
  }
  uint32_t run_len = 0, start = 0;
  for (uint32_t i = 0; i <= size; i++) {
    uint8_t c = (i < size) ? buf[i] : 0;
    if (c >= 0x20 && c <= 0x7E) {
      if (run_len == 0)
        start = i;
      run_len++;
    } else {
      if (run_len >= min_len) {
        for (uint32_t j = 0; j < run_len; j++)
          log_putchar((char)buf[start + j]);
        log_putchar('\n');
      }
      run_len = 0;
    }
  }
  kfree(buf);
}

void cmd_files(void) {
  log_writestring("RAM File Slots:\n");
  for (int i = 0; i < FILE_SLOTS; i++) {
    if (file_slots[i].ptr) {
      log_write_u32((uint32_t)i);
      log_writestring(": ");
      log_writestring(file_slots[i].name);
      log_writestring(" (");
      log_write_u32(file_slots[i].size);
      log_writestring(" bytes)\n");
    }
  }
}

void cmd_freeram(const char *arg) {
  const char *s = skip_spaces(arg);
  if (*s == '\0') {
    log_writestring("Usage: freeram <SLOT_NAME>\n");
    return;
  }
  for (int i = 0; i < FILE_SLOTS; i++) {
    if (file_slots[i].ptr && kstreq(s, file_slots[i].name)) {
      kfree(file_slots[i].ptr);
      file_slots[i].ptr = 0;
      file_slots[i].size = 0;
      file_slots[i].name[0] = '\0';
      log_writestring("Freed slot: ");
      log_writestring(s);
      log_putchar('\n');
      return;
    }
  }
  log_writestring("Slot not found: ");
  log_writestring(s);
  log_putchar('\n');
}

void cmd_mkdir(const char *args) {
  const char *p = skip_spaces(args);
  if (*p == '\0') {
    log_writestring("Usage: mkdir <DIR>\n");
    return;
  }
  if (!fat12_mkdir(p)) {
    log_writestring("mkdir: failed\n");
  }
}
