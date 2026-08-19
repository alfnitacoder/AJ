#include "fatent_ops.h"
#include "fat.h"
#include <stdint.h>

// FAT12 entry operations implementation

static uint32_t fat12_ops_get_entry(const void *fat_data, uint32_t cluster) {
  const uint8_t *fat = (const uint8_t *)fat_data;
  uint32_t offset = cluster + (cluster / 2u);
  uint16_t v;
  if (cluster & 1u)
    v = (uint16_t)(((uint16_t)fat[offset] >> 4) |
                   ((uint16_t)fat[offset + 1] << 4));
  else
    v = (uint16_t)((uint16_t)fat[offset] |
                   (((uint16_t)fat[offset + 1] & 0x0F) << 8));
  return (uint32_t)(v & 0x0FFF);
}

static void fat12_ops_set_entry(void *fat_data, uint32_t cluster, uint32_t value) {
  uint8_t *fat = (uint8_t *)fat_data;
  uint32_t offset = cluster + (cluster / 2u);
  if (cluster & 1u) {
    fat[offset] = (uint8_t)((fat[offset] & 0x0F) | ((value & 0x0F) << 4));
    fat[offset + 1] = (uint8_t)(((value >> 4) & 0xFF));
  } else {
    fat[offset] = (uint8_t)(value & 0xFF);
    fat[offset + 1] =
        (uint8_t)((fat[offset + 1] & 0xF0) | ((value >> 8) & 0x0F));
  }
}

static uint32_t fat12_ops_find_free(const void *fat_data, uint32_t start_cluster) {
  const uint8_t *fat = (const uint8_t *)fat_data;
  // FAT12 typically has max 2880 clusters (for 1.44MB floppy)
  // But we'll search up to a reasonable limit
  for (uint32_t i = (start_cluster >= 2) ? start_cluster : 2; i < 2880u; i++) {
    if (fat12_ops_get_entry(fat_data, i) == 0)
      return i;
  }
  return 0xFFFFFFFF;  // Not found
}

static int fat12_ops_is_eof(uint32_t value) {
  return (value >= 0xFF8 && value <= 0xFFF);
}

static int fat12_ops_is_bad(uint32_t value) {
  return (value == 0xFF7);
}

static uint32_t fat12_ops_eof_marker(void) {
  return 0xFFF;  // FAT12 EOF marker
}

static uint32_t fat12_ops_bad_marker(void) {
  return 0xFF7;  // FAT12 bad cluster marker
}

static uint32_t fat12_ops_entry_size(void) {
  return 12;  // 12 bits per entry (1.5 bytes)
}

static uint32_t fat12_ops_entry_count(const void *fs_ctx) {
  // For FAT12, we need the BPB to determine cluster count
  // This is a placeholder - actual implementation should use fs_ctx
  return 2880;  // Typical for 1.44MB floppy
}

// FAT12 operations structure
const fatent_ops_t fat12_ops = {
  .get_entry = fat12_ops_get_entry,
  .set_entry = fat12_ops_set_entry,
  .find_free = fat12_ops_find_free,
  .is_eof = fat12_ops_is_eof,
  .is_bad = fat12_ops_is_bad,
  .eof_marker = fat12_ops_eof_marker,
  .bad_marker = fat12_ops_bad_marker,
  .entry_size = fat12_ops_entry_size,
  .entry_count = fat12_ops_entry_count,
};

// FAT16 operations (stub - to be implemented)
static uint32_t fat16_ops_get_entry(const void *fat_data, uint32_t cluster) {
  const uint16_t *fat = (const uint16_t *)fat_data;
  return (uint32_t)fat[cluster];
}

static void fat16_ops_set_entry(void *fat_data, uint32_t cluster, uint32_t value) {
  uint16_t *fat = (uint16_t *)fat_data;
  fat[cluster] = (uint16_t)value;
}

static uint32_t fat16_ops_find_free(const void *fat_data, uint32_t start_cluster) {
  const uint16_t *fat = (const uint16_t *)fat_data;
  // FAT16 can have up to 65525 clusters
  for (uint32_t i = (start_cluster >= 2) ? start_cluster : 2; i < 65525u; i++) {
    if (fat[i] == 0)
      return i;
  }
  return 0xFFFFFFFF;
}

static int fat16_ops_is_eof(uint32_t value) {
  return (value >= 0xFFF8 && value <= 0xFFFF);
}

static int fat16_ops_is_bad(uint32_t value) {
  return (value == 0xFFF7);
}

static uint32_t fat16_ops_eof_marker(void) {
  return 0xFFFF;  // FAT16 EOF marker
}

static uint32_t fat16_ops_bad_marker(void) {
  return 0xFFF7;  // FAT16 bad cluster marker
}

static uint32_t fat16_ops_entry_size(void) {
  return 16;  // 16 bits (2 bytes) per entry
}

static uint32_t fat16_ops_entry_count(const void *fs_ctx) {
  // Placeholder - should use BPB from fs_ctx
  return 65525;  // Max for FAT16
}

const fatent_ops_t fat16_ops = {
  .get_entry = fat16_ops_get_entry,
  .set_entry = fat16_ops_set_entry,
  .find_free = fat16_ops_find_free,
  .is_eof = fat16_ops_is_eof,
  .is_bad = fat16_ops_is_bad,
  .eof_marker = fat16_ops_eof_marker,
  .bad_marker = fat16_ops_bad_marker,
  .entry_size = fat16_ops_entry_size,
  .entry_count = fat16_ops_entry_count,
};
