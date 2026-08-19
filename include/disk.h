#ifndef DISK_H
#define DISK_H

#include <stdint.h>

#define SECTOR_SIZE 512u
/* Bootloader cache at 0x51000 must stay below VGA at 0xA0000:
 * (0xA0000-0x51000)/512 = 632. Root often starts ~LBA 560–580 with 32
 * sectors — 600 left the last root sectors on the slow BIOS path. */
#define DISK_CACHE_SECTORS 632

extern volatile uint16_t ramdisk_sectors;
extern uint8_t ramdisk_drive;

void disk_init(uint8_t boot_drive, uint16_t ram_sectors);
extern volatile uint16_t ramdisk_sectors;
extern uint8_t boot_drive;
extern uint8_t ramdisk_drive;

int ramdisk_read_sector_lba(uint32_t lba, uint8_t *dst512);
int ramdisk_write_sector_lba(uint32_t lba, const uint8_t *src512);
int disk_read_sector(uint8_t drive, uint32_t lba, uint8_t *dst512);
int disk_write_sector(uint8_t drive, uint32_t lba, const uint8_t *src512);

/** Re-read root directory sectors from boot drive into cache (floppy only). */
void disk_refresh_root_from_boot(uint32_t root_lba, uint32_t root_sectors);

/** When boot is floppy: root LBA from cache BPB (0 if not floppy or invalid).
 */
uint32_t disk_floppy_root_lba(void);

/** Read directly from bootloader cache at DISK_CACHE_BASE (0x51000). num_bytes
 * multiple of 512. */
void disk_read_cache_region(uint32_t lba_offset, uint8_t *dst,
                            uint32_t num_bytes);

/** If floppy root was snapshotted at disk_init, return it (read-only). Caller
 * must not free. */
int disk_get_floppy_root_snapshot(uint32_t *out_lba, const uint8_t **out_buf,
                                  uint32_t *out_bytes);

#endif
