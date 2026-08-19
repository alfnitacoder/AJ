#include "disk.h"
#include "ata.h"
#include "debug_agent.h"
#include "e1000.h"
#include "kernel.h"
#include "ssh.h"
#include <stddef.h>
#include <stdint.h>

// Disable BIOS INT 13h calls by default - they crash on Proxmox and other KVM
// hypervisors due to the protected mode <-> real mode switching in the
// trampoline. Bootloader pre-loads 632 sectors (FAT/root). Model needs more.
#ifndef AJOS_NO_BIOS_DISK
#define AJOS_NO_BIOS_DISK 0
/* Per-I/O trace logs (rd_probe, rd_hit_cache, wr_probe, cache_write, ...).
 * Set to 1 to re-enable sector-level disk debugging on the console. */
#define DISK_TRACE_LOG 0
#endif

#define DISK_CACHE_BASE ((uint8_t *)0x51000u)
#define DISK_BOUNCE_PHYS 0x7F000u
#define CACHE_REFRESH_ROOT_START 520
#define CACHE_REFRESH_ROOT_END 541
#define ROOT_SNAPSHOT_SECTORS 14u

static uint8_t *disk_bounce = (uint8_t *)DISK_BOUNCE_PHYS;
/* Floppy root snapshot taken at disk_init so listing is never corrupted by
 * later overwrites. */
static uint8_t floppy_root_snapshot[ROOT_SNAPSHOT_SECTORS * SECTOR_SIZE];
static uint32_t floppy_root_snapshot_lba = 0;
static uint32_t floppy_root_snapshot_bytes = 0;
/* Bitmap: already did all-zero re-read for this LBA (stops BIOS read storm) */
static uint32_t cache_refreshed_bits;
static int verbose_disk_log = 0;
/* When boot is floppy: root LBA range; read root from BIOS every time (bypass
 * cache). */
static uint32_t root_lba_start = 0;
static uint32_t root_lba_end = 0;
static int ata_available = 0; // Flag to track if ATA is available
static int bios_disk_disabled = AJOS_NO_BIOS_DISK; // Runtime flag

volatile uint16_t ramdisk_sectors = 0;
uint8_t ramdisk_drive = 0x01;

// Extern BIOS thunks (kept for floppy/legacy fallback only)
extern uint32_t bios_int13_read_chs(uint32_t drive, uint32_t cyl, uint32_t head,
                                    uint32_t sect, uint32_t seg, uint32_t off);
extern uint32_t bios_int13_write_chs(uint32_t drive, uint32_t cyl,
                                     uint32_t head, uint32_t sect, uint32_t seg,
                                     uint32_t off);

void lba_to_chs(uint32_t lba, uint16_t *cyl, uint8_t *head, uint8_t *sect) {
  *cyl = (uint16_t)(lba / (2 * 18));
  *head = (uint8_t)((lba / 18) % 2);
  *sect = (uint8_t)((lba % 18) + 1);
}

// BIOS fallback (only used for floppy drives or when ATA is unavailable)
int bios_read_sector_lba(uint8_t drive, uint32_t lba, uint8_t *dst512) {
  // Check if BIOS disk access is disabled (Proxmox/KVM compatibility)
  if (bios_disk_disabled) {
    // BIOS INT 13h calls crash on Proxmox due to PM<->RM switching issues
    // Return failure - caller should use cached data or ATA
    return 0;
  }

  // Only use BIOS for floppy drives (0x00, 0x01) or if ATA is not available
  if (drive >= 0x80 && ata_available) {
    // Should have used ATA, this is a fallback that shouldn't happen
    log_writestring("[DISK] WARNING: BIOS fallback called for hard disk with "
                    "ATA available\n");
  }

  uint16_t cyl = 0;
  uint8_t head = 0;
  uint8_t sect = 0;
  lba_to_chs(lba, &cyl, &head, &sect);
  uint16_t seg = (uint16_t)(DISK_BOUNCE_PHYS >> 4);
  uint16_t off = (uint16_t)(DISK_BOUNCE_PHYS & 0x0F);

  if (verbose_disk_log) {
    log_writestring("[DISK] BIOS fallback read LBA ");
    log_write_u32(lba);
    log_writestring("\n");
  }

  // Disable E1000 interrupts during BIOS call to prevent storms/crashes
  e1000_disable_interrupts();

  uint32_t rc =
      bios_int13_read_chs((uint32_t)drive, (uint32_t)cyl, (uint32_t)head,
                          (uint32_t)sect, (uint32_t)seg, (uint32_t)off);

  e1000_enable_interrupts();

  uint8_t status = (uint8_t)(rc >> 8);
  if (status != 0) {
    if (verbose_disk_log) {
      log_writestring("[DISK] Int13 failed code: ");
      log_write_u32(status);
      log_putchar('\n');
    }
    return 0;
  }
  mem_copy(dst512, disk_bounce, SECTOR_SIZE);
  return 1;
}

// BIOS fallback (only used for floppy drives or when ATA is unavailable)
int bios_write_sector_lba(uint8_t drive, uint32_t lba, const uint8_t *src512) {
  // Check if BIOS disk access is disabled (Proxmox/KVM compatibility)
  if (bios_disk_disabled) {
    // BIOS INT 13h calls crash on Proxmox due to PM<->RM switching issues
    // Return failure - caller should use ATA or skip write
    return 0;
  }

  // Only use BIOS for floppy drives (0x00, 0x01) or if ATA is not available
  if (drive >= 0x80 && ata_available) {
    // Should have used ATA, this is a fallback that shouldn't happen
    log_writestring("[DISK] WARNING: BIOS fallback called for hard disk with "
                    "ATA available\n");
  }

  uint16_t cyl = 0;
  uint8_t head = 0;
  uint8_t sect = 0;
  lba_to_chs(lba, &cyl, &head, &sect);
  mem_copy(disk_bounce, (uint8_t *)src512, SECTOR_SIZE);
  uint16_t seg = (uint16_t)(DISK_BOUNCE_PHYS >> 4);
  uint16_t off = (uint16_t)(DISK_BOUNCE_PHYS & 0x0F);

  if (verbose_disk_log) {
    log_writestring("[DISK] BIOS fallback write LBA ");
    log_write_u32(lba);
    log_writestring("\n");
  }

  // Same as read path: E1000 (or other) IRQs during the real-mode INT 13h
  // trampoline use the wrong IDT and triple-fault — QEMU then reboots back
  // to the login prompt (seen as "touch logs me out").
  e1000_disable_interrupts();

  uint32_t rc =
      bios_int13_write_chs((uint32_t)drive, (uint32_t)cyl, (uint32_t)head,
                           (uint32_t)sect, (uint32_t)seg, (uint32_t)off);

  e1000_enable_interrupts();

  return (uint8_t)(rc >> 8) == 0;
}

void disk_init(uint8_t boot_drive, uint16_t ram_sectors) {
  ramdisk_drive = boot_drive;
  ramdisk_sectors = ram_sectors;

  // Log BIOS disk status
  if (bios_disk_disabled) {
    log_writestring("[DISK] BIOS INT 13h disabled (Proxmox/KVM mode)\n");
  }

  // Try to detect ATA devices
  if (ata_detect_all_devices()) {
    ata_available = 1;
    ata_device_t *dev = ata_get_active_device();
    if (dev) {
      // IMPORTANT:
      // - If we booted from a hard disk (drive >= 0x80), prefer ATA for disk
      // IO.
      // - If we booted from a floppy (drive < 0x80), keep using the boot drive
      //   (bootloader cache / BIOS fallback) so filesystem_init reads the OS
      //   image from the correct device.
      if (boot_drive >= 0x80) {
        log_writestring(
            "[DISK] ATA device detected. Using ATA as primary backend.\n");
        ramdisk_drive = 0x80; // Use hard disk drive number
        // Use ATA sector count for the boot disk
        if (dev->sector_count > 0 && dev->sector_count < 0x0FFFFFFF) {
          ramdisk_sectors =
              (uint16_t)(dev->sector_count < 65535 ? dev->sector_count : 65535);
          log_writestring("[DISK] ATA device reports ");
          log_write_u32(dev->sector_count);
          log_writestring(" sectors\n");
        } else if (ramdisk_sectors < 65535) {
          ramdisk_sectors = 65535;
        }
      } else {
        log_writestring(
            "[DISK] ATA device detected, but boot drive is floppy. "
            "Keeping boot drive and sector count from bootloader.\n");
        // Do NOT overwrite ramdisk_sectors - keep bootloader's value
        // so we use the correct layout for the floppy (OS image).
      }
    }
  } else {
    ata_available = 0;
    if (bios_disk_disabled) {
      log_writestring("[DISK] No ATA devices. Using bootloader cache only.\n");
    } else {
      log_writestring("[DISK] No ATA devices found. Using BIOS fallback.\n");
    }
  }

  /* When boot drive is floppy, remember root LBA range. Root is read from
   * bootloader cache only; do NOT refresh from BIOS here or we overwrite good
   * cache with bad BIOS data (e.g. truncated root → only PASSWD visible). */
  if (ramdisk_drive < 0x80u && ramdisk_sectors >= 14u) {
    uint32_t root_lba;
    uint32_t root_sectors = 14u;
    uint16_t reserved = *(uint16_t *)(DISK_CACHE_BASE + 14);
    if (reserved != 0u && reserved <= 600u)
      root_lba = (uint32_t)reserved + 18u;
    else {
      /* BPB invalid: scan cache for root dir (FAT root has multiple dir entries
       * per sector). */
      uint32_t best_lba = 534u; /* fallback when scan finds nothing (typical
                                   root_lba for ~260KB kernel) */
      unsigned best_n = 0;
      for (uint32_t lba = 528u; lba <= 542u && lba < DISK_CACHE_SECTORS;
           lba++) {
        const uint8_t *sec = DISK_CACHE_BASE + lba * SECTOR_SIZE;
        unsigned n = 0;
        for (unsigned i = 0; i < 16u; i++) {
          if (sec[i * 32u] == 0u)
            break;
          if (sec[i * 32u] != 0xE5u)
            n++;
        }
        if (n > best_n) {
          best_n = n;
          best_lba = lba;
        }
      }
      /* If cache appears empty, use later LBA so we don't snapshot zeros. */
      root_lba = (best_n > 0u) ? best_lba : 534u;
    }
    if (root_lba + root_sectors <= (uint32_t)ramdisk_sectors &&
        root_lba + root_sectors <= DISK_CACHE_SECTORS) {
      root_lba_start = root_lba;
      root_lba_end = root_lba + root_sectors;
      /* Snapshot root now so later overwrites of cache never affect listing. */
      {
        uint32_t n = root_sectors < ROOT_SNAPSHOT_SECTORS
                         ? root_sectors
                         : ROOT_SNAPSHOT_SECTORS;
        uint32_t i;
        for (i = 0; i < n; i++)
          mem_copy(floppy_root_snapshot + (uint32_t)i * SECTOR_SIZE,
                   DISK_CACHE_BASE + (root_lba + i) * SECTOR_SIZE, SECTOR_SIZE);
        floppy_root_snapshot_lba = root_lba;
        floppy_root_snapshot_bytes = n * SECTOR_SIZE;
        log_writestring("[DISK] floppy root snapshot taken, first byte=");
        log_write_u32((uint32_t)floppy_root_snapshot[0]);
        log_writestring("\n");
      }
      log_writestring("[DISK] floppy root from cache LBA ");
      log_write_u32(root_lba_start);
      log_writestring("-");
      log_write_u32(root_lba_end - 1);
      log_writestring(" (reserved=");
      log_write_u32((uint32_t)reserved);
      log_writestring(")\n");
    }
  }
}

uint32_t disk_floppy_root_lba(void) {
  if (ramdisk_drive >= 0x80u || ramdisk_sectors < 14u)
    return 0;
  uint16_t reserved = *(uint16_t *)(DISK_CACHE_BASE + 14);
  if (reserved != 0u && reserved <= 600u)
    return (uint32_t)reserved + 18u;
  /* Use snapshot LBA if we took one at init (BPB was invalid but we scanned
   * cache). */
  if (floppy_root_snapshot_bytes != 0u)
    return floppy_root_snapshot_lba;
  return 532u;
}

void disk_read_cache_region(uint32_t lba_offset, uint8_t *dst,
                            uint32_t num_bytes) {
  if (lba_offset >= DISK_CACHE_SECTORS ||
      num_bytes > (DISK_CACHE_SECTORS - lba_offset) * SECTOR_SIZE)
    return;
  mem_copy(dst, DISK_CACHE_BASE + lba_offset * SECTOR_SIZE, num_bytes);
}

int disk_get_floppy_root_snapshot(uint32_t *out_lba, const uint8_t **out_buf,
                                  uint32_t *out_bytes) {
  if (floppy_root_snapshot_bytes == 0u)
    return 0;
  *out_lba = floppy_root_snapshot_lba;
  *out_buf = floppy_root_snapshot;
  *out_bytes = floppy_root_snapshot_bytes;
  return 1;
}

void disk_refresh_root_from_boot(uint32_t root_lba, uint32_t root_sectors) {
  if (ramdisk_drive >= 0x80u || ramdisk_sectors == 0 || bios_disk_disabled)
    return;
  if (root_sectors == 0 || root_lba + root_sectors > (uint32_t)ramdisk_sectors)
    return;
  for (uint32_t i = 0; i < root_sectors && (root_lba + i) < DISK_CACHE_SECTORS;
       i++) {
    uint32_t lba = root_lba + i;
    if (bios_read_sector_lba(ramdisk_drive, lba, disk_bounce)) {
      uint8_t *cache_ptr = DISK_CACHE_BASE + lba * SECTOR_SIZE;
      mem_copy(cache_ptr, disk_bounce, SECTOR_SIZE);
    }
  }
}

int disk_read_sector(uint8_t drive, uint32_t lba, uint8_t *dst512) {
  // Sector count check (if known)
  // For floppy (0x00), we use the bootloader's ramdisk_sectors
  // For hard disks (0x80+), we ideally use the count from ATA IDENTIFY
  if (drive < 0x80 && ramdisk_sectors > 0 && lba >= (uint32_t)ramdisk_sectors)
    return 0;

  // #region agent log
#if DISK_TRACE_LOG
  static uint8_t disk_rd_probe_n;
  if (lba >= 550u && lba <= 560u && disk_rd_probe_n < 12u &&
      !ssh_shell_log_sink_active()) {
    disk_rd_probe_n++;
    log_writestring("[DISK] rd_probe drive=");
    log_write_hex8(drive);
    log_writestring(" ramdisk=");
    log_write_hex8(ramdisk_drive);
    log_writestring(" lba=");
    log_write_u32(lba);
    log_putchar('\n');
  }
#endif
  // #endregion

  // When boot is floppy and we're reading from it, check the root
  // snapshot/cache
  if (drive == ramdisk_drive && drive < 0x80u && root_lba_end != 0u &&
      lba >= root_lba_start && lba < root_lba_end && lba < DISK_CACHE_SECTORS) {
    uint8_t *cache_ptr = DISK_CACHE_BASE + lba * SECTOR_SIZE;
    mem_copy(dst512, cache_ptr, SECTOR_SIZE);
    // #region agent log
#if DISK_TRACE_LOG
    if (lba >= 550u && lba <= 580u && dst512[288] == 0x54u) {
      log_writestring("[DISK] rd_hit_rootrange lba=");
      log_write_u32(lba);
      log_writestring(" b288=");
      log_write_hex8(dst512[288]);
      log_putchar('\n');
    }
#endif
    // #endregion
    return 1;
  }

  // Floppy cache check (only apply to the boot floppy)
  if (drive == ramdisk_drive && drive < 0x80u && lba < DISK_CACHE_SECTORS) {
    uint8_t *cache_ptr = DISK_CACHE_BASE + lba * SECTOR_SIZE;
    mem_copy(dst512, cache_ptr, SECTOR_SIZE);
    // #region agent log
#if DISK_TRACE_LOG
    if (lba >= 550u && lba <= 580u && dst512[288] == 0x54u) {
      log_writestring("[DISK] rd_hit_cache lba=");
      log_write_u32(lba);
      log_writestring(" b288=");
      log_write_hex8(dst512[288]);
      log_putchar('\n');
    }
#endif
    // #endregion

    // Check if cached sector is all zeros (potential uninitialized cache)
    int all_zero = 1;
    for (int i = 0; i < 16; i++) { // Heuristic: just check start
      if (dst512[i] != 0) {
        all_zero = 0;
        break;
      }
    }

    if (all_zero && (lba == 0 || (lba >= CACHE_REFRESH_ROOT_START &&
                                  lba <= CACHE_REFRESH_ROOT_END))) {
      if (bios_read_sector_lba(drive, lba, dst512)) {
        mem_copy(cache_ptr, dst512, SECTOR_SIZE);
        return 1;
      }
    }
    return 1;
  }

  // ATA routing for hard disks
  if (ata_available && drive >= 0x80) {
    // Current ata.c only supports one "active" device.
    // Ideally we'd set the active device based on the drive ID (0x80 = master,
    // 0x81 = slave etc) For now, QEMU maps our model drive as primary master
    // (0x80).
    if (ata_read_sector(lba, dst512)) {
      return 1;
    }
  }

  // BIOS fallback
  return bios_read_sector_lba(drive, lba, dst512);
}

int ramdisk_read_sector_lba(uint32_t lba, uint8_t *dst512) {
  return disk_read_sector(ramdisk_drive, lba, dst512);
}

int ramdisk_write_sector_lba(uint32_t lba, const uint8_t *src512) {
  return disk_write_sector(ramdisk_drive, lba, src512);
}

int disk_write_sector(uint8_t drive, uint32_t lba, const uint8_t *src512) {
  int success = 0;

  // #region agent log
#if DISK_TRACE_LOG
  if (lba >= 550u && lba <= 560u) {
    static uint8_t disk_wr_src_probe_n;
    if (disk_wr_src_probe_n < 6u) {
      disk_wr_src_probe_n++;
      log_writestring("[DISK] wr_src_pre lba=");
      log_write_u32(lba);
      log_writestring(" drive=");
      log_write_hex8(drive);
      log_writestring(" src0=");
      log_write_hex8(src512[0]);
      log_writestring(" src288=");
      log_write_hex8(src512[288]);
      log_putchar('\n');
    }
  }
#endif
  // #endregion

  if (ata_available && drive >= 0x80) {
    success = ata_write_sector(lba, src512);
  } else {
    success = bios_write_sector_lba(drive, lba, src512);
  }

  // #region agent log
#if DISK_TRACE_LOG
  if (lba >= 550u && lba <= 560u) {
    static uint8_t disk_wr_probe_n;
    if (disk_wr_probe_n < 12u) {
      disk_wr_probe_n++;
      log_writestring("[DISK] wr_probe drive=");
      log_write_hex8(drive);
      log_writestring(" ramdisk=");
      log_write_hex8(ramdisk_drive);
      log_writestring(" lba=");
      log_write_u32(lba);
      log_writestring(" success=");
      log_write_hex8((uint8_t)success);
      log_writestring(" src0=");
      log_write_hex8(src512[0]);
      log_writestring(" src288=");
      log_write_hex8(src512[288]);
      log_putchar('\n');
    }
  }

  if (!success && drive == ramdisk_drive && drive < 0x80u &&
      lba < DISK_CACHE_SECTORS) {
    static uint8_t disk_wr_fail_log_n;
    if (disk_wr_fail_log_n < 5u) {
      disk_wr_fail_log_n++;
      agent_dbg_evt("C", "disk.c:disk_write_sector", "bio_wr_fail",
                    (uint32_t)lba, (uint32_t)(unsigned char)src512[0]);
    }
  }
#endif
  // #endregion

  /* Floppy reads use DISK_CACHE_BASE (see disk_read_sector). If the BIOS write
   * fails or is a no-op in QEMU, we still mirror into RAM so ls/cat match
   * touch/redir within the same boot session. */
  if (drive == ramdisk_drive && drive < 0x80u && lba < DISK_CACHE_SECTORS) {
    uint8_t *cache_ptr = DISK_CACHE_BASE + lba * SECTOR_SIZE;
    mem_copy(cache_ptr, src512, SECTOR_SIZE);

    // #region agent log
#if DISK_TRACE_LOG
    static uint8_t root_cache_sample_n;
    if (lba >= 550u && lba <= 560u && root_cache_sample_n < 20u) {
      root_cache_sample_n++;
      // Plain-text probe: source byte at offset 288 and cached byte at 288.
      // Also log cached attr byte (name[0] offset 288, attr at +11 => 299).
      log_writestring("[DISK] cache_write lba=");
      log_write_u32(lba);
      log_writestring(" b288_src=");
      log_write_hex8(src512[288]);
      log_writestring(" b288_cache=");
      log_write_hex8(cache_ptr[288]);
      log_writestring(" a299_cache=");
      log_write_hex8(cache_ptr[299]);
      log_putchar('\n');
    }

    if (lba >= 550u && lba <= 580u && src512[288] == 0x54u) {
      log_writestring("[DISK] wr_touch_mirror lba=");
      log_write_u32(lba);
      log_writestring(" success=");
      log_write_hex8((uint8_t)success);
      log_writestring(" src288=");
      log_write_hex8(src512[288]);
      log_writestring(" cache288=");
      log_write_hex8(cache_ptr[288]);
      log_writestring(" cache299=");
      log_write_hex8(cache_ptr[299]);
      log_putchar('\n');
    }
#endif
    // #endregion
  }
  return success;
}
