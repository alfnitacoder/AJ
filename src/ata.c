#include "ata.h"
#include "io.h"
#include "kernel.h"

// Maximum number of ATA devices we can detect
#define MAX_ATA_DEVICES 4

static ata_device_t ata_devices[MAX_ATA_DEVICES];
static int ata_device_count = 0;
static ata_device_t *active_device = NULL;

// Wait for status register to match mask/value
static int ata_wait_status_device(ata_device_t *dev, uint8_t mask, uint8_t value, uint32_t timeout) {
  uint32_t count = 0;
  while ((inb(dev->status_port) & mask) != value) {
    if (timeout && ++count > timeout) {
      return 0;
    }
    for (int i = 0; i < 10; i++)
      io_wait();
  }
  return 1;
}

// Probe a specific ATA device
static int ata_probe_device(int is_primary, int is_master) {
  ata_device_t *dev = &ata_devices[ata_device_count];
  
  // Initialize device structure
  dev->is_primary = is_primary;
  dev->is_master = is_master;
  dev->exists = 0;
  
  if (is_primary) {
    dev->data_port = ATA_PRIMARY_DATA;
    dev->error_port = ATA_PRIMARY_ERR;
    dev->features_port = ATA_PRIMARY_FEATURES;
    dev->sec_count_port = ATA_PRIMARY_SEC_COUNT;
    dev->lba_lo_port = ATA_PRIMARY_LBA_LO;
    dev->lba_mid_port = ATA_PRIMARY_LBA_MID;
    dev->lba_hi_port = ATA_PRIMARY_LBA_HI;
    dev->drive_sel_port = ATA_PRIMARY_DRIVE_SEL;
    dev->command_port = ATA_PRIMARY_COMMAND;
    dev->status_port = ATA_PRIMARY_STATUS;
    dev->control_port = ATA_PRIMARY_CONTROL;
  } else {
    dev->data_port = ATA_SECONDARY_DATA;
    dev->error_port = ATA_SECONDARY_ERR;
    dev->features_port = ATA_SECONDARY_FEATURES;
    dev->sec_count_port = ATA_SECONDARY_SEC_COUNT;
    dev->lba_lo_port = ATA_SECONDARY_LBA_LO;
    dev->lba_mid_port = ATA_SECONDARY_LBA_MID;
    dev->lba_hi_port = ATA_SECONDARY_LBA_HI;
    dev->drive_sel_port = ATA_SECONDARY_DRIVE_SEL;
    dev->command_port = ATA_SECONDARY_COMMAND;
    dev->status_port = ATA_SECONDARY_STATUS;
    dev->control_port = ATA_SECONDARY_CONTROL;
  }
  
  dev->drive_sel_value = is_master ? ATA_DRIVE_MASTER : ATA_DRIVE_SLAVE;
  
  // Disable interrupts (nIEN = 1)
  outb(dev->control_port, 0x02);
  io_wait();
  
  // Select the drive
  outb(dev->drive_sel_port, dev->drive_sel_value);
  for (int i = 0; i < 15; i++)
    io_wait();
  
  // Check if bus exists (status != 0xFF)
  uint8_t status = inb(dev->status_port);
  if (status == 0xFF) {
    return 0;  // No bus
  }
  
  // Send IDENTIFY command
  outb(dev->command_port, ATA_CMD_IDENTIFY);
  for (int i = 0; i < 15; i++)
    io_wait();
  
  status = inb(dev->status_port);
  if (status == 0) {
    return 0;  // No drive
  }
  
  // Wait for BSY to clear
  if (!ata_wait_status_device(dev, ATA_STATUS_BSY, 0, 100000)) {
    return 0;  // Timeout
  }
  
  status = inb(dev->status_port);
  if (status & ATA_STATUS_ERR) {
    return 0;  // Error
  }
  
  // Check if DRQ is set (data ready)
  if (status & ATA_STATUS_DRQ) {
    // Read IDENTIFY data
    uint16_t identify[256];
    for (int i = 0; i < 256; i++)
      identify[i] = inw(dev->data_port);
    
    // Extract sector count from IDENTIFY data (words 60-61)
    dev->sector_count = (uint32_t)identify[60] | ((uint32_t)identify[61] << 16);
    
    dev->exists = 1;
    return 1;
  }
  
  return 0;
}

// Detect all ATA devices
int ata_detect_all_devices(void) {
  ata_device_count = 0;
  active_device = NULL;
  
  log_writestring("[ATA] Detecting ATA devices...\n");
  
  // Probe Primary Master
  if (ata_probe_device(1, 1)) {
    log_writestring("[ATA] Primary Master detected\n");
    ata_device_count++;
    if (!active_device)
      active_device = &ata_devices[ata_device_count - 1];
  }
  
  // Probe Primary Slave
  if (ata_probe_device(1, 0)) {
    log_writestring("[ATA] Primary Slave detected\n");
    ata_device_count++;
    if (!active_device)
      active_device = &ata_devices[ata_device_count - 1];
  }
  
  // Probe Secondary Master
  if (ata_probe_device(0, 1)) {
    log_writestring("[ATA] Secondary Master detected\n");
    ata_device_count++;
    if (!active_device)
      active_device = &ata_devices[ata_device_count - 1];
  }
  
  // Probe Secondary Slave
  if (ata_probe_device(0, 0)) {
    log_writestring("[ATA] Secondary Slave detected\n");
    ata_device_count++;
    if (!active_device)
      active_device = &ata_devices[ata_device_count - 1];
  }
  
  if (ata_device_count == 0) {
    log_writestring("[ATA] No ATA devices found\n");
    return 0;
  }
  
  log_writestring("[ATA] Found ");
  log_write_u32(ata_device_count);
  log_writestring(" device(s), using first detected device\n");
  return 1;
}

// Legacy init function (for compatibility)
int ata_init(void) {
  return ata_detect_all_devices();
}

// Get the active device
ata_device_t *ata_get_active_device(void) {
  return active_device;
}

// Read a sector using the active device (with retry logic)
int ata_read_sector(uint32_t lba, uint8_t *buf) {
  if (!active_device || !active_device->exists)
    return 0;
  
  ata_device_t *dev = active_device;
  
  // Retry up to 3 times
  for (int retry = 0; retry < 3; retry++) {
    // Wait for BSY to clear
    if (!ata_wait_status_device(dev, ATA_STATUS_BSY, 0, 100000)) {
      if (retry < 2) continue;  // Retry
      return 0;  // Final failure
    }
    
    // Set up LBA addressing (28-bit LBA)
    // 0xE0 = LBA mode (bit 6) + upper 4 bits of LBA28 (bits 7,5,4,3)
    // Preserve drive select bit (bit 4: 0=master, 1=slave)
    uint8_t drive_bit = dev->drive_sel_value & 0x10;  // Extract bit 4
    outb(dev->drive_sel_port, 0xE0 | ((lba >> 24) & 0x0F) | drive_bit);
    outb(dev->sec_count_port, 1);
    outb(dev->lba_lo_port, (uint8_t)lba);
    outb(dev->lba_mid_port, (uint8_t)(lba >> 8));
    outb(dev->lba_hi_port, (uint8_t)(lba >> 16));
    outb(dev->command_port, ATA_CMD_READ_PIO);
    
    // Wait for BSY to clear
    if (!ata_wait_status_device(dev, ATA_STATUS_BSY, 0, 100000)) {
      if (retry < 2) continue;  // Retry
      return 0;  // Final failure
    }
    
    // Check for errors
    uint8_t status = inb(dev->status_port);
    if (status & ATA_STATUS_ERR) {
      uint8_t error = inb(dev->error_port);
      if (retry < 2) {
        // Log error and retry
        log_writestring("[ATA] Read error at LBA ");
        log_write_u32(lba);
        log_writestring(", error=0x");
        log_write_hex8(error);
        log_writestring(", retrying...\n");
        continue;
      }
      // Final failure
      log_writestring("[ATA] Read failed at LBA ");
      log_write_u32(lba);
      log_writestring(", error=0x");
      log_write_hex8(error);
      log_putchar('\n');
      return 0;
    }
    
    // Wait for DRQ to be set
    if (!ata_wait_status_device(dev, ATA_STATUS_DRQ, ATA_STATUS_DRQ, 100000)) {
      if (retry < 2) continue;  // Retry
      return 0;  // Final failure
    }
    
    // Read 256 words (512 bytes)
    uint16_t *ptr = (uint16_t *)buf;
    for (int i = 0; i < 256; i++)
      ptr[i] = inw(dev->data_port);
    
    return 1;  // Success
  }
  
  return 0;  // All retries failed
}

// Write a sector using the active device
int ata_write_sector(uint32_t lba, const uint8_t *buf) {
  if (!active_device || !active_device->exists)
    return 0;
  
  ata_device_t *dev = active_device;
  
  // Wait for BSY to clear
  if (!ata_wait_status_device(dev, ATA_STATUS_BSY, 0, 100000))
    return 0;
  
  // Set up LBA addressing (28-bit LBA)
  // 0xE0 = LBA mode (bit 6) + upper 4 bits of LBA28 (bits 7,5,4,3)
  // Preserve drive select bit (bit 4: 0=master, 1=slave)
  uint8_t drive_bit = dev->drive_sel_value & 0x10;  // Extract bit 4
  outb(dev->drive_sel_port, 0xE0 | ((lba >> 24) & 0x0F) | drive_bit);
  outb(dev->sec_count_port, 1);
  outb(dev->lba_lo_port, (uint8_t)lba);
  outb(dev->lba_mid_port, (uint8_t)(lba >> 8));
  outb(dev->lba_hi_port, (uint8_t)(lba >> 16));
  outb(dev->command_port, ATA_CMD_WRITE_PIO);
  
  // Wait for BSY to clear
  if (!ata_wait_status_device(dev, ATA_STATUS_BSY, 0, 100000))
    return 0;
  
  // Wait for DRQ to be set
  if (!ata_wait_status_device(dev, ATA_STATUS_DRQ, ATA_STATUS_DRQ, 100000))
    return 0;
  
  // Write 256 words (512 bytes)
  uint16_t *ptr = (uint16_t *)buf;
  for (int i = 0; i < 256; i++)
    outw(dev->data_port, ptr[i]);
  
  // Flush cache
  outb(dev->command_port, ATA_CMD_CACHE_FLUSH);
  ata_wait_status_device(dev, ATA_STATUS_BSY, 0, 100000);
  
  return 1;
}
