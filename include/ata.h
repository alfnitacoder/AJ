#ifndef ATA_H
#define ATA_H

#include <stdint.h>

// ATA IO Ports (Primary Bus)
#define ATA_PRIMARY_DATA 0x1F0
#define ATA_PRIMARY_ERR 0x1F1
#define ATA_PRIMARY_FEATURES 0x1F1
#define ATA_PRIMARY_SEC_COUNT 0x1F2
#define ATA_PRIMARY_LBA_LO 0x1F3
#define ATA_PRIMARY_LBA_MID 0x1F4
#define ATA_PRIMARY_LBA_HI 0x1F5
#define ATA_PRIMARY_DRIVE_SEL 0x1F6
#define ATA_PRIMARY_COMMAND 0x1F7
#define ATA_PRIMARY_STATUS 0x1F7
#define ATA_PRIMARY_CONTROL 0x3F6

// ATA IO Ports (Secondary Bus)
#define ATA_SECONDARY_DATA 0x170
#define ATA_SECONDARY_ERR 0x171
#define ATA_SECONDARY_FEATURES 0x171
#define ATA_SECONDARY_SEC_COUNT 0x172
#define ATA_SECONDARY_LBA_LO 0x173
#define ATA_SECONDARY_LBA_MID 0x174
#define ATA_SECONDARY_LBA_HI 0x175
#define ATA_SECONDARY_DRIVE_SEL 0x176
#define ATA_SECONDARY_COMMAND 0x177
#define ATA_SECONDARY_STATUS 0x177
#define ATA_SECONDARY_CONTROL 0x376

// Drive Select Values
#define ATA_DRIVE_MASTER 0xA0  // Primary Master or Secondary Master
#define ATA_DRIVE_SLAVE 0xB0   // Primary Slave or Secondary Slave

// Status Register Bits
#define ATA_STATUS_BSY 0x80
#define ATA_STATUS_DRDY 0x40
#define ATA_STATUS_DF 0x20
#define ATA_STATUS_DRQ 0x08
#define ATA_STATUS_ERR 0x01

// Commands
#define ATA_CMD_READ_PIO 0x20
#define ATA_CMD_WRITE_PIO 0x30
#define ATA_CMD_CACHE_FLUSH 0xE7
#define ATA_CMD_IDENTIFY 0xEC

// ATA Device Structure
typedef struct {
  int exists;
  int is_primary;  // 1 = primary bus, 0 = secondary bus
  int is_master;   // 1 = master, 0 = slave
  uint32_t data_port;
  uint32_t error_port;
  uint32_t features_port;
  uint32_t sec_count_port;
  uint32_t lba_lo_port;
  uint32_t lba_mid_port;
  uint32_t lba_hi_port;
  uint32_t drive_sel_port;
  uint32_t command_port;
  uint32_t status_port;
  uint32_t control_port;
  uint8_t drive_sel_value;
  uint32_t sector_count;  // From IDENTIFY data
} ata_device_t;

// Function prototypes
int ata_init(void);
int ata_read_sector(uint32_t lba, uint8_t *buf);
int ata_write_sector(uint32_t lba, const uint8_t *buf);
ata_device_t *ata_get_active_device(void);
int ata_detect_all_devices(void);

#endif
