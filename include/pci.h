#ifndef PCI_H
#define PCI_H

#include <stdint.h>

uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset);
uint16_t pci_cfg_read16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset);
uint8_t pci_cfg_read8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset);
void pci_cfg_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset,
                     uint32_t value);
void pci_cfg_write16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset,
                     uint16_t value);
int pci_func_present(uint8_t bus, uint8_t dev, uint8_t func);

#endif
