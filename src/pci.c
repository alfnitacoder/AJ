#include "pci.h"
#include "kernel.h"

uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func,
                        uint8_t offset) {
  // offset must be 4-byte aligned
  uint32_t address =
      (uint32_t)(0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) |
                 ((uint32_t)func << 8) | ((uint32_t)(offset & 0xFC)));
  outl(0xCF8, address);
  return inl(0xCFC);
}

uint16_t pci_cfg_read16(uint8_t bus, uint8_t dev, uint8_t func,
                        uint8_t offset) {
  uint32_t v = pci_cfg_read32(bus, dev, func, (uint8_t)(offset & 0xFC));
  return (uint16_t)((v >> ((offset & 2u) * 8u)) & 0xFFFFu);
}

uint8_t pci_cfg_read8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset) {
  uint32_t v = pci_cfg_read32(bus, dev, func, (uint8_t)(offset & 0xFC));
  return (uint8_t)((v >> ((offset & 3u) * 8u)) & 0xFFu);
}

void pci_cfg_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset,
                     uint32_t value) {
  uint32_t address =
      (uint32_t)(0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) |
                 ((uint32_t)func << 8) | ((uint32_t)(offset & 0xFC)));
  outl(0xCF8, address);
  outl(0xCFC, value);
}

void pci_cfg_write16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset,
                     uint16_t value) {
  uint32_t aligned_off = (uint32_t)(offset & 0xFCu);
  uint32_t address =
      (uint32_t)(0x80000000u | ((uint32_t)bus << 16) | ((uint32_t)dev << 11) |
                 ((uint32_t)func << 8) | aligned_off);
  outl(0xCF8, address);
  uint32_t cur = inl(0xCFC);
  uint32_t shift = (uint32_t)((offset & 2u) * 8u);
  uint32_t mask = 0xFFFFu << shift;
  uint32_t next = (cur & ~mask) | ((uint32_t)value << shift);
  outl(0xCFC, next);
}

int pci_func_present(uint8_t bus, uint8_t dev, uint8_t func) {
  uint16_t vendor = pci_cfg_read16(bus, dev, func, 0x00);
  return vendor != 0xFFFFu;
}
