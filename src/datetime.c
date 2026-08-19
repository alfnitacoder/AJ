#include "datetime.h"
#include "kernel.h"

static int cmos_is_updating(void) {
  outb(0x70, 0x0A);
  return (inb(0x71) & 0x80);
}

static uint8_t cmos_read(uint8_t reg) {
  outb(0x70, reg);
  return inb(0x71);
}

void get_datetime(struct datetime *dt) {
  while (cmos_is_updating())
    __asm__ volatile("pause");

  dt->sec = cmos_read(0x00);
  dt->min = cmos_read(0x02);
  dt->hour = cmos_read(0x04);
  dt->day = cmos_read(0x07);
  dt->month = cmos_read(0x08);
  dt->year = cmos_read(0x09);

  uint8_t status_b = cmos_read(0x0B);

  // Convert BCD to binary if needed
  if (!(status_b & 0x04)) {
    dt->sec = (uint8_t)((dt->sec & 0x0F) + ((dt->sec / 16) * 10));
    dt->min = (uint8_t)((dt->min & 0x0F) + ((dt->min / 16) * 10));
    dt->hour = (uint8_t)(((dt->hour & 0x0F) + (((dt->hour & 0x70) / 16) * 10)) |
                         (dt->hour & 0x80));
    dt->day = (uint8_t)((dt->day & 0x0F) + ((dt->day / 16) * 10));
    dt->month = (uint8_t)((dt->month & 0x0F) + ((dt->month / 16) * 10));
    dt->year = (uint16_t)((dt->year & 0x0F) + ((dt->year / 16) * 10));
  }

  // Handle 12-hour clock
  if (!(status_b & 0x02) && (dt->hour & 0x80)) {
    dt->hour = (uint8_t)(((dt->hour & 0x7F) + 12) % 24);
  }

  dt->year += 2000; // Assume 21st century
}

uint16_t datetime_to_fat_time(struct datetime *dt) {
  return (uint16_t)(((dt->hour & 0x1F) << 11) | ((dt->min & 0x3F) << 5) |
                    ((dt->sec / 2) & 0x1F));
}

uint16_t datetime_to_fat_date(struct datetime *dt) {
  uint16_t y = (dt->year >= 1980) ? (uint16_t)(dt->year - 1980) : 0;
  return (uint16_t)((y << 9) | ((dt->month & 0x0F) << 5) | (dt->day & 0x1F));
}
