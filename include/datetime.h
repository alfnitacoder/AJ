#ifndef DATETIME_H
#define DATETIME_H

#include <stdint.h>

struct datetime {
  uint8_t sec, min, hour, day, month;
  uint16_t year;
};

void get_datetime(struct datetime *dt);
uint16_t datetime_to_fat_time(struct datetime *dt);
uint16_t datetime_to_fat_date(struct datetime *dt);

#endif
