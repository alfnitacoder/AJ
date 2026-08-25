#ifndef DNSD_H
#define DNSD_H

#include "net.h"
#include <stdint.h>

void dnsd_init(void);
void dnsd_handle_packet(struct pbuf *p, uint32_t src_ip, uint16_t src_port,
                        uint16_t dst_port);
void dnsd_stat(void);

#endif // DNSD_H
