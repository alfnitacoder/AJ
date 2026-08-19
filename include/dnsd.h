#ifndef DNSD_H
#define DNSD_H

#include "net.h"
#include <stdint.h>

// DNS Flags
#define DNS_FLAG_QR 0x8000     // Query(0)/Response(1)
#define DNS_FLAG_OPCODE 0x7800 // Operation Code
#define DNS_FLAG_AA 0x0400     // Authoritative Answer
#define DNS_FLAG_TC 0x0200     // Truncated
#define DNS_FLAG_RD 0x0100     // Recursion Desired
#define DNS_FLAG_RA 0x0080     // Recursion Available
#define DNS_FLAG_RCODE 0x000F  // Response Code

// DNS Header (Big Endian)
struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t num_questions;
  uint16_t num_answers;
  uint16_t num_authrr;
  uint16_t num_extrarr;
} __attribute__((packed));

void dnsd_init(void);
void dnsd_handle_packet(struct pbuf *p, uint32_t src_ip, uint16_t src_port,
                        uint16_t dst_port);
void dnsd_stat(void);

#endif // DNSD_H
