#ifndef ARP_H
#define ARP_H

#include "net.h"
#include "pbuf.h"
#include <stdint.h>

// ARP hardware types
#define ARP_HTYPE_ETH 1

// ARP protocol types
#define ARP_PTYPE_IP 0x0800

// ARP opcodes
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

struct arp_hdr {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  eth_addr_t src_mac;
  uint32_t src_ip;
  eth_addr_t dst_mac;
  uint32_t dst_ip;
} __attribute__((packed));

void arp_init(void);
void arp_input(struct pbuf *p);
int arp_query(uint32_t ip);
uint32_t arp_get_ajos_ip(void);
void arp_set_ajos_ip(uint32_t ip);
int arp_get_mac_for_ip(uint32_t ip, eth_addr_t *out_mac);
uint32_t arp_get_ip_at(int idx);
uint8_t *arp_get_mac_at(int idx);

// ARP Cache item
typedef struct {
  uint32_t ip;
  eth_addr_t mac;
  uint32_t last_tick;
  uint8_t valid;
} arp_entry_t;

#define ARP_CACHE_SIZE 16

#endif
