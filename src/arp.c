#include "arp.h"
#include "net.h"
#include "pbuf.h"

extern uint32_t ip4_get_gateway(void);
#include <stddef.h>
#include <stdint.h>

// Extern kernel functions
extern void log_writestring(const char *s);
extern void log_write_hex32(uint32_t v);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern uint8_t e1000_mac[6];
extern uint32_t pit_ticks;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];
// A hardcoded static IP for AJOS in QEMU environment
static uint32_t ajos_ip = 0; // Will be initialized to 10.0.2.15

void arp_init(void) {
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    arp_cache[i].valid = 0;
  }
  // 10.0.2.15 stored in network byte order format (matches ip4_init style)
  // On little-endian: 0x0A00020F = 10.0.2.15
  ajos_ip = (10u << 24) | (0u << 16) | (2u << 8) | (15u);
}

static void arp_update_cache(uint32_t ip, eth_addr_t *mac) {
  // Find existing or old entry
  int empty_idx = -1;
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip) {
      for (int b = 0; b < 6; b++)
        arp_cache[i].mac.addr[b] = mac->addr[b];
      arp_cache[i].last_tick = pit_ticks;
      return;
    }
    if (!arp_cache[i].valid && empty_idx == -1)
      empty_idx = i;
  }

  /* Cache full: evict LRU entry, but never evict default gateway (off-subnet
   * TX to 8.8.8.8 etc. needs GW MAC; silent drop here used to wedge ping/DNS). */
  if (empty_idx == -1) {
    uint32_t gw = ip4_get_gateway();
    int victim = -1;
    uint32_t oldest = 0xFFFFFFFFu;
    for (int i = 0; i < ARP_CACHE_SIZE; i++) {
      if (!arp_cache[i].valid)
        continue;
      if (gw != 0u && arp_cache[i].ip == gw)
        continue;
      if (arp_cache[i].last_tick <= oldest) {
        oldest = arp_cache[i].last_tick;
        victim = i;
      }
    }
    if (victim >= 0)
      empty_idx = victim;
  }

  if (empty_idx != -1) {
    arp_cache[empty_idx].ip = ip;
    for (int b = 0; b < 6; b++)
      arp_cache[empty_idx].mac.addr[b] = mac->addr[b];
    arp_cache[empty_idx].last_tick = pit_ticks;
    arp_cache[empty_idx].valid = 1;
  }
}

void arp_input(struct pbuf *p) {
  if (p->len < sizeof(struct arp_hdr)) {
    pbuf_free(p);
    return;
  }

  struct arp_hdr *hdr = (struct arp_hdr *)p->payload;
  uint16_t op = ntohs(hdr->opcode);
  uint32_t src_ip = ntohl(hdr->src_ip);
  uint32_t dst_ip = ntohl(hdr->dst_ip);

  /*
  log_writestring("[ARP] Recv op=");
  log_write_u32(op);
  log_writestring(" src=");
  ...
  log_putchar('\n');
  */

  // Update cache with sender info for all incoming ARP packets
  arp_update_cache(src_ip, &hdr->src_mac);

  if (dst_ip != ajos_ip) {
    /*
    log_writestring("[ARP] Dropping (dst != ajos_ip: ");
    ...
    log_writestring(")\n");
    */
    pbuf_free(p);
    return;
  }

  if (op == ARP_OP_REPLY) {
    pbuf_free(p);
    return;
  }

  if (op == ARP_OP_REQUEST) {
    // Send reply
    hdr->opcode = htons(ARP_OP_REPLY);
    hdr->dst_mac = hdr->src_mac;
    for (int i = 0; i < 6; i++)
      hdr->src_mac.addr[i] = e1000_mac[i];

    uint32_t tmp = hdr->src_ip;
    hdr->src_ip = hdr->dst_ip;
    hdr->dst_ip = tmp;

    // We reuse the pbuf. ethernet_output will prepend the Ethernet header.
    ethernet_output(p, &hdr->dst_mac, ETHTYPE_ARP);
    return;
  }

  pbuf_free(p);
}

int arp_query(uint32_t ip) {
  static int logged_alloc_fail_once = 0;
  static int logged_hdr_fail_once = 0;
  static int logged_send_once = 0;
  // Check cache
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip) {
      return 1;
    }
  }

  // Send request
  struct pbuf *p = pbuf_alloc();
  if (!p)
  {
    if (!logged_alloc_fail_once) {
      logged_alloc_fail_once = 1;
      log_writestring("[ARP] arp_query: pbuf_alloc failed\n");
    }
    return 0;
  }

  // Leave room for Ethernet header (14 bytes)
  if (pbuf_header(p, 14) != 0) {
    if (!logged_hdr_fail_once) {
      logged_hdr_fail_once = 1;
      log_writestring("[ARP] arp_query: pbuf_header(+14) failed\n");
    }
    pbuf_free(p);
    return 0;
  }

  struct arp_hdr *hdr = (struct arp_hdr *)p->payload;
  hdr->htype = htons(ARP_HTYPE_ETH);
  hdr->ptype = htons(ARP_PTYPE_IP);
  hdr->hlen = 6;
  hdr->plen = 4;
  hdr->opcode = htons(ARP_OP_REQUEST);
  for (int i = 0; i < 6; i++) {
    hdr->src_mac.addr[i] = e1000_mac[i];
    hdr->dst_mac.addr[i] = 0; // ignored
  }
  hdr->src_ip = htonl(ajos_ip);
  hdr->dst_ip = htonl(ip);
  p->len = sizeof(struct arp_hdr);
  p->tot_len = sizeof(struct arp_hdr);

  eth_addr_t bcast = {{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  if (!logged_send_once) {
    logged_send_once = 1;
    log_writestring("[ARP] arp_query: sending ARP request\n");
  }
  ethernet_output(p, &bcast, ETHTYPE_ARP);
  return 0;
}

uint32_t arp_get_ip_at(int idx) {
  return (idx < ARP_CACHE_SIZE && arp_cache[idx].valid) ? arp_cache[idx].ip : 0;
}
uint8_t *arp_get_mac_at(int idx) {
  return (idx < ARP_CACHE_SIZE && arp_cache[idx].valid)
             ? arp_cache[idx].mac.addr
             : NULL;
}

uint32_t arp_get_ajos_ip(void) { return ajos_ip; }
void arp_set_ajos_ip(uint32_t ip) { ajos_ip = ip; }
void arp_get_ajos_mac(uint8_t *mac) {
  for (int i = 0; i < 6; i++)
    mac[i] = e1000_mac[i];
}

int arp_get_mac_for_ip(uint32_t ip, eth_addr_t *out_mac) {
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    if (arp_cache[i].valid && arp_cache[i].ip == ip) {
      if (out_mac) {
        for (int b = 0; b < 6; b++)
          out_mac->addr[b] = arp_cache[i].mac.addr[b];
      }
      return 1;
    }
  }
  return 0;
}
