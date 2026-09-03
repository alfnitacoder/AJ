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
extern uint8_t e1000_mac[2][6];
extern int e1000_default_device;
extern uint32_t pit_ticks;

static arp_entry_t arp_cache[ARP_CACHE_SIZE];

uint32_t arp_get_if_ip(int iface); /* forward: defined below */
// A hardcoded static IP for AJOS in QEMU environment
static uint32_t ajos_ip[2] = {0, 0}; // iface0/iface1 (dual-NIC AJOS)

void arp_init(void) {
  for (int i = 0; i < ARP_CACHE_SIZE; i++) {
    arp_cache[i].valid = 0;
  }
  // 10.0.2.15 stored in network byte order format (matches ip4_init style)
  // On little-endian: 0x0A00020F = 10.0.2.15
  ajos_ip[0] = (10u << 24) | (0u << 16) | (2u << 8) | (15u);
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

  if (dst_ip != ajos_ip[0] && dst_ip != ajos_ip[1]) {
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

  /* Dual-NIC: answer on the arrival NIC with the asked IP as the source. */
  extern int e1000_default_device;
  extern int e1000_active_rx_device;
  if (e1000_active_rx_device >= 0 && e1000_active_rx_device < 2)
    e1000_default_device = e1000_active_rx_device;

  if (op == ARP_OP_REQUEST) {
    // Send reply
    hdr->opcode = htons(ARP_OP_REPLY);
    hdr->dst_mac = hdr->src_mac;
    {
      int txd = (e1000_default_device >= 0 && e1000_default_device < 2)
                    ? e1000_default_device
                    : 0;
      for (int i = 0; i < 6; i++)
        hdr->src_mac.addr[i] = e1000_mac[txd][i];
    }

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
  {
    int txd = (e1000_default_device >= 0 && e1000_default_device < 2)
                  ? e1000_default_device
                  : 0;
    for (int i = 0; i < 6; i++) {
      hdr->src_mac.addr[i] = e1000_mac[txd][i];
      hdr->dst_mac.addr[i] = 0; // ignored
    }
    hdr->src_ip = htonl(arp_get_if_ip(txd));
  }
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

uint32_t arp_get_ajos_ip(void) { return ajos_ip[0]; }  /* compat: iface0 */
uint32_t arp_get_if_ip(int iface) { return (iface >= 0 && iface < 2) ? ajos_ip[iface] : 0; }
void arp_set_if_ip(int iface, uint32_t ip) { if (iface >= 0 && iface < 2) ajos_ip[iface] = ip; }
void arp_set_ajos_ip(uint32_t ip) { ajos_ip[0] = ip; }
void arp_get_ajos_mac(uint8_t *mac) {
  int txd = (e1000_default_device >= 0 && e1000_default_device < 2)
                ? e1000_default_device
                : 0;
  for (int i = 0; i < 6; i++)
    mac[i] = e1000_mac[txd][i];
}

/* Is this IP one of our own interface addresses? (loopback candidates) */
int arp_is_our_ip(uint32_t ip) {
  if (ip == arp_get_ajos_ip())
    return 1;
  if (ip == arp_get_if_ip(1))
    return 1;
  return 0;
}

int arp_get_mac_for_ip(uint32_t ip, eth_addr_t *out_mac) {
  /* IP broadcast destinations map straight to the Ethernet broadcast MAC.
   * Without this, broadcast-bound packets (DHCP offers!) queue behind an
   * ARP request for 255.255.255.255 that can never resolve, leaking pbufs
   * and pinning the CPU in the pending scan. */
  if (ip == 0xFFFFFFFFu || (ip & 0xFF000000u) == 0xFF000000u) {
    if (out_mac) {
      for (int b = 0; b < 6; b++)
        out_mac->addr[b] = 0xFFu;
    }
    return 1;
  }
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
