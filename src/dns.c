#include "arp.h"
#include "net.h"
#include "pbuf.h"
#include <stddef.h>
#include <stdint.h>
// No string.h in AJOS kernel

extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern uint32_t arp_get_ajos_ip(void);

static uint16_t dns_id = 0xABCD;
static ip_addr_t dns_server = 0;

// Expose last resolution result so the shell command can print synchronously
// (avoid printing from IRQ-driven packet handlers).
volatile int dns_got_reply = 0;
volatile uint32_t dns_last_ip = 0;
static uint16_t dns_pending_id = 0;

void dns_set_server(ip_addr_t ip) { dns_server = ip; }
ip_addr_t dns_get_server(void) { return dns_server; }
void dns_init(void) {
  // Avoid relying on non-zero .data init (some boot paths may not copy it).
  // QEMU user-net DNS proxy is typically 10.0.2.3
  dns_server = 0x0A000203u;
}

/* Returns wire length (bytes), or -1 on empty name. */
static int dns_encode_name(uint8_t *dst, const char *name) {
  if (!name || !name[0])
    return -1;
  int pos = 0;
  int section_len_pos = 0;
  dst[section_len_pos] = 0;

  for (int i = 0; name[i]; i++) {
    if (name[i] == '.') {
      dst[section_len_pos] = (uint8_t)(pos - section_len_pos);
      section_len_pos = pos + 1;
      dst[section_len_pos] = 0;
    } else {
      dst[pos + 1] = name[i];
    }
    pos++;
  }
  dst[section_len_pos] = (uint8_t)(pos - section_len_pos);
  dst[pos + 1] = 0;
  return pos + 2;
}

void dns_lookup(const char *name) {
  dns_got_reply = 0;
  dns_last_ip = 0;

  // Ensure ARP to the next hop is resolved before sending, otherwise the first
  // DNS query can be dropped (ip4_output triggers ARP and drops the packet).
  uint32_t my_ip = arp_get_ajos_ip();
  uint32_t mask = ip4_get_netmask();
  uint32_t gw = ip4_get_gateway();
  uint32_t next_hop = dns_server;
  if (my_ip != 0 && mask != 0 && gw != 0) {
    if ((dns_server & mask) != (my_ip & mask)) {
      next_hop = gw;
    }
  }

  eth_addr_t tmp;
  if (!arp_get_mac_for_ip(next_hop, &tmp)) {
    arp_query(next_hop);
    // Short spin wait (IRQ-driven RX will populate ARP cache).
    for (uint32_t spin = 0; spin < 2000000u; spin++) {
      if (arp_get_mac_for_ip(next_hop, &tmp)) {
        break;
      }
      __asm__ volatile("pause");
    }
  }

  // Send query (retry once if ARP wasn't ready)
  for (int attempt = 0; attempt < 2; attempt++) {
    struct pbuf *p = pbuf_alloc();
    if (!p)
      return;

    pbuf_header(p, -(int)sizeof(struct dns_hdr));
    struct dns_hdr *hdr = (struct dns_hdr *)p->payload;
    dns_pending_id = dns_id;
    hdr->id = htons(dns_id++);
    hdr->flags = htons(DNS_FLAG_RD);
    hdr->num_questions = htons(1);
    hdr->num_answers = 0;
    hdr->num_authrr = 0;
    hdr->num_extrarr = 0;

    int off = sizeof(struct dns_hdr);
    int enc = dns_encode_name((uint8_t *)p->payload + off, name);
    if (enc < 0) {
      pbuf_free(p);
      return;
    }
    off += enc;

    uint16_t *qinfo = (uint16_t *)((uint8_t *)p->payload + off);
    qinfo[0] = htons(DNS_RRTYPE_A);
    qinfo[1] = htons(DNS_RRCLASS_IN);
    off += 4;

    p->len = off;

    int ret = udp_output(p, dns_server, 1024 + (dns_id % 1000), 53);
    if (ret == 0) {
      return;
    }

    // If we get here, the packet likely got dropped due to ARP miss.
    arp_query(next_hop);
    for (uint32_t spin = 0; spin < 2000000u; spin++) {
      if (arp_get_mac_for_ip(next_hop, &tmp)) {
        break;
      }
      __asm__ volatile("pause");
    }
  }
}

void dns_input(struct pbuf *p) {
  if (p->len < sizeof(struct dns_hdr)) {
    pbuf_free(p);
    return;
  }

  struct dns_hdr *hdr = (struct dns_hdr *)p->payload;
  if (ntohs(hdr->id) != dns_pending_id) {
    pbuf_free(p);
    return;
  }
  uint16_t num_questions = ntohs(hdr->num_questions);
  uint16_t num_answers = ntohs(hdr->num_answers);

  if (!(ntohs(hdr->flags) & DNS_FLAG_QR)) {
    pbuf_free(p);
    return;
  }

  uint8_t *ptr = (uint8_t *)p->payload + sizeof(struct dns_hdr);
  // Skip questions
  for (int i = 0; i < num_questions; i++) {
    while (*ptr)
      ptr += (*ptr) + 1;
    ptr++;    // Tail 0
    ptr += 4; // Type and Class
  }

  // Parse answers
  for (int i = 0; i < num_answers; i++) {
    // Skip name (might be compression pointer)
    if ((*ptr & 0xC0) == 0xC0) {
      ptr += 2;
    } else {
      while (*ptr)
        ptr += (*ptr) + 1;
      ptr++;
    }

    uint16_t type = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    uint16_t class = ntohs(*(uint16_t *)ptr);
    ptr += 2;
    ptr += 4; // TTL
    uint16_t rdlen = ntohs(*(uint16_t *)ptr);
    ptr += 2;

    if (type == DNS_RRTYPE_A && rdlen == 4) {
      uint32_t ip = ntohl(*(uint32_t *)ptr);
      dns_last_ip = ip;
      dns_got_reply = 1;
      // Keep processing, but don't print here (IRQ context).
    }
    ptr += rdlen;
  }

  pbuf_free(p);
}
