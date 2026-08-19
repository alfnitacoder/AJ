#include "arp.h"
#include "net.h"
#include "pbuf.h"
#include <stddef.h>
#include <stdint.h>

// Extern kernel functions
extern void log_writestring(const char *s);
extern void log_write_hex32(uint32_t v);
extern void log_write_hex8(uint8_t v);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern int e1000_tx_send_raw(void *data, uint16_t len);
extern uint8_t e1000_mac[6];

static uint32_t eth_rx_count = 0;
static uint32_t eth_tx_count = 0;
static uint32_t eth_tx_attempt_count = 0;
static uint32_t eth_tx_fail_count = 0;

void ethernet_input(struct pbuf *p) {
  if (p == NULL || p->len < sizeof(struct eth_hdr)) {
    pbuf_free(p);
    return;
  }

  struct eth_hdr *hdr = (struct eth_hdr *)p->payload;
  uint16_t type = ntohs(hdr->type);

  /*
  log_writestring("[Eth] Recv type=0x");
  log_write_hex32(type);
  log_writestring(" len=");
  log_write_u32(p->len);
  log_putchar('\n');
  */

  eth_rx_count++;

  if (type == ETHTYPE_ARP) {
    if (pbuf_header(p, (int)sizeof(struct eth_hdr)) == 0) {
      if (p->len >= sizeof(struct eth_hdr)) {
        p->len -= sizeof(struct eth_hdr);
      }
      arp_input(p);
      return;
    }
  }

  if (type == ETHTYPE_IP) {
    if (pbuf_header(p, (int)sizeof(struct eth_hdr)) == 0) {
      if (p->len >= sizeof(struct eth_hdr)) {
        p->len -= sizeof(struct eth_hdr);
      }
      ip4_input(p);
      return;
    }
  }

  pbuf_free(p);
}

int ethernet_output(struct pbuf *p, eth_addr_t *dst, uint16_t type) {
  if (p == NULL || dst == NULL)
    return -1;

  // Prepend Ethernet header
  if (pbuf_header(p, -(int)sizeof(struct eth_hdr)) != 0) {
    static int logged_once = 0;
    if (!logged_once) {
      logged_once = 1;
      log_writestring("[Eth] ethernet_output: pbuf_header(-ETH) failed. len=");
      log_write_u32(p->len);
      log_writestring(" payload=");
      log_write_hex32((uint32_t)p->payload);
      log_writestring("\n");
    }
    pbuf_free(p);
    return -1;
  }

  struct eth_hdr *hdr = (struct eth_hdr *)p->payload;
  for (int i = 0; i < 6; i++) {
    hdr->dst.addr[i] = dst->addr[i];
    hdr->src.addr[i] = e1000_mac[i];
  }
  hdr->type = htons(type);
  p->len += sizeof(struct eth_hdr);

  // Send via NIC
  eth_tx_attempt_count++;
  int ret = e1000_tx_send_raw(p->payload, (uint16_t)p->len);
  if (ret != 0) {
    eth_tx_count++;
  } else {
    eth_tx_fail_count++;
  }

  pbuf_free(p);
  return ret;
}

// Stats API
uint32_t eth_get_rx_count(void) { return eth_rx_count; }
uint32_t eth_get_tx_count(void) { return eth_tx_count; }
uint32_t eth_get_tx_attempt_count(void) { return eth_tx_attempt_count; }
uint32_t eth_get_tx_fail_count(void) { return eth_tx_fail_count; }