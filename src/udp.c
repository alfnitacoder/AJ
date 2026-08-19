#include "net.h"
#include "pbuf.h"
#include <stddef.h>
#include <stdint.h>

// External handlers
extern void dhcp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst);
extern void dhcpd_handle_packet(struct pbuf *p); // Server
extern void dns_input(struct pbuf *p);
extern void dnsd_handle_packet(struct pbuf *p, uint32_t src, uint16_t src_port,
                               uint16_t dst_port);

extern void log_putchar(char c);

void udp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst) {
  if (p->len < sizeof(struct udp_hdr)) {
    pbuf_free(p);
    return;
  }

  struct udp_hdr *hdr = (struct udp_hdr *)p->payload;
  uint16_t src_port = ntohs(hdr->src_port);
  uint16_t dst_port = ntohs(hdr->dst_port);

  // For now, just drop or echo if it's a specific port
  if (dst_port == 7) {
    // Echo service
    pbuf_header(p, (int)sizeof(struct udp_hdr));
    p->len -= sizeof(struct udp_hdr);
    udp_output(p, src, dst_port, src_port);
    return;
  }

  if (dst_port == 68) {
    pbuf_header(p, (int)sizeof(struct udp_hdr));
    p->len -= sizeof(struct udp_hdr);
    dhcp_input(p, src, dst);
    return;
  }

  if (dst_port == 67) {
    pbuf_header(p, (int)sizeof(struct udp_hdr));
    p->len -= sizeof(struct udp_hdr);
    dhcpd_handle_packet(p);
    return;
  }

  if (dst_port == 53) {
    pbuf_header(p, (int)sizeof(struct udp_hdr));
    p->len -= sizeof(struct udp_hdr);
    dnsd_handle_packet(p, src, src_port, dst_port);
    return;
  }

  if (src_port == 53) {

    pbuf_header(p, (int)sizeof(struct udp_hdr));
    p->len -= sizeof(struct udp_hdr);
    dns_input(p);
    return;
  }

  pbuf_free(p);
}

int udp_output(struct pbuf *p, ip_addr_t dst, uint16_t src_port,
               uint16_t dst_port) {
  if (pbuf_header(p, -(int)sizeof(struct udp_hdr)) != 0) {
    pbuf_free(p);
    return -1;
  }

  struct udp_hdr *hdr = (struct udp_hdr *)p->payload;
  hdr->src_port = htons(src_port);
  hdr->dst_port = htons(dst_port);
  hdr->len = htons((uint16_t)p->len + sizeof(struct udp_hdr));
  hdr->chksum = 0; // Optional in IPv4, but good practice. Leave 0 for now.

  p->len += sizeof(struct udp_hdr);

  return ip4_output(p, dst, IP_PROTO_UDP);
}
