#include "auth.h"
#include "net.h"
#include "pbuf.h"
#include <stddef.h>
#include <stdint.h>

// Extern kernel functions
extern void log_writestring(const char *s);
extern void log_write_hex32(uint32_t v);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);

// Extern ARP functions
extern int arp_query(uint32_t ip);
extern int arp_get_mac_for_ip(uint32_t ip, eth_addr_t *out_mac);
extern uint32_t arp_get_ajos_ip(void);
extern uint32_t arp_get_if_ip(int iface);
// Extern DHCP negotiation state (so we can accept unicast ACKs before IP is
// set)
extern uint32_t dhcp_offered_ip;

static uint32_t ip4_rx_count = 0;
static uint32_t ip4_tx_count = 0;
static uint32_t ip4_policy_drop_count = 0;

// Very small interface config (defaults for QEMU user-net)
static uint32_t ip4_netmask = 0;
static uint32_t ip4_gateway = 0;
/* Dual-NIC: per-interface netmask/gateway (iface0 = primary, iface1 = second) */
static uint32_t ip4_if_nm[2] = {0, 0};
static uint32_t ip4_if_gw[2] = {0, 0};

uint32_t ip4_get_rx_count(void) { return ip4_rx_count; }
uint32_t ip4_get_tx_count(void) { return ip4_tx_count; }
uint32_t ip4_get_policy_drop_count(void) { return ip4_policy_drop_count; }

int ip4_policy_filter(struct pbuf *p, struct ip4_hdr *hdr, uint8_t hl) {

  uint32_t src = ntohl(hdr->src);

  // 1. Authenticated users are always allowed
  if (auth_is_authenticated(src)) {
    return 1; // ALLOW
  }

  // 2. Allow traffic destined to the router itself (AJOS)
  // This allows Ping replies, DNS replies, and accessing the captive portal
  uint32_t dst = ntohl(hdr->dst);
  if (dst == arp_get_ajos_ip()) {
    return 1; // ALLOW
  }

  // 2. Unauthenticated users: allow bootstrap services
  if (hdr->proto == IP_PROTO_UDP) {
    if (p->len < hl + sizeof(struct udp_hdr))
      return 0; // DROP truncated
    struct udp_hdr *uhdr = (struct udp_hdr *)((uint8_t *)p->payload + hl);
    uint16_t dport = ntohs(uhdr->dst_port);

    // DHCP (67/68) and DNS (53)
    if (dport == 67 || dport == 68 || dport == 53) {
      return 1; // ALLOW
    }
  } else if (hdr->proto == IP_PROTO_TCP) {
    if (p->len < hl + sizeof(struct tcp_hdr))
      return 0;
    struct tcp_hdr *thdr = (struct tcp_hdr *)((uint8_t *)p->payload + hl);
    uint16_t dport = ntohs(thdr->dst_port);
    // HTTP (80) and SSH (22)
    if (dport == 80 || dport == 22) {
      return 1; // ALLOW
    }
  }

  // Drop everything else
  return 0; // DROP
}

void ip4_init(void) {

  // Avoid relying on non-zero .data init (some boot paths may not copy it).
  // QEMU user-net defaults:
  ip4_netmask = 0xFFFFFF00u; // 255.255.255.0
  ip4_gateway = 0x0A000202u; // 10.0.2.2
}

void ip4_set_netmask_ip(int iface, ip_addr_t mask) { if (iface == 0) ip4_netmask = mask; if (iface >= 0 && iface < 2) ip4_if_nm[iface] = mask; }
void ip4_set_netmask(ip_addr_t mask) { ip4_set_netmask_ip(0, mask); }
ip_addr_t ip4_get_netmask(void) { return ip4_netmask; }
void ip4_set_gateway_ip(int iface, ip_addr_t gw) { if (iface == 0) ip4_gateway = gw; if (iface >= 0 && iface < 2) ip4_if_gw[iface] = gw; }

uint32_t ip4_get_if_netmask(int iface) {
  return (iface >= 0 && iface < 2) ? ip4_if_nm[iface] : 0;
}

uint32_t ip4_get_if_gw(int iface) {
  return (iface >= 0 && iface < 2) ? ip4_if_gw[iface] : 0;
}
void ip4_set_gateway(ip_addr_t gw) { ip4_set_gateway_ip(0, gw); }
ip_addr_t ip4_get_gateway(void) { return ip4_gateway; }

uint16_t net_checksum(void *data, int len) {
  uint32_t sum = 0;
  uint16_t *buf = (uint16_t *)data;

  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }

  if (len > 0) {
    sum += *(uint8_t *)buf;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)(~sum);
}

void ip4_input(struct pbuf *p) {
  ip4_rx_count++;
  if (p->len < sizeof(struct ip4_hdr)) {
    pbuf_free(p);
    return;
  }

  struct ip4_hdr *hdr = (struct ip4_hdr *)p->payload;
  uint32_t src = ntohl(hdr->src);
  uint32_t dst = ntohl(hdr->dst);

  /*
  log_writestring("[IP] Recv packet src=");
  log_write_u32((src >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((src >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((src >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(src & 0xFF);
  log_writestring(" dst=");
  log_write_u32((dst >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((dst >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((dst >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(dst & 0xFF);
  log_writestring(" proto=");
  log_write_u32(hdr->proto);
  log_putchar('\n');
  */

  // Verify version (4) and IHL (min 5)
  if ((hdr->v_hl >> 4) != 4) {
    pbuf_free(p);
    return;
  }

  uint8_t hl = (hdr->v_hl & 0x0F) * 4;
  if (p->len < hl) {
    pbuf_free(p);
    return;
  }

  // Checksum (zero it out for calculation if we were sending, but we are
  // receiving) Actually, standard check: sum including checksum field should be
  // 0xFFFF (or 0 after ~) Simple way: calculate with field as is, should be 0.
  if (net_checksum(hdr, hl) != 0) {
    // Checksum failed
    pbuf_free(p);
    return;
  }

  // Policy Filter: Enforce authentication
  if (!ip4_policy_filter(p, hdr, hl)) {
    ip4_policy_drop_count++;
    pbuf_free(p);
    return;
  }

  // Trim pbuf len to IP total length (handles Ethernet padding)
  uint16_t ip_len = ntohs(hdr->len);
  if (p->len > ip_len) {
    p->len = ip_len;
    // Assuming contiguous buffer for now; real lwIP would adjust tot_len chain
    p->tot_len = ip_len;
  } else if (p->len < ip_len) {
    // Truncated packet
    pbuf_free(p);
    return;
  }

  ip_addr_t ajos_ip = arp_get_ajos_ip();
  uint32_t ajos_ip1 = arp_get_if_ip(1);
  dst = ntohl(hdr->dst);

  // If we don't have an IP yet (0.0.0.0), we may still need to accept
  // unicast DHCP OFFER/ACK packets addressed to the offered IP.
  // In that state, accept:
  // - broadcast
  // - loopback
  // - 0.0.0.0
  // - dhcp_offered_ip (if set)
  // - and anything else only if ajos_ip is configured
  if (ajos_ip != 0 || ajos_ip1 != 0) {
    if (dst != ajos_ip && dst != ajos_ip1 && dst != IP_ADDR_BROADCAST &&
        dst != IP_ADDR_LOOPBACK) {
      // Not for us
      pbuf_free(p);
      return;
    }
  } else {
    // Bootstrap exception: allow DHCP replies even if they're unicast to the
    // offered IP (we don't know it until we parse the DHCP payload).
    if (hdr->proto == IP_PROTO_UDP && p->len >= hl + sizeof(struct udp_hdr)) {
      struct udp_hdr *uhdr = (struct udp_hdr *)((uint8_t *)p->payload + hl);
      uint16_t dport = ntohs(uhdr->dst_port);
      if (dport == 68) {
        // Accept: DHCP client port
        goto ip_accept_dst;
      }
    }
    if (!(dst == IP_ADDR_BROADCAST || dst == IP_ADDR_LOOPBACK || dst == 0 ||
          (dhcp_offered_ip != 0 && dst == dhcp_offered_ip))) {
      pbuf_free(p);
      return;
    }
  }

ip_accept_dst:
  if (hdr->proto == IP_PROTO_ICMP) {
    uint32_t src = ntohl(hdr->src);
    uint8_t ttl = hdr->ttl;
    pbuf_header(p, hl);
    p->len -= hl;
    icmp_input(p, src, ttl);
    return;
  }

  if (hdr->proto == IP_PROTO_UDP) {
    uint32_t src = ntohl(hdr->src);
    uint32_t dst_ip = ntohl(hdr->dst);
    pbuf_header(p, hl);
    p->len -= hl;
    udp_input(p, src, dst_ip);
    return;
  }

  if (hdr->proto == IP_PROTO_TCP) {
    uint32_t src = ntohl(hdr->src);
    uint32_t dst_ip = ntohl(hdr->dst);
    pbuf_header(p, hl);
    p->len -= hl;
    tcp_input(p, src, dst_ip);
    return;
  }

  pbuf_free(p);
}

int ip4_output_ttl(struct pbuf *p, ip_addr_t dst, uint8_t proto, uint8_t ttl) {
  ip4_tx_count++;
  if (pbuf_header(p, -(int)sizeof(struct ip4_hdr)) != 0) {
    pbuf_free(p);
    return -1;
  }

  struct ip4_hdr *hdr = (struct ip4_hdr *)p->payload;
  /* Dual-NIC route selection: match dst against each interface's subnet.
   * The matched interface supplies the source IP and the TX device. */
  int route_if = 0;
  for (int ri = 1; ri >= 0; ri--) {
    uint32_t rip = arp_get_if_ip(ri);
    uint32_t rnm = ip4_get_if_netmask(ri);
    if (rip != 0 && rnm != 0 && (dst & rnm) == (rip & rnm)) {
      route_if = ri;
      break;
    }
  }
  if (route_if == 0 && arp_get_if_ip(0) == 0 && arp_get_if_ip(1) != 0)
    route_if = 1; /* iface0 unconfigured, iface1 has the only IP */
  ip_addr_t ajos_ip = arp_get_if_ip(route_if);
  if (route_if == 0)
    ajos_ip = arp_get_ajos_ip(); /* legacy compat for iface0 */

  hdr->v_hl = 0x45; // v=4, hl=5 (20 bytes)
  hdr->tos = 0;
  hdr->len = htons((uint16_t)p->len + sizeof(struct ip4_hdr));
  hdr->id = 0; // Fixed ID for now
  hdr->off = 0;
  hdr->ttl = ttl;
  hdr->proto = proto;
  hdr->src = htonl(ajos_ip);
  hdr->dst = htonl(dst);
  hdr->chksum = 0;
  hdr->chksum = net_checksum(hdr, sizeof(struct ip4_hdr));

  p->len += sizeof(struct ip4_hdr);

  // Loopback handling: 127.x.x.x OR any of our own interface IPs
  // (dual-NIC: pinging our .240 on iface1 must loop back locally, not
  // go out the wire - the dev-1 TX may not even be needed for it).
  if ((dst & 0xFF000000u) == 0x7F000000u || dst == arp_get_ajos_ip() ||
      dst == arp_get_if_ip(1)) {
    ip4_input(p);
    return 0;
  }

  // Routing: if destination isn't on the local subnet, send to the gateway MAC.
  // This enables ping/DNS/etc to addresses outside 10.0.2.0/24 in QEMU
  // user-net.
  uint32_t next_hop = dst;
  {
    uint32_t nm = ip4_get_if_netmask(route_if);
    uint32_t gw = ip4_get_if_gw(route_if);
    if (nm == 0) nm = ip4_netmask;
    if (gw == 0) gw = ip4_gateway;
    if (ajos_ip != 0 && nm != 0 && gw != 0) {
      if ((dst & nm) != (ajos_ip & nm)) {
        next_hop = gw;
      }
    }
  }

  // Use ARP to find MAC
  eth_addr_t eth_dst;
  if (dst == 0xFFFFFFFFu) {
    for (int i = 0; i < 6; i++)
      eth_dst.addr[i] = 0xFF;
    {
      int er = ethernet_output(p, &eth_dst, ETHTYPE_IP);
      return (er != 0) ? 0 : -1;
    }
  }

  extern int e1000_default_device;
  if (route_if >= 0 && route_if < 2)
    e1000_default_device = route_if;
  if (arp_get_mac_for_ip(next_hop, &eth_dst)) {
    int er = ethernet_output(p, &eth_dst, ETHTYPE_IP);
    return (er != 0) ? 0 : -1;
  } else {
    // Trigger ARP query and drop packet (or queue it?)
    // Most simple OSs drop and rely on retry.
    arp_query(next_hop);
    pbuf_free(p);
    return -1;
  }
}

int ip4_output(struct pbuf *p, ip_addr_t dst, uint8_t proto) {
  return ip4_output_ttl(p, dst, proto, 64);
}
