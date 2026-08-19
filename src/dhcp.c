#include "net.h"
#include "pbuf.h"
#include <stddef.h>
#include <stdint.h>

// Extern kernel/arp functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void arp_get_ajos_mac(uint8_t *mac);
extern void arp_set_ajos_ip(uint32_t ip);
extern void dns_set_server(uint32_t ip);
extern void ip4_set_netmask(uint32_t mask);
extern void ip4_set_gateway(uint32_t gw);

static uint32_t dhcp_xid = 0x12345678;
// Expose basic DHCP state to the shell so `dhcp` can wait for ACK.
volatile int dhcp_got_offer = 0;
volatile int dhcp_got_ack = 0;
uint32_t dhcp_offered_ip = 0;
uint32_t dhcp_server_ip = 0;

// Use PIT ticks to vary transaction IDs across attempts.
extern volatile uint32_t pit_ticks;

static uint8_t *dhcp_add_option(uint8_t *opt, uint8_t type, uint8_t len,
                                const void *val) {
  *opt++ = type;
  *opt++ = len;
  for (int i = 0; i < len; i++) {
    *opt++ = ((uint8_t *)val)[i];
  }
  return opt;
}

static int dhcp_send_request(uint32_t offered_ip, ip_addr_t server_id,
                             ip_addr_t dst_ip) {
  struct pbuf *rp = pbuf_alloc();
  if (!rp) {
    return -1;
  }

  struct dhcp_msg *rmsg = (struct dhcp_msg *)rp->payload;
  for (int i = 0; i < (int)sizeof(struct dhcp_msg); i++)
    ((uint8_t *)rmsg)[i] = 0;

  rmsg->op = DHCP_BOOTREQUEST;
  rmsg->htype = 1;
  rmsg->hlen = 6;
  rmsg->xid = htonl(dhcp_xid);
  rmsg->flags = htons(0x8000);
  rmsg->cookie = htonl(0x63825363);

  uint8_t mac[6];
  arp_get_ajos_mac(mac);
  for (int i = 0; i < 6; i++)
    rmsg->chaddr[i] = mac[i];

  uint8_t *ropt = rmsg->options;
  uint8_t rtype = DHCP_REQUEST;
  ropt = dhcp_add_option(ropt, DHCP_OPTION_MSG_TYPE, 1, &rtype);

  // offered_ip and server_id are in host order here; convert to network on write
  uint32_t req_ip_n = htonl(offered_ip);
  uint32_t sid_n = htonl(server_id);
  ropt = dhcp_add_option(ropt, DHCP_OPTION_REQ_IP, 4, &req_ip_n);
  ropt = dhcp_add_option(ropt, DHCP_OPTION_SERVER_ID, 4, &sid_n);

  // Ask for common config too (some servers are picky)
  uint8_t prl[] = {DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER,
                   DHCP_OPTION_DNS_SERVER};
  ropt = dhcp_add_option(ropt, DHCP_OPTION_PARAMETER_REQUEST_LIST, sizeof(prl),
                         prl);

  *ropt++ = DHCP_OPTION_END;
  rp->len = sizeof(struct dhcp_msg);

  return udp_output(rp, dst_ip, 68, 67);
}

void dhcp_start(void) {
  dhcp_got_offer = 0;
  dhcp_got_ack = 0;
  // Don't reset dhcp_offered_ip and dhcp_server_ip - preserve them across retries
  // dhcp_offered_ip = 0;
  // dhcp_server_ip = 0;

  // Some servers/emulations behave better if XID changes between attempts.
  dhcp_xid ^= (uint32_t)pit_ticks;
  dhcp_xid += 0x1020304u;

  struct pbuf *p = pbuf_alloc();
  if (!p)
    return;

  struct dhcp_msg *msg = (struct dhcp_msg *)p->payload;
  for (int i = 0; i < (int)sizeof(struct dhcp_msg); i++)
    ((uint8_t *)msg)[i] = 0;

  msg->op = DHCP_BOOTREQUEST;
  msg->htype = 1; // Ethernet
  msg->hlen = 6;
  msg->xid = htonl(dhcp_xid);
  // Ask the server to broadcast replies (safer while our IP is 0.0.0.0).
  msg->flags = htons(0x8000);
  msg->cookie = htonl(0x63825363);

  uint8_t mac[6];
  arp_get_ajos_mac(mac);
  for (int i = 0; i < 6; i++)
    msg->chaddr[i] = mac[i];

  uint8_t *opt = msg->options;
  uint8_t type = DHCP_DISCOVER;
  opt = dhcp_add_option(opt, DHCP_OPTION_MSG_TYPE, 1, &type);

  // Parameter request list: Mask, Router, DNS
  uint8_t prl[] = {DHCP_OPTION_SUBNET_MASK, DHCP_OPTION_ROUTER,
                   DHCP_OPTION_DNS_SERVER};
  opt = dhcp_add_option(opt, DHCP_OPTION_PARAMETER_REQUEST_LIST, sizeof(prl),
                        prl);

  *opt++ = DHCP_OPTION_END;

  p->len = sizeof(struct dhcp_msg);

  // Send broadcast DISCOVER via UDP 67
  udp_output(p, 0xFFFFFFFF, 68, 67);
}

void dhcp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst) {
  // DHCP/BOOTP has a 240-byte fixed header (incl. magic cookie).
  // Servers may send fewer than sizeof(struct dhcp_msg) bytes, so parse
  // based on the actual UDP payload length.
  if (p->len < 240) {
    pbuf_free(p);
    return;
  }

  struct dhcp_msg *msg = (struct dhcp_msg *)p->payload;
  if (msg->op != DHCP_BOOTREPLY) {
    pbuf_free(p);
    return;
  }

  if (ntohl(msg->xid) != dhcp_xid) {
    pbuf_free(p);
    return;
  }

  uint8_t *opt = msg->options;
  uint8_t *opt_end = ((uint8_t *)p->payload) + p->len;
  uint8_t msg_type = 0;
  ip_addr_t server_id = 0;
  uint32_t netmask = 0;
  uint32_t router = 0;
  uint32_t requested_ip = 0; // Host order IP from REQUESTED_IP_ADDRESS option (option 50)

  while (opt < opt_end && *opt != DHCP_OPTION_END) {
    uint8_t type = *opt++;
    if (type == DHCP_OPTION_PADDING)
      continue;
    if (opt >= opt_end)
      break;
    uint8_t len = *opt++;
    if (opt + len > opt_end)
      break;

    if (type == DHCP_OPTION_MSG_TYPE && len == 1) {
      msg_type = *opt;
    } else if (type == DHCP_OPTION_SERVER_ID && len == 4) {
      server_id = ntohl(*(uint32_t *)opt); // host order
    } else if (type == DHCP_OPTION_SUBNET_MASK && len == 4) {
      netmask = ntohl(*(uint32_t *)opt); // host order
    } else if (type == DHCP_OPTION_ROUTER && len >= 4) {
      router = ntohl(*(uint32_t *)opt); // take first router, host order
    } else if (type == DHCP_OPTION_DNS_SERVER && len >= 4) {
      // Just take the first one
      dns_set_server(ntohl(*(uint32_t *)opt)); // host order
    } else if (type == DHCP_OPTION_REQ_IP && len == 4) {
      // Some servers echo back the requested IP in this option
      requested_ip = ntohl(*(uint32_t *)opt); // host order
    }
    opt += len;
  }

  // QEMU/SLIRP usually provides server-id, but if it's missing fall back
  // to the IP header source address.
  if (server_id == 0) {
    server_id = src;
  }

  if (msg_type == DHCP_OFFER) {
    uint32_t offered_ip = ntohl(msg->yiaddr); // host order
#ifdef AJOS_DHCP_DEBUG
    extern void log_write_hex32(uint32_t v);
    log_writestring("dhcp: OFFER yiaddr=0x");
    log_write_hex32(msg->yiaddr);
    log_writestring(" -> offered_ip=0x");
    log_write_hex32(offered_ip);
    log_putchar('\n');
#endif
    dhcp_got_offer = 1;
    dhcp_offered_ip = offered_ip;
    dhcp_server_ip = server_id;
    if (netmask)
      ip4_set_netmask(netmask);
    if (router)
      ip4_set_gateway(router);

    // Send REQUEST. In practice, some emulations are flaky, so we send both:
    // - broadcast (no ARP required)
    // - unicast to server-id (sometimes preferred)
    (void)dhcp_send_request(offered_ip, server_id, 0xFFFFFFFFu);
    if (server_id != 0 && server_id != 0xFFFFFFFFu) {
      (void)dhcp_send_request(offered_ip, server_id, server_id);
    }

  } else if (msg_type == DHCP_ACK) {
#ifdef AJOS_DHCP_DEBUG
    extern void log_write_hex32(uint32_t v);
    log_writestring("dhcp: ACK yiaddr=0x");
    log_write_hex32(msg->yiaddr);
    log_writestring(" ciaddr=0x");
    log_write_hex32(msg->ciaddr);
    log_writestring(" requested_ip=0x");
    log_write_hex32(requested_ip);
    log_writestring(" offered_ip=0x");
    log_write_hex32(dhcp_offered_ip);
    log_putchar('\n');
#endif

    // Try to get IP from yiaddr field first, then from requested_ip option, then from ciaddr
    uint32_t assigned = ntohl(msg->yiaddr); // host order

    if (assigned == 0 && requested_ip != 0) {
      assigned = requested_ip;
    }
    if (assigned == 0) {
      assigned = ntohl(msg->ciaddr); // Client IP address field (host order)
    }
    // If still 0, use the offered IP from the OFFER we received earlier
    if (assigned == 0 && dhcp_offered_ip != 0) {
      assigned = dhcp_offered_ip;
    }

    if (assigned != 0) {
      arp_set_ajos_ip(assigned);
      // Verify it was set
      extern uint32_t arp_get_ajos_ip(void);
      uint32_t verify = arp_get_ajos_ip();
      if (verify != assigned) {
        extern void log_write_hex32(uint32_t v);
        log_writestring("dhcp: ERROR - IP set failed! verify=0x");
        log_write_hex32(verify);
        log_putchar('\n');
      }
    }
    if (netmask)
      ip4_set_netmask(netmask);
    if (router)
      ip4_set_gateway(router);
    dhcp_got_ack = 1;
  }

  pbuf_free(p);
}
