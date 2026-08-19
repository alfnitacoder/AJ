#include "dhcpd.h"
#include "net.h"
#include <stddef.h>

// External functions
// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void log_write_hex32(uint32_t v);
extern uint32_t arp_get_ajos_ip(void);
extern int udp_output(struct pbuf *p, uint32_t dst, uint16_t src_port,
                      uint16_t dst_port);

// Helper memory functions
static void *kmemset(void *ptr, int value, size_t num) {
  unsigned char *p = ptr;
  while (num--)
    *p++ = (unsigned char)value;
  return ptr;
}

static void *kmemcpy(void *dst, const void *src, size_t num) {
  unsigned char *d = dst;
  const unsigned char *s = src;
  while (num--)
    *d++ = *s++;
  return dst;
}

// Server Configuration
static struct dhcp_config config;
#define MAX_LEASES 50
static struct dhcp_lease leases[MAX_LEASES];

// Initialize DHCP Server
void dhcpd_init(void) {
  // Configure Pool (Example: 10.0.2.50 - 10.0.2.100)
  // In a real setup, this might come from NETWORK.CFG
  uint32_t my_ip = arp_get_ajos_ip();
  
  // If IP is 0.0.0.0, use default for hotspot mode
  // This allows hotspot to work even before static IP is configured
  if (my_ip == 0) {
    my_ip = (10u << 24) | (0u << 16) | (2u << 8) | (15u); // 10.0.2.15
  }

  config.server_ip = my_ip;
  config.start_ip = (my_ip & 0xFFFFFF00) | 50; // .50
  config.end_ip = (my_ip & 0xFFFFFF00) | 100;  // .100
  config.netmask = 0x00FFFFFF;                 // 255.255.255.0
  config.gateway = my_ip;                      // We are the gateway
  config.dns = my_ip;                          // We are the DNS server
  config.lease_time = 3600;                    // 1 hour

  // Clear leases
  for (int i = 0; i < MAX_LEASES; i++) {
    leases[i].in_use = 0;
  }

  log_writestring("[DHCPD] Server initialized on port 67\n");
  log_writestring("[DHCPD] Pool: .50 - .100\n");
}

// Reinitialize DHCP server with current IP (call after IP changes)
void dhcpd_reinit(void) {
  uint32_t my_ip = arp_get_ajos_ip();
  
  // Only reinit if we have a valid IP
  if (my_ip != 0) {
    config.server_ip = my_ip;
    config.start_ip = (my_ip & 0xFFFFFF00) | 50;
    config.end_ip = (my_ip & 0xFFFFFF00) | 100;
    config.gateway = my_ip;
    config.dns = my_ip;
    
    log_writestring("[DHCPD] Reinitialized with new IP\n");
  }
}

// Helper code to write options
static uint8_t *dhcp_add_option(uint8_t *ptr, uint8_t code, uint8_t len,
                                const void *data) {
  *ptr++ = code;
  *ptr++ = len;
  kmemcpy(ptr, data, len);
  return ptr + len;
}

static uint8_t *dhcp_add_u32_option(uint8_t *ptr, uint8_t code, uint32_t val) {
  // DHCP options are network byte order (Big Endian)
  // Assuming our system is Little Endian, we need to swap?
  // Actually, AJOS networking seems to handle endianness manually or assume BE
  // in places. Standard DHCP is Big Endian. htonl implementation:
  uint8_t bytes[4];
  bytes[0] = (val >> 24) & 0xFF;
  bytes[1] = (val >> 16) & 0xFF;
  bytes[2] = (val >> 8) & 0xFF;
  bytes[3] = val & 0xFF;
  return dhcp_add_option(ptr, code, 4, bytes);
}

// Find or Create Lease
static struct dhcp_lease *dhcpd_find_lease(const uint8_t *mac) {
  // Look for existing lease
  for (int i = 0; i < MAX_LEASES; i++) {
    if (leases[i].in_use) {
      int match = 1;
      for (int j = 0; j < 6; j++) {
        if (leases[i].mac[j] != mac[j]) {
          match = 0;
          break;
        }
      }
      if (match)
        return &leases[i];
    }
  }

  // Allocate new lease
  for (int i = 0; i < MAX_LEASES; i++) {
    if (!leases[i].in_use) {
      leases[i].in_use = 1;
      for (int j = 0; j < 6; j++)
        leases[i].mac[j] = mac[j];

      // Assign next IP
      // Simple allocation: start_ip + index
      uint32_t new_ip =
          (config.start_ip & 0xFFFFFF00) | ((config.start_ip & 0xFF) + i);
      if (new_ip > config.end_ip) {
        leases[i].in_use = 0;
        return NULL; // Pool exhausted
      }
      leases[i].ip = new_ip;
      leases[i].expiry = 0; // TODO: Real timestamp
      return &leases[i];
    }
  }
  return NULL; // No free leases
}

// Send DHCP Packet (OFFER or ACK)
static void dhcpd_send_reply(struct dhcp_packet *req, uint8_t type,
                             struct dhcp_lease *lease) {
  struct pbuf *p = pbuf_alloc();
  if (!p)
    return;

  // Get current IP dynamically (in case it changed after init)
  uint32_t current_ip = arp_get_ajos_ip();
  if (current_ip == 0) {
    // Fallback to config if IP not set yet
    current_ip = config.server_ip;
  }

  // Calculate size (Header + Options)
  // For simplicity, allocate enough standard size
  // pbuf_alloc usually gives us PBUF_SIZE (default 1500 or so) payload

  struct dhcp_packet *reply = (struct dhcp_packet *)p->payload;
  kmemset(reply, 0, sizeof(struct dhcp_packet));

  // Basic Header
  reply->op = 2;    // BOOTREPLY
  reply->htype = 1; // Ethernet
  reply->hlen = 6;
  reply->xid = req->xid;
  reply->secs = 0;
  reply->flags = req->flags; // Copy flags (broadcast bit usually)
  reply->ciaddr = 0;
  reply->yiaddr = htonl(lease->ip);        // Your IP
  reply->siaddr = htonl(current_ip);       // Server IP (use current)
  reply->giaddr = 0;
  kmemcpy(reply->chaddr, req->chaddr, 16);
  reply->cookie = htonl(DHCP_MAGIC_COOKIE);

  // Options
  uint8_t *opts = reply->options;

  // Message Type
  uint8_t type_byte = type;
  opts = dhcp_add_option(opts, 53, 1, &type_byte);

  // Server Identifier
  opts = dhcp_add_u32_option(opts, 54, current_ip);

  // Lease Time
  opts = dhcp_add_u32_option(opts, 51, config.lease_time);

  // Subnet Mask
  opts = dhcp_add_u32_option(opts, 1, config.netmask);

  // Router (Gateway)
  opts = dhcp_add_u32_option(opts, 3, current_ip); // Option 3 is Router (use current IP)

  // DNS Server
  opts = dhcp_add_u32_option(opts, 6, current_ip); // Use current IP

  // End Option
  *opts++ = 255;

  // Adjust pbuf length
  p->len = (uint16_t)(((uint8_t *)opts) - ((uint8_t *)reply));

  // Send UDP packet
  // Destination: Broadcast 255.255.255.255
  // Port: 68 (Client)
  // udp_output(p, dst_ip, src_port, dst_port)
  udp_output(p, 0xFFFFFFFF, DHCP_SERVER_PORT, DHCP_CLIENT_PORT);

  pbuf_free(p);
}

// Handle Incoming Packet
void dhcpd_handle_packet(struct pbuf *p) {
  if (p->len < sizeof(struct dhcp_packet) - 308)
    return; // Too short

  struct dhcp_packet *pkt = (struct dhcp_packet *)p->payload;

  if (pkt->op != 1)
    return; // Ignore replies (only handle requests)

  // Parse Options to find Message Type
  int type = 0;
  uint8_t *opt = pkt->options;
  uint8_t *end = (uint8_t *)pkt + p->len;

  // Check cookie
  if (pkt->cookie != htonl(DHCP_MAGIC_COOKIE))
    return;

  while (opt < end && *opt != 255) {
    uint8_t code = *opt++;
    if (code == 0)
      continue; // Pad
    uint8_t len = *opt++;

    if (code == 53 && len == 1) { // DHCP Message Type
      type = *opt;
    }

    opt += len;
  }

  if (type == DHCP_DISCOVER) {
    log_writestring("[DHCPD] Received DISCOVER from ");
    log_write_hex32(pkt->chaddr[5]); // Just last byte
    log_putchar('\n');

    struct dhcp_lease *lease = dhcpd_find_lease(pkt->chaddr);
    if (lease) {
      dhcpd_send_reply(pkt, DHCP_OFFER, lease);
      log_writestring("[DHCPD] Sent OFFER: ");
      log_write_u32(lease->ip); // Note: this prints raw bits unless helper used
      log_putchar('\n');
    }
  } else if (type == DHCP_REQUEST) {
    log_writestring("[DHCPD] Received REQUEST\n");
    // Should verify requested IP matches lease
    struct dhcp_lease *lease = dhcpd_find_lease(pkt->chaddr);
    if (lease) {
      dhcpd_send_reply(pkt, DHCP_ACK, lease);
      log_writestring("[DHCPD] Sent ACK\n");
    }
  }
}

void dhcpd_stat(void) {
  log_writestring("[DHCPD] Active Leases:\n");
  for (int i = 0; i < MAX_LEASES; i++) {
    if (leases[i].in_use) {
      log_writestring("  IP: ");
      // Simple print IP bytes
      uint8_t *ip = (uint8_t *)&leases[i].ip;
      log_write_u32(ip[3]);
      log_putchar('.');
      log_write_u32(ip[2]);
      log_putchar('.');
      log_write_u32(ip[1]);
      log_putchar('.');
      log_write_u32(ip[0]);
      log_writestring("  MAC: ");
      log_write_hex32(leases[i].mac[5]); // Just last byte for brevity?
      log_putchar('\n');
    }
  }
}
