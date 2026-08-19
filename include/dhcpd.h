#ifndef DHCPD_H
#define DHCPD_H

#include "net.h"
#include <stdint.h>

// DHCP Ports
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

// DHCP Message Types (Option 53)
#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7
#define DHCP_INFORM 8

// DHCP Header Structure
struct dhcp_packet {
  uint8_t op;           // 1=BootRequest, 2=BootReply
  uint8_t htype;        // Hardware type (1=Ethernet)
  uint8_t hlen;         // Hardware addr len (6=Ethernet)
  uint8_t hops;         // Gateway hops
  uint32_t xid;         // Transaction ID
  uint16_t secs;        // Seconds elapsed
  uint16_t flags;       // Broadcast flag
  uint32_t ciaddr;      // Client IP
  uint32_t yiaddr;      // Your IP (assigned)
  uint32_t siaddr;      // Server IP
  uint32_t giaddr;      // Gateway IP
  uint8_t chaddr[16];   // Client Hardware Address
  uint8_t sname[64];    // Server Hostname
  uint8_t file[128];    // Boot Filename
  uint32_t cookie;      // Magic Cookie (0x63825363)
  uint8_t options[308]; // Options area
} __attribute__((packed));

#define DHCP_MAGIC_COOKIE 0x63825363

// DHCP Lease Structure
struct dhcp_lease {
  uint32_t ip;
  uint8_t mac[6];
  uint32_t expiry; // Timestamp when lease expires
  uint8_t in_use;
};

// DHCP Server Configuration
struct dhcp_config {
  uint32_t server_ip;
  uint32_t start_ip;
  uint32_t end_ip;
  uint32_t netmask;
  uint32_t gateway;
  uint32_t dns;
  uint32_t lease_time;
};

// Function Declarations
void dhcpd_init(void);
void dhcpd_reinit(void);
void dhcpd_handle_packet(struct pbuf *p);
void dhcpd_stat(void);

#endif // DHCPD_H
