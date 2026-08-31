#ifndef NET_H
#define NET_H

#include "pbuf.h"
#include <stdint.h>

#define ETH_ADDR_LEN 6

typedef struct eth_addr {
  uint8_t addr[ETH_ADDR_LEN];
} __attribute__((packed)) eth_addr_t;

struct eth_hdr {
  eth_addr_t dst;
  eth_addr_t src;
  uint16_t type;
} __attribute__((packed));

// Simple IP type
typedef uint32_t ip_addr_t;

#define ETHTYPE_ARP 0x0806
#define ETHTYPE_IP 0x0800
#define ETHTYPE_IPV6 0x86DD

#define IP_PROTO_ICMP 1
#define IP_PROTO_UDP 17
#define IP_PROTO_TCP 6

#define IP_ADDR_LOOPBACK 0x7F000001
#define IP_ADDR_BROADCAST 0xFFFFFFFF

struct ip4_hdr {
  uint8_t v_hl;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t off;
  uint8_t ttl;
  uint8_t proto;
  uint16_t chksum;
  ip_addr_t src;
  ip_addr_t dst;
} __attribute__((packed));

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11

extern volatile uint32_t icmp_last_time_exceeded_src;
extern volatile uint32_t icmp_last_time_exceeded_tick;
extern volatile uint16_t icmp_last_time_exceeded_id;
extern volatile uint16_t icmp_last_time_exceeded_seq;

struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t chksum;
  uint16_t id;
  uint16_t seqno;
} __attribute__((packed));

// Byte swapping for network order (Big Endian)
static inline uint16_t htons(uint16_t v) {
  return (uint16_t)((v << 8) | (v >> 8));
}
#define ntohs htons

void ethernet_input(struct pbuf *p);
struct udp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint16_t len;
  uint16_t chksum;
} __attribute__((packed));

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct tcp_hdr {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t seqno;
  uint32_t ackno;
  uint16_t _offset_flags; // High 4 bits: offset, Low 12 bits: flags
  uint16_t window;
  uint16_t chksum;
  uint16_t urgptr;
} __attribute__((packed));

#define TCP_HDR_OFFSET(h) (ntohs((h)->_offset_flags) >> 12)
#define TCP_HDR_FLAGS(h) (ntohs((h)->_offset_flags) & 0x0FFF)

enum tcp_state {
  TCP_CLOSED,
  TCP_LISTEN,
  TCP_SYN_SENT,
  TCP_SYN_RCVD,
  TCP_ESTABLISHED,
  TCP_FIN_WAIT_1,
  TCP_FIN_WAIT_2,
  TCP_CLOSE_WAIT,
  TCP_CLOSING,
  TCP_LAST_ACK,
  TCP_TIME_WAIT
};

struct tcp_pcb {
  ip_addr_t local_ip;
  ip_addr_t remote_ip;
  uint16_t local_port;
  uint16_t remote_port;
  volatile enum tcp_state state;
  uint32_t state_tick; /* last time this pcb saw a packet (idle reaper) */
  uint32_t snd_nxt;
  uint32_t snd_una; // Send unacknowledged
  uint32_t rcv_nxt;
  /* Peer's advertised recv window (bytes we may have in flight beyond snd_una).
   * Updated from every inbound TCP segment (RFC 793). Was ignored → we could
   * blast past the client's buffer and "kill" SSH after any verbose command. */
  uint16_t peer_wnd;

  // Minimal retransmission tracking (driven by PIT ticks)
  uint32_t last_tx_tick;
  uint16_t last_tx_flags;
  uint8_t rtx_count;

  // Track one small data segment for best-effort retransmit (e.g. HTTP
  // request).
  uint32_t last_tx_seq;
  uint16_t last_tx_len;
#define TCP_RTX_DATA_MAX 256
  uint8_t last_tx_data[TCP_RTX_DATA_MAX];

  // Simple application RX buffer (used by `http_get` to print synchronously,
  // and to stage incoming TLS ciphertext before tls_pump() decrypts it).
  // Must hold at least one full TLS 1.2 record: servers commonly pack up
  // to the protocol max of 2^14 (16384) plaintext bytes per record, which
  // on the wire is 5 (header) + 8 (GCM explicit nonce) + 16384 + 16 (tag)
  // = 16413 bytes. Below that, a single maximal record can never be
  // "complete" in this buffer and the connection stalls forever waiting
  // for more bytes that already arrived (seen live against nginx sites
  // serving pages > 16KB, e.g. wantok.vu).
  //
  // Sized for 3 records at once (not just 1) so a big page needs a third
  // as many window-reopen round trips through QEMU's slirp NAT, which
  // measured a consistent ~5s tax per reopen against a real site at the
  // 1-record size. Confirmed live, repeatedly: a 261KB page (17 records)
  // that took ~81s at 16640 completed in ~2.8s at this size — a bigger
  // win than the naive "3x fewer reopens" math suggests, so there's
  // likely a threshold in slirp's own forwarding behavior beyond just
  // linear round-trip counting. (An earlier attempt at this same change
  // was reverted after one bad test run; in hindsight that was most
  // likely a one-off against a real-world link with measured packet loss
  // — ~20% in a ping sample — not a bug in the larger buffer itself.)
  //
  // Kept safely under 65536: the wire window field is 16 bits and
  // app_rx_len below is itself a uint16_t, so anything from here up to
  // 65535 is representable, but a buffer size that's an exact multiple
  // of 65536 truncates the *advertised window* to zero, not merely a
  // small one — caught live going straight from 16640 to 131072.
#define TCP_APP_RX_MAX 49152
  volatile uint16_t app_rx_len;
  uint8_t app_rx_buf[TCP_APP_RX_MAX];
};

int ethernet_output(struct pbuf *p, eth_addr_t *dst, uint16_t type);

void ip4_input(struct pbuf *p);
int ip4_output(struct pbuf *p, ip_addr_t dst, uint8_t proto);
int ip4_output_ttl(struct pbuf *p, ip_addr_t dst, uint8_t proto, uint8_t ttl);
uint32_t ip4_get_policy_drop_count(void);
int ip4_policy_filter(struct pbuf *p, struct ip4_hdr *hdr, uint8_t hl);

void icmp_input(struct pbuf *p, ip_addr_t src, uint8_t ttl);

void udp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst);
int udp_output(struct pbuf *p, ip_addr_t dst, uint16_t src_port,
               uint16_t dst_port);

void tcp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst);
void tcp_init(void);
void tcp_tick(uint32_t now_ticks);
struct tcp_pcb *tcp_get_free_pcb(void);
int tcp_connect(struct tcp_pcb *pcb, ip_addr_t remote_ip, uint16_t remote_port);
int tcp_send(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len);
int tcp_close(struct tcp_pcb *pcb);
void tcp_announce_window(struct tcp_pcb *pcb);

uint16_t net_checksum(void *data, int len);

// Network configuration
int netcfg_load_from_buffer(const char *buf, int len);

// Simple IP type

// Network byte order macros for 32-bit (IPv4)
//
// AJOS convention: IPv4 addresses are stored internally as 0x0A00020F for
// 10.0.2.15 (i.e., "big-endian numeric"). But the CPU is little-endian, so
// when we read/write 32-bit fields in on-wire headers, we must byteswap.
static inline uint32_t htonl(uint32_t v) {
  return ((v & 0xFF000000u) >> 24) | ((v & 0x00FF0000u) >> 8) |
         ((v & 0x0000FF00u) << 8) | ((v & 0x000000FFu) << 24);
}
#define ntohl htonl

// DHCP
#define DHCP_BOOTREQUEST 1
#define DHCP_BOOTREPLY 2

struct dhcp_msg {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  ip_addr_t ciaddr;
  ip_addr_t yiaddr;
  ip_addr_t siaddr;
  ip_addr_t giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint32_t cookie;
  uint8_t options[308]; // Fixed size for simplicity in AJOS
} __attribute__((packed));

#define DHCP_MSG_LEN sizeof(struct dhcp_msg)

#define DHCP_DISCOVER 1
#define DHCP_OFFER 2
#define DHCP_REQUEST 3
#define DHCP_DECLINE 4
#define DHCP_ACK 5
#define DHCP_NAK 6
#define DHCP_RELEASE 7

#define DHCP_OPTION_PADDING 0
#define DHCP_OPTION_SUBNET_MASK 1
#define DHCP_OPTION_ROUTER 3
#define DHCP_OPTION_DNS_SERVER 6
#define DHCP_OPTION_HOSTNAME 12
#define DHCP_OPTION_REQ_IP 50
#define DHCP_OPTION_LEASE_TIME 51
#define DHCP_OPTION_MSG_TYPE 53
#define DHCP_OPTION_SERVER_ID 54
#define DHCP_OPTION_PARAMETER_REQUEST_LIST 55
#define DHCP_OPTION_END 255

void dhcp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst);
void dhcp_start(void);

// DNS
struct dns_hdr {
  uint16_t id;
  uint16_t flags;
  uint16_t num_questions;
  uint16_t num_answers;
  uint16_t num_authrr;
  uint16_t num_extrarr;
} __attribute__((packed));

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_OPCODE 0x7800
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_FLAG_RCODE 0x000F

#define DNS_RRTYPE_A 1
#define DNS_RRCLASS_IN 1

void dns_input(struct pbuf *p);
void dns_lookup(const char *name);
void dns_init(void);
ip_addr_t dns_get_server(void);

// Basic IPv4 interface config (netmask/gateway)
void ip4_init(void);
void ip4_set_netmask(ip_addr_t mask);
ip_addr_t ip4_get_netmask(void);
void ip4_set_gateway(ip_addr_t gw);
void ip4_set_netmask_ip(int iface, ip_addr_t mask);
void ip4_set_gateway_ip(int iface, ip_addr_t gw);
uint32_t ip4_get_if_netmask(int iface);
uint32_t ip4_get_if_gw(int iface);
ip_addr_t ip4_get_gateway(void);

#endif
/* 0 = accepted for transmit (snd_nxt advanced); -1 = dropped (queued for rtx). */
int tcp_send_data(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len);
