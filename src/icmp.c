#include "net.h"
#include "pbuf.h"
#include <stddef.h>
#include <stdint.h>

// Extern kernel functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);

// Last echo reply info (for the `ping` shell command)
volatile uint32_t icmp_last_echo_reply_src = 0;
volatile uint16_t icmp_last_echo_reply_id = 0;
volatile uint16_t icmp_last_echo_reply_seq = 0;
volatile uint8_t icmp_last_echo_reply_ttl = 0;
volatile uint32_t icmp_echo_reply_count = 0;

// Last Time Exceeded info (for `traceroute`)
volatile uint32_t icmp_last_time_exceeded_src = 0;
volatile uint32_t icmp_last_time_exceeded_tick = 0;
volatile uint16_t icmp_last_time_exceeded_id = 0;
volatile uint16_t icmp_last_time_exceeded_seq = 0;

void icmp_input(struct pbuf *p, ip_addr_t src, uint8_t ttl) {
  if (p->len < sizeof(struct icmp_hdr)) {
    pbuf_free(p);
    return;
  }

  struct icmp_hdr *hdr = (struct icmp_hdr *)p->payload;

  if (hdr->type == ICMP_TYPE_ECHO_REQUEST) {
    // Echo Reply: Swap types, recalculate checksum
    hdr->type = ICMP_TYPE_ECHO_REPLY;
    hdr->chksum = 0;

    // The checksum covers header and data. p->len is current payload len (ICMP)
    hdr->chksum = net_checksum(hdr, p->len);

    // Send back via IP layer
    // pbuf still points to ICMP header. ip4_output will prepend IP header.
    ip4_output(p, src, IP_PROTO_ICMP);
    return;
  }

  if (hdr->type == ICMP_TYPE_ECHO_REPLY) {
    icmp_last_echo_reply_src = src;
    icmp_last_echo_reply_id = ntohs(hdr->id);
    icmp_last_echo_reply_seq = ntohs(hdr->seqno);
    icmp_last_echo_reply_ttl = ttl;
    icmp_echo_reply_count++;

    pbuf_free(p);
    return;
  }

  if (hdr->type == ICMP_TYPE_TIME_EXCEEDED) {
    // Time Exceeded Message Format:
    // [IP Header] [ICMP Header (Type 11, Code 0, Chksum, Unused 4 bytes)]
    // [Original IP Header (20 bytes)] [Original 64 bits of Data]
    //
    // The Original 64 bits of Data for an ICMP Echo Request (our probe)
    // contains: [Type(1), Code(1), Chksum(2), ID(2), Seq(2)]
    //
    // So we need to parse:
    // p->payload (ICMP Header) + 8 bytes (Header len) -> Original IP Header
    // Original IP Header + IHL -> Original ICMP Header
    // Original ICMP Header -> ID, Seq

    if (p->len >= 8 + sizeof(struct ip4_hdr) + 8) {
      uint8_t *data =
          (uint8_t *)p->payload + 8; // Skip ICMP Time Exceeded Header
      struct ip4_hdr *orig_ip = (struct ip4_hdr *)data;
      uint8_t orig_ihl = (orig_ip->v_hl & 0x0F) * 4;

      if (p->len >= 8 + orig_ihl + 8) {
        uint8_t *orig_icmp_data = data + orig_ihl;
        // Treat as ICMP header to extract ID and Seq
        struct icmp_hdr *orig_icmp = (struct icmp_hdr *)orig_icmp_data;

        // Only care if it was our ECHO REQUEST
        if (orig_icmp->type == ICMP_TYPE_ECHO_REQUEST) {
          extern uint32_t pit_ticks;
          icmp_last_time_exceeded_src = src;
          icmp_last_time_exceeded_tick = pit_ticks;
          icmp_last_time_exceeded_id = ntohs(orig_icmp->id);
          icmp_last_time_exceeded_seq = ntohs(orig_icmp->seqno);
        }
      }
    }
    pbuf_free(p);
    return;
  }

  pbuf_free(p);
}
