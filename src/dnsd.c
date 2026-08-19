#include "dnsd.h"
#include "net.h"
#include "pbuf.h"
#include <stddef.h>

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void log_write_hex32(uint32_t v);
extern uint32_t arp_get_ajos_ip(void);
extern int udp_output(struct pbuf *p, uint32_t dst, uint16_t src_port,
                      uint16_t dst_port);

// Helper to allow htons() usage if not defined
static uint16_t dns_htons(uint16_t v) { return (v << 8) | (v >> 8); }
static uint16_t dns_ntohs(uint16_t v) { return (v << 8) | (v >> 8); }
static uint32_t dns_htonl(uint32_t v) {
  return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v & 0xFF0000) >> 8) |
         ((v >> 24) & 0xFF);
}

// Stats
static uint32_t dns_queries_handled = 0;

void dnsd_init(void) {
  log_writestring("[DNSD] Hijacker initialized on port 53\n");
}

void dnsd_handle_packet(struct pbuf *p, uint32_t src_ip, uint16_t src_port,
                        uint16_t dst_port) {
  if (p->len < sizeof(struct dns_hdr))
    return;

  struct dns_hdr *hdr = (struct dns_hdr *)p->payload;
  uint16_t flags = dns_ntohs(hdr->flags);

  // Only handle Queries (QR=0) and standard opcode (0)
  if ((flags & DNS_FLAG_QR) != 0)
    return;
  if ((flags & DNS_FLAG_OPCODE) != 0)
    return;

  uint16_t q_count = dns_ntohs(hdr->num_questions);
  if (q_count != 1)
    return; // Only process single question packets for simplicity

  // Create Response
  // Re-use incoming pbuf if it has space, or allocate new.
  // Safer to allocate new to avoid thrashing received buffer if we needed it.

  struct pbuf *resp = pbuf_alloc();
  if (!resp)
    return;

  // We need to copy the query question section verbatim
  // Structure: [Header] [QuestionName... 0] [Type:2] [Class:2]
  int q_len = 0;
  uint8_t *q_start = (uint8_t *)p->payload + sizeof(struct dns_hdr);
  uint8_t *ptr = q_start;

  // Find end of name
  while (*ptr != 0 && (ptr - (uint8_t *)p->payload < p->len)) {
    ptr += (*ptr) + 1;
  }
  if (*ptr != 0) {
    pbuf_free(resp);
    return;
  } // Malformed
  ptr++;    // Skip 0
  ptr += 4; // Skip Type and Class

  q_len = (int)(ptr - q_start);

  int resp_size =
      sizeof(struct dns_hdr) + q_len + 16; // Header + Q + Answer Header + IP

  // Copy Header
  struct dns_hdr *rh = (struct dns_hdr *)resp->payload;
  rh->id = hdr->id;              // Echo ID
  rh->flags = dns_htons(0x8400); // QR=1, AA=1, RA=0, RCODE=0
  rh->num_questions = dns_htons(1);
  rh->num_answers = dns_htons(1);
  rh->num_authrr = 0;
  rh->num_extrarr = 0;

  // Copy Question
  uint8_t *data = (uint8_t *)resp->payload + sizeof(struct dns_hdr);
  for (int i = 0; i < q_len; i++)
    data[i] = q_start[i];
  data += q_len;

  // Append Answer
  // Name: Pointer to query name (offset 12 = 0x0C)
  // 0xC00C
  *data++ = 0xC0;
  *data++ = 0x0C;

  // Type: A (1)
  *data++ = 0;
  *data++ = 1;

  // Class: IN (1)
  *data++ = 0;
  *data++ = 1;

  // TTL: 60
  *data++ = 0;
  *data++ = 0;
  *data++ = 0;
  *data++ = 60;

  // Data Length: 4
  *data++ = 0;
  *data++ = 4;

  // IP Address: 10.0.2.15 (or dynamic)
  uint32_t my_ip = arp_get_ajos_ip();
  // IP is network byte order in packet
  // my_ip from AJOS is usually host or network?
  // arp_get_ajos_ip usually returns logical IP (Likely Big Endian or Little
  // Endian depending on arch) But typically we write bytes. 10.0.2.15 -> 0A 00
  // 02 0F
  *data++ = (my_ip >> 24) & 0xFF; // If my_ip is BE (0x0A...) -> 0A
  // If my_ip is LE (0x...0A) -> this logic depends.
  // AJOS networking seems slightly mixed, but typically IP vars are BE.
  *data++ = (my_ip >> 16) & 0xFF;
  *data++ = (my_ip >> 8) & 0xFF;
  *data++ = (my_ip) & 0xFF;

  resp->len = (uint16_t)(data - (uint8_t *)resp->payload);

  // Send back to the client
  // src_ip and src_port are already passed to us from udp_input
  udp_output(resp, src_ip, 53, src_port);
  
  // Note: udp_output will free the pbuf, so we don't free it here
  dns_queries_handled++;
}

void dnsd_stat(void) {
  log_writestring("[DNSD] Queries handled: ");
  log_write_u32(dns_queries_handled);
  log_putchar('\n');
}
