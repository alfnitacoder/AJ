#ifndef PBUF_H
#define PBUF_H

#include <stddef.h>
#include <stdint.h>

// Simplified Packet Buffer (inspired by LwIP/BSD)
// Fixed size for now to simplify allocation.
#define PBUF_SIZE 2048
/* pbuf_alloc() starts payload here; never copy more than this many bytes at payload. */
#define PBUF_HEADROOM 64u
#define PBUF_PAYLOAD_CAP (PBUF_SIZE - PBUF_HEADROOM)

struct pbuf {
  struct pbuf *next; // Next buffer in chain (or queue)
  uint8_t *payload;  // Pointer to actual data start
  uint32_t len;      // Length of data in this buffer
  uint32_t tot_len;  // Total length of packet (if chained)

  // Internal storage
  uint8_t buffer_s[PBUF_SIZE];
};

// API
void pbuf_init(void);
struct pbuf *pbuf_alloc(void);
void pbuf_free(struct pbuf *p);

// Adjusts the payload pointer (e.g. to reserve space for headers)
// offset > 0: shrinking payload (moving pointer forward)
// offset < 0: expanding payload (moving pointer backward)
// Returns 0 on success, -1 if out of bounds.
int pbuf_header(struct pbuf *p, int offset);

#endif
