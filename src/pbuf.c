#include <pbuf.h>

// We need kmalloc/kfree from kernel.c (or a shared header if we refactored)
// For now, let's declare them extern since they are in kernel.c
extern void *kmalloc(uint32_t size);
extern void kfree(void *ptr);
extern void serial_writestring(const char *s); // For debugging

void pbuf_init(void) {
  // Nothing special needed if using kmalloc
}

struct pbuf *pbuf_alloc(void) {
  // Allocate the struct (which includes the buffer)
  struct pbuf *p = (struct pbuf *)kmalloc(sizeof(struct pbuf));
  if (p == NULL) {
    return NULL;
  }

  // Initialize
  p->next = NULL;
  p->payload = p->buffer_s + PBUF_HEADROOM;
  p->len = 0;
  // Usually alloc implies we have space, but payload len
  // is determined by what we put in it.
  // Let's set len to 0 initially, user sets it.
  // Wait, existing stacks usually alloc with a requested size.
  // Since we use fixed size, let's say capacity is PBUF_SIZE.
  p->tot_len = 0;

  return p;
}

void pbuf_free(struct pbuf *p) {
  if (p == NULL) {
    return;
  }
  // If chained, we might want to free the whole chain?
  // For now, simple single free (caller handles chain walk if needed,
  // or we can recurse).
  // Let's allow freeing a chain for convenience.
  struct pbuf *q = p;
  while (q != NULL) {
    struct pbuf *next = q->next;
    kfree(q);
    q = next;
  }
}

int pbuf_header(struct pbuf *p, int offset) {
  if (p == NULL)
    return -1;

  // allow moving payload pointer
  uint8_t *new_payload = p->payload + offset;

  // Check bounds
  // Lower bound: buffer_s
  // Upper bound: buffer_s + PBUF_SIZE
  if (new_payload < p->buffer_s || new_payload >= (p->buffer_s + PBUF_SIZE)) {
    return -1;
  }

  p->payload = new_payload;
  // Note: len is not automatically updated, as this is just reservation.
  return 0;
}
