#ifndef E1000_H
#define E1000_H

#include <stdint.h>

void e1000_probe(void);
extern int e1000_device_count;
extern uint8_t e1000_mac[6];

int e1000_tx_send_raw(const uint8_t *frame, uint16_t len);
int e1000_rx_poll_one(void);
// NAPI-style polling helpers (Linux-inspired): IRQ schedules, timer/busy-waits poll.
void e1000_napi_schedule(void);
int e1000_napi_is_scheduled(void);
int e1000_napi_poll(int budget);
void cmd_ifconfig(const char *args);

void e1000_disable_interrupts(void);
void e1000_enable_interrupts(void);

/* Debug: rx_head vs HW RDH/RDT, DD at head, flags+ICR (see e1000_debug_snap). */
void e1000_debug_snap(uint32_t *out_ring_pack, uint32_t *out_flags_icr);

// Constants
#define MAX_E1000_DEVICES 1
#define E1000_TX_RING_SIZE 32
#define E1000_RX_RING_SIZE 32

extern uint8_t e1000_mac[6];

#endif
