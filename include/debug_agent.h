#ifndef DEBUG_AGENT_H
#define DEBUG_AGENT_H

#include <stdint.h>

/* One NDJSON line on COM1 for Cursor debug mode (session 6dc877). */
void agent_dbg_evt(const char *hypothesisId, const char *location,
                   const char *message, uint32_t data1, uint32_t data2);

/* One short line (COM1-safe): icmp count before/after wait, eth & ip4 rx deltas,
 * policy drops, last echo-reply src, pit tick. */
void agent_dbg_ping_to(uint32_t icmp_before, uint32_t icmp_after,
                       uint32_t eth_delta, uint32_t ip4_delta,
                       uint32_t policy_drops, uint32_t last_echo_src);

/* COM1-safe: ring_pack, flg_icr (e1000_debug_snap), netdev registry count, pit. */
void agent_dbg_ping_hw(uint32_t ring_pack, uint32_t flg_icr, uint32_t netdev_cnt);

#endif
