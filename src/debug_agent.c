#include "debug_agent.h"
#include "kernel.h"

extern volatile uint32_t pit_ticks;

static void append_u32(char *b, int *i, int cap, uint32_t v) {
  char t[12];
  int k = 0;
  if (v == 0) {
    if (*i < cap - 1)
      b[(*i)++] = '0';
    return;
  }
  while (v && k < 11) {
    t[k++] = (char)('0' + (v % 10u));
    v /= 10u;
  }
  while (k > 0 && *i < cap - 1)
    b[(*i)++] = t[--k];
}

void agent_dbg_evt(const char *hypothesisId, const char *location,
                   const char *message, uint32_t data1, uint32_t data2) {
  char b[384];
  int i = 0;
  const int cap = (int)sizeof(b);
  const char *s;
  uint32_t eflags;
  __asm__ volatile("pushf; pop %0" : "=r"(eflags) : : "memory");
  __asm__ volatile("cli" ::: "memory");
#define W(str)                                                               \
  do {                                                                       \
    for (s = (str); *s && i < cap - 2; s++)                                    \
      b[i++] = *s;                                                           \
  } while (0)

  W("{\"sessionId\":\"6dc877\",\"hypothesisId\":\"");
  W(hypothesisId);
  W("\",\"location\":\"");
  W(location);
  W("\",\"message\":\"");
  W(message);
  W("\",\"data\":{\"d1\":");
  append_u32(b, &i, cap, data1);
  W(",\"d2\":");
  append_u32(b, &i, cap, data2);
  W("},\"timestamp\":");
  append_u32(b, &i, cap, pit_ticks);
  W("}\n");
  b[i] = '\0';
  serial_writestring(b);
  if (eflags & 0x200u)
    __asm__ volatile("sti" ::: "memory");
#undef W
}

void agent_dbg_ping_to(uint32_t icmp_before, uint32_t icmp_after,
                       uint32_t eth_delta, uint32_t ip4_delta,
                       uint32_t policy_drops, uint32_t last_echo_src) {
  char b[160];
  int i = 0;
  const int cap = (int)sizeof(b);
  const char *s;
  uint32_t eflags;
  __asm__ volatile("pushf; pop %0" : "=r"(eflags) : : "memory");
  __asm__ volatile("cli" ::: "memory");
#define W(str)                                                               \
  do {                                                                       \
    for (s = (str); *s && i < cap - 2; s++)                                    \
      b[i++] = *s;                                                           \
  } while (0)
  W("@6dc877 ping ");
  append_u32(b, &i, cap, icmp_before);
  W(" ");
  append_u32(b, &i, cap, icmp_after);
  W(" ");
  append_u32(b, &i, cap, eth_delta);
  W(" ");
  append_u32(b, &i, cap, ip4_delta);
  W(" ");
  append_u32(b, &i, cap, policy_drops);
  W(" ");
  append_u32(b, &i, cap, last_echo_src);
  W(" ");
  append_u32(b, &i, cap, pit_ticks);
  W("\n");
  b[i] = '\0';
  serial_writestring(b);
  if (eflags & 0x200u)
    __asm__ volatile("sti" ::: "memory");
#undef W
}

void agent_dbg_ping_hw(uint32_t ring_pack, uint32_t flg_icr, uint32_t netdev_cnt) {
  char b[120];
  int i = 0;
  const int cap = (int)sizeof(b);
  const char *s;
  uint32_t eflags;
  __asm__ volatile("pushf; pop %0" : "=r"(eflags) : : "memory");
  __asm__ volatile("cli" ::: "memory");
#define W(str)                                                               \
  do {                                                                       \
    for (s = (str); *s && i < cap - 2; s++)                                    \
      b[i++] = *s;                                                           \
  } while (0)
  W("@6dc877 hw ");
  append_u32(b, &i, cap, ring_pack);
  W(" ");
  append_u32(b, &i, cap, flg_icr);
  W(" ");
  append_u32(b, &i, cap, netdev_cnt);
  W(" ");
  append_u32(b, &i, cap, pit_ticks);
  W("\n");
  b[i] = '\0';
  serial_writestring(b);
  if (eflags & 0x200u)
    __asm__ volatile("sti" ::: "memory");
#undef W
}
