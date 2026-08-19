#include "netdev.h"
#include "kernel.h"
#include <stddef.h>

// Small fixed registry (AJOS currently has 1 NIC, but keep it extensible).
#define NETDEV_MAX 4

struct netdev_napi_entry {
  const char *name;
  netdev_napi_is_scheduled_fn is_scheduled;
  netdev_napi_poll_fn poll;
};

static struct netdev_napi_entry g_netdevs[NETDEV_MAX];
static int g_netdev_count = 0;

int netdev_napi_register(const char *name, netdev_napi_is_scheduled_fn is_sched,
                         netdev_napi_poll_fn poll) {
  /* One-time init in case these are in BSS range we skip (disk cache). */
  static int napi_inited = 0;
  if (!napi_inited) {
    napi_inited = 1;
    g_netdev_count = 0;
    for (int i = 0; i < NETDEV_MAX; i++) {
      g_netdevs[i].name = NULL;
      g_netdevs[i].is_scheduled = NULL;
      g_netdevs[i].poll = NULL;
    }
  }
  if (!poll)
    return 0;
  if (g_netdev_count < 0 || g_netdev_count >= NETDEV_MAX)
    g_netdev_count = 0;
  if (g_netdev_count >= NETDEV_MAX)
    return 0;
  g_netdevs[g_netdev_count].name = name;
  g_netdevs[g_netdev_count].is_scheduled = is_sched;
  g_netdevs[g_netdev_count].poll = poll;
  g_netdev_count++;
  return 1;
}

int netdev_napi_any_scheduled(void) {
  for (int i = 0; i < g_netdev_count; i++) {
    if (g_netdevs[i].is_scheduled && g_netdevs[i].is_scheduled())
      return 1;
  }
  return 0;
}

int netdev_napi_registry_count(void) {
  if (g_netdev_count < 0 || g_netdev_count > NETDEV_MAX)
    return 0;
  return g_netdev_count;
}

int netdev_napi_poll(int budget) {
  if (budget <= 0)
    return 0;
  if (g_netdev_count <= 0)
    return 0;

  int remaining = budget;
  int total = 0;

  // Prefer draining scheduled NICs first (IRQ signaled work).
  if (netdev_napi_any_scheduled()) {
    for (int i = 0; i < g_netdev_count && remaining > 0; i++) {
      if (g_netdevs[i].is_scheduled && !g_netdevs[i].is_scheduled())
        continue;
      int got = g_netdevs[i].poll(remaining);
      if (got < 0)
        got = 0;
      total += got;
      remaining -= got;
      // If driver didn't consume budget, give others a chance anyway.
    }
    return total;
  }

  // Safety-net polling: give each NIC a slice of the budget.
  for (int i = 0; i < g_netdev_count && remaining > 0; i++) {
    int slice = remaining;
    // Keep it fair-ish: don't let a single NIC monopolize large budgets.
    if (slice > 32)
      slice = 32;
    int got = g_netdevs[i].poll(slice);
    if (got < 0)
      got = 0;
    total += got;
    remaining -= got;
  }
  return total;
}

