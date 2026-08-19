#ifndef NETDEV_H
#define NETDEV_H

// Minimal "net_device + NAPI" inspired RX polling registry.
// Drivers register (is_scheduled, poll) hooks; the kernel calls netdev_napi_poll().

#include <stdint.h>

typedef int (*netdev_napi_is_scheduled_fn)(void);
typedef int (*netdev_napi_poll_fn)(int budget);

// Register a NIC's NAPI hooks. Returns 1 on success, 0 on failure.
int netdev_napi_register(const char *name, netdev_napi_is_scheduled_fn is_sched,
                         netdev_napi_poll_fn poll);

// Returns 1 if any registered NIC reports scheduled work.
int netdev_napi_any_scheduled(void);

// Poll RX across NICs with a total budget. Returns number of packets processed.
int netdev_napi_poll(int budget);

// Number of NICs registered for NAPI (debug / diagnostics).
int netdev_napi_registry_count(void);

#endif

