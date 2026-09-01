#include "debug_agent.h"
#include "e1000.h"
#include "kernel.h"
#include "minoca/mm.h"
#include "net.h"
#include "netdev.h"
#include "pci.h"

typedef struct {
  int present;
  uint8_t bus, dev, func;
  uint16_t vendor_id, device_id;
  uint16_t io_base;
  uint32_t mmio_phys;
  volatile uint8_t *mmio;
  uint8_t irq_line;
  uint8_t mac[6];
  int enabled;  // Interface enabled/disabled
  char name[8]; // Interface name (eth0, eth1, etc.)
} e1000_dev_t;

// E1000 TX descriptor (legacy)
typedef struct __attribute__((packed)) {
  uint64_t addr;
  uint16_t length;
  uint8_t cso;
  uint8_t cmd;
  uint8_t status;
  uint8_t css;
  uint16_t special;
} e1000_tx_desc_t;

typedef struct __attribute__((packed)) {
  uint64_t addr;
  uint16_t length;
  uint16_t checksum;
  uint8_t status;
  uint8_t errors;
  uint16_t special;
} e1000_rx_desc_t;

// Per-device TX/RX rings
typedef struct {
  volatile e1000_tx_desc_t tx_ring[E1000_TX_RING_SIZE]
      __attribute__((aligned(4096)));
  uint8_t tx_bufs[E1000_TX_RING_SIZE][2048] __attribute__((aligned(16)));
  uint32_t tx_tail;

  volatile e1000_rx_desc_t rx_ring[E1000_RX_RING_SIZE]
      __attribute__((aligned(4096)));
  uint8_t rx_bufs[E1000_RX_RING_SIZE][2048] __attribute__((aligned(16)));
  uint32_t rx_head;
} e1000_rings_t;

static e1000_dev_t e1000_devices[MAX_E1000_DEVICES];
static e1000_rings_t e1000_rings_storage[MAX_E1000_DEVICES]
    __attribute__((aligned(4096)));
static e1000_rings_t *e1000_rings[MAX_E1000_DEVICES];
int e1000_device_count = 0;
int e1000_default_device = 0; /* non-static: eth/arp select the TX NIC via this */
int e1000_active_rx_device = -1; /* arrival NIC marker (arp/ip4 replies) */

// Legacy compatibility: expose first device's MAC
uint8_t e1000_mac[MAX_E1000_DEVICES][6] = {{0,0,0,0,0,0},{0,0,0,0,0,0}}; // per-NIC MAC (ajlangweb dual-NIC)

// Linux-inspired "NAPI-style" polling state:
// - IRQ handler schedules polling and masks further NIC interrupts
// - Poller drains RX ring with a budget and re-enables interrupts when idle
static volatile int e1000_napi_scheduled = 0;

// Forward declarations of static functions
static void e1000_tx_init(int dev_idx);
static void e1000_rx_init(int dev_idx);
static void e1000_reset(uint16_t io_base);
static void e1000_force_link_dev(e1000_dev_t *dev);
static int e1000_eerd_read_word(uint16_t io_base, uint16_t addr,
                                uint16_t *out_word);
static void e1000_read_mac_from_rar0(uint16_t io_base, uint8_t mac[6]);
static void e1000_program_rar0(e1000_dev_t *dev, const uint8_t mac[6]);

static uint32_t e1000_io_read(uint16_t io_base, uint16_t reg) {
  outl(io_base, (uint32_t)reg);
  return inl((uint16_t)(io_base + 4));
}

static void e1000_io_write(uint16_t io_base, uint16_t reg, uint32_t v) {
  outl(io_base, (uint32_t)reg);
  outl((uint16_t)(io_base + 4), v);
}

static uint32_t e1000_mmio_read(volatile uint8_t *base, uint32_t reg) {
  return *(volatile uint32_t *)(base + reg);
}

static void e1000_mmio_write(volatile uint8_t *base, uint32_t reg, uint32_t v) {
  *(volatile uint32_t *)(base + reg) = v;
}

static inline uint32_t e1000_reg_read(e1000_dev_t *dev, uint32_t reg) {
  // Prefer MMIO when available: it's the primary interface for the QEMU e1000
  // device and avoids relying on IOADDR/IODATA semantics.
  if (dev && dev->mmio)
    return e1000_mmio_read(dev->mmio, reg);
  if (dev && dev->io_base)
    return e1000_io_read(dev->io_base, (uint16_t)reg);
  return 0;
}

static inline void e1000_reg_write(e1000_dev_t *dev, uint32_t reg, uint32_t v) {
  if (dev && dev->mmio) {
    e1000_mmio_write(dev->mmio, reg, v);
    return;
  }
  if (dev && dev->io_base) {
    e1000_io_write(dev->io_base, (uint16_t)reg, v);
  }
}

static void e1000_tx_init(int dev_idx) {
  if (dev_idx < 0 || dev_idx >= e1000_device_count ||
      !e1000_devices[dev_idx].present ||
      (!e1000_devices[dev_idx].mmio && !e1000_devices[dev_idx].io_base)) {
    return;
  }

  e1000_dev_t *dev = &e1000_devices[dev_idx];
  e1000_rings_t *rings = e1000_rings[dev_idx];

  for (uint32_t i = 0; i < E1000_TX_RING_SIZE; i++) {
    rings->tx_ring[i].addr = (uint32_t)&rings->tx_bufs[i][0];
    rings->tx_ring[i].length = 0;
    rings->tx_ring[i].cso = 0;
    rings->tx_ring[i].cmd = 0;
    rings->tx_ring[i].status = 0x1; // DD
    rings->tx_ring[i].css = 0;
    rings->tx_ring[i].special = 0;
  }
  rings->tx_tail = 0;

  const uint32_t REG_TDBAL = 0x3800;
  const uint32_t REG_TDLEN = 0x3808;
  const uint32_t REG_TDH = 0x3810;
  const uint32_t REG_TDT = 0x3818;
  const uint32_t REG_TCTL = 0x0400;
  const uint32_t REG_TIPG = 0x0410;

  uint32_t ring_phys = (uint32_t)&rings->tx_ring[0];

  e1000_reg_write(dev, REG_TDBAL, ring_phys);
  e1000_reg_write(dev, 0x3804, 0); // TDBAH
  e1000_reg_write(dev, REG_TDLEN,
                   (uint32_t)(sizeof(e1000_tx_desc_t) * E1000_TX_RING_SIZE));
  e1000_reg_write(dev, REG_TDH, 0);
  e1000_reg_write(dev, REG_TDT, 0);

  uint32_t tctl = 0;
  tctl |= (1u << 1);     // EN
  tctl |= (1u << 3);     // PSP
  tctl |= (0x10u << 4);  // CT
  tctl |= (0x40u << 12); // COLD
  e1000_reg_write(dev, REG_TCTL, tctl);
  e1000_reg_write(dev, REG_TIPG, 0x0060200Au);
}

int e1000_tx_send_raw(const uint8_t *frame, uint16_t len) {
  static int logged_bad_dev_once = 0;
  static int logged_bad_len_once = 0;
  static int logged_tx_timeout_once = 0;
  int dev_idx = e1000_default_device;
  if (dev_idx < 0 || dev_idx >= e1000_device_count ||
      !e1000_devices[dev_idx].present ||
      (!e1000_devices[dev_idx].mmio && !e1000_devices[dev_idx].io_base) ||
      !e1000_devices[dev_idx].enabled) {
    if (!logged_bad_dev_once) {
      logged_bad_dev_once = 1;
      log_writestring("[e1000] tx_send_raw: dev not ready. dev_idx=");
      log_write_u32((uint32_t)dev_idx);
      log_writestring(" dev_count=");
      log_write_u32((uint32_t)e1000_device_count);
      log_writestring(" present=");
      if (dev_idx >= 0 && dev_idx < e1000_device_count)
        log_write_u32((uint32_t)e1000_devices[dev_idx].present);
      else
        log_write_u32(0);
      log_writestring(" enabled=");
      if (dev_idx >= 0 && dev_idx < e1000_device_count)
        log_write_u32((uint32_t)e1000_devices[dev_idx].enabled);
      else
        log_write_u32(0);
      log_writestring(" io_base=0x");
      if (dev_idx >= 0 && dev_idx < e1000_device_count)
        log_write_hex32((uint32_t)e1000_devices[dev_idx].io_base);
      else
        log_write_hex32(0);
      log_writestring(" mmio=");
      if (dev_idx >= 0 && dev_idx < e1000_device_count)
        log_write_hex32((uint32_t)e1000_devices[dev_idx].mmio);
      else
        log_write_hex32(0);
      log_putchar('\n');
    }
    return 0;
  }

  e1000_dev_t *dev = &e1000_devices[dev_idx];
  e1000_rings_t *rings = e1000_rings[dev_idx];
  if (!rings) {
    if (!logged_bad_dev_once) {
      logged_bad_dev_once = 1;
      log_writestring("[e1000] tx_send_raw: rings=NULL\n");
    }
    return 0;
  }

  uint16_t original_len = len;
  if (len < 60)
    len = 60;
  /* Max Ethernet frame: 1518 (1522 w/ VLAN). The old limit of 1500 rejected
   * standard full-MSS TCP segments (1460 payload -> 1514-byte frame, and even
   * a 1456-payload segment -> 1510), silently dropping any reply larger than
   * ~1446 bytes of payload. Combined with the once-only "len too big" log and
   * the SSH retry loop giving up after 256 tries, this made every big SFTP
   * reply (READDIR NAME, large DATA) vanish: the OpenSSH client, which has no
   * SFTP timeouts, hung forever on `ls`. Hardware handles up to 16KB frames;
   * keep the conservative 1518 boundary. */
  if (len > 1518)
  {
    if (!logged_bad_len_once) {
      logged_bad_len_once = 1;
      log_writestring("[e1000] tx_send_raw: len too big: ");
      log_write_u32((uint32_t)len);
      log_writestring(" (orig ");
      log_write_u32((uint32_t)original_len);
      log_writestring(")\n");
    }
    return 0;
  }

  uint32_t idx = rings->tx_tail % E1000_TX_RING_SIZE;
  volatile e1000_tx_desc_t *d = &rings->tx_ring[idx];
  // Ensure descriptor is free (DD=1). If not, ring is full or wedged.
  if ((d->status & 0x1u) == 0) {
    // #region agent log
    {
      static uint32_t e1000_txfull_n;
      if ((++e1000_txfull_n % 32u) == 1u)
        agent_dbg_evt("E", "e1000_tx", "ring_full", idx, (uint32_t)len);
    }
    // #endregion
    return 0;
  }

  for (uint16_t i = 0; i < len; i++) {
    rings->tx_bufs[idx][i] = (i < original_len) ? frame[i] : 0;
  }

  d->length = len;
  d->cmd = 0x1u | 0x2u | 0x8u; // EOP | IFCS | RS
  d->status = 0;

  const uint32_t REG_TDT = 0x3818;
  uint32_t next = (idx + 1u) % E1000_TX_RING_SIZE;
  e1000_reg_write(dev, REG_TDT, next);
  rings->tx_tail = next;

  // Wait briefly for completion so we can detect TX not working at all.
  for (uint32_t spin = 0; spin < 20000u; spin++) {
    if (d->status & 0x1u)
      return 1;
    __asm__ volatile("pause");
  }

  if (!logged_tx_timeout_once) {
    logged_tx_timeout_once = 1;
    log_writestring("[e1000] TX timeout. regs: ");
    uint32_t ctrl = e1000_reg_read(dev, 0x0000);
    uint32_t status = e1000_reg_read(dev, 0x0008);
    uint32_t tctl = e1000_reg_read(dev, 0x0400);
    uint32_t tipg = e1000_reg_read(dev, 0x0410);
    uint32_t tdbal = e1000_reg_read(dev, 0x3800);
    uint32_t tdlen = e1000_reg_read(dev, 0x3808);
    uint32_t tdh = e1000_reg_read(dev, 0x3810);
    uint32_t tdt = e1000_reg_read(dev, 0x3818);
    log_writestring("CTRL=0x");
    log_write_hex32(ctrl);
    log_writestring(" STATUS=0x");
    log_write_hex32(status);
    log_writestring(" TCTL=0x");
    log_write_hex32(tctl);
    log_writestring(" TIPG=0x");
    log_write_hex32(tipg);
    log_writestring(" TDBAL=0x");
    log_write_hex32(tdbal);
    log_writestring(" TDLEN=0x");
    log_write_hex32(tdlen);
    log_writestring(" TDH=0x");
    log_write_hex32(tdh);
    log_writestring(" TDT=0x");
    log_write_hex32(tdt);
    log_putchar('\n');
  }
  return 0;
}

static void e1000_irq_handler(struct regs *r) {
  (void)r;
  if (e1000_device_count == 0)
    return;
  const uint32_t REG_ICR = 0x00C0;
  const uint32_t REG_IMC = 0x00D8;
  /* Service every present NIC: either may signal RX (dual-NIC AJOS). */
  for (int di = 0; di < e1000_device_count; di++) {
    e1000_dev_t *dev = &e1000_devices[di];
    if (!dev->present || (!dev->mmio && !dev->io_base))
      continue;
    uint32_t icr = e1000_reg_read(dev, REG_ICR);
    (void)icr;
    // Schedule NAPI-style polling and mask interrupts so the timer/busy-wait poller
    // can drain the RX ring with a bounded budget. This makes RX robust on
    // emulators where IRQ delivery can be flaky (or bursts can cause storms).
    if (!e1000_napi_scheduled) {
      e1000_reg_write(dev, REG_IMC, 0xFFFFFFFFu);
    }
  }
  if (!e1000_napi_scheduled)
    e1000_napi_scheduled = 1;
}

static void e1000_rx_init(int dev_idx) {
  if (dev_idx < 0 || dev_idx >= e1000_device_count ||
      !e1000_devices[dev_idx].present ||
      (!e1000_devices[dev_idx].mmio && !e1000_devices[dev_idx].io_base)) {
    return;
  }

  e1000_dev_t *dev = &e1000_devices[dev_idx];
  e1000_rings_t *rings = e1000_rings[dev_idx];

  for (uint32_t i = 0; i < E1000_RX_RING_SIZE; i++) {
    rings->rx_ring[i].addr = (uint32_t)&rings->rx_bufs[i][0];
    rings->rx_ring[i].status = 0;
    rings->rx_ring[i].errors = 0;
    rings->rx_ring[i].length = 0;
    rings->rx_ring[i].checksum = 0;
    rings->rx_ring[i].special = 0;
  }
  rings->rx_head = 0;

  const uint32_t REG_RDBAL = 0x2800;
  const uint32_t REG_RDLEN = 0x2808;
  const uint32_t REG_RDH = 0x2810;
  const uint32_t REG_RDT = 0x2818;
  const uint32_t REG_RCTL = 0x0100;
  const uint32_t REG_IMS = 0x00D0;

  uint32_t ring_phys = (uint32_t)&rings->rx_ring[0];

  e1000_reg_write(dev, REG_RDBAL, ring_phys);
  e1000_reg_write(dev, 0x2804, 0); // RDBAH
  e1000_reg_write(dev, REG_RDLEN,
                   (uint32_t)(sizeof(e1000_rx_desc_t) * E1000_RX_RING_SIZE));
  e1000_reg_write(dev, REG_RDH, 0);
  e1000_reg_write(dev, REG_RDT, (uint32_t)(E1000_RX_RING_SIZE - 1));

  const uint32_t REG_MTA = 0x5200;
  for (int i = 0; i < 128; i++) {
    e1000_reg_write(dev, REG_MTA + (uint32_t)(i * 4), 0);
  }

  e1000_reg_read(dev, 0x00C0); // REG_ICR

  if (dev_idx == 0 && dev->irq_line > 0 && dev->irq_line < 16) {
    log_writestring("e1000: registering IRQ handler for irq=");
    log_write_u32((uint32_t)dev->irq_line);
    log_putchar('\n');
    register_interrupt_handler(32 + dev->irq_line, e1000_irq_handler);
    pic_unmask_irq(dev->irq_line);
    const uint32_t IMS_MASK = (1u << 4) | (1u << 6) | (1u << 7) | (1u << 16);
    e1000_reg_write(dev, REG_IMS, IMS_MASK);
  }

  const uint32_t REG_RDTR = 0x2820;
  const uint32_t REG_RADV = 0x282C;
  e1000_reg_write(dev, REG_RDTR, 0x80);
  e1000_reg_write(dev, REG_RADV, 0x80);

  uint32_t rctl = 0;
  rctl |= (1u << 1);  // EN
  rctl |= (1u << 2);  // SBP
  rctl |= (1u << 3);  // UPE
  rctl |= (1u << 4);  // MPE
  rctl |= (1u << 15); // BAM
  rctl |= (1u << 26); // SECRC
  e1000_reg_write(dev, REG_RCTL, rctl);
}

int e1000_rx_poll_one(void) {
  for (int dev_idx = 0; dev_idx < e1000_device_count; dev_idx++) {
    e1000_dev_t *dev = &e1000_devices[dev_idx];
    if (!dev->present || (!dev->mmio && !dev->io_base) || !dev->enabled)
      continue;

    e1000_rings_t *rings = e1000_rings[dev_idx];
    uint32_t idx = rings->rx_head % E1000_RX_RING_SIZE;
    volatile e1000_rx_desc_t *d = &rings->rx_ring[idx];
    if ((d->status & 0x1u) == 0)
      continue;

    uint16_t len = d->length;
    if (len > 2048)
      len = 2048;

    struct pbuf *p = pbuf_alloc();
    if (p) {
      /* p->payload is buffer_s + PBUF_HEADROOM; copying len > PBUF_PAYLOAD_CAP
       * overflows past buffer_s[] and corrupts the heap (SSH/TCP then die). */
      if (len > PBUF_PAYLOAD_CAP)
        len = PBUF_PAYLOAD_CAP;
      for (int i = 0; i < len; i++) {
        p->payload[i] = rings->rx_bufs[idx][i];
      }
      p->len = len;
      p->tot_len = len;
      /* Mark the arrival NIC: arp replies leave via the same interface. */
      e1000_active_rx_device = dev_idx;
      ethernet_input(p);
    } else {
      // #region agent log
      static uint32_t rx_oom_n;
      if ((++rx_oom_n % 16u) == 1u)
        agent_dbg_evt("A", "e1000_rx", "pbuf_oom", (uint32_t)len,
                      (uint32_t)dev_idx);
      // #endregion
    }

    d->status = 0;
    const uint32_t REG_RDT = 0x2818;
    /* QEMU e1000_has_rxbufs() returns false when RDH == RDT (no RX space).
     * Writing RDT == idx after consuming descriptor idx can match RDH and wedge
     * RX (seen post-SSH: RDH=RDT=27, eth_rx stuck at 0). RDT is the index of
     * the last recycled descriptor; match init (RDH=0, RDT=N-1) via (idx-1)%N. */
    uint32_t rdt_val =
        (idx + (uint32_t)E1000_RX_RING_SIZE - 1u) % (uint32_t)E1000_RX_RING_SIZE;
    e1000_reg_write(dev, REG_RDT, rdt_val);
    rings->rx_head = (idx + 1u) % E1000_RX_RING_SIZE;
    return 1;
  }
  return 0;
}

void e1000_napi_schedule(void) { e1000_napi_scheduled = 1; }

int e1000_napi_is_scheduled(void) { return e1000_napi_scheduled ? 1 : 0; }

/* RX ring health check + recovery, every napi poll.
 *
 * Old behavior: only device 0, only when RDH == RDT, blind re-point of RDT.
 * That blind re-point could race an arriving packet and desync the driver's
 * rx_head from the hardware RDH; once desynced, the driver consumed the
 * wrong descriptors and the NIC went deaf from the outside (ARP requests
 * went unanswered, the interface effectively died hours into uptime).
 *
 * New behavior: for EVERY device, compare the hardware RDH against the
 * driver's rx_head. Pending-but-unconsumed descriptors whose DD bit never
 * sets (8 consecutive polls) mean the indexes desynced - force them back
 * into agreement (rx_head = RDH, RDT = RDH-1). In-sync rings are untouched. */
static void e1000_rx_qemu_unstick_rdh_rdt(void) {
  const uint32_t REG_RDH = 0x2810;
  const uint32_t REG_RDT = 0x2818;
  for (int di = 0; di < e1000_device_count; di++) {
    e1000_dev_t *dev = &e1000_devices[di];
    if (!dev->present || (!dev->mmio && !dev->io_base) || !dev->enabled)
      continue;
    e1000_rings_t *rings = e1000_rings[di];
    if (!rings)
      continue;
    uint32_t rdh = e1000_reg_read(dev, REG_RDH) % E1000_RX_RING_SIZE;
    uint32_t pending =
        (rdh + (uint32_t)E1000_RX_RING_SIZE - rings->rx_head) %
        (uint32_t)E1000_RX_RING_SIZE;
    if (pending == 0)
      continue; /* idle and in sync */
    volatile e1000_rx_desc_t *d = &rings->rx_ring[rings->rx_head];
    if (d->status & 0x1u)
      continue; /* descriptor ready; the poll will consume it normally */
    /* RDH claims pending data but the head descriptor has no DD bit:
     * the indexes desynced. Confirm it sticks for 8 consecutive polls
     * (~160ms at 50 polls/s) before forcing a re-sync. */
    static uint8_t stuck_n[MAX_E1000_DEVICES];
    if (++stuck_n[di] < 8u)
      continue;
    stuck_n[di] = 0;
    rings->rx_head = rdh;
    uint32_t fix =
        (rdh + (uint32_t)E1000_RX_RING_SIZE - 1u) % (uint32_t)E1000_RX_RING_SIZE;
    e1000_reg_write(dev, REG_RDT, fix);
    // #region agent log
    static uint32_t unstick_log_n;
    if (++unstick_log_n <= 4u)
      agent_dbg_evt("M", "e1000", "rx_resync", di, fix);
    // #endregion
  }
}

static int e1000_rx_pending_any(void) {
  for (int dev_idx = 0; dev_idx < e1000_device_count; dev_idx++) {
    e1000_dev_t *dev = &e1000_devices[dev_idx];
    if (!dev->present || (!dev->mmio && !dev->io_base) || !dev->enabled)
      continue;
    e1000_rings_t *rings = e1000_rings[dev_idx];
    if (!rings)
      continue;
    uint32_t idx = rings->rx_head % E1000_RX_RING_SIZE;
    volatile e1000_rx_desc_t *d = &rings->rx_ring[idx];
    if (d->status & 0x1u)
      return 1;
  }
  return 0;
}

int e1000_napi_poll(int budget) {
  if (budget <= 0)
    return 0;
  e1000_rx_qemu_unstick_rdh_rdt();
  int done = 0;
  for (int i = 0; i < budget; i++) {
    if (!e1000_rx_poll_one())
      break;
    done++;
  }

  // If we were scheduled via IRQ, complete when ring is empty and re-enable
  // interrupts.
  static uint32_t napi_zero_while_pending;
  if (e1000_napi_scheduled) {
    if (!e1000_rx_pending_any()) {
      e1000_napi_scheduled = 0;
      e1000_enable_interrupts();
      napi_zero_while_pending = 0;
    } else if (done == 0) {
      /* Runtime (post-SSH ping): eth_rx/ip4_rx stayed 0 while NAPI was "scheduled"
       * with DD seemingly set but poll_one never advanced — IMS stayed masked and
       * RX starved. Force-complete NAPI and re-arm IRQ after repeated idle polls. */
      if (++napi_zero_while_pending >= 128u) {
        napi_zero_while_pending = 0;
        e1000_napi_scheduled = 0;
        if (e1000_device_count > 0 && e1000_devices[0].present &&
            (e1000_devices[0].mmio || e1000_devices[0].io_base)) {
          (void)e1000_reg_read(&e1000_devices[0], 0x00C0u); /* ICR: clear causes */
        }
        e1000_enable_interrupts();
        // #region agent log
        agent_dbg_evt("I", "e1000", "napi_unstick", 128u, 0u);
        // #endregion
      }
    } else {
      napi_zero_while_pending = 0;
    }
  } else {
    napi_zero_while_pending = 0;
  }
  return done;
}

void e1000_debug_snap(uint32_t *out_ring_pack, uint32_t *out_flags_icr) {
  // #region agent log
  if (!out_ring_pack || !out_flags_icr)
    return;
  *out_ring_pack = 0;
  *out_flags_icr = 0;
  if (e1000_device_count <= 0)
    return;
  e1000_dev_t *dev = &e1000_devices[0];
  if (!dev->present || (!dev->mmio && !dev->io_base))
    return;
  e1000_rings_t *rings = e1000_rings[0];
  if (!rings)
    return;
  const uint32_t REG_RDH = 0x2810;
  const uint32_t REG_RDT = 0x2818;
  const uint32_t REG_ICR = 0x00C0;
  uint32_t rdh = e1000_reg_read(dev, REG_RDH) % E1000_RX_RING_SIZE;
  uint32_t rdt = e1000_reg_read(dev, REG_RDT) % E1000_RX_RING_SIZE;
  uint32_t rh = rings->rx_head % E1000_RX_RING_SIZE;
  uint32_t idx = rh;
  volatile e1000_rx_desc_t *d = &rings->rx_ring[idx];
  uint32_t dd = (d->status & 1u) ? 1u : 0u;
  *out_ring_pack =
      (rh & 31u) | ((rdh & 31u) << 8) | ((rdt & 31u) << 16) | (dd << 24);
  uint32_t icr = e1000_reg_read(dev, REG_ICR);
  uint32_t fl = 0;
  if (e1000_napi_scheduled)
    fl |= 1u;
  if (e1000_rx_pending_any())
    fl |= 2u;
  if (dev->enabled)
    fl |= 4u;
  fl |= (icr & 0xFFFFu) << 16;
  *out_flags_icr = fl;
  // #endregion
}

static int e1000_eerd_read_word(uint16_t io_base, uint16_t addr,
                                uint16_t *out_word) {
  const uint16_t REG_EERD = 0x14;
  uint32_t v = (1u << 0) | ((uint32_t)addr << 8);
  e1000_io_write(io_base, REG_EERD, v);
  for (uint32_t i = 0; i < 100000u; i++) {
    uint32_t r = e1000_io_read(io_base, REG_EERD);
    if (r & (1u << 4)) {
      *out_word = (uint16_t)((r >> 16) & 0xFFFFu);
      return 1;
    }
  }
  return 0;
}

static void e1000_force_link_dev(e1000_dev_t *dev) {
  if (!dev)
    return;
  const uint32_t REG_CTRL = 0x0000;
  uint32_t ctrl = e1000_reg_read(dev, REG_CTRL);
  ctrl |= (1u << 6);   // SLU
  ctrl &= ~(1u << 2);  // LRST off
  ctrl &= ~(1u << 11); // FRCSPD off
  ctrl &= ~(1u << 12); // FRCDPX off
  e1000_reg_write(dev, REG_CTRL, ctrl);
  const uint32_t REG_TIPG = 0x0410;
  e1000_reg_write(dev, REG_TIPG, 0x0060200A);
}

static void e1000_reset(uint16_t io_base) {
  const uint16_t REG_CTRL = 0x0000;
  e1000_io_write(io_base, REG_CTRL, (1u << 26) | (1u << 6));
  for (uint32_t i = 0; i < 200000u; i++) {
    uint32_t v = e1000_io_read(io_base, REG_CTRL);
    if ((v & (1u << 26)) == 0)
      break;
    __asm__ volatile("pause");
  }
}

static void e1000_read_mac_from_rar0(uint16_t io_base, uint8_t mac[6]) {
  const uint16_t REG_RAL0 = 0x5400;
  const uint16_t REG_RAH0 = 0x5404;
  uint32_t ral = e1000_io_read(io_base, REG_RAL0);
  uint32_t rah = e1000_io_read(io_base, REG_RAH0);
  mac[0] = (uint8_t)(ral & 0xFFu);
  mac[1] = (uint8_t)((ral >> 8) & 0xFFu);
  mac[2] = (uint8_t)((ral >> 16) & 0xFFu);
  mac[3] = (uint8_t)((ral >> 24) & 0xFFu);
  mac[4] = (uint8_t)(rah & 0xFFu);
  mac[5] = (uint8_t)((rah >> 8) & 0xFFu);
}

static void e1000_program_rar0(e1000_dev_t *dev, const uint8_t mac[6]) {
  const uint32_t REG_RAL0 = 0x5400;
  const uint32_t REG_RAH0 = 0x5404;
  uint32_t ral = (uint32_t)mac[0] | ((uint32_t)mac[1] << 8) |
                 ((uint32_t)mac[2] << 16) | ((uint32_t)mac[3] << 24);
  uint32_t rah = (uint32_t)mac[4] | ((uint32_t)mac[5] << 8) | (1u << 31); // AV
  e1000_reg_write(dev, REG_RAL0, ral);
  e1000_reg_write(dev, REG_RAH0, rah);
}

void e1000_probe(void) {
  /* May be in BSS range we skip (disk cache); ensure clean so no garbage pointer writes. */
  e1000_napi_scheduled = 0;
  e1000_device_count = 0;
  for (int i = 0; i < MAX_E1000_DEVICES; i++) {
    e1000_rings[i] = NULL;
    e1000_devices[i].present = 0;
    e1000_devices[i].mmio = NULL;
    e1000_devices[i].io_base = 0;
    e1000_devices[i].mmio_phys = 0;
    e1000_devices[i].name[0] = 'e';
    e1000_devices[i].name[1] = 't';
    e1000_devices[i].name[2] = 'h';
    e1000_devices[i].name[3] = '0' + (char)i;
    e1000_devices[i].name[4] = '\0';
  }

  for (uint16_t bus = 0; bus < 8 && e1000_device_count < MAX_E1000_DEVICES;
       bus++) {
    for (uint8_t dev = 0; dev < 32 && e1000_device_count < MAX_E1000_DEVICES;
         dev++) {
      if (!pci_func_present((uint8_t)bus, dev, 0))
        continue;
      uint8_t header = pci_cfg_read8((uint8_t)bus, dev, 0, 0x0E);
      uint8_t max_func = (header & 0x80u) ? 8 : 1;
      for (uint8_t func = 0;
           func < max_func && e1000_device_count < MAX_E1000_DEVICES; func++) {
        if (!pci_func_present((uint8_t)bus, dev, func))
          continue;
        uint16_t vendor = pci_cfg_read16((uint8_t)bus, dev, func, 0x00);
        uint16_t device = pci_cfg_read16((uint8_t)bus, dev, func, 0x02);
        if (!(vendor == 0x8086u && (device == 0x100Eu || device == 0x1004u)))
          continue;

        int dev_idx = e1000_device_count;
        if (dev_idx < 0 || dev_idx >= MAX_E1000_DEVICES)
          continue;
        /* Static per-device rings: kmalloc of ~133KB per NIC was fragile
         * early in boot; BSS storage is deterministic for MAX=2 devices. */
        e1000_rings[dev_idx] = &e1000_rings_storage[dev_idx];
        e1000_device_count++;
        e1000_dev_t *e = &e1000_devices[dev_idx];
        e->present = 1;
        e->enabled = 1;
        e->bus = (uint8_t)bus;
        e->dev = dev;
        e->func = func;
        e->vendor_id = vendor;
        e->device_id = device;

        for (uint8_t bar = 0; bar < 6; bar++) {
          uint32_t barv =
              pci_cfg_read32((uint8_t)bus, dev, func, 0x10 + bar * 4);
          if (barv & 0x1u)
            e->io_base = (uint16_t)(barv & 0xFFFCu);
          else if (e->mmio_phys == 0)
            e->mmio_phys = (barv & 0xFFFFFFF0u);
        }
        e->irq_line = pci_cfg_read8((uint8_t)bus, dev, func, 0x3C);
        uint16_t cmd = pci_cfg_read16((uint8_t)bus, dev, func, 0x04);
        // Enable IO space, memory space, and bus mastering (16-bit write; do
        // not clobber the PCI status register).
        pci_cfg_write16((uint8_t)bus, dev, func, 0x04,
                        (uint16_t)(cmd | 0x0007u));

        if (e->io_base)
          e1000_reset(e->io_base);
        if (e->mmio_phys) {
          // IMPORTANT: do NOT map device MMIO into low identity-mapped RAM.
          // Paging currently identity-maps 0..64MB for kernel/PMM. Mapping MMIO
          // at 0x01000000 (16MB) would overwrite the RAM mapping and can corrupt
          // heap/rings or turn normal RAM accesses into MMIO accesses.
          //
          // Map each device into a high virtual region instead.
          uint32_t virt_base = 0x20000000u + (uint32_t)(dev_idx * 0x01000000u);
          paging_map_mmio_4mb(virt_base, e->mmio_phys);
          e->mmio = (volatile uint8_t *)virt_base;
        }

        uint16_t w0, w1, w2;
        if (e->io_base && e1000_eerd_read_word(e->io_base, 0, &w0) &&
            e1000_eerd_read_word(e->io_base, 1, &w1) &&
            e1000_eerd_read_word(e->io_base, 2, &w2)) {
          e->mac[0] = (uint8_t)(w0 & 0xFFu);
          e->mac[1] = (uint8_t)((w0 >> 8) & 0xFFu);
          e->mac[2] = (uint8_t)(w1 & 0xFFu);
          e->mac[3] = (uint8_t)((w1 >> 8) & 0xFFu);
          e->mac[4] = (uint8_t)(w2 & 0xFFu);
          e->mac[5] = (uint8_t)((w2 >> 8) & 0xFFu);
        } else if (e->mmio) {
          uint32_t ral = e1000_mmio_read(e->mmio, 0x5400);
          uint32_t rah = e1000_mmio_read(e->mmio, 0x5404);
          for (int i = 0; i < 4; i++)
            e->mac[i] = (uint8_t)((ral >> (i * 8)) & 0xFF);
          for (int i = 0; i < 2; i++)
            e->mac[4 + i] = (uint8_t)((rah >> (i * 8)) & 0xFF);
        }

        /* Save per-device MAC for ALL devices (dual-NIC); dev0 keeps the
         * legacy "global MAC" log. */
        for (int i = 0; i < 6; i++)
          e1000_mac[dev_idx][i] = e->mac[i];

        if (dev_idx == 0) {
          log_writestring("e1000: set global MAC\n");

          log_writestring("[e1000] BARs: io_base=0x");
          log_write_hex32((uint32_t)e->io_base);
          log_writestring(" mmio_phys=0x");
          log_write_hex32((uint32_t)e->mmio_phys);
          log_writestring(" mmio_virt=0x");
          log_write_hex32((uint32_t)e->mmio);
          log_writestring(" irq=");
          log_write_u32((uint32_t)e->irq_line);
          log_putchar('\n');
        }

        e1000_program_rar0(e, e->mac);
        e1000_force_link_dev(e);
        e1000_tx_init(dev_idx);
        e1000_rx_init(dev_idx);

        // Register NAPI-style hooks so the kernel can RX-poll generically.
        (void)netdev_napi_register(e->name, e1000_napi_is_scheduled,
                                  e1000_napi_poll);
      }
    }
  }
}

void cmd_ifconfig(const char *args) {
  const char *s = skip_spaces(args);

  // Parse interface name and action
  char ifname[16] = {0};
  int ifname_len = 0;
  const char *action = 0;

  // Extract interface name (eth0, eth1, etc.)
  while (*s && (unsigned char)*s > ' ' &&
         ifname_len < (int)sizeof(ifname) - 1) {
    ifname[ifname_len++] = *s++;
  }
  ifname[ifname_len] = '\0';

  action = skip_spaces(s);

  // If no interface specified, show all
  if (ifname_len == 0) {
    extern uint32_t arp_get_ajos_ip(void);
    extern uint32_t ip4_get_netmask(void);
    extern uint32_t ip4_get_gateway(void);
    extern uint32_t dns_get_server(void);

    uint32_t my_ip = arp_get_ajos_ip();
    uint32_t mask = ip4_get_netmask();
    uint32_t gw = ip4_get_gateway();
    uint32_t dns = dns_get_server();

    // Show all interfaces
    for (int i = 0; i < e1000_device_count; i++) {
      e1000_dev_t *dev = &e1000_devices[i];
      log_writestring("Interface: ");
      log_writestring(dev->name);
      log_writestring(" (");
      log_writestring(dev->enabled ? "UP" : "DOWN");
      if (i == e1000_default_device) {
        log_writestring(", DEFAULT");
      }
      log_writestring(")\n");

      log_writestring("  MAC: ");
      for (int j = 0; j < 6; j++) {
        log_write_hex8(dev->mac[j]);
        if (j < 5)
          log_putchar(':');
      }
      log_putchar('\n');

      {
        /* Per-interface addresses: the global my_ip/mask/gw describe
         * iface0 only - showing them for every NIC lied about dual-NIC. */
        extern uint32_t arp_get_if_ip(int iface);
        extern uint32_t ip4_get_if_netmask(int iface);
        extern uint32_t ip4_get_if_gw(int iface);
        uint32_t if_ip = arp_get_if_ip(i);
        uint32_t if_mask = ip4_get_if_netmask(i);
        uint32_t if_gw = ip4_get_if_gw(i);

        log_writestring("  IP: ");
        if (if_ip == 0) {
          log_writestring("(unset)");
        } else {
          log_write_u32((if_ip >> 24) & 0xFF);
          log_putchar('.');
          log_write_u32((if_ip >> 16) & 0xFF);
          log_putchar('.');
          log_write_u32((if_ip >> 8) & 0xFF);
          log_putchar('.');
          log_write_u32(if_ip & 0xFF);
        }
        log_putchar('\n');

        log_writestring("  Netmask: ");
        log_write_u32((if_mask >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((if_mask >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((if_mask >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(if_mask & 0xFF);
        log_putchar('\n');

        log_writestring("  Gateway: ");
        log_write_u32((if_gw >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((if_gw >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((if_gw >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(if_gw & 0xFF);
        log_putchar('\n');

        log_writestring("  DNS: ");
        log_write_u32((dns >> 24) & 0xFF);
        log_putchar('.');
        log_write_u32((dns >> 16) & 0xFF);
        log_putchar('.');
        log_write_u32((dns >> 8) & 0xFF);
        log_putchar('.');
        log_write_u32(dns & 0xFF);
        log_putchar('\n');
      }
    }
    return;
  }

  // Find interface by name
  int dev_idx = -1;
  for (int i = 0; i < e1000_device_count; i++) {
    if (kstreq(ifname, e1000_devices[i].name)) {
      dev_idx = i;
      break;
    }
  }

  if (dev_idx < 0) {
    log_writestring("ifconfig: interface not found: ");
    log_writestring(ifname);
    log_putchar('\n');
    return;
  }

  e1000_dev_t *dev = &e1000_devices[dev_idx];

  // Handle actions: up, down, default
  if (action && *action) {
    if (kstreq(action, "up")) {
      dev->enabled = 1;
      e1000_tx_init(dev_idx);
      e1000_rx_init(dev_idx);
      log_writestring(dev->name);
      log_writestring(": enabled\n");
      return;
    } else if (kstreq(action, "down")) {
      dev->enabled = 0;
      log_writestring(dev->name);
      log_writestring(": disabled\n");
      return;
    } else if (kstreq(action, "default")) {
      e1000_default_device = dev_idx;
      // Update global MAC for networking stack
      for (int i = 0; i < 6; i++) {
        e1000_mac[dev_idx][i] = dev->mac[i];
      }
      log_writestring(dev->name);
      log_writestring(": set as default interface\n");
      return;
    } else {
      log_writestring("Usage: ifconfig [<interface>] [up|down|default]\n");
      return;
    }
  }

  // Show single interface details
  log_writestring("Interface: ");
  log_writestring(dev->name);
  log_writestring(" (");
  log_writestring(dev->enabled ? "UP" : "DOWN");
  if (dev_idx == e1000_default_device) {
    log_writestring(", DEFAULT");
  }
  log_writestring(")\n");

  log_writestring("  MAC: ");
  for (int j = 0; j < 6; j++) {
    log_write_hex8(dev->mac[j]);
    if (j < 5)
      log_putchar(':');
  }
  log_putchar('\n');

  if (dev_idx == e1000_default_device) {
    extern uint32_t arp_get_ajos_ip(void);
    extern uint32_t ip4_get_netmask(void);
    extern uint32_t ip4_get_gateway(void);
    extern uint32_t dns_get_server(void);

    uint32_t my_ip = arp_get_ajos_ip();
    uint32_t mask = ip4_get_netmask();
    uint32_t gw = ip4_get_gateway();
    uint32_t dns = dns_get_server();

    log_writestring("  IP: ");
    log_write_u32((my_ip >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((my_ip >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((my_ip >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(my_ip & 0xFF);
    log_putchar('\n');

    log_writestring("  Netmask: ");
    log_write_u32((mask >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((mask >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((mask >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(mask & 0xFF);
    log_putchar('\n');

    log_writestring("  Gateway: ");
    log_write_u32((gw >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((gw >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((gw >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(gw & 0xFF);
    log_putchar('\n');

    log_writestring("  DNS: ");
    log_write_u32((dns >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((dns >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((dns >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(dns & 0xFF);
    log_putchar('\n');
  }
  return;

  // Parse new IP
  uint32_t ip = 0;
  uint32_t part;
  for (int i = 0; i < 4; i++) {
    part = 0;
    while (*s >= '0' && *s <= '9') {
      part = part * 10 + (*s - '0');
      s++;
    }
    ip = (ip << 8) | (part & 0xFF);
    if (*s == '.')
      s++;
  }

  log_write_u32(ip & 0xFF);
  log_putchar('\n');
}

void e1000_disable_interrupts(void) {
  for (int i = 0; i < e1000_device_count; i++) {
    e1000_dev_t *dev = &e1000_devices[i];
    if (!dev->present || (!dev->mmio && !dev->io_base))
      continue;
    const uint32_t REG_IMC = 0x00D8;
    e1000_reg_write(dev, REG_IMC, 0xFFFFFFFFu);
  }
}

void e1000_enable_interrupts(void) {
  for (int i = 0; i < e1000_device_count; i++) {
    e1000_dev_t *dev = &e1000_devices[i];
    if (!dev->present || (!dev->mmio && !dev->io_base) || !dev->enabled)
      continue;
    const uint32_t REG_IMS = 0x00D0;
    const uint32_t IMS_MASK = (1u << 4) | (1u << 6) | (1u << 7) | (1u << 16);
    e1000_reg_write(dev, REG_IMS, IMS_MASK);
  }
}
