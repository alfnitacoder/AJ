#include "debug_agent.h"
#include "net.h"
#include "pbuf.h"
#include "ssh.h"
#include <stddef.h>
#include <stdint.h>

// Extern kernel functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void log_write_hex32(uint32_t v);
extern void log_write_hex8(uint8_t v);

#define TCP_MAX_PCBS 16
// Forward declaration for HTTP callback
static void tcp_check_http_data(struct tcp_pcb *pcb, uint8_t *data, int len);
static struct tcp_pcb tcp_pcbs[TCP_MAX_PCBS];
static uint16_t tcp_local_port_next = 10000;

extern uint32_t arp_get_ajos_ip(void);
extern uint32_t pit_ticks;
extern int arp_query(uint32_t ip);
extern int arp_get_mac_for_ip(uint32_t ip, eth_addr_t *out_mac);
extern uint32_t ip4_get_netmask(void);
extern uint32_t ip4_get_gateway(void);

#define TCP_RTX_TIMEOUT_TICKS 100u // ~1s at PIT_HZ=100
#define TCP_RTX_MAX 3

#define TCP_LOCAL_RECV_WINDOW 32768u

void tcp_init(void) {
  for (int i = 0; i < TCP_MAX_PCBS; i++) {
    tcp_pcbs[i].state = TCP_CLOSED;
    tcp_pcbs[i].last_tx_tick = 0;
    tcp_pcbs[i].last_tx_flags = 0;
    tcp_pcbs[i].rtx_count = 0;
    tcp_pcbs[i].last_tx_seq = 0;
    tcp_pcbs[i].last_tx_len = 0;
    tcp_pcbs[i].app_rx_len = 0;
    tcp_pcbs[i].peer_wnd = 65535u;
  }
}

struct tcp_pcb *tcp_get_free_pcb(void) {
  for (int i = 0; i < TCP_MAX_PCBS; i++) {
    if (tcp_pcbs[i].state == TCP_CLOSED) {
      return &tcp_pcbs[i];
    }
  }
  return NULL;
}

struct tcp_pcb *tcp_get_pcb_at(int idx) {
  if (idx >= 0 && idx < TCP_MAX_PCBS) {
    return &tcp_pcbs[idx];
  }
  return NULL;
}

static struct tcp_pcb *tcp_find_pcb(ip_addr_t local_ip, uint16_t local_port,
                                    ip_addr_t remote_ip, uint16_t remote_port) {
  struct tcp_pcb *listener = NULL;

  for (int i = 0; i < TCP_MAX_PCBS; i++) {
    if (tcp_pcbs[i].state == TCP_CLOSED)
      continue;

    // Check for exact match (Active Connection) - must match all 4 fields
    // This includes SYN_RCVD, ESTABLISHED, etc. - any non-LISTEN state
    if (tcp_pcbs[i].local_port == local_port &&
        tcp_pcbs[i].remote_port == remote_port &&
        tcp_pcbs[i].remote_ip == remote_ip &&
        tcp_pcbs[i].local_ip == local_ip) {
      // Found exact match - return immediately (prioritize active connections)
      return &tcp_pcbs[i];
    }

    // Check for listener match (save for later, only if no exact match found)
    // Listeners match if port matches and either:
    // 1. local_ip is 0 (listen on all interfaces), OR
    // 2. local_ip matches the destination IP
    if (tcp_pcbs[i].local_port == local_port &&
        tcp_pcbs[i].state == TCP_LISTEN &&
        (tcp_pcbs[i].local_ip == 0 || tcp_pcbs[i].local_ip == local_ip)) {
      listener = &tcp_pcbs[i];
    }
  }
  return listener;
}

static uint16_t tcp_checksum(struct pbuf *p, ip_addr_t src, ip_addr_t dst) {
  struct {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t proto;
    uint16_t len;
  } __attribute__((packed)) pseudo;

  pseudo.src = htonl(src);
  pseudo.dst = htonl(dst);
  pseudo.zero = 0;
  pseudo.proto = IP_PROTO_TCP;
  pseudo.len = htons(p->len);

  uint32_t sum = 0;
  uint16_t *ps = (uint16_t *)&pseudo;
  for (int i = 0; i < (int)(sizeof(pseudo) / 2); i++) {
    sum += ntohs(ps[i]);
  }

  uint16_t *pd = (uint16_t *)p->payload;
  int len = p->len;
  while (len > 1) {
    sum += ntohs(*pd++);
    len -= 2;
  }
  if (len > 0) {
    sum += (*(uint8_t *)pd) << 8;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return htons((uint16_t)~sum);
}

static void tcp_track_tx(struct tcp_pcb *pcb, uint16_t flags, uint32_t seqno,
                         const uint8_t *data, uint16_t data_len) {
  // Track handshake/close, and also a single small data segment.
  pcb->last_tx_tick = pit_ticks;
  pcb->last_tx_flags = flags;
  pcb->last_tx_seq = seqno;
  pcb->rtx_count = 0;

  pcb->last_tx_len = 0;
  if (data && data_len > 0 && data_len <= TCP_RTX_DATA_MAX) {
    pcb->last_tx_len = data_len;
    for (uint16_t i = 0; i < data_len; i++) {
      pcb->last_tx_data[i] = data[i];
    }
  }
}

/* Returns 0 if the segment was handed to IP (snd_nxt updated when advance_seq).
 * Returns -1 on alloc failure or if ip4_output could not transmit (pbuf freed);
 * snd_nxt is NOT advanced so retransmit uses the correct sequence number. */
static int tcp_output_segment_at(struct tcp_pcb *pcb, uint16_t flags,
                                 uint32_t seqno, const uint8_t *data,
                                 uint16_t data_len, int advance_seq) {
  /* Peer receive window: do not send new data if it would not fit (retransmits
   * use advance_seq==0 and skip this). */
  if (data_len > 0 && advance_seq != 0) {
    uint32_t flight = pcb->snd_nxt - pcb->snd_una;
    uint32_t wnd = (uint32_t)pcb->peer_wnd;
    uint32_t can = (flight < wnd) ? (wnd - flight) : 0u;
    if (data_len > can) {
      // #region agent log
      {
        static uint32_t tcp_wnd_log_n;
        if ((++tcp_wnd_log_n % 48u) == 1u)
          agent_dbg_evt("A", "tcp_output", "wnd_block", (uint32_t)data_len,
                        can);
      }
      // #endregion
      return -1;
    }
  }

  struct pbuf *p = pbuf_alloc();
  if (!p) {
    // #region agent log
    agent_dbg_evt("D", "tcp_output", "pbuf_fail", (uint32_t)data_len, 0u);
    // #endregion
    return -1;
  }

  /*
  log_writestring("[TCP] TX seq=");
  log_write_u32(seqno);
  log_writestring(" ack=");
  log_write_u32(pcb->rcv_nxt);
  log_writestring(" flags=0x");
  log_write_hex32(flags);
  log_writestring(" len=");
  log_write_u32(data_len);
  log_putchar('\n');
  */

  // Build header + payload in the pbuf
  pbuf_header(p, -(int)sizeof(struct tcp_hdr));
  struct tcp_hdr *hdr = (struct tcp_hdr *)p->payload;
  hdr->src_port = htons(pcb->local_port);
  hdr->dst_port = htons(pcb->remote_port);
  hdr->seqno = htonl(seqno);
  hdr->ackno = htonl(pcb->rcv_nxt);
  /* Advertise actual free space in app_rx_buf, not a static constant. The
   * receive path below copies incoming data into app_rx_buf up to
   * TCP_APP_RX_MAX but always acks the full segment regardless of how
   * much was actually stored (to keep rcv_nxt in sync) — so if we ever
   * advertise more window than we truly have room for, the peer can
   * legally send more than fits, and the excess is silently dropped
   * *and acked*, meaning it's gone for good (no retransmit, since we
   * claimed to have received it). Capping the advertised window to real
   * free space is what makes that combination safe. (SSH connections
   * don't route through app_rx_buf, so this is effectively unrestricted
   * for them.) */
  {
    /* The wire window field is 16 bits (max 65535) regardless of how big
     * TCP_APP_RX_MAX is — this stack doesn't negotiate window scaling
     * (RFC 1323). Computing this in uint32_t and clamping explicitly,
     * rather than truncating a uint16_t cast, matters because the
     * truncation is *silent*: TCP_APP_RX_MAX - app_rx_len can be an exact
     * multiple of 65536 (e.g. 131072 - 0), which truncates to plain 0 —
     * advertising a zero window from the very start of every connection,
     * not a merely-too-small one. Seen live: bumping TCP_APP_RX_MAX past
     * 65536 for more per-window throughput instead stalled every fetch
     * completely. */
    uint32_t free_space =
        (pcb->app_rx_len < TCP_APP_RX_MAX) ? (TCP_APP_RX_MAX - pcb->app_rx_len)
                                            : 0;
    uint16_t win = (free_space > 65535u) ? 65535u : (uint16_t)free_space;
    hdr->window = htons(win);
  }
  hdr->chksum = 0;
  hdr->urgptr = 0;

  uint16_t offset_flags = (5 << 12) | flags;
  hdr->_offset_flags = htons(offset_flags);

  // Copy payload right after header
  uint8_t *pl = (uint8_t *)p->payload + sizeof(struct tcp_hdr);
  uint16_t copy_len = data_len;
  // Respect actual available space after headroom + header.
  uint8_t *end = p->buffer_s + PBUF_SIZE;
  uint16_t avail = 0;
  if (end > pl) {
    avail = (uint16_t)(end - pl);
  }
  if (copy_len > avail)
    copy_len = avail;
  for (uint16_t i = 0; i < copy_len; i++) {
    pl[i] = data ? data[i] : 0;
  }
  /*
  if (copy_len >= 4) {
    log_writestring("[TCP] Payload start: ");
    log_write_hex8(pl[0]);
    log_putchar(' ');
    log_write_hex8(pl[1]);
    log_putchar(' ');
    log_write_hex8(pl[2]);
    log_putchar(' ');
    log_write_hex8(pl[3]);
    log_putchar('\n');
  }
  */

  p->len = (uint16_t)(sizeof(struct tcp_hdr) + copy_len);
  hdr->chksum = tcp_checksum(p, pcb->local_ip, pcb->remote_ip);

  /* Advance snd_nxt only after a successful hand-off to IP/Ethernet.
   * Old code advanced before ip4_output(); on TX ring full / ARP miss the
   * packet was dropped but snd_nxt still moved — SSH burst output then
   * desynced sequence numbers and broke every interactive command. */
  int ipr = ip4_output(p, pcb->remote_ip, IP_PROTO_TCP);
  if (ipr != 0) {
    // #region agent log
    agent_dbg_evt("A", "tcp_output", "ip4_fail", (uint32_t)data_len,
                  (uint32_t)ipr);
    // #endregion
    return -1;
  }

  if (advance_seq && (flags & (TCP_SYN | TCP_FIN))) {
    pcb->snd_nxt++;
  }
  if (advance_seq && copy_len > 0) {
    pcb->snd_nxt += copy_len;
  }

  return 0;
}

static void tcp_send_ack(struct tcp_pcb *pcb, uint16_t flags) {
  (void)tcp_output_segment_at(pcb, flags, pcb->snd_nxt, NULL, 0, 0);
}

/* Re-announce the current receive window in a fresh ACK. The window we
 * advertise (see tcp_output_segment_at) reflects app_rx_buf's free space
 * at send time, but we only ever send an ACK synchronously in response to
 * an incoming segment. If a large response fills app_rx_buf enough to
 * advertise a small window, the peer correctly pauses — and if the
 * caller then drains app_rx_buf asynchronously (e.g. a poll loop calling
 * tls_read(), which decrypts and compacts it), nothing tells the peer the
 * window reopened until its own next segment happens to arrive, which
 * may never come if it's the one waiting on us. Callers that drain
 * app_rx_buf outside of the packet-receive path should call this right
 * after, or a large-enough page (needing several times the buffer's
 * capacity, e.g. seen live against a WordPress site sending it in ~16KB
 * chunks) can silently stall after the first chunk. */
void tcp_announce_window(struct tcp_pcb *pcb) {
  if (!pcb || pcb->state != TCP_ESTABLISHED)
    return;
  tcp_send_ack(pcb, TCP_ACK);
}

int tcp_connect(struct tcp_pcb *pcb, ip_addr_t remote_ip,
                uint16_t remote_port) {
  if (!pcb)
    return -1;

  pcb->local_ip = arp_get_ajos_ip();
  pcb->remote_ip = remote_ip;
  pcb->local_port = tcp_local_port_next++;
  if (tcp_local_port_next > 60000)
    tcp_local_port_next = 10000;
  pcb->remote_port = remote_port;

  pcb->state = TCP_SYN_SENT;
  pcb->snd_nxt = 100; // Simpler ISN for now
  pcb->snd_una = pcb->snd_nxt;
  pcb->rcv_nxt = 0;
  pcb->app_rx_len = 0;
  pcb->peer_wnd = 65535u;

  // Resolve next-hop MAC first so the initial SYN isn't dropped due to ARP
  // miss. This keeps tcp_connect output synchronous (no delayed packets after
  // prompt).
  uint32_t mask = ip4_get_netmask();
  uint32_t gw = ip4_get_gateway();
  uint32_t next_hop = remote_ip;
  if (pcb->local_ip != 0 && mask != 0 && gw != 0) {
    if ((remote_ip & mask) != (pcb->local_ip & mask)) {
      next_hop = gw;
    }
  }
  eth_addr_t tmp;
  uint32_t start = pit_ticks;
  while (!arp_get_mac_for_ip(next_hop, &tmp)) {
    arp_query(next_hop);
    if ((uint32_t)(pit_ticks - start) > (TCP_RTX_TIMEOUT_TICKS)) {
      break; // we'll fall back to normal retransmit path
    }
    __asm__ volatile("pause");
  }

  uint32_t seq = pcb->snd_nxt;
  if (tcp_output_segment_at(pcb, TCP_SYN, seq, NULL, 0, 1) != 0)
    return -1;
  tcp_track_tx(pcb, TCP_SYN, seq, NULL, 0);
  return 0;
}

int tcp_send(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len) {
  if (!pcb || pcb->state != TCP_ESTABLISHED)
    return -1;
  if (len == 0)
    return 0;
  // Send one PSH|ACK segment (no segmentation yet)
  uint32_t seq = pcb->snd_nxt;
  if (tcp_output_segment_at(pcb, TCP_PSH | TCP_ACK, seq, data, len, 1) != 0)
    return -1;
  tcp_track_tx(pcb, TCP_PSH | TCP_ACK, seq, data, len);
  return 0;
}

int tcp_close(struct tcp_pcb *pcb) {
  if (!pcb)
    return -1;
  if (pcb->state != TCP_ESTABLISHED && pcb->state != TCP_CLOSE_WAIT)
    return -1;
  uint32_t seq = pcb->snd_nxt;
  if (tcp_output_segment_at(pcb, TCP_FIN | TCP_ACK, seq, NULL, 0, 1) != 0)
    return -1;
  pcb->snd_una = seq;
  pcb->state = TCP_LAST_ACK;
  tcp_track_tx(pcb, TCP_FIN | TCP_ACK, seq, NULL, 0);
  return 0;
}

void tcp_tick(uint32_t now_ticks) {
  (void)now_ticks;
  for (int i = 0; i < TCP_MAX_PCBS; i++) {
    struct tcp_pcb *pcb = &tcp_pcbs[i];
    // Retransmit for handshake/close, and best-effort for last small data
    // segment.
    if (pcb->last_tx_flags == 0)
      continue;

    /* Bytes in flight: peer has not ACKed up to snd_nxt. */
    int outstanding = (pcb->snd_una < pcb->snd_nxt);

    /*
     * Initial transmit failed before snd_nxt was bumped (TX ring full, etc.):
     * tcp_track_tx recorded the segment but snd_una == snd_nxt == last_tx_seq.
     * Without this, we never rtx and e.g. SSH never sends the version line.
     */
    if (!outstanding) {
      if (pcb->last_tx_len > 0 && pcb->snd_nxt == pcb->last_tx_seq)
        outstanding = 1;
      else if ((pcb->last_tx_flags & (TCP_SYN | TCP_FIN)) &&
               pcb->snd_nxt == pcb->last_tx_seq)
        outstanding = 1;
    }

    if (!outstanding)
      continue;
    if ((uint32_t)(pit_ticks - pcb->last_tx_tick) < TCP_RTX_TIMEOUT_TICKS)
      continue;
    if (pcb->rtx_count >= TCP_RTX_MAX) {
      // Give up on this tracked segment.
      pcb->last_tx_flags = 0;
      pcb->last_tx_len = 0;
      if (pcb->state == TCP_SYN_SENT || pcb->state == TCP_SYN_RCVD ||
          pcb->state == TCP_LAST_ACK) {
        pcb->state = TCP_CLOSED;
      }
      continue;
    }

    pcb->rtx_count++;
    pcb->last_tx_tick = pit_ticks;
    /*
     * Rtx uses advance_seq=0 so duplicate rtx does not double-advance snd_nxt.
     * If the first attempt never advanced snd_nxt, bump it after a successful
     * rtx so the sequence space matches what we actually put on the wire.
     */
    uint32_t bump = 0;
    if (pcb->snd_nxt == pcb->last_tx_seq) {
      if (pcb->last_tx_flags & (TCP_SYN | TCP_FIN))
        bump = 1;
      else
        bump = pcb->last_tx_len;
    }
    if (tcp_output_segment_at(pcb, pcb->last_tx_flags, pcb->last_tx_seq,
                              (pcb->last_tx_len ? pcb->last_tx_data : NULL),
                              pcb->last_tx_len, 0) == 0 &&
        bump != 0) {
      pcb->snd_nxt += bump;
    }
  }
}

static void tcp_input_body(struct pbuf *p, ip_addr_t src, ip_addr_t dst) {
  if (p->len < sizeof(struct tcp_hdr)) {
    pbuf_free(p);
    return;
  }

  struct tcp_hdr *hdr = (struct tcp_hdr *)p->payload;
  uint16_t dst_port = ntohs(hdr->dst_port);
  uint16_t src_port = ntohs(hdr->src_port);
  uint16_t flags = TCP_HDR_FLAGS(hdr);
  uint32_t seq = ntohl(hdr->seqno);
  uint32_t ack = ntohl(hdr->ackno);
  uint16_t off_words = TCP_HDR_OFFSET(hdr);
  if (off_words < 5 || off_words > 15) {
    // Bogus TCP header length; drop.
    pbuf_free(p);
    return;
  }
  uint16_t hdr_len = (uint16_t)(off_words * 4);
  int tcp_payload_len = (int)p->len - (int)hdr_len;

  struct tcp_pcb *pcb = tcp_find_pcb(dst, dst_port, src, src_port);
  if (!pcb) {
    // No listening socket or active connection
#ifdef AJOS_TCP_VERBOSE
    if (dst_port == 22 || dst_port == 80) {
      ssh_suppress_log_mirror_to_session++;
      log_writestring("[TCP] No PCB found for port ");
      log_write_u32(dst_port);
      log_writestring(", flags=0x");
      log_write_u32(flags);
      log_putchar('\n');
      ssh_suppress_log_mirror_to_session--;
    }
#endif
    pbuf_free(p);
    return;
  }

  /* Pure ACKs on established SSH flood serial/IRQ during heavy TX (e.g. ping
   * mirror); skip per-packet debug — same info as client window updates. */
#ifdef AJOS_TCP_VERBOSE
  int tcp_ssh_ack_only_noise =
      (dst_port == 22 && pcb->state == TCP_ESTABLISHED && tcp_payload_len <= 0);
  if ((dst_port == 22 || dst_port == 80) && !tcp_ssh_ack_only_noise) {
    ssh_suppress_log_mirror_to_session++;
    log_writestring("[TCP] Received packet for port ");
    log_write_u32(dst_port);
    log_writestring(" from ");
    log_write_u32((src >> 24) & 0xFF);
    log_putchar('.');
    log_write_u32((src >> 16) & 0xFF);
    log_putchar('.');
    log_write_u32((src >> 8) & 0xFF);
    log_putchar('.');
    log_write_u32(src & 0xFF);
    log_putchar('\n');
    log_writestring("[TCP] Found PCB: state=");
    log_write_u32(pcb->state);
    log_writestring(", flags=0x");
    log_write_u32(flags);
    log_writestring(", seq=");
    log_write_u32(seq);
    log_writestring(", ack=");
    log_write_u32(ack);
    log_putchar('\n');
    ssh_suppress_log_mirror_to_session--;
  }
#else
  (void)tcp_payload_len;
#endif

  if (pcb->state == TCP_LISTEN) {
    if (flags & TCP_SYN) {
      // Accept connection: Create NEW PCB
      struct tcp_pcb *npcb = tcp_get_free_pcb();
      if (!npcb) {
        // No resources, drop packet (or could send RST)
#ifdef AJOS_TCP_VERBOSE
        ssh_suppress_log_mirror_to_session++;
        log_writestring("[TCP] No free PCBs for new connection on port ");
        log_write_u32(dst_port);
        log_putchar('\n');
        ssh_suppress_log_mirror_to_session--;
#endif
        pbuf_free(p);
        return;
      }

      // Set local_ip to the destination IP (our IP), not the listener's IP
      // This ensures exact match works for subsequent packets
      npcb->local_ip = dst;
      npcb->local_port = pcb->local_port;
      npcb->remote_ip = src;
      npcb->remote_port = src_port;
      npcb->rcv_nxt = seq + 1;
      npcb->snd_nxt = 1000 + (pit_ticks % 10000); // Randomize ISN slightly
      npcb->snd_una = npcb->snd_nxt;
      npcb->state = TCP_SYN_RCVD;
      npcb->app_rx_len = 0;  // Initialize RX buffer
      npcb->peer_wnd = 65535u;

#ifdef AJOS_TCP_VERBOSE
      ssh_suppress_log_mirror_to_session++;
      log_writestring("[TCP] SYN received on port ");
      log_write_u32(dst_port);
      log_writestring(", created new PCB, sending SYN+ACK, state=SYN_RCVD\n");
      log_writestring("[TCP] New PCB: local_ip=");
      log_write_u32((npcb->local_ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((npcb->local_ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((npcb->local_ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(npcb->local_ip & 0xFF);
      log_writestring(", remote_ip=");
      log_write_u32((npcb->remote_ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((npcb->remote_ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((npcb->remote_ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(npcb->remote_ip & 0xFF);
      log_putchar('\n');
      ssh_suppress_log_mirror_to_session--;
#endif

      // Send SYN+ACK from the NEW PCB
      if (tcp_output_segment_at(npcb, TCP_SYN | TCP_ACK, npcb->snd_nxt, NULL, 0,
                                1) != 0) {
        npcb->state = TCP_CLOSED;
        pbuf_free(p);
        return;
      }
      tcp_track_tx(npcb, TCP_SYN | TCP_ACK, npcb->snd_una, NULL, 0);
      
      // Return immediately - don't process this packet further
      pbuf_free(p);
      return;
      
      // Initialize app_rx_len for the new connection
      npcb->app_rx_len = 0;
      
      // Return after handling SYN - don't process further
      pbuf_free(p);
      return;
    } else {
      // Not a SYN on listening socket - ignore
      pbuf_free(p);
      return;
    }
  } else if (pcb->state == TCP_SYN_SENT) {
    if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
      if (ack == pcb->snd_nxt) {
        pcb->rcv_nxt = seq + 1;
        pcb->snd_una = ack;
        pcb->state = TCP_ESTABLISHED;
        pcb->last_tx_flags = 0;
        pcb->last_tx_len = 0;
        pcb->peer_wnd = ntohs(hdr->window);
        tcp_send_ack(pcb, TCP_ACK);
      }
    } else if (flags & TCP_RST) {
      pcb->state = TCP_CLOSED;
    }
  } else if (pcb->state == TCP_SYN_RCVD) {
    if (flags & TCP_ACK) {
#ifdef AJOS_TCP_VERBOSE
      ssh_suppress_log_mirror_to_session++;
      log_writestring("[TCP] SYN_RCVD: Received ACK, ack=");
      log_write_u32(ack);
      log_writestring(", expected snd_nxt=");
      log_write_u32(pcb->snd_nxt);
      log_putchar('\n');
      ssh_suppress_log_mirror_to_session--;
#endif
      // After sending SYN|ACK we advanced snd_nxt by 1, so ACK should equal
      // snd_nxt.
        if (ack == pcb->snd_nxt) {
        pcb->state = TCP_ESTABLISHED;
        pcb->snd_una = ack;
        pcb->last_tx_flags = 0;
        pcb->last_tx_len = 0;
        pcb->peer_wnd = ntohs(hdr->window);

#ifdef AJOS_TCP_VERBOSE
        ssh_suppress_log_mirror_to_session++;
        log_writestring("[TCP] Connection ESTABLISHED on port ");
        log_write_u32(pcb->local_port);
        log_putchar('\n');
        ssh_suppress_log_mirror_to_session--;
#endif

        // Notify SSH handler of new connection (SSH sends version string on
        // connect)
        if (pcb->local_port == 22) {
          extern void ssh_handle_new_connection(struct tcp_pcb * pcb);
#ifdef AJOS_TCP_VERBOSE
          ssh_suppress_log_mirror_to_session++;
          log_writestring("[TCP] SSH connection established, notifying handler\n");
          ssh_suppress_log_mirror_to_session--;
#endif
          ssh_handle_new_connection(pcb);
        }

        /* Many clients (e.g. OpenSSH) piggyback the first data segment on the
         * ACK that completes the handshake. We used to drop it, which broke SSH
         * ident/KEX (connection reset at kex_exchange_identification). */
        uint16_t hl_ack = (uint16_t)(off_words * 4);
        if (hl_ack >= sizeof(struct tcp_hdr) && hl_ack <= p->len) {
          int dlen = p->len - hl_ack;
          if (dlen > 0 && seq == pcb->rcv_nxt) {
            pcb->rcv_nxt += (uint32_t)dlen;
            uint8_t *pay = (uint8_t *)p->payload + hl_ack;
            if (pcb->local_port == 22) {
              /* Stream to SSH rx_buf; do not use app_rx (avoids wrong plaintext
               * length splits on ciphertext and avoids stall at TCP_APP_RX_MAX). */
              ssh_handle_connection(pcb, pay, dlen);
            } else {
              int copy = dlen;
              int avail = (int)TCP_APP_RX_MAX - (int)pcb->app_rx_len;
              if (copy > avail)
                copy = avail;
              for (int i = 0; i < copy; i++) {
                pcb->app_rx_buf[pcb->app_rx_len + (uint16_t)i] = pay[i];
              }
              pcb->app_rx_len = (uint16_t)(pcb->app_rx_len + (uint16_t)copy);
              if (pcb->local_port == 80) {
                tcp_check_http_data(pcb, pay, dlen);
              }
            }
            tcp_send_ack(pcb, TCP_ACK);
          }
        }
      } else {
#ifdef AJOS_TCP_VERBOSE
        ssh_suppress_log_mirror_to_session++;
        log_writestring("[TCP] SYN_RCVD: ACK mismatch, dropping\n");
        ssh_suppress_log_mirror_to_session--;
#endif
      }
    } else if (flags & TCP_RST) {
#ifdef AJOS_TCP_VERBOSE
      ssh_suppress_log_mirror_to_session++;
      log_writestring("[TCP] SYN_RCVD: Received RST, closing\n");
      ssh_suppress_log_mirror_to_session--;
#endif
      pcb->state = TCP_CLOSED;
    }
  } else if (pcb->state == TCP_ESTABLISHED) {
    if (flags & TCP_RST) {
#ifdef AJOS_TCP_VERBOSE
      ssh_suppress_log_mirror_to_session++;
      log_writestring("[TCP] ESTABLISHED: RST, closing pcb\n");
      ssh_suppress_log_mirror_to_session--;
#endif
      pcb->state = TCP_CLOSED;
      pcb->last_tx_flags = 0;
      pcb->last_tx_len = 0;
      if (pcb->local_port == 22) {
        ssh_handle_connection_close(pcb);
      }
      pbuf_free(p);
      return;
    }
    // Update snd_una on ACKs and clear retransmit tracking when covered.
    if (flags & TCP_ACK) {
      if (ack > pcb->snd_una) {
        pcb->snd_una = ack;
      }
      if (pcb->last_tx_flags != 0) {
        uint32_t tracked_end = pcb->last_tx_seq;
        if (pcb->last_tx_flags & (TCP_SYN | TCP_FIN)) {
          tracked_end += 1;
        } else {
          tracked_end += pcb->last_tx_len;
        }
        if (ack >= tracked_end) {
          pcb->last_tx_flags = 0;
          pcb->last_tx_len = 0;
          pcb->rtx_count = 0;
        }
      }
    }
    pcb->peer_wnd = ntohs(hdr->window);
    if (flags & TCP_FIN) {
      pcb->rcv_nxt = seq + 1;
      tcp_send_ack(pcb, TCP_ACK);
      pcb->state = TCP_CLOSE_WAIT;
      // Notify SSH handler of connection close (Minoca OS pattern: cleanup on close)
      if (pcb->local_port == 22) {
#ifdef AJOS_TCP_VERBOSE
        ssh_suppress_log_mirror_to_session++;
        log_writestring("[TCP] SSH connection: Client sent FIN (disconnect)\n");
        ssh_suppress_log_mirror_to_session--;
#endif
        extern void ssh_handle_connection_close(struct tcp_pcb *pcb);
        ssh_handle_connection_close(pcb);
      }
      // We don't send our FIN yet. We wait for the application to call
      // tcp_close().
    } else {
      // Data?
      uint16_t hl = (uint16_t)(off_words * 4);
      if (hl < sizeof(struct tcp_hdr) || hl > p->len) {
        pbuf_free(p);
        return;
      }
      int data_len = p->len - hl;
      if (data_len > 0) {
        // Minimal in-order receive:
        // Only accept payload if it matches rcv_nxt, otherwise send a duplicate
        // ACK. This prevents "acknowledging holes" which can make http_get
        // capture only later (often binary/compressed) bytes and miss the HTTP
        // status line.
        if (seq == pcb->rcv_nxt) {
          pcb->rcv_nxt += (uint32_t)data_len;

          // Save response bytes for synchronous printing by shell commands
          // like `http_get`. Don't print here (IRQ context).
          uint8_t *payload = (uint8_t *)p->payload + hl;
          if (pcb->local_port == 22) {
            ssh_handle_connection(pcb, payload, data_len);
          } else {
            int copy = data_len;
            int avail = (int)TCP_APP_RX_MAX - (int)pcb->app_rx_len;
            if (copy > avail)
              copy = avail;
            for (int i = 0; i < copy; i++) {
              pcb->app_rx_buf[pcb->app_rx_len + (uint16_t)i] = payload[i];
            }
            pcb->app_rx_len = (uint16_t)(pcb->app_rx_len + (uint16_t)copy);
            if (pcb->app_rx_len < TCP_APP_RX_MAX && pcb->local_port == 80) {
              tcp_check_http_data(pcb, payload, data_len);
            }
          }
        }

        // Always ACK what we have (either advanced or duplicate ACK).
        tcp_send_ack(pcb, TCP_ACK);
      }
    }
  } else if (pcb->state == TCP_LAST_ACK) {
    if (flags & TCP_ACK) {
      pcb->state = TCP_CLOSED;
      pcb->last_tx_flags = 0;
      pcb->last_tx_len = 0;
      // Notify SSH handler when connection fully closed (Minoca OS pattern)
      if (pcb->local_port == 22) {
        extern void ssh_handle_connection_close(struct tcp_pcb *pcb);
        ssh_handle_connection_close(pcb);
      }
    }
  }

  pbuf_free(p);
}

void tcp_input(struct pbuf *p, ip_addr_t src, ip_addr_t dst) {
  /* Do NOT wrap the whole stack frame in ssh_suppress_log_mirror_to_session:
   * ssh_handle_connection() runs inside tcp_input_body and calls shell_execute;
   * a global suppress here forced all command output to VGA/serial only. */
  tcp_input_body(p, src, dst);
}

// Send data over an established TCP connection (e.g. SSH version banner).
// Must match tcp_send(): track the segment so tcp_tick() can retransmit if lost.
int tcp_send_data(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len) {
  if (!pcb || pcb->state != TCP_ESTABLISHED)
    return -1;

  uint32_t seq = pcb->snd_nxt;
  if (tcp_output_segment_at(pcb, TCP_PSH | TCP_ACK, seq, data, len, 1) != 0) {
    /* TX ring full / ARP miss: keep snd_nxt; tcp_tick will rtx same seq. */
    tcp_track_tx(pcb, TCP_PSH | TCP_ACK, seq, data, len);
    return -1;
  }
  tcp_track_tx(pcb, TCP_PSH | TCP_ACK, seq, data, len);
  return 0;
}

// Check if this is an HTTP connection and handle it
static void tcp_check_http_data(struct tcp_pcb *pcb, uint8_t *data, int len) {
  // Only handle port 80 connections
  if (pcb->local_port != 80) {
    return;
  }

  // Use accumulated buffer instead of individual packet data
  // This ensures we have the complete request, especially for POST with body
  // Only process if we have accumulated enough data (at least headers)
  if (pcb->app_rx_len < 14) {
    return; // Wait for more data
  }

  // Check if we have a complete request (ends with \r\n\r\n or have
  // Content-Length) For POST, wait until we have the full body based on
  // Content-Length
  int has_double_crlf = 0;
  for (int i = 0; i < pcb->app_rx_len - 3; i++) {
    if (pcb->app_rx_buf[i] == '\r' && pcb->app_rx_buf[i + 1] == '\n' &&
        pcb->app_rx_buf[i + 2] == '\r' && pcb->app_rx_buf[i + 3] == '\n') {
      has_double_crlf = 1;
      break;
    }
  }

  if (!has_double_crlf) {
    return; // Wait for headers to complete
  }

  // For POST, check if we have the full body
  if (pcb->app_rx_buf[0] == 'P' && pcb->app_rx_buf[1] == 'O' &&
      pcb->app_rx_buf[2] == 'S' && pcb->app_rx_buf[3] == 'T') {
    // Find Content-Length header
    int content_length = -1;
    for (int i = 0; i < pcb->app_rx_len - 15; i++) {
      if (pcb->app_rx_buf[i] == 'C' && pcb->app_rx_buf[i + 1] == 'o' &&
          pcb->app_rx_buf[i + 2] == 'n' && pcb->app_rx_buf[i + 3] == 't' &&
          pcb->app_rx_buf[i + 4] == 'e' && pcb->app_rx_buf[i + 5] == 'n' &&
          pcb->app_rx_buf[i + 6] == 't' && pcb->app_rx_buf[i + 7] == '-' &&
          pcb->app_rx_buf[i + 8] == 'L' && pcb->app_rx_buf[i + 9] == 'e' &&
          pcb->app_rx_buf[i + 10] == 'n' && pcb->app_rx_buf[i + 11] == 'g' &&
          pcb->app_rx_buf[i + 12] == 't' && pcb->app_rx_buf[i + 13] == 'h' &&
          pcb->app_rx_buf[i + 14] == ':') {
        // Parse Content-Length value
        int j = i + 15;
        while (j < pcb->app_rx_len && pcb->app_rx_buf[j] == ' ')
          j++;
        content_length = 0;
        while (j < pcb->app_rx_len && pcb->app_rx_buf[j] >= '0' &&
               pcb->app_rx_buf[j] <= '9') {
          content_length = content_length * 10 + (pcb->app_rx_buf[j] - '0');
          j++;
        }
        break;
      }
    }

    if (content_length >= 0) {
      // Find where body starts (after \r\n\r\n)
      int body_start = -1;
      for (int i = 0; i < pcb->app_rx_len - 3; i++) {
        if (pcb->app_rx_buf[i] == '\r' && pcb->app_rx_buf[i + 1] == '\n' &&
            pcb->app_rx_buf[i + 2] == '\r' && pcb->app_rx_buf[i + 3] == '\n') {
          body_start = i + 4;
          break;
        }
      }

      if (body_start >= 0) {
        int body_received = pcb->app_rx_len - body_start;
        if (body_received < content_length) {
          return; // Wait for full body
        }
      }
    }
  }

  // Call HTTP handler with accumulated buffer
  extern void http_handle_connection(struct tcp_pcb * pcb, const uint8_t *data,
                                     int len);
  http_handle_connection(pcb, pcb->app_rx_buf, pcb->app_rx_len);

  // Clear buffer after processing request (ready for next request)
  pcb->app_rx_len = 0;
}

