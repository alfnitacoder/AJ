#include "ssh.h"
#include "auth.h"
#include "crypto.h"
#include "debug_agent.h"
#include "kernel.h"
#include "net.h"
#include "netdev.h"
#include "pbuf.h"
#include "sftp.h"
#include "openssh/sshbuf.h"
#include "openssh/ssherr.h"
#include <stddef.h>
#include <stdint.h>

uint32_t ssh_log_mirror_depth = 0;
uint32_t ssh_suppress_log_mirror_to_session = 0;

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void log_write_hex32(uint32_t v);
extern void log_write_hex8(uint8_t v);

/* Keep real console log for sshd start/stop/status (user-facing). */
static void (*const ssh_console_writestring)(const char *) = log_writestring;
static void (*const ssh_console_write_u32)(uint32_t) = log_write_u32;
static void (*const ssh_console_putchar)(char) = log_putchar;

/* Protocol / handshake chatter off unless built with -DAJOS_SSH_VERBOSE. */
#ifndef AJOS_SSH_VERBOSE
static void ssh_log_writestring(const char *s) { (void)s; }
static void ssh_log_write_u32(uint32_t v) { (void)v; }
static void ssh_log_putchar(char c) { (void)c; }
static void ssh_log_write_hex8(uint8_t v) { (void)v; }
static void ssh_log_write_hex32(uint32_t v) { (void)v; }
#define log_writestring ssh_log_writestring
#define log_write_u32 ssh_log_write_u32
#define log_putchar ssh_log_putchar
#define log_write_hex8 ssh_log_write_hex8
#define log_write_hex32 ssh_log_write_hex32
#endif

extern struct tcp_pcb *tcp_get_free_pcb(void);
extern int tcp_send_data(struct tcp_pcb *pcb, const uint8_t *data,
                         uint16_t len);
extern int tcp_close(struct tcp_pcb *pcb);
extern void shell_execute(const char *line);
extern void readline(const char *prompt, char *line, size_t line_size);
void *kmalloc(uint32_t size);
void kfree(void *ptr);
extern int memcmp(const void *s1, const void *s2, size_t n);
extern uint32_t pit_ticks;

static uint8_t *sshd_tx_buffer = 0;
static uint8_t *sshd_rx_buffer = 0;
/* seq(4) + max SSH plaintext (4 + packet_length) for HMAC input (RFC 4253). */
static uint8_t ssh_mac_plain_scratch[36000];

/* SSH_MSG_CHANNEL_DATA payload build: recipient(4) + string len(4) + bytes.
 * Must not live on the stack — a ~16KB pkt[] here overflowed the kernel stack
 * after a few SSH commands (echo + shell output). */
#define SSH_CHANNEL_DATA_CHUNK 4096
static uint8_t ssh_chan_payload_scratch[8 + SSH_CHANNEL_DATA_CHUNK];

/*
 * sshd_tx_buffer + ssh_chan_payload_scratch are global. log_putchar can mirror
 * into SSH (ssh_shell_mirror_putchar -> ssh_send_channel_data_raw) and corrupt
 * a packet in flight.
 *
 * Do NOT use cli/sti here: holding IF=0 for a large help(1)/ping output blocks
 * PIT + NIC IRQs, pit_ticks stops, tcp_tick never runs, ping wait loops never
 * time out, and the whole network stack wedges (including serial console).
 *
 * Instead bump ssh_suppress_log_mirror_to_session (see log_putchar in kernel.c)
 * so IRQ/time context does not re-enter the SSH TX path while we use globals.
 */
static uint32_t ssh_tx_mirror_guard_depth;
/* When >0, ssh_send_packet / ssh_send_packet_sshbuf skip guard enter (outer holds). */
static uint32_t ssh_skip_tx_irq_wrappers;
/* Nested CHANNEL_DATA TX depth — defer WINDOW_ADJUST so we never re-enter
 * ssh_send_packet while sshd_tx_buffer / scratch is in use (editor redraw). */
static uint32_t ssh_channel_tx_depth;

static void ssh_tx_irq_enter(void)
{
  if (ssh_tx_mirror_guard_depth++ == 0u)
    ssh_suppress_log_mirror_to_session++;
}

static void ssh_tx_irq_leave(void)
{
  if (ssh_tx_mirror_guard_depth == 0u)
    return;
  if (--ssh_tx_mirror_guard_depth == 0u && ssh_suppress_log_mirror_to_session > 0u)
    ssh_suppress_log_mirror_to_session--;
}

// SSH Connections
#define SSH_MAX_CONNECTIONS 4
static struct ssh_connection ssh_connections[SSH_MAX_CONNECTIONS];
/* Shell output mirror (used from ssh_destroy_connection and log sink). */
static struct ssh_connection *ssh_shell_log_conn;
static uint32_t ssh_shell_log_sink_depth;
/* Incremented only around shell_execute() invoked from ssh_flush_pending_shell_commands. */
static volatile uint32_t ssh_remote_shell_execute_depth;
static char ssh_mirror_buf[2048];
static size_t ssh_mirror_len;
static int sshd_active = 0;
static struct tcp_pcb *sshd_listen_pcb = 0;

/* Raw stdin ring: keystrokes while a remote command (e.g. edit) is running. */
#define SSH_STDIN_RING 256
static uint8_t ssh_stdin_buf[SSH_STDIN_RING];
static uint16_t ssh_stdin_r;
static uint16_t ssh_stdin_w;

void ssh_stdin_reset(void)
{
  ssh_stdin_r = 0;
  ssh_stdin_w = 0;
}

int ssh_stdin_has_data(void)
{
  return ssh_stdin_r != ssh_stdin_w;
}

static void ssh_stdin_push(uint8_t c)
{
  uint16_t next = (uint16_t)((ssh_stdin_w + 1u) % SSH_STDIN_RING);
  if (next == ssh_stdin_r)
    return; /* full: drop */
  ssh_stdin_buf[ssh_stdin_w] = c;
  ssh_stdin_w = next;
}

int ssh_stdin_getchar(void)
{
  if (ssh_stdin_r == ssh_stdin_w)
    return -1;
  uint8_t c = ssh_stdin_buf[ssh_stdin_r];
  ssh_stdin_r = (uint16_t)((ssh_stdin_r + 1u) % SSH_STDIN_RING);
  return (int)c;
}

// Global buffer for server's KEXINIT payload - survives everything
// This MUST be global (not static inside function) to avoid stack corruption
static uint8_t server_kexinit_payload[512];

/* Allocate heavy SSH transport buffers only when a client connects.
 * Early boot allocations this large were destabilizing init on AJOS. */
static int ssh_ensure_io_buffers(void)
{
  if (!sshd_tx_buffer)
  {
    /* +32 for MAC trailer when transport encryption is enabled. */
    sshd_tx_buffer = (uint8_t *)kmalloc(36000);
    if (!sshd_tx_buffer)
      return 0;
  }
  if (!sshd_rx_buffer)
  {
    sshd_rx_buffer = (uint8_t *)kmalloc(35000);
    if (!sshd_rx_buffer)
      return 0;
  }
  return 1;
}

/* KEX name-list (strict-s first for OpenSSH 9.x; find_common skips non-matches). */
static const char ssh_server_kex_algs[] =
    "kex-strict-s-v00@openssh.com,"
    "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha1,"
    "diffie-hellman-group1-sha1";

// Safe permanent storage for server's KEXINIT payload (I_S)
// This survives stack reuse, crypto, memory corruption, everything
// We use this instead of conn->i_s because conn->i_s gets corrupted during RSA signing
// Made non-static so crypto.c can access it directly
uint8_t safe_i_s[512];
uint32_t safe_i_s_len = 0;

// Helper: Cleanup SSH connection (Minoca OS pattern: TelnetdDestroySession)
static void ssh_destroy_connection(struct ssh_connection *conn)
{
  if (!conn)
  {
    return;
  }

  // Free backlog buffer if allocated
  if (conn->backlog_buf)
  {
    kfree(conn->backlog_buf);
    conn->backlog_buf = NULL;
    conn->backlog_alloc = 0;
    conn->backlog_len = 0;
  }

  // Free OpenSSH buffers
  if (conn->tx_buf)
  {
    sshbuf_free(conn->tx_buf);
    conn->tx_buf = NULL;
  }
  if (conn->rx_buf)
  {
    sshbuf_free(conn->rx_buf);
    conn->rx_buf = NULL;
  }

  /* Flush shell mirror while PCB is still valid for TCP send. */
  if (ssh_shell_log_conn == conn)
  {
    ssh_shell_log_flush();
    ssh_shell_log_conn = NULL;
    ssh_shell_log_sink_depth = 0;
    ssh_mirror_len = 0;
  }

  sftp_session_close(conn);

  // Clear connection state
  conn->pcb = NULL;
  conn->state = SSH_STATE_VERSION_EXCHANGE;
  conn->authenticated = 0;
  conn->client_channel = 0;
  conn->has_client_channel = 0;
  conn->server_channel = 0;
  conn->client_window = 0;
  conn->server_window = 0;
  conn->deferred_window_adjust = 0;
  conn->shell_session_started = 0;
  conn->ssh_welcome_sent = 0;
  conn->shell_ignore_next_lf = 0;
  conn->shell_line_len = 0;
  conn->shell_pending_count = 0;
  conn->username[0] = '\0';
  conn->encrypted = 0;
  conn->processing = 0;
  conn->computing_keys = 0;
  conn->closing = 0;

  // Clear exchange hash components
  conn->v_c_len = 0;
  conn->i_c_len = 0;
  conn->i_s_len = 0;
  conn->k_s_len = 0;
  conn->gex_p_len = 0;
  conn->gex_g_len = 0;
  conn->gex_e_len = 0;
  conn->gex_f_len = 0;
  conn->negotiated_sig_alg[0] = '\0';
  conn->k_mpint_len = 0;
  conn->keys_derived = 0;
  conn->kex_strict = 0;

  log_writestring("[SSH] Connection destroyed and cleaned up\n");
}

// Helper: Find or allocate SSH connection (Minoca OS pattern: TelnetdCreateSession)
static struct ssh_connection *ssh_find_connection(struct tcp_pcb *pcb)
{
  /* If TCP closed without ssh_handle_connection_close (e.g. RST not handled
   * before), pcb can be reused while this slot still points at it → wrong
   * session and immediate client disconnect at ident. */
  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    if (ssh_connections[i].pcb &&
        ssh_connections[i].pcb->state == TCP_CLOSED)
    {
      log_writestring("[SSH] Reaping zombie session (pcb already CLOSED)\n");
      ssh_destroy_connection(&ssh_connections[i]);
    }
  }

  // First, try to find existing connection
  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    if (ssh_connections[i].pcb == pcb)
    {
      return &ssh_connections[i];
    }
  }

  // Allocate new connection slot
  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    if (ssh_connections[i].pcb == NULL)
    {
      if (!ssh_ensure_io_buffers())
      {
        log_writestring("[SSH] Failed to allocate IO buffers\n");
        return NULL;
      }

      struct ssh_connection *conn = &ssh_connections[i];

      // Initialize connection (similar to Minoca OS session initialization)
      conn->pcb = pcb;
      conn->state = SSH_STATE_VERSION_EXCHANGE;
      conn->authenticated = 0;
      conn->client_channel = 0;
      conn->has_client_channel = 0;
      conn->server_channel = 0;
      conn->client_window = 0;
      conn->server_window = 65536;
      conn->deferred_window_adjust = 0;
      conn->shell_session_started = 0;
      conn->sftp_active = 0;
      conn->ssh_welcome_sent = 0;
      conn->shell_ignore_next_lf = 0;
      conn->shell_line_len = 0;
      conn->shell_pending_count = 0;
      conn->username[0] = '\0';
      conn->encrypted = 0;
      conn->recv_packet_count = 0;
      conn->send_packet_count = 0;
      conn->processing = 0;
      conn->computing_keys = 0;
      conn->closing = 0;

      // Initialize crypto state
      conn->crypto.cipher_type = 0; // No encryption initially
      conn->crypto.mac_type = 0;
      conn->crypto.seq_number = 0;
      for (int j = 0; j < 16; j++)
      {
        conn->crypto.key[j] = (uint8_t)(0xAA + j);
      }

      // Initialize exchange hash components
      conn->v_c_len = 0;
      conn->i_c_len = 0;
      conn->i_s_len = 0;
      conn->k_s_len = 0;
      conn->gex_p_len = 0;
      conn->gex_g_len = 0;
      conn->gex_e_len = 0;
      conn->gex_f_len = 0;
      conn->negotiated_sig_alg[0] = '\0';
      conn->k_mpint_len = 0;
      conn->keys_derived = 0;
      conn->kex_strict = 0;

      // Initialize backlog buffer (allocate on demand)
      conn->backlog_buf = NULL;
      conn->backlog_alloc = 0;
      conn->backlog_len = 0;

      // Initialize OpenSSH buffers
      conn->tx_buf = sshbuf_new();
      conn->rx_buf = sshbuf_new();
      if (!conn->tx_buf || !conn->rx_buf)
      {
        log_writestring("[SSH] Failed to allocate sshbuf\n");
        if (conn->tx_buf)
          sshbuf_free(conn->tx_buf);
        if (conn->rx_buf)
          sshbuf_free(conn->rx_buf);
        conn->tx_buf = NULL;
        conn->rx_buf = NULL;
        conn->pcb = NULL; /* release slot; caller must close TCP pcb */
        return NULL;
      }

      log_writestring("[SSH] New connection slot allocated\n");
      return conn;
    }
  }

  log_writestring("[SSH] No free connection slots available\n");
  return NULL;
}

// Helper: Read 32-bit big-endian integer
static uint32_t ssh_read_u32(const uint8_t *data)
{
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
         ((uint32_t)data[2] << 8) | data[3];
}

// Helper: Write 32-bit big-endian integer
static void ssh_write_u32(uint8_t *data, uint32_t value)
{
  data[0] = (value >> 24) & 0xFF;
  data[1] = (value >> 16) & 0xFF;
  data[2] = (value >> 8) & 0xFF;
  data[3] = value & 0xFF;
}

/*
 * Plaintext SSH binary packet already in sshd_tx_buffer[0 .. total_size-1].
 * HMAC(seq, plaintext), AES-128-CTR encrypt in place, append MAC, TCP send.
 * If e1000 TX is momentarily full, tcp_send_data fails without advancing TCP
 * seq — old code still bumped snd_nxt and send_seq and advanced CTR, corrupting
 * the session after any bursty command output.
 */
static void ssh_send_encrypted_aes_hmac(struct ssh_connection *conn,
                                        int total_size)
{
  uint8_t mac_buf[32];
  uint8_t ctr_saved[16];

  for (int i = 0; i < 16; i++)
    ctr_saved[i] = conn->crypto.send_ctr[i];

  /* Encrypt + MAC once. Retries only re-attempt TCP — redoing AES/HMAC on
   * soft-float i386 made every bursty SSH command (cat/edit) stall ~5s. */
  {
    uint8_t seq_be[4];
    ssh_write_u32(seq_be, conn->crypto.send_seq);
    ssh_hmac_sha256_two(conn->crypto.send_mac_key, 32, seq_be, 4, sshd_tx_buffer,
                        (size_t)total_size, mac_buf);
    for (int i = 0; i < 16; i++)
      conn->crypto.send_ctr[i] = ctr_saved[i];
    aes128_ctr_crypt(conn->crypto.send_key, conn->crypto.send_ctr, sshd_tx_buffer,
                     total_size);
    for (int mi = 0; mi < 32; mi++)
      sshd_tx_buffer[total_size + mi] = mac_buf[mi];
  }

  for (int tries = 0; tries < 256; tries++)
  {
    if (tcp_send_data(conn->pcb, sshd_tx_buffer,
                      (uint16_t)(total_size + 32)) == 0)
    {
      conn->crypto.send_seq++;
      return;
    }
    netdev_napi_poll(16);
    tcp_tick(pit_ticks);
    for (volatile uint32_t s = 0; s < 4000u; s++)
      __asm__ volatile("pause");
  }
  /* Roll back CTR so a failed send does not desync the cipher state. */
  for (int i = 0; i < 16; i++)
    conn->crypto.send_ctr[i] = ctr_saved[i];
  log_writestring("[SSH] encrypted tcp_send failed after retries\n");
}

/* True if blob contains ASCII substring needle (OpenSSH kex-strict marker). */
static int ssh_blob_contains(const uint8_t *p, uint32_t plen, const char *needle)
{
  uint32_t nlen = 0;
  while (needle[nlen])
    nlen++;
  if (plen < nlen)
    return 0;
  for (uint32_t i = 0; i + nlen <= plen; i++)
  {
    uint32_t j;
    for (j = 0; j < nlen; j++)
    {
      if (p[i + j] != (uint8_t)needle[j])
        break;
    }
    if (j == nlen)
      return 1;
  }
  return 0;
}

// Helper: Find first matching algorithm in two comma-separated lists
// server_list: "alg1,alg2,alg3"
// client_list: raw bytes from name-list (not null-terminated)
static int ssh_find_common_alg(const char *server_list,
                               const uint8_t *client_list,
                               uint32_t client_list_len, char *out_name,
                               uint32_t out_max)
{
  const char *s_ptr = server_list;
  while (*s_ptr)
  {
    // Extract next server algorithm
    char s_alg[64];
    int s_len = 0;
    while (*s_ptr && *s_ptr != ',' && s_len < 63)
    {
      s_alg[s_len++] = *s_ptr++;
    }
    s_alg[s_len] = '\0';
    if (*s_ptr == ',')
      s_ptr++;

    // Look for s_alg in client_list
    const uint8_t *c_ptr = client_list;
    uint32_t remaining = client_list_len;
    while (remaining >= (uint32_t)s_len)
    {
      // Check if it matches at current position
      int match = 1;
      for (int i = 0; i < s_len; i++)
      {
        if (c_ptr[i] != (uint8_t)s_alg[i])
        {
          match = 0;
          break;
        }
      }
      // Must be full match (either at string end or comma)
      if (match)
      {
        int at_start = (c_ptr == client_list || *(c_ptr - 1) == ',');
        int at_end = (remaining == (uint32_t)s_len || c_ptr[s_len] == ',');
        if (at_start && at_end)
        {
          // Found it!
          int copy = s_len;
          if (copy >= (int)out_max)
            copy = out_max - 1;
          for (int i = 0; i < copy; i++)
            out_name[i] = s_alg[i];
          out_name[copy] = '\0';
          return 1;
        }
      }
      c_ptr++;
      remaining--;
    }
  }
  return 0;
}

// Simple XOR encryption/decryption (for testing - can be upgraded to AES)
static void ssh_xor_crypt(uint8_t *data, int len, const uint8_t *key,
                          int key_len)
{
  for (int i = 0; i < len; i++)
  {
    data[i] ^= key[i % key_len];
  }
}

// Read SSH packet with proper structure
// SSH packet format: [packet_length(4)] [padding_length(1)] [payload] [padding]
// [MAC]
static int ssh_read_packet(struct ssh_connection *conn, const uint8_t *data,
                           int len, uint8_t *msg_type, const uint8_t **payload,
                           int *payload_len)
{
  if (len < 5)
    return 0; // Need at least packet_length(4) + padding_length(1)

  uint32_t packet_length = ssh_read_u32(data);
  if (packet_length > 35000 || packet_length < 1)
    return 0; // Sanity check
  if (len < (int)(packet_length + 4))
    return 0; // Need full packet (4-byte length + packet_length bytes)

  // Decrypt if encryption is active (decrypt everything after packet_length)
  // AES path is handled in main loop; here only XOR test cipher
  if (conn->encrypted && conn->crypto.cipher_type == SSH_CIPHER_XOR_TEST)
  {
    for (int i = 0; i < (int)packet_length && i < 35000; i++)
    {
      sshd_rx_buffer[i] = data[4 + i] ^ conn->crypto.key[i % 16];
    }
  }
  else
  {
    // Copy to static buffer even if not encrypted for consistency
    for (int i = 0; i < (int)packet_length && i < 35000; i++)
    {
      sshd_rx_buffer[i] = data[4 + i];
    }
  }

  uint8_t padding_length = sshd_rx_buffer[0]; // First byte after packet_length
  if (padding_length >= packet_length)
    return 0; // Invalid padding

  // payload_size = packet_length - padding_length - 1 (the padding_length byte
  // itself)
  int payload_size = packet_length - padding_length - 1;
  if (payload_size < 1)
    return 0; // Need at least message type

  *msg_type = sshd_rx_buffer[1];   // First byte of payload is message type
  *payload = sshd_rx_buffer + 2;   // Skip padding_length(1) + msg_type(1)
  *payload_len = payload_size - 1; // Rest of payload (excluding msg_type)

  return 1;
}

// Helper: Send SSH packet using OpenSSH buffer (new implementation)
// This uses sshbuf for safer buffer management
static int ssh_send_packet_sshbuf(struct ssh_connection *conn, uint8_t msg_type,
                                  const uint8_t *data, size_t data_len)
{
  int r;

  if (!conn || !conn->tx_buf)
  {
    log_writestring("[SSH] Invalid connection or tx_buf\n");
    return SSH_ERR_INTERNAL_ERROR;
  }

  // Clear the buffer for new packet
  sshbuf_reset(conn->tx_buf);

  // Add message type
  if ((r = sshbuf_put_u8(conn->tx_buf, msg_type)) != 0)
  {
    log_writestring("[SSH] Failed to add message type\n");
    return r;
  }

  // Add payload data
  if (data && data_len > 0)
  {
    if ((r = sshbuf_put(conn->tx_buf, data, data_len)) != 0)
    {
      log_writestring("[SSH] Failed to add payload data\n");
      return r;
    }
  }

  // Get the payload (message type + data)
  size_t payload_len = sshbuf_len(conn->tx_buf);
  const uint8_t *payload = sshbuf_ptr(conn->tx_buf);

  // Calculate padding (RFC 4253: packet_length + 4 must be multiple of block_size)
  int block_size = (conn->encrypted &&
                    conn->crypto.cipher_type == SSH_CIPHER_AES128_CTR)
                       ? 16
                       : 8;
  int padding_len = (block_size - ((5 + payload_len) % block_size)) % block_size;
  if (padding_len < 4)
  {
    padding_len += block_size; // Ensure minimum 4 bytes
  }

  // Total packet length (not including the 4-byte length field)
  int total_packet_len = 1 + payload_len + padding_len; // padding_length(1) + payload + padding

  if (4 + total_packet_len > 35000)
  {
    log_writestring("[SSH] Packet too large\n");
    return SSH_ERR_INVALID_ARGUMENT;
  }

  int own_irq = (ssh_skip_tx_irq_wrappers == 0u);
  if (own_irq)
    ssh_tx_irq_enter();

  // Build final packet in static buffer (for now, until we can encrypt in-place)
  // Write packet length (doesn't include the 4-byte length field itself)
  ssh_write_u32(sshd_tx_buffer, total_packet_len);

  // Write padding length
  sshd_tx_buffer[4] = (uint8_t)padding_len;

  // Copy payload (message type + data)
  for (size_t i = 0; i < payload_len; i++)
  {
    sshd_tx_buffer[5 + i] = payload[i];
  }

  // Add padding (zeros for now)
  for (int i = 0; i < padding_len; i++)
  {
    sshd_tx_buffer[5 + payload_len + i] = 0;
  }

  int total_size = 4 + total_packet_len;
  if (conn->encrypted && conn->crypto.cipher_type == SSH_CIPHER_XOR_TEST)
  {
    ssh_xor_crypt(sshd_tx_buffer + 4, total_packet_len, conn->crypto.key, 16);
  }

  if (msg_type != SSH_MSG_CHANNEL_DATA &&
      msg_type != SSH_MSG_CHANNEL_WINDOW_ADJUST)
  {
    log_writestring("[SSH] Sending packet (sshbuf): type=");
    log_write_u32(msg_type);
    log_writestring(", size=");
    log_write_u32(conn->encrypted && conn->crypto.mac_len > 0 ? total_size + 32
                                                                : total_size);
    log_putchar('\n');
  }

  if (conn->encrypted && conn->crypto.cipher_type == SSH_CIPHER_AES128_CTR &&
      conn->crypto.mac_len > 0)
  {
    ssh_send_encrypted_aes_hmac(conn, total_size);
  }
  else
  {
    tcp_send_data(conn->pcb, sshd_tx_buffer, (uint16_t)total_size);
    if (!conn->encrypted)
      conn->send_packet_count++;
  }
  if (own_irq)
    ssh_tx_irq_leave();
  return 0;
}

// Helper: Send SSH packet with proper structure (legacy implementation)
static void ssh_send_packet(struct ssh_connection *conn, uint8_t msg_type,
                            const uint8_t *data, int data_len)
{
  int own_irq = (ssh_skip_tx_irq_wrappers == 0u);
  if (own_irq)
    ssh_tx_irq_enter();

  // SSH packet format: [packet_length(4)] [padding_length(1)] [payload]
  // [padding] [MAC] packet_length = 1 (padding_length byte) + payload_len +
  // padding_len Total (packet_length + padding) must be multiple of block_size

  int payload_len = 1 + (data_len > 0 ? data_len : 0); // msg_type(1) + data
  int block_size = (conn->encrypted &&
                    conn->crypto.cipher_type == SSH_CIPHER_AES128_CTR)
                       ? 16
                       : 8;

  // RFC 4253: total_packet_len + 4 must be a multiple of block_size
  // total_packet_len = 1 + payload_len + padding_len
  // So: (1 + payload_len + padding_len + 4) % 8 == 0
  // (5 + payload_len + padding_len) % 8 == 0
  int padding_len =
      (block_size - ((5 + payload_len) % block_size)) % block_size;
  if (padding_len < 4)
  {
    padding_len += block_size; // Ensure minimum 4 bytes
  }

  // Total packet length (not including the 4-byte length field)
  int total_packet_len =
      1 + payload_len + padding_len; // padding_length(1) + payload + padding

  if (4 + total_packet_len > 35000)
  {
    log_writestring("[SSH] Packet too large\n");
    if (own_irq)
      ssh_tx_irq_leave();
    return;
  }

  // Write packet length (doesn't include the 4-byte length field itself)
  ssh_write_u32(sshd_tx_buffer, total_packet_len);

  // Write padding length
  sshd_tx_buffer[4] = (uint8_t)padding_len;

  // Write message type
  sshd_tx_buffer[5] = msg_type;

  // Write payload data
  if (data && data_len > 0)
  {
    int copy = data_len;
    if (copy > 35000 - 6)
      copy = 35000 - 6;
    for (int i = 0; i < copy; i++)
    {
      sshd_tx_buffer[6 + i] = data[i];
    }
  }

  // Add padding (random bytes - simplified to zeros for now)
  // Padding starts after payload (after msg_type + data)
  int padding_start =
      6 +
      data_len; // Correct start: length(4) + pad_len(1) + msg_type(1) + data
  for (int i = 0; i < padding_len; i++)
  {
    sshd_tx_buffer[padding_start + i] =
        0; // In real SSH, these should be random
  }

  int total_size = 4 + total_packet_len;
  if (conn->encrypted && conn->crypto.cipher_type == SSH_CIPHER_XOR_TEST)
  {
    ssh_xor_crypt(sshd_tx_buffer + 4, total_packet_len, conn->crypto.key, 16);
  }

  /* High-volume types: logging from TX path (often nested in IRQ) stalls RX. */
  if (msg_type != SSH_MSG_CHANNEL_DATA &&
      msg_type != SSH_MSG_CHANNEL_WINDOW_ADJUST)
  {
    log_writestring("[SSH] Sending packet: type=");
    log_write_u32(msg_type);
    log_writestring(", size=");
    log_write_u32(conn->encrypted && conn->crypto.mac_len > 0 ? total_size + 32
                                                              : total_size);
    log_putchar('\n');
  }

  if (conn->encrypted && conn->crypto.cipher_type == SSH_CIPHER_AES128_CTR &&
      conn->crypto.mac_len > 0)
  {
    ssh_send_encrypted_aes_hmac(conn, total_size);
  }
  else
  {
    tcp_send_data(conn->pcb, sshd_tx_buffer, (uint16_t)total_size);
    if (!conn->encrypted)
      conn->send_packet_count++;
  }

  if (own_irq)
    ssh_tx_irq_leave();
}

// Handle SSH version exchange
// Handle new SSH connection (called when TCP connection is established)
void ssh_handle_new_connection(struct tcp_pcb *pcb)
{
  struct ssh_connection *conn = ssh_find_connection(pcb);
  if (!conn)
  {
    log_writestring("[SSH] Failed to allocate connection slot\n");
    if (pcb && pcb->state == TCP_ESTABLISHED)
      tcp_close(pcb);
    return;
  }

  log_writestring("[SSH] New connection from ");
  log_write_u32((pcb->remote_ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((pcb->remote_ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((pcb->remote_ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(pcb->remote_ip & 0xFF);
  log_putchar('\n');

  /*
   * Send SSH version string immediately (retry if TX ring was momentarily full).
   * Do NOT call netdev_napi_poll here: we are inside tcp_input() and NAPI drains
   * RX -> ethernet_input -> tcp_input again, which corrupts stack state and can
   * wedge ICMP/ping and the rest of the network ("nc kills the network").
   * Back off with a short CPU spin so the e1000 can complete prior descriptors.
   */
  if (pcb->state == TCP_ESTABLISHED)
  {
    int ok = 0;
    for (int tries = 0; tries < 48 && pcb->state == TCP_ESTABLISHED; tries++)
    {
      if (tcp_send_data(pcb, (const uint8_t *)SSH_VERSION_STRING,
                        SSH_VERSION_LEN) == 0)
      {
        ok = 1;
        break;
      }
      for (volatile uint32_t spin = 0; spin < 12000u; spin++)
        __asm__ volatile("pause");
    }
    if (ok)
      log_writestring("[SSH] Sent version string\n");
    else
      log_writestring("[SSH] Version string not tx yet (will rtx)\n");
  }
  else
  {
    log_writestring("[SSH] Connection not established yet, state=");
    log_write_u32(pcb->state);
    log_putchar('\n');
  }
}

// Forward declarations
static void ssh_handle_kexinit(struct ssh_connection *conn, const uint8_t *data,
                               int len);

static void ssh_handle_version(struct ssh_connection *conn, const uint8_t *data,
                               int len)
{
  // Client sends: "SSH-2.0-ClientName\r\n"
  // Version exchange is plain text, not in SSH packet format
  log_writestring("[SSH] Handling version exchange, len=");
  log_write_u32(len);
  log_putchar('\n');

  if (len >= 4 && data[0] == 'S' && data[1] == 'S' && data[2] == 'H' &&
      data[3] == '-')
  {
    // Log client version
    log_writestring("[SSH] Client version: ");
    int i = 0;
    while (i < len && i < 64 && data[i] != '\r' && data[i] != '\n')
    {
      log_putchar(data[i]);
      i++;
    }
    log_putchar('\n');

    // Store client version for exchange hash
    // Store client version for exchange hash (must strip CR/LF per RFC
    // 4253 4.2)
    if (len < 256)
    {
      int v_len = 0;
      for (int j = 0; j < len; j++)
      {
        if (data[j] != '\r' && data[j] != '\n')
        {
          conn->v_c[v_len++] = data[j];
        }
      }
      conn->v_c_len = v_len;
    }

    // Version string was already sent in ssh_handle_new_connection
    // After version exchange, server should send KEXINIT first (not wait for
    // client) Send KEXINIT immediately
    log_writestring("[SSH] Version exchange complete, sending KEXINIT\n");

    // Send our KEXINIT immediately (server sends first in SSH-2.0)
    // === BUILD SERVER KEXINIT ===
    int pos = 0;

    // Cookie (16 random bytes - simplified to zeros)
    for (int i = 0; i < 16; i++)
    {
      server_kexinit_payload[pos++] = 0;
    }

    // KEX algorithms (strict-s + DH methods for OpenSSH 9.x interop)
    const char *kex_algs = ssh_server_kex_algs;
    uint32_t kex_len = 0;
    while (kex_algs[kex_len])
      kex_len++;
    ssh_write_u32(server_kexinit_payload + pos, kex_len);
    pos += 4;
    for (uint32_t i = 0; i < kex_len; i++)
    {
      server_kexinit_payload[pos++] = kex_algs[i];
    }

    // Server host key algorithms - offer rsa-sha2-* only (no ssh-rsa: we have
    // no SHA-1 implementation so the ssh-rsa fallback produces a SHA-256 hash
    // with a SHA-1 DER prefix which OpenSSH rejects).
    const char *host_key_algs = "rsa-sha2-512,rsa-sha2-256";
    uint32_t host_key_len = 25; /* exact strlen; wrong length shifts all following KEXINIT fields */
    ssh_write_u32(server_kexinit_payload + pos, host_key_len);
    pos += 4;
    for (uint32_t i = 0; i < host_key_len; i++)
    {
      server_kexinit_payload[pos++] = host_key_algs[i];
    }

    // Encryption algorithms
    const char *enc_algs = "aes128-ctr,aes128-cbc,3des-cbc";
    uint32_t enc_len = 30;
    ssh_write_u32(server_kexinit_payload + pos, enc_len);
    pos += 4;
    for (uint32_t i = 0; i < enc_len; i++)
    {
      server_kexinit_payload[pos++] = enc_algs[i];
    }

    // Encryption algorithms server->client
    ssh_write_u32(server_kexinit_payload + pos, enc_len);
    pos += 4;
    for (uint32_t i = 0; i < enc_len; i++)
    {
      server_kexinit_payload[pos++] = enc_algs[i];
    }

    /* Only offer SHA-256 MAC (we have no HMAC-SHA1); avoids mac_len mismatch. */
    const char *mac_algs = "hmac-sha2-256";
    uint32_t mac_len = 13;
    ssh_write_u32(server_kexinit_payload + pos, mac_len);
    pos += 4;
    for (uint32_t i = 0; i < mac_len; i++)
    {
      server_kexinit_payload[pos++] = mac_algs[i];
    }

    // MAC algorithms server->client
    ssh_write_u32(server_kexinit_payload + pos, mac_len);
    pos += 4;
    for (uint32_t i = 0; i < mac_len; i++)
    {
      server_kexinit_payload[pos++] = mac_algs[i];
    }

    // Compression algorithms client->server - use none (compression can be
    // none)
    const char *comp_algs = "none";
    uint32_t comp_len = 4;
    ssh_write_u32(server_kexinit_payload + pos, comp_len);
    pos += 4;
    for (uint32_t i = 0; i < comp_len; i++)
    {
      server_kexinit_payload[pos++] = comp_algs[i];
    }

    // Compression algorithms server->client
    ssh_write_u32(server_kexinit_payload + pos, comp_len);
    pos += 4;
    for (uint32_t i = 0; i < comp_len; i++)
    {
      server_kexinit_payload[pos++] = comp_algs[i];
    }

    // Languages (empty)
    ssh_write_u32(server_kexinit_payload + pos, 0);
    pos += 4;
    ssh_write_u32(server_kexinit_payload + pos, 0);
    pos += 4;

    // First KEX packet follows (0 for server)
    server_kexinit_payload[pos++] = 0;

    // Reserved (0)
    ssh_write_u32(server_kexinit_payload + pos, 0);
    pos += 4;

    // Debug: show what we just built - check bytes 16-19 (algorithm length)
    log_writestring("[DEBUG] KEXINIT built, pos=");
    log_write_u32(pos);
    log_writestring(" b16=");
    log_write_hex8(server_kexinit_payload[16]);
    log_writestring(" b17=");
    log_write_hex8(server_kexinit_payload[17]);
    log_writestring(" b18=");
    log_write_hex8(server_kexinit_payload[18]);
    log_writestring(" b19=");
    log_write_hex8(server_kexinit_payload[19]);
    log_putchar('\n');

    // === STORE I_S INTO SAFE PERMANENT BUFFER ===
    // Store the KEXINIT payload bytes we built (including the SSH message
    // number byte) for exchange hash construction.
    // Store into safe_i_s (global, survives everything) instead of conn->i_s
    // because conn->i_s gets corrupted during the long RSA signing computation.
    if ((pos + 1) <= (int)sizeof(safe_i_s))
    {
      safe_i_s[0] = SSH_MSG_KEXINIT; // 0x14
      for (int i = 0; i < pos; i++)
        safe_i_s[1 + i] = server_kexinit_payload[i];
      safe_i_s_len = (uint32_t)(pos + 1);

      // Also store in conn->i_s for compatibility (but we'll use safe_i_s in hash)
      conn->i_s[0] = SSH_MSG_KEXINIT; // 0x14
      for (int i = 0; i < pos; i++)
        conn->i_s[1 + i] = server_kexinit_payload[i];
      conn->i_s_len = (size_t)(pos + 1);

      log_writestring("[SSH] SAFE I_S stored: len=");
      log_write_u32(safe_i_s_len);
      log_writestring(", first 16 bytes: ");
      for (int i = 0; i < 16 && i < (int)safe_i_s_len; i++)
      {
        log_write_hex8(safe_i_s[i]);
        log_putchar(' ');
      }
      log_putchar('\n');
    }
    else
    {
      log_writestring("[ERROR] I_S storage failed - wrong size! pos=");
      log_write_u32(pos);
      log_putchar('\n');
    }

    // === SEND IT ===
    // Use sshbuf version for better buffer management
    if (ssh_send_packet_sshbuf(conn, SSH_MSG_KEXINIT, server_kexinit_payload, pos) != 0)
    {
      // Fallback to legacy if sshbuf fails
      ssh_send_packet(conn, SSH_MSG_KEXINIT, server_kexinit_payload, pos);
    }

    // Wait for client's KEXINIT before sending NEWKEYS
    conn->state = SSH_STATE_KEXINIT;
    log_writestring("[SSH] KEXINIT sent, waiting for client KEXINIT\n");
  }
}

// Handle key exchange init (client sent KEXINIT)
static void ssh_handle_kexinit(struct ssh_connection *conn, const uint8_t *data,
                               int len)
{
  log_writestring("[SSH] Received client KEXINIT, len=");
  log_write_u32(len);
  log_putchar('\n');

  // Store client KEXINIT for exchange hash.
  // Store the KEXINIT payload bytes we received (including the SSH message
  // number byte). RFC 4253 section 8 defines I_C/I_S as the payload of the
  // SSH_MSG_KEXINIT message, which includes the message number.
  if (len > 0 && (len + 1) <= 2048)
  {
    conn->i_c[0] = SSH_MSG_KEXINIT; // 0x14
    for (int i = 0; i < len; i++)
      conn->i_c[1 + i] = data[i];
    conn->i_c_len = (size_t)(len + 1);
    log_writestring("[SSH] Stored client KEXINIT (I_C) for exchange hash\n");
  }

  // Negotiate algorithms
  // KEXINIT payload structure: [cookie(16)] [kex_algs(string)]
  // [host_key_algs(string)] ...
  //
  // OpenSSH 9+ sends kex-strict-c-v00@openssh.com in the kex list; both peers
  // reset MAC packet sequence to 0 after NEWKEYS. If we miss this, we use
  // recv_seq = recv_packet_count + 1 while the client uses 0 → first MAC fails
  // with otherwise valid decryption. Search the whole payload (unique marker).
  conn->kex_strict = 0;
  if (len > 0)
    conn->kex_strict = (uint8_t)ssh_blob_contains(
        data, (uint32_t)len, "kex-strict-c-v00@openssh.com");
  if (conn->kex_strict)
    log_writestring(
        "[SSH] Client strict KEX (kex-strict-c): MAC seq resets at NEWKEYS\n");

  if (len > 16 + 4)
  {
    uint32_t kex_algs_len = ssh_read_u32(data + 16);
    log_writestring("[SSH] Client KEX algorithms length: ");
    log_write_u32(kex_algs_len);
    log_putchar('\n');

    if (len >= (int)(16 + 4 + kex_algs_len + 4))
    {
      const uint8_t *client_kex = data + 16 + 4;

      // Negotiate key exchange method (same order as server KEXINIT string)
      char negotiated_kex[64];
      if (ssh_find_common_alg(ssh_server_kex_algs, client_kex, kex_algs_len,
                              negotiated_kex, sizeof(negotiated_kex)))
      {
        log_writestring("[SSH] Negotiated KEX method: ");
        log_writestring(negotiated_kex);
        log_putchar('\n');
      }
      else
      {
        log_writestring("[SSH] WARNING: No common KEX method found!\n");
      }

      uint32_t host_key_algs_offset = 16 + 4 + kex_algs_len;
      uint32_t host_key_algs_len = ssh_read_u32(data + host_key_algs_offset);
      log_writestring("[SSH] Client host key algorithms length: ");
      log_write_u32(host_key_algs_len);
      log_putchar('\n');

      if (len >= (int)(host_key_algs_offset + 4 + host_key_algs_len))
      {
        const char *server_algs = "rsa-sha2-512,rsa-sha2-256";
        if (ssh_find_common_alg(server_algs, data + host_key_algs_offset + 4,
                                host_key_algs_len, conn->negotiated_sig_alg,
                                sizeof(conn->negotiated_sig_alg)))
        {
          log_writestring("[SSH] Negotiated signature algorithm: ");
          log_writestring(conn->negotiated_sig_alg);
          log_putchar('\n');
        }
        else
        {
          log_writestring(
              "[SSH] WARNING: No common host key algorithm found!\n");
        }
      }
    }
  }

  // After receiving client KEXINIT, wait for their key exchange message
  // They will send either:
  // - SSH_MSG_KEXDH_GEX_REQUEST (34) if group-exchange
  // - SSH_MSG_KEXDH_INIT (30) if regular DH
  conn->state = SSH_STATE_KEXDH;
  log_writestring("[SSH] Waiting for client key exchange message (GEX_REQUEST or KEXDH_INIT)\n");
}

// Handle DH Key Exchange Init
static void ssh_handle_kexdh_init(struct ssh_connection *conn,
                                  const uint8_t *data, int len)
{
  log_writestring("[SSH] Received KEXDH_INIT, sending KEXDH_REPLY\n");

  // Format: [host_key(S)] [f(mpint)] [signature(string)]
  // We'll send a very minimal/dummy response to satisfy the client
  uint8_t reply[1024];
  int pos = 0;

  // 1. Host key (ssh-rsa dummy)
  // Format: string K_S (which itself contains string "ssh-rsa", mpint e, mpint
  // n) NOTE: K_S always uses "ssh-rsa" as the key type, even when using
  // rsa-sha2-* for signatures
  int ks_start = pos;
  pos += 4; // space for K_S length

  const char *key_type = "ssh-rsa";
  ssh_write_u32(reply + pos, 7);
  for (int i = 0; i < 7; i++)
    reply[pos + 4 + i] = key_type[i];
  pos += 11;

  // e = 3
  ssh_write_u32(reply + pos, 1);
  reply[pos + 4] = 0x03;
  pos += 5;

  // n = dummy 256+1 bytes (2048-bit positive)
  ssh_write_u32(reply + pos, 257);
  reply[pos + 4] = 0x00; // Positive indicator
  for (int i = 0; i < 256; i++)
    reply[pos + 5 + i] = 0xAA;
  pos += 261;

  ssh_write_u32(reply + ks_start, pos - ks_start - 4);

  // 2. f (mpint) - dummy server DH public key (256+1 bytes)
  ssh_write_u32(reply + pos, 257);
  reply[pos + 4] = 0x00; // Positive indicator
  for (int i = 0; i < 256; i++)
    reply[pos + 5 + i] = 0xBB;
  pos += 261;

  // 3. Signature (dummy)
  // Format: string containing [string "rsa-sha2-512", string signature-blob]
  int sig_start = pos;
  pos += 4; // length of signature string (outer)

  const char *sig_alg = "rsa-sha2-512";
  ssh_write_u32(reply + pos, 12);
  for (int i = 0; i < 12; i++)
    reply[pos + 4 + i] = sig_alg[i];
  pos += 16;

  ssh_write_u32(reply + pos, 256);
  for (int i = 0; i < 256; i++)
    reply[pos + 4 + i] = 0xCC;
  pos += 260;

  ssh_write_u32(reply + sig_start, pos - sig_start - 4);

  ssh_send_packet(conn, SSH_MSG_KEXDH_REPLY, reply, pos);

  // After DH reply, we MUST send NEWKEYS
  log_writestring("[SSH] DH complete, sending NEWKEYS\n");
  ssh_send_packet(conn, SSH_MSG_NEWKEYS, NULL, 0);
}

// Handle Group Exchange Request (type 34)
// Client sends: [min(4)] [preferred(4)] [max(4)]
static void ssh_handle_kexdh_gex_request(struct ssh_connection *conn,
                                         const uint8_t *data, int len)
{
  if (len < 12)
  {
    log_writestring("[SSH] GEX_REQUEST too short\n");
    return;
  }

  uint32_t min = ssh_read_u32(data);
  uint32_t preferred = ssh_read_u32(data + 4);
  uint32_t max = ssh_read_u32(data + 8);

  // Store GEX parameters for exchange hash
  conn->gex_min = min;
  conn->gex_preferred = preferred;
  conn->gex_max = max;

  log_writestring("[SSH] GEX_REQUEST: min=");
  log_write_u32(min);
  log_writestring(", preferred=");
  log_write_u32(preferred);
  log_writestring(", max=");
  log_write_u32(max);
  log_putchar('\n');

  // Send GEX_GROUP message (type 31) with prime and generator
  // Format: [prime(mpint)] [generator(mpint)]
  // Using MODP group14 (2048-bit) - RFC 3526
  // The actual group14 prime is: 2^2048 - 2^1984 - 1 + 2^64 * ([2^1918 * pi] +
  // 124476) For a working implementation, we'd embed the full prime, but for
  // now using a known-good pattern
  uint8_t group_msg[1024];
  int pos = 0;

  // Prime p (MODP group14, 2048-bit) from RFC 3526 section 3.
  // IMPORTANT: Our bigint implementation is 256 bytes (2048 bits), so we must
  // use a 2048-bit group here or KEX will be mathematically inconsistent with
  // the client.
  static const uint8_t modp_group14_prime[] = {
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
      0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
      0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
      0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
      0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
      0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
      0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
      0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
      0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
      0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
      0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
      0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
      0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
      0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
      0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
      0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
      0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
      0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
      0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
      0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
      0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAC, 0xAA, 0x68, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF};
  log_writestring("[SSH] Sending GEX_GROUP (31) with prime length: ");
  log_write_u32(sizeof(modp_group14_prime) * 8);
  log_writestring(" bits\n");

  // Check if MSB is set (needs positive indicator byte)
  int needs_pad = (modp_group14_prime[0] & 0x80) ? 1 : 0;
  uint32_t prime_len =
      sizeof(modp_group14_prime) + needs_pad; // Final length including pad
  ssh_write_u32(group_msg + pos, prime_len);
  pos += 4;
  if (needs_pad)
  {
    group_msg[pos++] = 0x00; // Positive indicator
  }

  // Copy full prime bytes
  for (int i = 0; i < (int)sizeof(modp_group14_prime); i++)
  {
    group_msg[pos++] = modp_group14_prime[i];
  }

  // Generator g (usually 2 for MODP groups)
  uint32_t gen_len = 1; // Shortest mpint for value 2 is 0x02
  ssh_write_u32(group_msg + pos, gen_len);
  pos += 4;
  group_msg[pos++] = 0x02; // Generator = 2

  // Store prime p and generator g for exchange hash
  // p is stored starting at group_msg[4] (after length), total prime_len bytes
  uint32_t p_data_len = prime_len + 4; // Include length prefix
  if (p_data_len < 512)
  {
    for (int i = 0; i < p_data_len; i++)
    {
      conn->gex_p[i] = group_msg[i];
    }
    conn->gex_p_len = p_data_len;
  }

  // g is stored at group_msg[p_data_len], total gen_len + 4 bytes
  uint32_t g_data_len = gen_len + 4; // Include length prefix
  if (g_data_len < 16)
  {
    for (int i = 0; i < g_data_len; i++)
    {
      conn->gex_g[i] = group_msg[p_data_len + i];
    }
    conn->gex_g_len = g_data_len;
  }

  log_writestring("[SSH] Sending GEX_GROUP (31) with prime and generator\n");
  ssh_send_packet(conn, SSH_MSG_KEXDH_GEX_GROUP, group_msg, pos);

  log_writestring("[SSH] GEX_GROUP sent, waiting for GEX_INIT (32)\n");
  conn->state = SSH_STATE_KEXDH;
}

// Handle Group Exchange Init (type 32) - same format as KEXDH_INIT
static void ssh_handle_kexdh_gex_init(struct ssh_connection *conn,
                                      const uint8_t *data, int len)
{
  log_writestring("[SSH] Received KEXDH_GEX_INIT, sending GEX_REPLY\n");

  // Mark that we're doing heavy key computation; close handler should not
  // destroy/reset this connection struct while we are working.
  conn->computing_keys = 1;

  // Prevent duplicate processing (re-transmissions from backlog)
  // If we already computed f (server DH public key), we already did this step.
  // This prevents running heavy crypto twice for the same connection key
  // exchange.
  if (conn->gex_f_len > 0)
  {
    log_writestring("[SSH] Ignoring duplicate GEX_INIT (already processed)\n");
    conn->computing_keys = 0;
    return;
  }

  // Store client DH public value (e) for exchange hash
  // Format: mpint (length prefix + value)
  if (len < 4)
  {
    log_writestring("[SSH] GEX_INIT too short\n");
    return;
  }
  uint32_t e_len = ssh_read_u32(data);
  if (e_len < 512 && len >= (int)(4 + e_len))
  {
    for (uint32_t i = 0; i < e_len + 4 && i < 512; i++)
    {
      conn->gex_e[i] = data[i];
    }
    conn->gex_e_len = e_len + 4; // Include length prefix
  }

  // Use the same handler as regular KEXDH_INIT, but send GEX_REPLY (33) instead
  // Buffer needs to hold: host key (530) + prime (385) + generator + f + K (260) + signature (276) = ~2000 bytes
  uint8_t reply[2048];
  int pos = 0;

  // 1. Host key - use real RSA key values
  int ks_start = pos;
  pos += 4; // Reserve space for host key blob length

  // Get the real RSA public key blob
  uint8_t key_blob[300];
  int key_blob_len = ssh_get_rsa_public_key_blob(key_blob, sizeof(key_blob));
  if (key_blob_len > 0 && (pos + key_blob_len) < sizeof(reply))
  {
    log_writestring("[SSH] Host key blob length: ");
    log_write_u32(key_blob_len);
    log_putchar('\n');
    for (int i = 0; i < key_blob_len; i++)
    {
      reply[pos++] = key_blob[i];
    }
  }
  else
  {
    log_writestring("[SSH] ERROR: Failed to get RSA public key blob, len=");
    log_write_u32(key_blob_len);
    log_putchar('\n');
    return;
  }

  // Write the total host key blob length (as string length prefix)
  uint32_t total_ks_len = pos - ks_start - 4; // Exclude the length field itself
  ssh_write_u32(reply + ks_start, total_ks_len);

  // Store host key (K_S) for exchange hash
  // K_S includes the 4-byte length prefix, so we store the entire string
  uint32_t ks_len = pos - ks_start;
  log_writestring("[SSH] Storing K_S: ks_len=");
  log_write_u32(ks_len);
  log_writestring(", ks_start=");
  log_write_u32(ks_start);
  log_putchar('\n');

  // K_S can be up to ~530 bytes (host key blob with length prefix)
  // conn->k_s is now 1024 bytes, so it should fit
  if (ks_len > 0 && ks_len <= 1024)
  {
    for (int i = 0; i < ks_len; i++)
    {
      conn->k_s[i] = reply[ks_start + i];
    }
    conn->k_s_len = ks_len;
    log_writestring("[SSH] K_S stored successfully, len=");
    log_write_u32(conn->k_s_len);
    log_writestring(", first 8 bytes: ");
    for (int i = 0; i < 8 && i < ks_len; i++)
    {
      log_write_hex8(conn->k_s[i]);
      log_putchar(' ');
    }
    log_writestring("\n[SSH] K_S (hostkey string, full hex):\n");
    for (uint32_t i = 0; i < conn->k_s_len; i++)
    {
      log_write_hex8(conn->k_s[i]);
      if ((i % 16) == 15)
        log_putchar('\n');
      else
        log_putchar(' ');
    }
    log_putchar('\n');
  }
  else
  {
    log_writestring("[SSH] ERROR: K_S storage failed! ks_len=");
    log_write_u32(ks_len);
    log_writestring(" (max 1024)\n");
    // CRITICAL: If K_S can't be stored, we can't compute the correct hash
    // Try to store at least the length prefix
    if (ks_len >= 4)
    {
      for (int i = 0; i < 4; i++)
      {
        conn->k_s[i] = reply[ks_start + i];
      }
      conn->k_s_len = 4; // At least store the length
      log_writestring("[SSH] WARNING: Stored only K_S length prefix (4 bytes)\n");
    }
    else
    {
      conn->k_s_len = 0;
    }
  }

  // 2. f (mpint) - server DH public key
  // We need to compute f = g^y mod p
  // First, set up y (private key). For simplicity/speed in this OS, use a fixed
  // random-ish y. In production, this should be random every time.
  uint8_t y[256];
  for (int i = 0; i < 256; i++)
    y[i] = 0;
  y[255] = 0x5A;
  y[254] = 0xA5;
  y[253] = 0x12;
  y[252] = 0x34; // y = 0x3412A55A...

  // Extract p, g, e from stored mpints and pad to 256 bytes
  uint8_t p_val[256], g_val[256], e_val[256];
  for (int i = 0; i < 256; i++)
  {
    p_val[i] = 0;
    g_val[i] = 0;
    e_val[i] = 0;
  }

  // Extract mpint value: [4-byte length][value]. Use ALL value bytes so a
  // leading 0x00 (positive sign in SSH mpint) is not dropped — dropping it
  // would produce the wrong number for 256-byte p/e.
  int p_value_len = conn->gex_p_len - 4;
  if (p_value_len > 256)
    for (int i = 0; i < 256; i++)
      p_val[i] = conn->gex_p[4 + p_value_len - 256 + i];
  else
    for (int i = 0; i < p_value_len; i++)
      p_val[256 - p_value_len + i] = conn->gex_p[4 + i];

  int g_value_len = conn->gex_g_len - 4;
  if (g_value_len > 256)
    for (int i = 0; i < 256; i++)
      g_val[i] = conn->gex_g[4 + g_value_len - 256 + i];
  else
    for (int i = 0; i < g_value_len; i++)
      g_val[256 - g_value_len + i] = conn->gex_g[4 + i];

  int e_value_len = conn->gex_e_len - 4;
  if (e_value_len > 256)
    for (int i = 0; i < 256; i++)
      e_val[i] = conn->gex_e[4 + e_value_len - 256 + i];
  else
    for (int i = 0; i < e_value_len; i++)
      e_val[256 - e_value_len + i] = conn->gex_e[4 + i];

#ifdef AJOS_SSH_DH_DEBUG
  // Debug: dump DH inputs/outputs to validate bigint math against a host-side
  // big-int implementation.
  log_writestring("[SSH] DH y (last 16 bytes): ");
  for (int i = 256 - 16; i < 256; i++)
  {
    log_write_hex8(y[i]);
    log_putchar(' ');
  }
  log_putchar('\n');

  log_writestring("[SSH] DH p_val (256 bytes, big-endian):\n");
  for (int i = 0; i < 256; i++)
  {
    log_write_hex8(p_val[i]);
    if ((i % 16) == 15)
      log_putchar('\n');
    else
      log_putchar(' ');
  }

  log_writestring("[SSH] DH g_val (256 bytes, big-endian):\n");
  for (int i = 0; i < 256; i++)
  {
    log_write_hex8(g_val[i]);
    if ((i % 16) == 15)
      log_putchar('\n');
    else
      log_putchar(' ');
  }

  log_writestring("[SSH] DH e_val (256 bytes, big-endian):\n");
  for (int i = 0; i < 256; i++)
  {
    log_write_hex8(e_val[i]);
    if ((i % 16) == 15)
      log_putchar('\n');
    else
      log_putchar(' ');
  }
#endif

  // Compute f = g^y mod p (bigint_mod_exp matches OpenSSL DH for exchange hash)
  uint8_t f_val[256];
  bigint_mod_exp(g_val, y, p_val, f_val);

#ifdef AJOS_SSH_DH_DEBUG
  log_writestring("[SSH] DH f_val = g^y mod p (256 bytes, big-endian):\n");
  for (int i = 0; i < 256; i++)
  {
    log_write_hex8(f_val[i]);
    if ((i % 16) == 15)
      log_putchar('\n');
    else
      log_putchar(' ');
  }
#endif

  // Write f to reply (as mpint)
  // Skip leading zeros
  int f_start_idx = 0;
  while (f_start_idx < 256 && f_val[f_start_idx] == 0)
    f_start_idx++;
  int f_size = 256 - f_start_idx;
  if (f_size == 0)
    f_size = 1; // value 0

  // If MSB set, prepend 0x00
  int f_pad = (f_val[f_start_idx] & 0x80) ? 1 : 0;

  int f_start_pkt = pos;
  ssh_write_u32(reply + pos, f_size + f_pad);
  pos += 4;
  if (f_pad)
    reply[pos++] = 0x00;
  for (int i = 0; i < f_size; i++)
    reply[pos++] = f_val[f_start_idx + i];

  // Store server DH public value (f) for exchange hash
  uint32_t f_len = pos - f_start_pkt;
  if (f_len < 512)
  {
    for (int i = 0; i < f_len; i++)
    {
      conn->gex_f[i] = reply[f_start_pkt + i];
    }
    conn->gex_f_len = f_len;
  }

  // 3. Compute shared secret K = e^y mod p
  uint8_t k_val[256];
  bigint_mod_exp(e_val, y, p_val, k_val);

#ifdef AJOS_SSH_DH_DEBUG
  log_writestring("[SSH] DH K_val = e^y mod p (256 bytes, big-endian):\n");
  for (int i = 0; i < 256; i++)
  {
    log_write_hex8(k_val[i]);
    if ((i % 16) == 15)
      log_putchar('\n');
    else
      log_putchar(' ');
  }
#endif

  // Convert K to mpint format for signing
  uint8_t k_mpint[512];
  int k_start_idx = 0;
  while (k_start_idx < 256 && k_val[k_start_idx] == 0)
    k_start_idx++;
  int k_size = 256 - k_start_idx;
  if (k_size == 0)
    k_size = 1;

  int k_pad = (k_val[k_start_idx] & 0x80) ? 1 : 0;
  int k_pos = 0;

  k_mpint[k_pos++] = ((k_size + k_pad) >> 24) & 0xFF;
  k_mpint[k_pos++] = ((k_size + k_pad) >> 16) & 0xFF;
  k_mpint[k_pos++] = ((k_size + k_pad) >> 8) & 0xFF;
  k_mpint[k_pos++] = (k_size + k_pad) & 0xFF;
  if (k_pad)
    k_mpint[k_pos++] = 0x00;
  for (int i = 0; i < k_size; i++)
    k_mpint[k_pos++] = k_val[k_start_idx + i];

  const uint8_t *k = k_mpint;
  size_t k_len = k_pos;

  // 4. Signature - compute real signature using exchange hash
  int sig_start = pos;
  pos += 4; // Reserve space for signature length

  // Compute and sign exchange hash
  uint8_t signature[512];
  size_t sig_out_len = sizeof(signature);

  log_writestring("[SSH] Computing exchange hash and signing...\n");
  log_writestring("[SSH] Exchange hash components:\n");
  log_writestring("[SSH]   V_C len=");
  log_write_u32(conn->v_c_len);
  log_writestring(", I_C len=");
  log_write_u32(conn->i_c_len);
  log_writestring(", I_S len=");
  log_write_u32(conn->i_s_len);
  log_writestring(", K_S len=");
  log_write_u32(conn->k_s_len);

  // Debug K_S content
  if (conn->k_s_len > 0)
  {
    log_writestring(", K_S first 8 bytes: ");
    for (int i = 0; i < 8 && i < (int)conn->k_s_len; i++)
    {
      log_write_hex8(conn->k_s[i]);
      log_putchar(' ');
    }
  }
  else
  {
    log_writestring(" [ERROR: K_S is empty!]");
  }
  log_putchar('\n');

  // Get server version string (strip CR/LF for hash)
  const char *v_s_full = SSH_VERSION_STRING;
  char v_s_stripped[64];
  size_t v_s_len = 0;
  for (size_t i = 0; i < SSH_VERSION_LEN; i++)
  {
    if (v_s_full[i] != '\r' && v_s_full[i] != '\n')
    {
      v_s_stripped[v_s_len++] = v_s_full[i];
    }
  }
  log_writestring("[SSH]   V_S len=");
  log_write_u32(v_s_len);
  log_writestring(", K len=");
  log_write_u32(k_len);
  log_putchar('\n');

  // Determine which signature algorithm to use based on what client negotiated
  // If no algorithm negotiated yet, use the first server preference
  const char *sig_algorithm = "rsa-sha2-512";
  if (conn->negotiated_sig_alg[0] != '\0')
  {
    sig_algorithm = conn->negotiated_sig_alg;
  }

  log_writestring("[SSH] Using signature algorithm: ");
  log_writestring(sig_algorithm);
  log_putchar('\n');

  // Use safe_i_s instead of conn->i_s (conn->i_s gets corrupted during RSA signing)
  // Debug: Verify safe I_S is correct
  log_writestring("[DEBUG] Using SAFE I_S: len=");
  log_write_u32(safe_i_s_len);
  log_writestring(" b16=");
  log_write_hex8(safe_i_s[17]);
  log_writestring(" b17=");
  log_write_hex8(safe_i_s[18]);
  log_writestring(" b18=");
  log_write_hex8(safe_i_s[19]);
  log_writestring(" b19=");
  log_write_hex8(safe_i_s[20]);
  log_putchar('\n');

  // Store H (session_id) and K (mpint) for key derivation when we receive NEWKEYS
  uint8_t exchange_hash_buf[32];
  conn->keys_derived = 0;
  if (ssh_compute_exchange_hash(
          conn->v_c, conn->v_c_len, (const uint8_t *)v_s_stripped, v_s_len,
          conn->i_c, conn->i_c_len, safe_i_s, safe_i_s_len, conn->k_s,
          conn->k_s_len, conn->gex_min, conn->gex_preferred, conn->gex_max,
          conn->gex_p, conn->gex_p_len, conn->gex_g, conn->gex_g_len,
          conn->gex_e, conn->gex_e_len, conn->gex_f, conn->gex_f_len, k, k_len,
          exchange_hash_buf))
  {
    for (int i = 0; i < 32; i++)
      conn->exchange_hash[i] = exchange_hash_buf[i];
    if (k_len <= sizeof(conn->k_mpint))
    {
      for (size_t i = 0; i < k_len; i++)
        conn->k_mpint[i] = k_mpint[i];
      conn->k_mpint_len = (uint16_t)k_len;
    }
  }

  if (ssh_sign_exchange_hash(
          conn->v_c, conn->v_c_len, (const uint8_t *)v_s_stripped, v_s_len,
          conn->i_c, conn->i_c_len, safe_i_s, safe_i_s_len, conn->k_s,
          conn->k_s_len, conn->gex_min, conn->gex_preferred, conn->gex_max,
          // Note: n = preferred (negotiated group size) per RFC 4419
          conn->gex_p, conn->gex_p_len, conn->gex_g, conn->gex_g_len,
          conn->gex_e, conn->gex_e_len, conn->gex_f, conn->gex_f_len, k, k_len,
          sig_algorithm, signature, &sig_out_len))
  {

    log_writestring("[SSH] Signature computed successfully, encoded len=");
    log_write_u32(sig_out_len);
    log_putchar('\n');

    // Write encoded signature into reply
    // The encoded signature (from ssh_sign_exchange_hash) already includes:
    // algorithm_name_string || signature_blob_string
    // This is exactly the content for the 'signature' field (which is a
    // string). So we just need to copy it. The outer length will be fixed up at
    // sig_start.
    if (sig_out_len > 0 && sig_out_len <= 512 && (pos + sig_out_len) < sizeof(reply))
    {
      for (size_t i = 0; i < sig_out_len; i++)
      {
        reply[pos++] = signature[i];
      }
    }
    else
    {
      log_writestring("[SSH] ERROR: Signature buffer overflow! sig_len=");
      log_write_u32(sig_out_len);
      log_writestring(", pos=");
      log_write_u32(pos);
      log_writestring(", buffer_size=");
      log_write_u32(sizeof(reply));
      log_putchar('\n');
      return; // Don't send corrupted packet
    }
  }
  else
  {
    log_writestring("[SSH] ERROR: Signature computation failed!\n");
    // Fallback to dummy signature if computation fails
    // The dummy format must be: string "rsa-sha2-512" || string signature_blob
    const char *sig_alg = "rsa-sha2-512";
    ssh_write_u32(reply + pos, 12);
    for (int i = 0; i < 12; i++)
      reply[pos + 4 + i] = sig_alg[i];
    pos += 16;

    ssh_write_u32(reply + pos, 256);
    for (int i = 0; i < 256; i++)
      reply[pos + 4 + i] = 0xCC;
    pos += 260;
  }

  /*
   * Derive transport keys ONLY after RSA signing finishes. ssh_sign_exchange_hash
   * uses large stack/heap temporaries that have been observed to corrupt other
   * members of struct ssh_connection (we already keep I_S in safe_i_s for that
   * reason). If we derive keys before signing, derived_* MAC/IV material can be
   * clobbered while the exchange hash used for the signature is recomputed
   * inside the signer — KEX still passes but the first encrypted MAC fails.
   */
  if (conn->k_mpint_len > 0)
  {
    ssh_derive_transport_keys(conn->exchange_hash, conn->k_mpint,
                              conn->k_mpint_len, conn->derived_recv_iv,
                              conn->derived_recv_key, conn->derived_send_iv,
                              conn->derived_send_key, conn->derived_recv_mac_key,
                              conn->derived_send_mac_key);
    conn->keys_derived = 1;
  }

  // Write the total signature length at sig_start
  // Content length = algorithm_name_string + signature_blob_string
  uint32_t sig_content_len = pos - sig_start - 4;
  ssh_write_u32(reply + sig_start, sig_content_len);

  log_writestring("[SSH] Signature field: total_len=");
  log_write_u32(sig_content_len);
  log_putchar('\n');

  // If the peer disconnected while we were computing, abort without sending.
  if (!conn->pcb || conn->closing)
  {
    log_writestring("[SSH] Peer disconnected during key exchange; aborting\n");
    conn->computing_keys = 0;
    ssh_destroy_connection(conn);
    return;
  }

  ssh_send_packet(conn, SSH_MSG_KEXDH_GEX_REPLY, reply, pos);

  log_writestring(
      "[SSH] GEX_REPLY sent with real RSA signature, sending NEWKEYS\n");
  ssh_send_packet(conn, SSH_MSG_NEWKEYS, NULL, 0);

  // After sending NEWKEYS, wait for client's NEWKEYS
  conn->state = SSH_STATE_KEXDH; // Keep in KEXDH until client sends NEWKEYS

  // Calculation and exchange complete
  conn->computing_keys = 0;
}

// Handle service request
static void ssh_handle_service_request(struct ssh_connection *conn,
                                       const uint8_t *data, int len)
{
  // Client requests service (usually "ssh-userauth")
  // Parse service name from data
  if (len < 4)
    return;
  uint32_t service_len = ssh_read_u32(data);
  if (service_len > len - 4)
    return;

  // Accept the service request
  uint8_t response_data[256];
  uint32_t service_name_len = sizeof(SSH_SERVICE_USERAUTH) - 1;
  ssh_write_u32(response_data, service_name_len);
  for (uint32_t i = 0; i < service_name_len; i++)
  {
    response_data[4 + i] = SSH_SERVICE_USERAUTH[i];
  }

  ssh_send_packet(conn, SSH_MSG_SERVICE_ACCEPT, response_data,
                  4 + service_name_len);
  conn->state = SSH_STATE_AUTHENTICATION;
  log_writestring("[SSH] Service accepted: ssh-userauth\n");
}

/* RFC 4252: USERAUTH_FAILURE = name-list (SSH string) + boolean partial_success */
static void ssh_send_userauth_failure_password(struct ssh_connection *conn)
{
  const char *m = SSH_AUTH_METHOD_PASSWORD;
  uint32_t ml = 0;
  while (m[ml])
    ml++;
  uint8_t buf[64];
  if (4u + ml + 1u > sizeof(buf))
    return;
  ssh_write_u32(buf, ml);
  for (uint32_t i = 0; i < ml; i++)
    buf[4 + i] = (uint8_t)m[i];
  buf[4 + ml] = 0; /* partial success = FALSE */
  ssh_send_packet(conn, SSH_MSG_USERAUTH_FAILURE, buf, 4u + ml + 1u);
}

static int ssh_method_is(const uint8_t *p, uint32_t n, const char *s)
{
  uint32_t i = 0;
  while (s[i])
  {
    if (i >= n || p[i] != (uint8_t)s[i])
      return 0;
    i++;
  }
  return i == n;
}

// Handle authentication request
static void ssh_handle_auth_request(struct ssh_connection *conn,
                                    const uint8_t *data, int len)
{
  // SSH authentication format: [username_len(4)] [username] [service_len(4)]
  // [service] [method_len(4)] [method] [method-specific]
  if (len < 12)
    return;

  uint32_t username_len = ssh_read_u32(data);
  if (username_len > 64u || 4u + username_len > (uint32_t)len)
    return;

  char username[65] = {0};
  for (uint32_t i = 0; i < username_len && i < 64; i++)
    username[i] = (char)data[4 + i];

  uint32_t offset = 4u + username_len;
  if (offset + 4u > (uint32_t)len)
    return;

  uint32_t service_len = ssh_read_u32(data + offset);
  if (service_len > 256u || offset + 4u + service_len > (uint32_t)len)
    return;
  offset += 4u + service_len;

  if (offset + 4u > (uint32_t)len)
    return;

  uint32_t method_len = ssh_read_u32(data + offset);
  offset += 4u;
  if (method_len > 64u || offset + method_len > (uint32_t)len)
    return;

  const uint8_t *method_ptr = data + offset;

  log_writestring("[SSH] USERAUTH: user=");
  log_writestring(username);
  log_writestring(" method_len=");
  log_write_u32(method_len);
  log_putchar('\n');

  /* "none" or unsupported: offer password (client will retry). */
  if (!ssh_method_is(method_ptr, method_len, "password"))
  {
    ssh_send_userauth_failure_password(conn);
    if (ssh_method_is(method_ptr, method_len, "none"))
      log_writestring("[SSH] USERAUTH: method=none, sent failure+password list\n");
    else
      log_writestring("[SSH] USERAUTH: unsupported method, sent failure+password list\n");
    return;
  }

  offset += method_len;
  if (offset + 1u > (uint32_t)len)
    return;

  /* password: boolean change_password, string password */
  (void)data[offset]; /* change_password — ignored */
  offset += 1u;
  if (offset + 4u > (uint32_t)len)
    return;

  uint32_t password_len = ssh_read_u32(data + offset);
  offset += 4u;
  if (password_len > 1024u || offset + password_len > (uint32_t)len)
    return;

  char password[129] = {0};
  for (uint32_t i = 0; i < password_len && i < 128; i++)
    password[i] = (char)data[offset + i];

  log_writestring("[SSH] USERAUTH: password attempt (len=");
  log_write_u32(password_len);
  log_writestring(")\n");

  if (auth_check_credentials(username, password))
  {
    ssh_send_packet(conn, SSH_MSG_USERAUTH_SUCCESS, NULL, 0);
    conn->authenticated = 1;
    conn->state = SSH_STATE_CHANNEL_OPEN;
    int j = 0;
    while (j < (int)sizeof(conn->username) - 1 && username[j])
    {
      conn->username[j] = username[j];
      j++;
    }
    conn->username[j] = '\0';
    log_writestring("[SSH] USERAUTH_SUCCESS for: ");
    log_writestring(username);
    log_putchar('\n');
  }
  else
  {
    ssh_send_userauth_failure_password(conn);
    log_writestring("[SSH] USERAUTH: bad password, sent failure\n");
  }
}

/* RFC 4254: tell client they may send `add_bytes` more on this channel. */
static void ssh_send_channel_window_adjust(struct ssh_connection *conn,
                                           uint32_t add_bytes)
{
  if (!conn->has_client_channel || add_bytes == 0)
    return;
  /* Never nest a send inside CHANNEL_DATA TX — corrupts global TX buffers and
   * can stall the session (editor looks like it is "still loading"). */
  if (ssh_channel_tx_depth > 0u)
  {
    conn->deferred_window_adjust += add_bytes;
    return;
  }
  uint8_t pay[8];
  ssh_write_u32(pay, conn->client_channel);
  ssh_write_u32(pay + 4, add_bytes);
  ssh_send_packet(conn, SSH_MSG_CHANNEL_WINDOW_ADJUST, pay, 8);
}

static void ssh_flush_deferred_window_adjust(struct ssh_connection *conn)
{
  if (!conn || conn->deferred_window_adjust == 0u || ssh_channel_tx_depth > 0u)
    return;
  uint32_t add = conn->deferred_window_adjust;
  conn->deferred_window_adjust = 0u;
  ssh_send_channel_window_adjust(conn, add);
}

/* Client extended our outbound credit (bytes we may send to them). */
static void ssh_handle_channel_window_adjust(struct ssh_connection *conn,
                                             const uint8_t *payload, int len)
{
  if (len < 8)
    return;
  uint32_t recipient = ssh_read_u32(payload);
  if (recipient != conn->server_channel)
    return;
  uint32_t add = ssh_read_u32(payload + 4);
  conn->client_window += add;
}

static void ssh_handle_channel_data(struct ssh_connection *conn,
                                    const uint8_t *data, int len);

/*
 * While shell_execute runs inside ssh_handle_connection (conn->processing=1),
 * inbound TCP payloads are appended to rx_buf but not decrypted. Outbound
 * CHANNEL_DATA can exhaust client_window; ssh_wait would call NAPI forever
 * without ever applying WINDOW_ADJUST. Drain complete encrypted packets from
 * rx_buf when they are CHANNEL_WINDOW_ADJUST only (never ssh_flush_pending here).
 */
static void ssh_drain_rx_encrypted_window_adjust(struct ssh_connection *conn)
{
  if (!conn || !conn->encrypted || conn->crypto.cipher_type != SSH_CIPHER_AES128_CTR ||
      !conn->rx_buf)
    return;

  for (;;)
  {
    const uint8_t *rx = (const uint8_t *)sshbuf_ptr(conn->rx_buf);
    size_t rx_len = sshbuf_len(conn->rx_buf);
    if (rx_len < 16)
      return;

    uint8_t ctr_try[16];
    uint32_t packet_length;
    for (int _i = 0; _i < 16; _i++)
      ctr_try[_i] = conn->crypto.recv_ctr[_i];
    for (int _i = 0; _i < 16; _i++)
      sshd_rx_buffer[_i] = rx[_i];
    aes128_ctr_crypt(conn->crypto.recv_key, ctr_try, sshd_rx_buffer, 16);
    packet_length = ssh_read_u32(sshd_rx_buffer);

    if (packet_length > 35000 || packet_length < 1)
      return;

    size_t full_len = 4 + (size_t)packet_length;
    size_t mac_len = (size_t)conn->crypto.mac_len;
    if (rx_len < full_len + mac_len)
      return;

    for (int i = 0; i < 16; i++)
      conn->crypto.recv_ctr[i] = ctr_try[i];
    for (size_t i = 16; i < full_len; i++)
      sshd_rx_buffer[i] = rx[i];
    aes128_ctr_crypt(conn->crypto.recv_key, conn->crypto.recv_ctr,
                     sshd_rx_buffer + 16, (int)(full_len - 16));

    if (mac_len > 0)
    {
      uint8_t seq_be[4];
      ssh_write_u32(seq_be, conn->crypto.recv_seq);
      if (4u + full_len > sizeof(ssh_mac_plain_scratch))
        return;
      for (size_t mi = 0; mi < 4; mi++)
        ssh_mac_plain_scratch[mi] = seq_be[mi];
      for (size_t mi = 0; mi < full_len; mi++)
        ssh_mac_plain_scratch[4 + mi] = sshd_rx_buffer[mi];
      uint8_t expected_mac[32];
      ssh_hmac_sha256(conn->crypto.recv_mac_key, 32, ssh_mac_plain_scratch,
                      4u + full_len, expected_mac);
      int mac_ok = 1;
      for (size_t i = 0; i < mac_len && i < 32; i++)
        if (expected_mac[i] != rx[full_len + i])
          mac_ok = 0;
      if (!mac_ok)
        return;
    }

    uint8_t padding_length = sshd_rx_buffer[4];
    int payload_size = (int)packet_length - (int)padding_length - 1;
    if (payload_size < 1)
    {
      sshbuf_consume(conn->rx_buf, full_len + mac_len);
      conn->crypto.recv_seq++;
      continue;
    }
    uint8_t msg_type = sshd_rx_buffer[5];
    const uint8_t *payload = sshd_rx_buffer + 6;
    int payload_len = payload_size - 1;

    if (msg_type == SSH_MSG_EXT_INFO)
    {
      sshbuf_consume(conn->rx_buf, full_len + mac_len);
      conn->crypto.recv_seq++;
      continue;
    }
    if (msg_type == SSH_MSG_IGNORE)
    {
      sshbuf_consume(conn->rx_buf, full_len + mac_len);
      conn->crypto.recv_seq++;
      continue;
    }
    if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST)
    {
      ssh_handle_channel_window_adjust(conn, payload, payload_len);
      sshbuf_consume(conn->rx_buf, full_len + mac_len);
      conn->crypto.recv_seq++;
      continue;
    }
    /* CHANNEL_DATA: must apply handler at outer drain depth so Ctrl+C / input
     * are not dropped while ssh_wait pumps during heavy log mirror (ping).
     * Nested depth > 0: echo→ssh_wait→drain again — consume-only to avoid
     * unbounded recursion; drops at most nested keystrokes (rare). */
    if (msg_type == SSH_MSG_CHANNEL_DATA)
    {
      static uint32_t ssh_drain_ch_depth;
      if (ssh_drain_ch_depth > 0u)
      {
        // #region agent log
        {
          static uint32_t ssh_drain_nested_drop_log;
          if ((++ssh_drain_nested_drop_log % 32u) == 0u)
            agent_dbg_evt("D", "ssh_drain", "ch_data_nested_consume",
                          ssh_drain_nested_drop_log, conn->client_window);
        }
        // #endregion
        sshbuf_consume(conn->rx_buf, full_len + mac_len);
        conn->crypto.recv_seq++;
        continue;
      }
      // #region agent log
      {
        static uint32_t ssh_drain_handler_log;
        if ((++ssh_drain_handler_log % 64u) == 0u)
          agent_dbg_evt("E", "ssh_drain", "ch_data_handler",
                        ssh_drain_handler_log, conn->client_window);
      }
      // #endregion
      ssh_drain_ch_depth++;
      ssh_handle_channel_data(conn, payload, payload_len);
      ssh_drain_ch_depth--;
      sshbuf_consume(conn->rx_buf, full_len + mac_len);
      conn->crypto.recv_seq++;
      continue;
    }
    return;
  }
}

/* Drain NIC/TCP; then apply WINDOW_ADJUST already sitting in rx_buf (see above). */
static void ssh_net_pump_for_channel(struct ssh_connection *conn)
{
  netdev_napi_poll(24);
  tcp_tick(pit_ticks);
  if (conn)
    ssh_drain_rx_encrypted_window_adjust(conn);
}

void ssh_flow_pump_from_shell(void)
{
  if (ssh_shell_log_conn && ssh_shell_log_sink_depth > 0u)
  {
    ssh_net_pump_for_channel(ssh_shell_log_conn);
  }
}

/*
 * RFC 4254: do not send CHANNEL_DATA past the client's initial/max window.
 * Old code zeroed the counter but still sent — OpenSSH stops extending TCP
 * window and the session looks like "network died after any command".
 */
static void ssh_wait_client_send_window(struct ssh_connection *conn,
                                        uint32_t need_bytes)
{
  uint32_t start = pit_ticks;
  while (conn->client_window < need_bytes)
  {
    if ((uint32_t)(pit_ticks - start) > (100u * 60u))
    {
      // #region agent log
      agent_dbg_evt("B", "ssh_wait", "timeout", need_bytes,
                    conn->client_window);
      // #endregion
      log_writestring("[SSH] channel send window timeout (client not extending)\n");
      return;
    }
    __asm__ volatile("sti");
    ssh_net_pump_for_channel(conn);
    for (volatile uint32_t s = 0; s < 12000u; s++)
      __asm__ volatile("pause");
  }
}

/* SSH_MSG_CHANNEL_DATA: recipient (client's channel id) + SSH string (len + bytes). */
static void ssh_send_channel_data_raw(struct ssh_connection *conn,
                                      const uint8_t *data, uint32_t data_len)
{
  if (!conn->authenticated || !conn->has_client_channel)
    return;

  ssh_tx_irq_enter();
  ssh_skip_tx_irq_wrappers++;
  ssh_channel_tx_depth++;

  for (uint32_t off = 0; off < data_len;)
  {
    uint32_t chunk = data_len - off;
    if (chunk > SSH_CHANNEL_DATA_CHUNK)
      chunk = SSH_CHANNEL_DATA_CHUNK;

    if (conn->client_window < chunk)
      ssh_wait_client_send_window(conn, chunk);
    if (conn->client_window < chunk)
      break;

    conn->client_window -= chunk;

    ssh_write_u32(ssh_chan_payload_scratch, conn->client_channel);
    ssh_write_u32(ssh_chan_payload_scratch + 4, chunk);
    for (uint32_t i = 0; i < chunk; i++)
      ssh_chan_payload_scratch[8 + i] = data[off + i];
    ssh_send_packet(conn, SSH_MSG_CHANNEL_DATA, ssh_chan_payload_scratch,
                    (int)(8 + chunk));
    off += chunk;
  }

  ssh_channel_tx_depth--;
  ssh_skip_tx_irq_wrappers--;
  ssh_tx_irq_leave();
  ssh_flush_deferred_window_adjust(conn);
}

void ssh_channel_write(struct ssh_connection *conn, const uint8_t *data,
                       uint32_t len)
{
  ssh_send_channel_data_raw(conn, data, len);
}

/* PTY / interactive SSH: LF alone advances a line without CR → "staircase" text.
 * Emit CRLF for each '\n' not already preceded by '\r'. */
static void ssh_send_channel_cstr(struct ssh_connection *conn, const char *s)
{
  if (!s || !*s)
    return;
  while (*s)
  {
    const char *line_start = s;
    while (*s && *s != '\n')
      s++;
    size_t line_len = (size_t)(s - line_start);
    if (line_len > 0)
      ssh_send_channel_data_raw(conn, (const uint8_t *)line_start, (uint32_t)line_len);
    if (*s == '\n')
    {
      if (s == line_start || s[-1] != '\r')
        ssh_send_channel_data_raw(conn, (const uint8_t *)"\r", 1);
      ssh_send_channel_data_raw(conn, (const uint8_t *)"\n", 1);
      s++;
    }
  }
}

/* Match local console: "AJOS [user]:/path> " using SSH auth name + FAT cwd. */
static void ssh_send_session_prompt(struct ssh_connection *conn)
{
  char prompt[160];
  const char *u = conn->username[0] ? conn->username : NULL;
  shell_format_prompt(prompt, sizeof(prompt), u);
  ssh_send_channel_cstr(conn, prompt);
}

/*
 * Send welcome + prompt once the session channel exists. Call right after
 * CHANNEL_OPEN_CONFIRMATION so the client sees a prompt even if it never sends
 * "shell" (or we fail to parse it). Idempotent.
 */
static void ssh_ensure_shell_ui(struct ssh_connection *conn)
{
  if (conn->ssh_welcome_sent)
    return;
  if (!conn->encrypted || !conn->authenticated || !conn->has_client_channel)
    return;

  conn->ssh_welcome_sent = 1;
  conn->shell_session_started = 1;
  conn->shell_line_len = 0;
  conn->shell_ignore_next_lf = 0;

  ssh_send_channel_cstr(conn, "Welcome to AJOS over SSH!\r\n");
  ssh_send_session_prompt(conn);
  log_writestring("[SSH] Sent welcome + session prompt on channel\n");
}

/* Mirror kernel log_putchar output into the SSH session (not VGA/serial). */

int ssh_shell_log_sink_active(void)
{
  return (ssh_shell_log_conn != NULL && ssh_shell_log_sink_depth > 0) ? 1 : 0;
}

void ssh_shell_log_flush(void)
{
  if (ssh_shell_log_conn && ssh_mirror_len > 0)
  {
    ssh_send_channel_data_raw(ssh_shell_log_conn, (const uint8_t *)ssh_mirror_buf,
                              (uint32_t)ssh_mirror_len);
    ssh_mirror_len = 0;
  }
}

void ssh_shell_mirror_putchar(char c)
{
  if (!ssh_shell_log_conn)
    return;
  if (c == '\n')
  {
    if (ssh_mirror_len == 0 || ssh_mirror_buf[ssh_mirror_len - 1] != '\r')
    {
      if (ssh_mirror_len >= sizeof(ssh_mirror_buf))
        ssh_shell_log_flush();
      if (ssh_mirror_len < sizeof(ssh_mirror_buf))
        ssh_mirror_buf[ssh_mirror_len++] = '\r';
    }
    if (ssh_mirror_len >= sizeof(ssh_mirror_buf))
      ssh_shell_log_flush();
    if (ssh_mirror_len < sizeof(ssh_mirror_buf))
      ssh_mirror_buf[ssh_mirror_len++] = '\n';
    /* Do NOT flush on every newline — soft-float AES/HMAC per line made
     * cat/edit stall ~5s. Buffer until full or explicit ssh_shell_log_flush. */
    return;
  }
  if (ssh_mirror_len < sizeof(ssh_mirror_buf))
    ssh_mirror_buf[ssh_mirror_len++] = (char)c;
  if (ssh_mirror_len >= sizeof(ssh_mirror_buf))
    ssh_shell_log_flush();
}

void ssh_shell_log_sink_set(struct ssh_connection *conn)
{
  if (ssh_shell_log_sink_depth == 0)
  {
    ssh_shell_log_conn = conn;
    ssh_mirror_len = 0;
  }
  else
  {
    /* Nested shell_execute (e.g. net_pump_rx delivered more SSH channel data
     * while a command like `dns` is running). Flush buffered output so the
     * inner command does not steal the mirror buffer, then stay attached. */
    ssh_shell_log_flush();
  }
  ssh_shell_log_sink_depth++;
}

void ssh_shell_log_sink_clear(struct ssh_connection *conn)
{
  if (ssh_shell_log_conn != conn || ssh_shell_log_sink_depth == 0)
    return;
  ssh_shell_log_flush();
  ssh_shell_log_sink_depth--;
  if (ssh_shell_log_sink_depth == 0)
  {
    ssh_shell_log_conn = NULL;
    ssh_mirror_len = 0;
  }
}

void ssh_shell_log_sink_recover_stale(void)
{
  if (ssh_shell_log_sink_depth == 0u || !ssh_shell_log_conn)
    return;
  struct ssh_connection *c = ssh_shell_log_conn;
  if (!c->pcb || c->pcb->state != TCP_ESTABLISHED)
  {
    // #region agent log
    agent_dbg_evt("F", "ssh_sink", "recover_stale", ssh_shell_log_sink_depth,
                  c->pcb ? (uint32_t)(unsigned long)(void *)c->pcb : 0u);
    // #endregion
    ssh_mirror_len = 0;
    ssh_shell_log_conn = NULL;
    ssh_shell_log_sink_depth = 0u;
    log_writestring("[SSH] Cleared stale shell log sink (SSH TCP not established)\n");
  }
}

void ssh_shell_log_sink_clear_for_local_shell(void)
{
  if (ssh_remote_shell_execute_depth != 0u)
    return;
  if (ssh_shell_log_conn == NULL && ssh_shell_log_sink_depth == 0u)
    return;
  // #region agent log
  agent_dbg_evt("H", "ssh_sink", "local_clear", ssh_shell_log_sink_depth,
                ssh_shell_log_conn ? 1u : 0u);
  // #endregion
  ssh_mirror_len = 0u;
  ssh_shell_log_conn = NULL;
  ssh_shell_log_sink_depth = 0u;
}

static void ssh_enqueue_shell_command(struct ssh_connection *conn, const char *cmd);
static void ssh_flush_pending_shell_commands(struct ssh_connection *conn);

/*
 * RFC 4254: CHANNEL_REQUEST
 * uint32 recipient, string type, boolean want_reply, type-specific...
 */
/* After non-interactive exec, tell the client the session ended (RFC 4254). */
static void ssh_send_channel_exit_status_eof_close(struct ssh_connection *conn,
                                                    uint32_t exit_status)
{
  uint8_t req[32];
  int i = 0;
  ssh_write_u32(req + i, conn->client_channel);
  i += 4;
  const char *es = "exit-status";
  uint32_t el = 11;
  ssh_write_u32(req + i, el);
  i += 4;
  for (uint32_t k = 0; k < el; k++)
    req[i++] = (uint8_t)es[k];
  req[i++] = 0; /* want_reply */
  ssh_write_u32(req + i, exit_status);
  i += 4;
  ssh_send_packet(conn, SSH_MSG_CHANNEL_REQUEST, req, i);

  uint8_t ec[4];
  ssh_write_u32(ec, conn->client_channel);
  ssh_send_packet(conn, SSH_MSG_CHANNEL_EOF, ec, 4);
  ssh_send_packet(conn, SSH_MSG_CHANNEL_CLOSE, ec, 4);
}

static void ssh_handle_channel_request(struct ssh_connection *conn,
                                       const uint8_t *p, int len)
{
  if (len < 4 + 4 + 1)
    return;
  uint32_t recipient = ssh_read_u32(p);
  if (recipient != conn->server_channel)
    return;

  int off = 4;
  uint32_t typ_len = ssh_read_u32(p + off);
  off += 4;
  if (typ_len > 256 || off + (int)typ_len + 1 > len)
    return;
  const uint8_t *typ = p + off;
  off += (int)typ_len;
  uint8_t want_reply = p[off];
  off++;

  log_writestring("[SSH] Channel request: ");
  if (typ_len == 7 && memcmp(typ, "pty-req", 7) == 0)
    log_writestring("pty-req\n");
  else if (typ_len == 5 && memcmp(typ, "shell", 5) == 0)
    log_writestring("shell\n");
  else if (typ_len == 4 && memcmp(typ, "exec", 4) == 0)
    log_writestring("exec\n");
  else if (typ_len == 9 && memcmp(typ, "subsystem", 9) == 0)
    log_writestring("subsystem\n");
  else if (typ_len == 3 && memcmp(typ, "env", 3) == 0)
    log_writestring("env\n");
  else
  {
    log_writestring("other (len=");
    log_write_u32(typ_len);
    log_writestring(")\n");
  }

  /* RFC 4254 exec: string command — non-interactive `ssh host cmd`. */
  if (typ_len == 4 && memcmp(typ, "exec", 4) == 0)
  {
    if (off + 4 > len)
      return;
    uint32_t cmd_len = ssh_read_u32(p + off);
    off += 4;
    if (cmd_len > 4096u || off + (int)cmd_len > len)
      return;
    char cmdbuf[512];
    int cpy = (int)cmd_len;
    if (cpy >= (int)sizeof(cmdbuf))
      cpy = (int)sizeof(cmdbuf) - 1;
    for (int j = 0; j < cpy; j++)
      cmdbuf[j] = (char)p[off + j];
    cmdbuf[cpy] = '\0';

    if (want_reply)
    {
      uint8_t response[4];
      ssh_write_u32(response, conn->client_channel);
      ssh_send_packet(conn, SSH_MSG_CHANNEL_SUCCESS, response, 4);
    }

    ssh_enqueue_shell_command(conn, cmdbuf);
    ssh_flush_pending_shell_commands(conn);
    ssh_send_channel_exit_status_eof_close(conn, 0);
    return;
  }

  /* RFC 4254 subsystem: string name. OpenSSH sftp(1) requests "sftp". */
  if (typ_len == 9 && memcmp(typ, "subsystem", 9) == 0)
  {
    if (off + 4 > len)
      return;
    uint32_t name_len = ssh_read_u32(p + off);
    off += 4;
    if (name_len > 256u || off + (int)name_len > len)
      return;
    int is_sftp = (name_len == 4 && memcmp(p + off, "sftp", 4) == 0);
    uint8_t response[4];
    ssh_write_u32(response, conn->client_channel);
    if (is_sftp && sftp_session_init(conn))
    {
      ssh_console_writestring("[SSH] SFTP subsystem started\n");
      if (want_reply)
        ssh_send_packet(conn, SSH_MSG_CHANNEL_SUCCESS, response, 4);
    }
    else if (want_reply)
      ssh_send_packet(conn, SSH_MSG_CHANNEL_FAILURE, response, 4);
    return;
  }

  /* Known no-ops / interactive setup. Unknown types fail (do not claim
   * success for an unimplemented subsystem-like request). */
  int ok = 0;
  if ((typ_len == 7 && memcmp(typ, "pty-req", 7) == 0) ||
      (typ_len == 5 && memcmp(typ, "shell", 5) == 0) ||
      (typ_len == 3 && memcmp(typ, "env", 3) == 0) ||
      (typ_len == 13 && memcmp(typ, "window-change", 13) == 0))
    ok = 1;

  if (want_reply)
  {
    uint8_t response[4];
    ssh_write_u32(response, conn->client_channel);
    ssh_send_packet(conn, ok ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE,
                    response, 4);
  }

  if (typ_len == 5 && memcmp(typ, "shell", 5) == 0)
    ssh_ensure_shell_ui(conn);
}

// Handle channel open
static void ssh_handle_channel_open(struct ssh_connection *conn,
                                    const uint8_t *data, int len)
{
  if (!conn->authenticated)
  {
    uint8_t failure_data[20];
    ssh_write_u32(failure_data, conn->client_channel); // Recipient channel
    ssh_write_u32(failure_data + 4,
                  1);                    // Reason code: SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
    ssh_write_u32(failure_data + 8, 0);  // Description length
    ssh_write_u32(failure_data + 12, 0); // Language tag length
    ssh_send_packet(conn, SSH_MSG_CHANNEL_OPEN_FAILURE, failure_data, 16);
    return;
  }

  // Parse channel open request
  if (len < 20)
    return;

  uint32_t channel_type_len = ssh_read_u32(data);
  if (channel_type_len > len - 4)
    return;

  // Read channel type (should be "session")
  uint32_t sender_channel = ssh_read_u32(data + 4 + channel_type_len);
  uint32_t initial_window = ssh_read_u32(data + 8 + channel_type_len);
  uint32_t max_packet = ssh_read_u32(data + 12 + channel_type_len);

  // Accept channel and assign IDs (client may use 0 for first channel — do not
  // treat client_channel==0 as "unset".)
  conn->client_channel = sender_channel;
  conn->has_client_channel = 1;
  conn->server_channel =
      1000 + (conn->pcb->remote_ip & 0xFF); // Simple ID generation
  conn->client_window = initial_window;
  conn->shell_session_started = 0;
  sftp_session_close(conn);
  conn->ssh_welcome_sent = 0;
  conn->shell_ignore_next_lf = 0;
  conn->shell_line_len = 0;

  // Send channel open confirmation
  uint8_t response[20];
  ssh_write_u32(response, conn->client_channel);     // Recipient channel
  ssh_write_u32(response + 4, conn->server_channel); // Sender channel
  ssh_write_u32(response + 8, conn->server_window);  // Initial window size
  ssh_write_u32(response + 12, 32768);               // Maximum packet size
  ssh_send_packet(conn, SSH_MSG_CHANNEL_OPEN_CONFIRMATION, response, 16);
  conn->state = SSH_STATE_ACTIVE;
  log_writestring("[SSH] Channel opened (client chan id=");
  log_write_u32(sender_channel);
  log_writestring(")\n");
  /* Interactive welcome+prompt only after client sends "shell" (see
   * ssh_handle_channel_request). If we enable line discipline here, OpenSSH's
   * non-interactive `ssh host cmd` (exec) never runs and the client hangs. */
}

static void ssh_enqueue_shell_command(struct ssh_connection *conn,
                                      const char *cmd)
{
  if (conn->shell_pending_count >= SSH_SHELL_PENDING_MAX)
  {
    log_writestring("[SSH] shell pending queue full, dropping command\n");
    return;
  }
  char *dst = conn->shell_pending_lines[conn->shell_pending_count++];
  int i;
  for (i = 0; i < 255 && cmd[i]; i++)
    dst[i] = cmd[i];
  dst[i] = '\0';
}

/*
 * Run lines queued by CHANNEL_DATA after the current ciphertext record is
 * consumed. Clears conn->processing so nested tcp_input/ssh_handle_connection
 * can decrypt client CHANNEL_DATA while a command runs (e.g. ping + net_pump).
 */
static void ssh_flush_pending_shell_commands(struct ssh_connection *conn)
{
  if (conn->shell_pending_count == 0)
    return;

  while (conn->shell_pending_count > 0)
  {
    char cmd[256];
    {
      const char *front = conn->shell_pending_lines[0];
      int i;
      for (i = 0; i < 256; i++)
        cmd[i] = front[i];
      conn->shell_pending_count--;
      for (int p = 0; p < conn->shell_pending_count; p++)
        for (i = 0; i < 256; i++)
          conn->shell_pending_lines[p][i] =
              conn->shell_pending_lines[p + 1][i];
    }

    conn->processing = 0;
    ssh_remote_shell_execute_depth++;
    ssh_stdin_reset();
    ssh_shell_log_sink_set(conn);
    /* After sink set: command chatter stays on the SSH session, not VGA/serial. */
    log_writestring("[SSH] Executing: ");
    log_writestring(cmd);
    log_putchar('\n');
    shell_execute(cmd);
    ssh_shell_log_flush();
    ssh_shell_log_sink_clear(conn);
    ssh_stdin_reset();
    ssh_remote_shell_execute_depth--;
    conn->processing = 1;
  }

  if (conn->shell_session_started)
    ssh_send_session_prompt(conn);
}

/* Run buffered line and redraw prompt (interactive shell only). */
static void ssh_shell_flush_line(struct ssh_connection *conn)
{
  ssh_send_channel_cstr(conn, "\r\n");

  if (conn->shell_line_len > 0)
  {
    conn->shell_line[conn->shell_line_len] = '\0';
    ssh_enqueue_shell_command(conn, conn->shell_line);
  }

  conn->shell_line_len = 0;
  /* Prompt only if nothing queued; otherwise flush_pending sends it after run. */
  if (conn->shell_pending_count == 0)
    ssh_send_session_prompt(conn);
}

// Handle channel data (shell input)
static void ssh_handle_channel_data(struct ssh_connection *conn,
                                    const uint8_t *data, int len)
{
  if (conn->state != SSH_STATE_ACTIVE)
    return;

  // SSH channel data format: [recipient_channel(4)] [string data]
  if (len < 4)
    return;
  uint32_t recipient_channel = ssh_read_u32(data);
  if (recipient_channel != conn->server_channel)
    return;

  if (len < 8)
    return;
  uint32_t str_len = ssh_read_u32(data + 4);
  if (str_len > 65536 || 8 + (int)str_len > len)
    return;

  const uint8_t *p = data + 8;
  int n = (int)str_len;

  if (conn->sftp_active)
  {
    sftp_feed(conn, p, (uint32_t)n);
    goto channel_window_refill;
  }

  /* Interactive line discipline after "shell" (PTY) is up. */
  if (conn->shell_session_started)
  {
    /* While a remote command runs (editor, etc.), feed raw bytes to stdin
     * instead of the shell line editor so input_getkey() can read them. */
    if (ssh_remote_shell_execute_depth > 0u)
    {
      for (int i = 0; i < n; i++)
        ssh_stdin_push(p[i]);
      goto channel_window_refill;
    }

    for (int i = 0; i < n; i++)
    {
      uint8_t c = p[i];

      if (c == '\r')
      {
        ssh_shell_flush_line(conn);
        conn->shell_ignore_next_lf = 1;
        continue;
      }
      if (c == '\n')
      {
        if (conn->shell_ignore_next_lf)
        {
          conn->shell_ignore_next_lf = 0;
          continue;
        }
        ssh_shell_flush_line(conn);
        continue;
      }

      conn->shell_ignore_next_lf = 0;

      if (c == 0x7f || c == 0x08)
      {
        if (conn->shell_line_len > 0)
        {
          conn->shell_line_len--;
          ssh_send_channel_cstr(conn, "\b \b");
        }
        continue;
      }

      if (c == '\t')
      {
        char matches[32][SHELL_TAB_MATCH_LEN];
        size_t len = conn->shell_line_len;
        size_t old_len = len;
        int n = shell_tab_complete(conn->shell_line, &len,
                                   sizeof(conn->shell_line), matches, 32);
        if (n <= 0)
          continue;

        if (len > old_len)
        {
          /* Echo only the newly completed suffix. */
          ssh_send_channel_data_raw(
              conn, (const uint8_t *)(conn->shell_line + old_len),
              (uint32_t)(len - old_len));
        }
        conn->shell_line_len = (uint16_t)len;

        if (n > 1)
        {
          ssh_send_channel_cstr(conn, "\r\n");
          for (int m = 0; m < n; m++)
          {
            ssh_send_channel_cstr(conn, matches[m]);
            ssh_send_channel_cstr(conn, "  ");
          }
          ssh_send_channel_cstr(conn, "\r\n");
          ssh_send_session_prompt(conn);
          if (conn->shell_line_len > 0)
            ssh_send_channel_data_raw(conn, (const uint8_t *)conn->shell_line,
                                      conn->shell_line_len);
        }
        continue;
      }

      /* Echo printable; ignore other control chars. */
      if (c >= 32 && c != 127)
      {
        if (conn->shell_line_len < (uint16_t)(sizeof(conn->shell_line) - 1))
        {
          conn->shell_line[conn->shell_line_len++] = (char)c;
          ssh_send_channel_data_raw(conn, &c, 1);
        }
      }
    }
    goto channel_window_refill;
  }

  /* Non-interactive: one packet = one command (e.g. exec). */
  char cmd[256] = {0};
  int copy = n;
  if (copy > 255)
    copy = 255;
  for (int i = 0; i < copy; i++)
    cmd[i] = (char)p[i];

  while (copy > 0 && (cmd[copy - 1] == '\n' || cmd[copy - 1] == '\r'))
  {
    cmd[copy - 1] = '\0';
    copy--;
  }

  if (copy > 0)
  {
    cmd[copy] = '\0';
    ssh_enqueue_shell_command(conn, cmd);
  }

channel_window_refill:
  /* Refill client's send window so they can emit more CHANNEL_DATA (keystrokes). */
  ssh_send_channel_window_adjust(conn, str_len);
}

/* Reset transport crypto to post-NEWKEYS canonical state (after RX failure). */
static void ssh_restore_derived_crypto(struct ssh_connection *conn)
{
  if (!conn->keys_derived)
    return;
  for (int i = 0; i < 16; i++)
  {
    conn->crypto.recv_ctr[i] = conn->derived_recv_iv[i];
    conn->crypto.send_ctr[i] = conn->derived_send_iv[i];
    conn->crypto.recv_key[i] = conn->derived_recv_key[i];
    conn->crypto.send_key[i] = conn->derived_send_key[i];
  }
  for (int i = 0; i < 32; i++)
  {
    conn->crypto.recv_mac_key[i] = conn->derived_recv_mac_key[i];
    conn->crypto.send_mac_key[i] = conn->derived_send_mac_key[i];
  }
  conn->crypto.recv_send_swapped = 0;
  conn->crypto.k_value_only_tried = 0;
  if (conn->kex_strict)
  {
    conn->crypto.recv_seq = 0;
    conn->crypto.send_seq = 0;
  }
  else
  {
    conn->crypto.recv_seq = conn->recv_packet_count + 1;
    conn->crypto.send_seq = conn->send_packet_count;
  }
}

// Main SSH connection handler
void ssh_handle_connection(struct tcp_pcb *pcb, const uint8_t *data, int len)
{
  struct ssh_connection *conn = ssh_find_connection(pcb);
  if (!conn)
  {
    log_writestring("[SSH] No connection slot available\n");
    return;
  }

  /* Recover leaked SSH TX mirror-suppress (should match ssh_tx_mirror_guard_depth). */
  if (ssh_tx_mirror_guard_depth != 0u)
  {
    log_writestring("[SSH] WARN: ssh TX mirror-guard leak at RX entry, resetting\n");
    uint32_t d = ssh_tx_mirror_guard_depth;
    ssh_tx_mirror_guard_depth = 0u;
    if (ssh_suppress_log_mirror_to_session >= d)
      ssh_suppress_log_mirror_to_session -= d;
    else
      ssh_suppress_log_mirror_to_session = 0u;
  }

  // Always append incoming bytes to the per-connection RX buffer. SSH runs
  // over a TCP stream, so we must handle partial packets and coalesced packets.
  if (len > 0 && data && conn->rx_buf)
  {
    int r = sshbuf_put(conn->rx_buf, data, (size_t)len);
    if (r != 0)
    {
      log_writestring("[SSH] ERROR: rx_buf append failed; dropping RX buffer\n");
      sshbuf_reset(conn->rx_buf);
      return;
    }
  }

  // Re-entrancy guard: if we're already processing, just buffer and return.
  if (conn->processing)
  {
    static uint32_t ssh_reenter_skip_log;
    if ((++ssh_reenter_skip_log % 64u) == 0u && len > 0)
    {
      // #region agent log
      agent_dbg_evt("C", "ssh_rx", "reenter_skip", (uint32_t)len,
                    (uint32_t)sshbuf_len(conn->rx_buf));
      // #endregion
      log_writestring("[SSH] DBG: processing=1, append-only (reentrant tcp); rx_len=");
      log_write_u32((uint32_t)sshbuf_len(conn->rx_buf));
      log_putchar('\n');
    }
    return;
  }
  conn->processing = 1;

  while (conn->rx_buf && sshbuf_len(conn->rx_buf) > 0)
  {
    const uint8_t *rx = (const uint8_t *)sshbuf_ptr(conn->rx_buf);
    size_t rx_len = sshbuf_len(conn->rx_buf);

    // Version exchange is line-based plain text, not SSH packet framing.
    if (conn->state == SSH_STATE_VERSION_EXCHANGE)
    {
      // Look for '\n' in buffered data.
      size_t nl = 0;
      int found = 0;
      for (; nl < rx_len; nl++)
      {
        if (rx[nl] == '\n')
        {
          found = 1;
          break;
        }
      }
      if (!found)
        break; // Need more bytes

      size_t line_len = nl + 1;
      ssh_handle_version(conn, rx, (int)line_len);
      sshbuf_consume(conn->rx_buf, line_len);
      continue;
    }

    // When encryption is active, packet_length is inside ciphertext; decrypt first block to get it.
    if (conn->encrypted && conn->crypto.cipher_type == SSH_CIPHER_AES128_CTR)
    {
      if (rx_len < 16)
        break;
      /* Do not log here: this runs from tcp_input/IRQ; per-packet serial I/O
       * stalls the CPU long enough to miss NIC RX and “kill” ICMP/SSH. */
      /* Use a scratch CTR for the first block so failed probes do not advance recv_ctr. */
      uint8_t ctr_try[16];
      uint32_t packet_length;
#define SSH_DECRYPT_FIRST_BLOCK()                                         \
  do                                                                      \
  {                                                                       \
    for (int _i = 0; _i < 16; _i++)                                       \
      ctr_try[_i] = conn->crypto.recv_ctr[_i];                            \
    for (int _i = 0; _i < 16; _i++)                                       \
      sshd_rx_buffer[_i] = rx[_i];                                        \
    aes128_ctr_crypt(conn->crypto.recv_key, ctr_try, sshd_rx_buffer, 16); \
    packet_length = ssh_read_u32(sshd_rx_buffer);                         \
  } while (0)

      SSH_DECRYPT_FIRST_BLOCK();
      if (packet_length > 35000 || packet_length < 1)
      {
        if (!conn->crypto.recv_send_swapped && conn->k_mpint_len > 0)
        {
          uint8_t riv[16], siv[16], rk[16], sk[16], rm[32], sm[32];
          ssh_derive_transport_keys(conn->exchange_hash, conn->k_mpint,
                                    conn->k_mpint_len, riv, rk, siv, sk, rm, sm);
          for (int i = 0; i < 16; i++)
          {
            conn->crypto.recv_ctr[i] = siv[i];
            conn->crypto.send_ctr[i] = riv[i];
            conn->crypto.recv_key[i] = sk[i];
            conn->crypto.send_key[i] = rk[i];
          }
          for (int i = 0; i < 32; i++)
          {
            conn->crypto.recv_mac_key[i] = sm[i];
            conn->crypto.send_mac_key[i] = rm[i];
          }
          conn->crypto.recv_send_swapped = 1;
          log_writestring("[SSH] Retried with recv=(B,D) send=(A,C), MAC keys swapped\n");
          SSH_DECRYPT_FIRST_BLOCK();
        }
        if ((packet_length > 35000 || packet_length < 1) &&
            !conn->crypto.k_value_only_tried && conn->k_mpint_len > 4)
        {
          uint8_t riv[16], siv[16], rk[16], sk[16], rm[32], sm[32];
          ssh_derive_transport_keys_k_value_only(conn->exchange_hash,
                                                 conn->k_mpint + 4,
                                                 (uint16_t)(conn->k_mpint_len - 4),
                                                 riv, rk, siv, sk, rm, sm);
          for (int i = 0; i < 16; i++)
          {
            conn->crypto.recv_ctr[i] = riv[i];
            conn->crypto.send_ctr[i] = siv[i];
            conn->crypto.recv_key[i] = rk[i];
            conn->crypto.send_key[i] = sk[i];
          }
          for (int i = 0; i < 32; i++)
          {
            conn->crypto.recv_mac_key[i] = rm[i];
            conn->crypto.send_mac_key[i] = sm[i];
          }
          conn->crypto.recv_send_swapped = 0;
          conn->crypto.k_value_only_tried = 1;
          log_writestring("[SSH] Retried with K value-only (no length prefix) in KDF\n");
          SSH_DECRYPT_FIRST_BLOCK();
        }
      }
#undef SSH_DECRYPT_FIRST_BLOCK
      if (packet_length > 35000 || packet_length < 1)
      {
        log_writestring("[SSH] Encrypted packet length invalid (decrypted=");
        log_write_u32(packet_length);
        log_writestring("), decrypted[0..3]=");
        for (int di = 0; di < 4; di++)
        {
          log_write_hex8(sshd_rx_buffer[di]);
          if (di < 3)
            log_putchar(' ');
        }
        log_writestring(", ciphertext[0..3]=");
        for (int di = 0; di < 4; di++)
        {
          log_write_hex8(rx[di]);
          if (di < 3)
            log_putchar(' ');
        }
        log_putchar('\n');
        if (conn->k_mpint_len > 0)
        {
          uint8_t riv[16], rk[16], siv[16], sk[16], kstream[16];
          ssh_derive_transport_keys(conn->exchange_hash, conn->k_mpint,
                                    conn->k_mpint_len, riv, rk, siv, sk, NULL, NULL);
          aes128_ctr_keystream_block(rk, riv, kstream);
          log_writestring("[SSH] our keystream[0..3]=");
          for (int di = 0; di < 4; di++)
          {
            log_write_hex8(kstream[di]);
            if (di < 3)
              log_putchar(' ');
          }
          log_writestring(" (canonical recv IV+key A,C)\n");
        }
        log_writestring("[SSH] resetting RX\n");
        ssh_restore_derived_crypto(conn);
        sshbuf_reset(conn->rx_buf);
        break;
      }
      size_t full_len = 4 + (size_t)packet_length;
      size_t mac_len = (size_t)conn->crypto.mac_len;
      /* Must not advance recv_ctr until full ciphertext + MAC are present.
       * TCP can deliver the first 16 bytes in one segment and the rest later;
       * committing early desyncs AES-CTR and kills the session (e.g. after ping). */
      if (rx_len < full_len + mac_len)
        break;
      /* Commit first-block keystream consumption; remainder continues recv_ctr. */
      for (int i = 0; i < 16; i++)
        conn->crypto.recv_ctr[i] = ctr_try[i];
      for (size_t i = 16; i < full_len; i++)
        sshd_rx_buffer[i] = rx[i];
      aes128_ctr_crypt(conn->crypto.recv_key, conn->crypto.recv_ctr,
                       sshd_rx_buffer + 16, (int)(full_len - 16));
      if (mac_len > 0)
      {
        uint8_t seq_be[4];
        ssh_write_u32(seq_be, conn->crypto.recv_seq);
        uint8_t expected_mac[32];
        if (4u + full_len > sizeof(ssh_mac_plain_scratch))
        {
          log_writestring("[SSH] MAC scratch overflow, resetting RX\n");
          ssh_restore_derived_crypto(conn);
          sshbuf_reset(conn->rx_buf);
          break;
        }
        for (size_t mi = 0; mi < 4; mi++)
          ssh_mac_plain_scratch[mi] = seq_be[mi];
        for (size_t mi = 0; mi < full_len; mi++)
          ssh_mac_plain_scratch[4 + mi] = sshd_rx_buffer[mi];
        ssh_hmac_sha256(conn->crypto.recv_mac_key, 32, ssh_mac_plain_scratch,
                        4u + full_len, expected_mac);
        int mac_ok = 1;
        for (size_t i = 0; i < mac_len && i < 32; i++)
          if (expected_mac[i] != rx[full_len + i])
            mac_ok = 0;
        /* OpenSSH: recv uses integrity key E (c->s). If MAC fails but decrypt
           length looks valid, try F (s->c) — catches accidental E/F swap in KDF. */
        if (!mac_ok && conn->crypto.recv_seq == 0)
        {
          uint8_t alt_mac[32];
          ssh_hmac_sha256(conn->crypto.send_mac_key, 32, ssh_mac_plain_scratch,
                          4u + full_len, alt_mac);
          int alt_ok = 1;
          for (size_t i = 0; i < mac_len && i < 32; i++)
            if (alt_mac[i] != rx[full_len + i])
              alt_ok = 0;
          if (alt_ok)
          {
            mac_ok = 1;
            log_writestring(
                "[SSH] MAC ok with send_mac_key (F); swapping recv/send MAC keys\n");
            for (size_t mi = 0; mi < 32; mi++)
            {
              uint8_t t = conn->crypto.recv_mac_key[mi];
              conn->crypto.recv_mac_key[mi] = conn->crypto.send_mac_key[mi];
              conn->crypto.send_mac_key[mi] = t;
            }
            if (conn->keys_derived)
            {
              for (size_t mi = 0; mi < 32; mi++)
              {
                uint8_t t = conn->derived_recv_mac_key[mi];
                conn->derived_recv_mac_key[mi] =
                    conn->derived_send_mac_key[mi];
                conn->derived_send_mac_key[mi] = t;
              }
            }
            for (size_t mi = 0; mi < 32; mi++)
              expected_mac[mi] = alt_mac[mi];
          }
        }
        if (!mac_ok)
        {
          log_writestring("[SSH] MAC verification failed, resetting RX\n");
          ssh_restore_derived_crypto(conn);
          sshbuf_reset(conn->rx_buf);
          break;
        }
      }
      uint8_t padding_length = sshd_rx_buffer[4];
      int payload_size = packet_length - padding_length - 1;
      if (payload_size < 1)
      {
        sshbuf_consume(conn->rx_buf, full_len + mac_len);
        conn->crypto.recv_seq++;
        ssh_flush_pending_shell_commands(conn);
        continue;
      }
      uint8_t msg_type = sshd_rx_buffer[5];
      const uint8_t *payload = sshd_rx_buffer + 6;
      int payload_len = payload_size - 1;

      int ssh_drop_tcp_after_packet = 0;
      switch (msg_type)
      {
      case SSH_MSG_EXT_INFO:
        /* OpenSSH may send EXT_INFO (7) as first encrypted packet; ignore. */
        log_writestring("[SSH] EXT_INFO received (ignored)\n");
        break;
      case SSH_MSG_DISCONNECT:
        log_writestring("[SSH] Client SSH_MSG_DISCONNECT, closing TCP\n");
        ssh_drop_tcp_after_packet = 1;
        break;
      case SSH_MSG_CHANNEL_EOF:
        /* Client half-closed channel; TCP may stay up until CHANNEL_CLOSE. */
        log_writestring("[SSH] Client CHANNEL_EOF (ignored)\n");
        break;
      case SSH_MSG_CHANNEL_CLOSE:
        log_writestring("[SSH] Client CHANNEL_CLOSE, closing TCP\n");
        ssh_drop_tcp_after_packet = 1;
        break;
      case SSH_MSG_SERVICE_REQUEST:
        ssh_handle_service_request(conn, payload, payload_len);
        break;
      case SSH_MSG_USERAUTH_REQUEST:
        ssh_handle_auth_request(conn, payload, payload_len);
        break;
      case SSH_MSG_CHANNEL_OPEN:
        ssh_handle_channel_open(conn, payload, payload_len);
        break;
      case SSH_MSG_CHANNEL_DATA:
        ssh_handle_channel_data(conn, payload, payload_len);
        break;
      case SSH_MSG_CHANNEL_WINDOW_ADJUST:
        ssh_handle_channel_window_adjust(conn, payload, payload_len);
        break;
      case SSH_MSG_CHANNEL_REQUEST:
        ssh_handle_channel_request(conn, payload, payload_len);
        break;
      default:
        log_writestring("[SSH] Unhandled encrypted message type: ");
        log_write_u32(msg_type);
        log_putchar('\n');
        break;
      }
      sshbuf_consume(conn->rx_buf, full_len + mac_len);
      conn->crypto.recv_seq++;
      ssh_flush_pending_shell_commands(conn);
      if (ssh_drop_tcp_after_packet && conn->pcb)
        tcp_close(conn->pcb);
      continue;
    }

    /* Unencrypted path: only when not yet encrypted (KEX phase). When encrypted, never interpret raw RX as plaintext. */
    if (conn->encrypted)
      break; /* Wait for more data or next packet; do not interpret ciphertext as plaintext. */
    if (rx_len < 4)
      break;

    uint32_t packet_length = ssh_read_u32(rx);
    if (packet_length > 35000 || packet_length < 1)
    {
      log_writestring("[SSH] Packet too large: ");
      log_write_u32(packet_length);
      log_writestring(", clearing RX buffer\n");
      sshbuf_reset(conn->rx_buf);
      break;
    }

    size_t full_len = 4 + (size_t)packet_length;
    if (rx_len < full_len)
      break; // Incomplete packet

    uint8_t msg_type;
    const uint8_t *payload;
    int payload_len;

    log_writestring("[SSH] Parsing packet: len=");
    log_write_u32((uint32_t)full_len);
    log_writestring(", packet_length=");
    log_write_u32(packet_length);
    log_putchar('\n');

    if (!ssh_read_packet(conn, rx, (int)full_len, &msg_type, &payload, &payload_len))
    {
      log_writestring("[SSH] Failed to parse packet; dropping 1 byte to resync\n");
      sshbuf_consume(conn->rx_buf, 1);
      continue;
    }

    log_writestring("[SSH] Parsed packet: type=");
    log_write_u32(msg_type);
    log_writestring(", payload_len=");
    log_write_u32(payload_len);
    log_putchar('\n');

    switch (msg_type)
    {
    case SSH_MSG_KEXINIT:
      ssh_handle_kexinit(conn, payload, payload_len);
      break;
    case SSH_MSG_KEXDH_INIT:
      ssh_handle_kexdh_init(conn, payload, payload_len);
      break;
    case SSH_MSG_KEXDH_GEX_REQUEST:
      ssh_handle_kexdh_gex_request(conn, payload, payload_len);
      break;
    case SSH_MSG_KEXDH_GEX_INIT:
      ssh_handle_kexdh_gex_init(conn, payload, payload_len);
      break;
    case SSH_MSG_NEWKEYS:
      log_writestring("[SSH] Client NEWKEYS received\n");
      log_writestring("[SSH] Key exchange complete, applying transport keys\n");
      if (conn->keys_derived)
      {
        for (int i = 0; i < 16; i++)
        {
          conn->crypto.recv_ctr[i] = conn->derived_recv_iv[i];
          conn->crypto.send_ctr[i] = conn->derived_send_iv[i];
          conn->crypto.recv_key[i] = conn->derived_recv_key[i];
          conn->crypto.send_key[i] = conn->derived_send_key[i];
        }
        for (int i = 0; i < 32; i++)
        {
          conn->crypto.recv_mac_key[i] = conn->derived_recv_mac_key[i];
          conn->crypto.send_mac_key[i] = conn->derived_send_mac_key[i];
        }
        conn->crypto.cipher_type = SSH_CIPHER_AES128_CTR;
        conn->crypto.mac_type = SSH_MAC_HMAC_SHA2_256;
        conn->crypto.mac_len = 32;
        conn->crypto.recv_send_swapped = 0;
        conn->crypto.k_value_only_tried = 0;
        if (conn->kex_strict)
        {
          conn->crypto.recv_seq = 0;
          conn->crypto.send_seq = 0;
        }
        else
        {
          conn->crypto.recv_seq = conn->recv_packet_count + 1;
          conn->crypto.send_seq = conn->send_packet_count;
        }
        conn->encrypted = 1;
        log_writestring("[SSH] Transport encryption enabled (AES-128-CTR + HMAC-SHA2-256)\n");
        log_writestring("[SSH] MAC seq start: recv_seq=");
        log_write_u32(conn->crypto.recv_seq);
        log_writestring(", send_seq=");
        log_write_u32(conn->crypto.send_seq);
        log_writestring(", kex_strict=");
        log_write_u32(conn->kex_strict);
        log_putchar('\n');
        log_writestring("[SSH] KDF debug: k_mpint_len=");
        log_write_u32(conn->k_mpint_len);
        log_writestring(", recv_iv[0..3]=");
        for (int i = 0; i < 4; i++)
        {
          log_write_hex8(conn->crypto.recv_ctr[i]);
          if (i < 3)
            log_putchar(' ');
        }
        log_writestring(", recv_key[0..3]=");
        for (int i = 0; i < 4; i++)
        {
          log_write_hex8(conn->crypto.recv_key[i]);
          if (i < 3)
            log_putchar(' ');
        }
        log_writestring(", H[0..3]=");
        for (int i = 0; i < 4; i++)
        {
          log_write_hex8(conn->exchange_hash[i]);
          if (i < 3)
            log_putchar(' ');
        }
        log_writestring(", K_mpint[0..7]=");
        for (int i = 0; i < 8 && i < conn->k_mpint_len; i++)
        {
          log_write_hex8(conn->k_mpint[i]);
          if (i < 7)
            log_putchar(' ');
        }
        log_putchar('\n');
      }
      else if (conn->k_mpint_len > 0)
      {
        uint8_t recv_iv[16], send_iv[16];
        ssh_derive_transport_keys(conn->exchange_hash, conn->k_mpint,
                                  conn->k_mpint_len, recv_iv, conn->crypto.recv_key,
                                  send_iv, conn->crypto.send_key,
                                  conn->crypto.recv_mac_key, conn->crypto.send_mac_key);
        for (int i = 0; i < 16; i++)
        {
          conn->crypto.recv_ctr[i] = recv_iv[i];
          conn->crypto.send_ctr[i] = send_iv[i];
        }
        conn->crypto.cipher_type = SSH_CIPHER_AES128_CTR;
        conn->crypto.mac_type = SSH_MAC_HMAC_SHA2_256;
        conn->crypto.mac_len = 32;
        conn->crypto.recv_send_swapped = 0;
        conn->crypto.k_value_only_tried = 0;
        if (conn->kex_strict)
        {
          conn->crypto.recv_seq = 0;
          conn->crypto.send_seq = 0;
        }
        else
        {
          conn->crypto.recv_seq = conn->recv_packet_count + 1;
          conn->crypto.send_seq = conn->send_packet_count;
        }
        conn->encrypted = 1;
        log_writestring("[SSH] Transport encryption enabled (AES-128-CTR + HMAC-SHA2-256)\n");
        log_writestring("[SSH] MAC seq start: recv_seq=");
        log_write_u32(conn->crypto.recv_seq);
        log_writestring(", send_seq=");
        log_write_u32(conn->crypto.send_seq);
        log_writestring(", kex_strict=");
        log_write_u32(conn->kex_strict);
        log_putchar('\n');
        log_writestring("[SSH] KDF debug (fallback): k_mpint_len=");
        log_write_u32(conn->k_mpint_len);
        log_writestring(", recv_iv[0..3]=");
        for (int i = 0; i < 4; i++)
        {
          log_write_hex8(conn->crypto.recv_ctr[i]);
          if (i < 3)
            log_putchar(' ');
        }
        log_writestring(", H[0..3]=");
        for (int i = 0; i < 4; i++)
        {
          log_write_hex8(conn->exchange_hash[i]);
          if (i < 3)
            log_putchar(' ');
        }
        log_putchar('\n');
      }
      if (conn->state == SSH_STATE_KEXINIT || conn->state == SSH_STATE_KEXDH ||
          conn->state == SSH_STATE_SERVICE_REQUEST)
      {
        conn->state = SSH_STATE_SERVICE_REQUEST;
        log_writestring("[SSH] Ready for service requests\n");
      }
      break;
    case SSH_MSG_SERVICE_REQUEST:
      ssh_handle_service_request(conn, payload, payload_len);
      break;
    case SSH_MSG_USERAUTH_REQUEST:
      ssh_handle_auth_request(conn, payload, payload_len);
      break;
    case SSH_MSG_CHANNEL_OPEN:
      ssh_handle_channel_open(conn, payload, payload_len);
      break;
    case SSH_MSG_CHANNEL_DATA:
      ssh_handle_channel_data(conn, payload, payload_len);
      break;
    case SSH_MSG_CHANNEL_REQUEST:
      ssh_handle_channel_request(conn, payload, payload_len);
      break;
    default:
      log_writestring("[SSH] Unhandled message type: ");
      log_write_u32(msg_type);
      log_putchar('\n');
      break;
    }

    // Consume the fully processed packet bytes.
    sshbuf_consume(conn->rx_buf, full_len);
    conn->recv_packet_count++;
    ssh_flush_pending_shell_commands(conn);
  }

  if (ssh_tx_mirror_guard_depth != 0u)
  {
    log_writestring("[SSH] WARN: ssh TX mirror-guard leak at RX exit, resetting\n");
    uint32_t d = ssh_tx_mirror_guard_depth;
    ssh_tx_mirror_guard_depth = 0u;
    if (ssh_suppress_log_mirror_to_session >= d)
      ssh_suppress_log_mirror_to_session -= d;
    else
      ssh_suppress_log_mirror_to_session = 0u;
  }
  conn->processing = 0;
}

// Update SSH listener IP (called when IP changes)
void sshd_update_listener_ip(uint32_t ip)
{
  if (sshd_listen_pcb && sshd_active)
  {
    sshd_listen_pcb->local_ip = (ip != 0) ? ip : 0; // 0 = any interface
    ssh_console_writestring("[SSHD] Listener IP updated\n");
  }
}

// Start SSH server (listen on port 22)
void sshd_start(void)
{
  if (sshd_active && sshd_listen_pcb)
  {
    ssh_console_writestring("[SSHD] Already running\n");
    // Update IP in case it changed
    extern uint32_t arp_get_ajos_ip(void);
    uint32_t current_ip = arp_get_ajos_ip();
    sshd_update_listener_ip(current_ip);
    return;
  }

  sshd_listen_pcb = tcp_get_free_pcb();
  if (!sshd_listen_pcb)
  {
    ssh_console_writestring("[SSHD] No free PCBs\n");
    return;
  }

  extern uint32_t arp_get_ajos_ip(void);
  sshd_listen_pcb->local_port = 22;
  sshd_listen_pcb->state = TCP_LISTEN;
  uint32_t current_ip = arp_get_ajos_ip();
  // Always listen on all interfaces (0.0.0.0) for SSH
  sshd_listen_pcb->local_ip =
      0; // 0 = any interface (allows connections from any IP)
  sshd_active = 1;

  ssh_console_writestring(
      "[SSHD] Server started on port 22 (listening on all interfaces)\n");
}

// Handle SSH connection close (Minoca OS pattern: TelnetdDestroySession)
void ssh_handle_connection_close(struct tcp_pcb *pcb)
{
  struct ssh_connection *conn = NULL;

  // Find the connection
  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    if (ssh_connections[i].pcb == pcb)
    {
      conn = &ssh_connections[i];
      break;
    }
  }

  if (conn)
  {
    // If we're in the middle of an expensive key exchange calculation,
    // don't reset the connection struct under the running computation.
    // Just mark it closing; the KEX path will notice and abort safely.
    if (conn->computing_keys)
    {
      log_writestring("[SSH] Connection closed during KEX; deferring cleanup\n");
      conn->closing = 1;
      conn->pcb = NULL;
      return;
    }
    log_writestring("[SSH] Connection closed, cleaning up\n");
    ssh_destroy_connection(conn);
  }
}

// Stop SSH server (Minoca OS pattern: proper cleanup of all sessions)
void sshd_stop(void)
{
  if (!sshd_active)
  {
    ssh_console_writestring("[SSHD] Not running\n");
    return;
  }

  // Close and cleanup all active connections (Minoca OS pattern)
  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    if (ssh_connections[i].pcb)
    {
      extern int tcp_close(struct tcp_pcb * pcb);
      tcp_close(ssh_connections[i].pcb);
      ssh_destroy_connection(&ssh_connections[i]);
    }
  }

  // Close listen socket
  if (sshd_listen_pcb)
  {
    sshd_listen_pcb->state = TCP_CLOSED;
    sshd_listen_pcb = NULL;
  }

  sshd_active = 0;
  ssh_console_writestring("[SSHD] Server stopped\n");
}

// Initialize SSH server
void ssh_init(void)
{
  /* May be in BSS range we skip (disk cache 0x51000-0xA0000); ensure clean. */
  sshd_active = 0;
  sshd_listen_pcb = NULL;
  sshd_tx_buffer = NULL;
  sshd_rx_buffer = NULL;
  safe_i_s_len = 0;

  /* Lazy allocate IO buffers on first incoming SSH connection. */

  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    ssh_connections[i].pcb = 0;
  }
  /* Boot must stay deterministic and quiet; crypto selftests are expensive and
   * have produced noisy/corrupted serial output in early init. Keep runtime SSH
   * enabled, but skip deep selftests during kernel startup. */
  log_writestring("[SSH] Server initialized\n");
  // Auto-start SSH server
  sshd_start();
}

// SSH server statistics
void sshd_stat(void)
{
  int active = 0;
  for (int i = 0; i < SSH_MAX_CONNECTIONS; i++)
  {
    if (ssh_connections[i].pcb &&
        ssh_connections[i].pcb->state == TCP_ESTABLISHED)
    {
      active++;
    }
  }
  ssh_console_writestring("[SSHD] Active connections: ");
  ssh_console_write_u32(active);
  ssh_console_putchar('\n');
  ssh_console_writestring("[SSHD] Server status: ");
  ssh_console_writestring(sshd_active ? "RUNNING" : "STOPPED");
  ssh_console_putchar('\n');
}

// Helper functions (need to be defined or declared)
static void kstrncpy(char *dest, const char *src, size_t n)
{
  size_t i;
  for (i = 0; i < n - 1 && src[i]; i++)
  {
    dest[i] = src[i];
  }
  dest[i] = '\0';
}
