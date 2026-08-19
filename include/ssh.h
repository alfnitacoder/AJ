#ifndef SSH_H
#define SSH_H

#include "net.h"
#include "openssh/sshbuf.h"
#include <stdint.h>

// SSH Protocol Version Strings
#define SSH_VERSION_STRING "SSH-2.0-AJOS_1.0\r\n"
#define SSH_VERSION_LEN 18

// SSH Message Types (simplified)
#define SSH_MSG_DISCONNECT 1
#define SSH_MSG_IGNORE 2
#define SSH_MSG_UNIMPLEMENTED 3
#define SSH_MSG_DEBUG 4
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT 6
#define SSH_MSG_EXT_INFO 7
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_NEWKEYS 21
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_KEXDH_REPLY 31
#define SSH_MSG_KEXDH_GEX_REQUEST 34
#define SSH_MSG_KEXDH_GEX_GROUP \
  31 // Same as KEXDH_REPLY, but for group-exchange
#define SSH_MSG_KEXDH_GEX_INIT 32
#define SSH_MSG_KEXDH_GEX_REPLY 33
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_BANNER 53
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA 94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF 96
#define SSH_MSG_CHANNEL_CLOSE 97
#define SSH_MSG_CHANNEL_REQUEST 98
#define SSH_MSG_CHANNEL_SUCCESS 99
#define SSH_MSG_CHANNEL_FAILURE 100

// SSH Service Names
#define SSH_SERVICE_USERAUTH "ssh-userauth"
#define SSH_SERVICE_CONNECTION "ssh-connection"

// SSH Authentication Methods
#define SSH_AUTH_METHOD_PASSWORD "password"
#define SSH_AUTH_METHOD_PUBLICKEY "publickey"
#define SSH_AUTH_METHOD_NONE "none"

// SSH Channel Types
#define SSH_CHANNEL_SESSION "session"

// SSH Channel Request Types
#define SSH_CHANNEL_REQUEST_PTY "pty-req"
#define SSH_CHANNEL_REQUEST_SHELL "shell"
#define SSH_CHANNEL_REQUEST_EXEC "exec"

/* Deferred shell lines: run after current SSH packet is consumed so
 * conn->processing can drop during shell_execute (nested tcp_input/SSH RX). */
#define SSH_SHELL_PENDING_MAX 4

// SSH Encryption State
#define SSH_CIPHER_NONE 0
#define SSH_CIPHER_AES128_CTR 1
#define SSH_CIPHER_XOR_TEST 2
#define SSH_MAC_NONE 0
#define SSH_MAC_HMAC_SHA2_256 1
struct ssh_crypto
{
  uint8_t cipher_type; // SSH_CIPHER_*
  uint8_t mac_type;    // SSH_MAC_*
  uint8_t mac_len;     // 0 or 32 for hmac-sha2-256
  uint8_t key[32];     // Encryption key (legacy / XOR test)
  uint8_t iv[16];      // IV / counter for CTR
  uint32_t seq_number; // (legacy)
  // AES-128-CTR: separate keys/IVs for each direction
  uint8_t recv_key[16];
  uint8_t recv_ctr[16];
  uint8_t send_key[16];
  uint8_t send_ctr[16];
  // MAC keys (hmac-sha2-256): E=recv, F=send
  uint8_t recv_mac_key[32];
  uint8_t send_mac_key[32];
  uint32_t recv_seq; // sequence number for received packets (MAC verify)
  uint32_t send_seq; // sequence number for sent packets (MAC append)
  uint8_t recv_send_swapped;   // 1 if we swapped recv=(B,D) send=(A,C) for client compatibility
  uint8_t k_value_only_tried; // 1 if we already retried with K value-only (no 4-byte length) in KDF
};

// SSH Server State
struct ssh_connection
{
  struct tcp_pcb *pcb;
  uint32_t state;
  uint8_t authenticated;
  uint32_t client_channel;
  uint8_t has_client_channel; /* 1 after CHANNEL_OPEN: client id may legally be 0 */
  uint32_t server_channel;
  /* Outbound credit: bytes we may send (client's CHANNEL_OPEN initial window);
   * extended by client SSH_MSG_CHANNEL_WINDOW_ADJUST (93). */
  uint32_t client_window;
  /* Initial window we advertise for client → server CHANNEL_DATA (RFC 4254). */
  uint32_t server_window;
  /* WINDOW_ADJUST bytes deferred while nested inside CHANNEL_DATA TX. */
  uint32_t deferred_window_adjust;
  uint8_t shell_session_started; /* 1 = interactive line discipline + echo */
  uint8_t ssh_welcome_sent;     /* 1 after welcome+prompt sent (idempotent) */
  uint8_t shell_ignore_next_lf;  /* after CR, ignore one LF (CRLF) */
  uint16_t shell_line_len;
  char shell_line[256];
  uint8_t shell_pending_count;
  char shell_pending_lines[SSH_SHELL_PENDING_MAX][256];
  char username[64];
  struct ssh_crypto crypto;
  uint32_t recv_packet_count; // packets received from client (before encryption); used to set recv_seq at NEWKEYS
  uint32_t send_packet_count; // packets sent by server (before encryption); used to set send_seq at NEWKEYS
  uint8_t encrypted;      // Whether encryption is active
  uint8_t processing;     // Re-entrancy guard
  uint8_t computing_keys; // Specific guard for key exchange calculation
  uint8_t closing;        // Connection is closing (FIN/RST seen)

  // Backlog buffer for re-entrant packets
  uint8_t *backlog_buf;
  uint32_t backlog_len;
  uint32_t backlog_alloc;

  // Exchange hash components (for signature computation)
  uint8_t v_c[256]; // Client version string
  size_t v_c_len;
  uint8_t i_c[2048]; // Client KEXINIT payload
  size_t i_c_len;
  uint8_t i_s[2048]; // Server KEXINIT payload
  size_t i_s_len;
  uint8_t k_s[1024]; // Server host key blob (needs to be large enough for RSA-2048 key)
  size_t k_s_len;
  uint32_t gex_min, gex_preferred, gex_max; // GEX parameters
  uint8_t gex_p[512];                       // Prime p (mpint format)
  size_t gex_p_len;
  uint8_t gex_g[16]; // Generator g (mpint format)
  size_t gex_g_len;
  uint8_t gex_e[512]; // Client DH public value (mpint format)
  size_t gex_e_len;
  uint8_t gex_f[512]; // Server DH public value (mpint format)
  size_t gex_f_len;
  char negotiated_sig_alg[32]; // Negotiated signature algorithm (e.g.,
                               // "rsa-sha2-512", "ssh-rsa")

  // For key derivation after NEWKEYS (RFC 4253): session_id = H, K in mpint form
  uint8_t exchange_hash[32];   // H = session_id
  uint8_t k_mpint[280];        // Shared secret K (mpint encoding)
  uint16_t k_mpint_len;

  // Pre-derived transport keys (computed in GEX_REPLY with same K,H as signature)
  uint8_t derived_recv_iv[16];
  uint8_t derived_recv_key[16];
  uint8_t derived_send_iv[16];
  uint8_t derived_send_key[16];
  uint8_t derived_recv_mac_key[32];
  uint8_t derived_send_mac_key[32];
  uint8_t keys_derived;        // 1 if derived_* are valid
  uint8_t kex_strict;          // OpenSSH strict KEX: MAC seq resets to 0 after NEWKEYS

  // OpenSSH buffer support (for packet construction)
  struct sshbuf *tx_buf; // Buffer for constructing outgoing packets
  struct sshbuf *rx_buf; // Buffer for receiving packets
};

#define SSH_STATE_VERSION_EXCHANGE 0
#define SSH_STATE_KEXINIT 1
#define SSH_STATE_KEXDH 2
#define SSH_STATE_SERVICE_REQUEST 3
#define SSH_STATE_AUTHENTICATION 4
#define SSH_STATE_CHANNEL_OPEN 5
#define SSH_STATE_ACTIVE 6

// Function Declarations
void ssh_init(void);
void ssh_handle_connection(struct tcp_pcb *pcb, const uint8_t *data, int len);
void ssh_handle_connection_close(struct tcp_pcb *pcb); // Minoca OS pattern: cleanup on close
void ssh_handle_new_connection(struct tcp_pcb *pcb);
void sshd_start(void);
void sshd_stop(void);
void sshd_stat(void);
void ssh_handle_new_connection(struct tcp_pcb *pcb);
void sshd_stat(void);
void sshd_start(void);
void sshd_stop(void);
void sshd_update_listener_ip(uint32_t ip);

/* Route log_putchar from shell commands to the SSH client's channel (see ssh.c). */
void ssh_shell_log_sink_set(struct ssh_connection *conn);
void ssh_shell_log_sink_clear(struct ssh_connection *conn);
/* If SSH disconnected abnormally while a sink was active, drop it so console
 * shells are not stuck mirroring to a dead session. */
void ssh_shell_log_sink_recover_stale(void);
/* Drop SSH mirror sink when the line-oriented shell runs from the local console
 * (not from ssh_flush_pending_shell_commands). Prevents stuck depth/conn from
 * ssh_shell_log_sink_clear mismatches leaving log_putchar routed only to SSH. */
void ssh_shell_log_sink_clear_for_local_shell(void);
void ssh_shell_mirror_putchar(char c);
void ssh_shell_log_flush(void);
int ssh_shell_log_sink_active(void);
extern uint32_t ssh_log_mirror_depth;
/* When >0, log_putchar must not mirror to SSH (e.g. inside tcp_input — avoids
 * feedback: TCP debug on port 22 → CHANNEL_DATA → more ACKs → more logs). */
extern uint32_t ssh_suppress_log_mirror_to_session;

/* While a shell command mirrors output over SSH, poll NIC + drain WINDOW_ADJUST
 * from rx_buf (safe to call from ping / long-running commands). */
void ssh_flow_pump_from_shell(void);

/* Raw stdin for interactive programs (editor) while a remote SSH command runs.
 * Channel bytes are diverted from the line editor into this ring. */
void ssh_stdin_reset(void);
int ssh_stdin_has_data(void);
int ssh_stdin_getchar(void); /* -1 if empty; otherwise 0..255 */

#endif // SSH_H
