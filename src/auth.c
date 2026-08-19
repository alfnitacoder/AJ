#include "auth.h"
#include "user.h"
#include <stddef.h>
#include <stdint.h>

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern volatile uint32_t pit_ticks; /* ticks at PIT_HZ == 100 */

/* Authenticated-source table (firewall whitelist used by ip4_policy_filter).
 * Each entry is an IP that logged in via the captive portal or SSH; entries
 * expire after AUTH_TIMEOUT_TICKS of inactivity so a shared/NAT IP does not
 * stay trusted forever after one login. */
#define MAX_AUTH_IPS 50
#define AUTH_TIMEOUT_TICKS (5u * 60u * 100u) /* 5 minutes at 100 Hz */

struct auth_entry {
  uint32_t ip;
  uint32_t last_seen; /* pit_ticks when last verified/refreshed */
  uint8_t valid;
};

static struct auth_entry sessions[MAX_AUTH_IPS];

void auth_init(void) {
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    sessions[i].valid = 0;
  }
  log_writestring("[AUTH] Session manager initialized\n");
}

int auth_check_credentials(const char *user, const char *pass) {
  // Use user database for authentication
  return user_check_password(user, pass);
}

static void log_ip(uint32_t ip) {
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
}

void auth_set_authenticated(uint32_t ip) {
  // Refresh if already authenticated
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (sessions[i].valid && sessions[i].ip == ip) {
      sessions[i].last_seen = pit_ticks;
      return; // Already allowed
    }
  }

  // Find free slot (or the oldest expired one)
  int slot = -1;
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (!sessions[i].valid) {
      slot = i;
      break;
    }
  }
  if (slot == -1) {
    for (int i = 0; i < MAX_AUTH_IPS; i++) {
      if (pit_ticks - sessions[i].last_seen > AUTH_TIMEOUT_TICKS) {
        slot = i;
        break;
      }
    }
  }

  if (slot == -1) {
    log_writestring("[AUTH] Error: User session table full!\n");
    return;
  }

  sessions[slot].ip = ip;
  sessions[slot].last_seen = pit_ticks;
  sessions[slot].valid = 1;
  log_writestring("[AUTH] Authorized IP: ");
  log_ip(ip);
  log_putchar('\n');
}

int auth_is_authenticated(uint32_t ip) {
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (sessions[i].valid && sessions[i].ip == ip) {
      if (pit_ticks - sessions[i].last_seen > AUTH_TIMEOUT_TICKS) {
        sessions[i].valid = 0; // Expired
        log_writestring("[AUTH] Session expired for IP: ");
        log_ip(ip);
        log_putchar('\n');
        return 0;
      }
      sessions[i].last_seen = pit_ticks; // Refresh idle timer
      return 1;
    }
  }
  return 0;
}

void auth_logout(uint32_t ip) {
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (sessions[i].valid && sessions[i].ip == ip) {
      sessions[i].valid = 0;
      return;
    }
  }
}

void auth_stat(void) {
  log_writestring("[AUTH] Active Sessions:\n");
  int count = 0;
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (sessions[i].valid) {
      log_writestring("  IP: ");
      log_ip(sessions[i].ip);
      log_writestring("  idle ");
      log_write_u32(pit_ticks - sessions[i].last_seen);
      log_writestring("/");
      log_write_u32(AUTH_TIMEOUT_TICKS);
      log_writestring(" ticks\n");
      count++;
    }
  }
  if (count == 0)
    log_writestring("  (None)\n");
}
