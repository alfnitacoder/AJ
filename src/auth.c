#include "auth.h"
#include "user.h"
#include <stddef.h>

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);

// Session State
#define MAX_AUTH_IPS 50
struct auth_entry {
  uint32_t ip;
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

void auth_set_authenticated(uint32_t ip) {
  // Check if already authenticated
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (sessions[i].valid && sessions[i].ip == ip) {
      return; // Already allowed
    }
  }

  // Find free slot
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (!sessions[i].valid) {
      sessions[i].ip = ip;
      sessions[i].valid = 1;
      log_writestring("[AUTH] Authorized IP: ");
      // Print IP (Big Endian usually in network stack, let's assume standard
      // behavior) ip is passed as uint32_t.
      log_write_u32((ip >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32((ip >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32(ip & 0xFF);
      log_putchar('\n');
      return;
    }
  }
  log_writestring("[AUTH] Error: User session table full!\n");
}

int auth_is_authenticated(uint32_t ip) {
  for (int i = 0; i < MAX_AUTH_IPS; i++) {
    if (sessions[i].valid && sessions[i].ip == ip) {
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
      log_write_u32(((sessions[i].ip) >> 24) & 0xFF);
      log_putchar('.');
      log_write_u32(((sessions[i].ip) >> 16) & 0xFF);
      log_putchar('.');
      log_write_u32(((sessions[i].ip) >> 8) & 0xFF);
      log_putchar('.');
      log_write_u32((sessions[i].ip) & 0xFF);
      log_putchar('\n');
      count++;
    }
  }
  if (count == 0)
    log_writestring("  (None)\n");
}
