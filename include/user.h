#ifndef USER_H
#define USER_H

#include <stdint.h>

// User account structure (like /etc/passwd entry)
struct user_entry {
  char username[32];
  /* "sha512$<16 hex salt>$<128 hex digest>" (152 chars + NUL); legacy
   * PASSWD files store 8 djb2 hex chars and still verify. */
  char password_hash[160];
  uint32_t uid;             // User ID
  uint32_t gid;             // Group ID (simplified: all users in group 0)
  char home[64];            // Home directory (for future use)
  char shell[64];           // Shell (for future use)
  uint8_t active;           // Whether account is active
};

#define MAX_USERS 50
#define DEFAULT_UID_START 1000

// Password file location (like /etc/passwd)
#define PASSWD_FILE "PASSWD"

// Function Declarations
void user_init(void);
int user_add(const char *username, const char *password);
int user_del(const char *username);
int user_change_password(const char *username, const char *old_pass, const char *new_pass);
int user_check_password(const char *username, const char *password);
struct user_entry *user_find(const char *username);
void user_list(void);
int user_load_from_file(void);
int user_save_to_file(void);

#endif // USER_H
