#include "user.h"
#include <stddef.h>
#include <stdint.h>

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern int fat12_read_file_to_ram(const char *path, uint8_t **out_buf, uint32_t *out_size);
extern int fat12_write_file(const char *fn, const uint8_t *data, uint32_t size);
extern void kfree(void *ptr);
extern void *kmalloc(uint32_t size);
// Memory functions - use inline implementations
static void _kmemcpy(void *dst, const void *src, size_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  for (size_t i = 0; i < n; i++) {
    d[i] = s[i];
  }
}

static void _kmemset(void *ptr, int value, size_t num) {
  uint8_t *p = (uint8_t *)ptr;
  for (size_t i = 0; i < num; i++) {
    p[i] = (uint8_t)value;
  }
}

// User database
static struct user_entry users[MAX_USERS];
static uint32_t next_uid = DEFAULT_UID_START;
static int users_loaded = 0;
/* Boot stability mode: avoid FAT writes from auth path until disk write
 * backend is stabilized. */
static int user_db_persist_enabled = 0;

// Simple string comparison
static int _strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(unsigned char *)s1 - *(unsigned char *)s2;
}

// Simple string length
static int _strlen(const char *s) {
  int len = 0;
  while (s[len]) len++;
  return len;
}

// Simple string copy
static void _strncpy(char *dest, const char *src, int n) {
  int i = 0;
  while (i < n - 1 && src[i]) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

/* Strip leading/trailing whitespace and CR/LF (serial terminals paste junk). */
static void trim_inplace(char *s) {
  int start = 0;
  int len;
  if (!s || !s[0])
    return;
  while (s[start] &&
         ((unsigned char)s[start] <= ' ' || s[start] == '\r' || s[start] == '\n'))
    start++;
  if (start > 0) {
    int i = 0;
    while (s[start + i]) {
      s[i] = s[start + i];
      i++;
    }
    s[i] = '\0';
  }
  len = _strlen(s);
  while (len > 0 && ((unsigned char)s[len - 1] <= ' ' || s[len - 1] == '\r' ||
                     s[len - 1] == '\n')) {
    len--;
    s[len] = '\0';
  }
}

// Simple password hashing (djb2 algorithm - can be upgraded to bcrypt/sha256 later)
static void hash_password(const char *password, char *hash_out) {
  uint32_t hash = 5381;
  int i = 0;
  /* Caller may pass a 64-byte field; always leave a clean NUL-terminated digest. */
  for (int j = 0; j < 16; j++)
    hash_out[j] = '\0';
  while (password[i]) {
    hash = ((hash << 5) + hash) + (unsigned char)password[i];
    i++;
  }

  /* 32-bit hash as 8 hex digits (matches PASSWD / mkfat12 default) */
  const char *hex = "0123456789ABCDEF";
  for (int j = 0; j < 8; j++)
    hash_out[j] = hex[(hash >> (28 - j * 4)) & 0xF];
  hash_out[8] = '\0';
}

/* In-memory default when no valid PASSWD entries (matches tools/mkfat12.py). */
static void seed_default_user(void) {
  _kmemset(users, 0, sizeof(users));
  next_uid = DEFAULT_UID_START;
  users_loaded = 1;
  _kmemset(&users[0], 0, sizeof(struct user_entry));
  _strncpy(users[0].username, "user", 32);
  hash_password("pass", users[0].password_hash);
  users[0].uid = 1000;
  users[0].gid = 0;
  _strncpy(users[0].home, "/", 64);
  _strncpy(users[0].shell, "/bin/sh", 64);
  users[0].active = 1;
  next_uid = 1001;
  if (user_db_persist_enabled) {
    user_save_to_file();
  }
}

/* Copy hash so PASSWD / FAT quirks (spaces, case) cannot break strcmp. */
static int verify_password(const char *password, const char *hash) {
  char computed_hash[64];
  char norm[64];
  _kmemset(norm, 0, sizeof(norm));
  if (hash) {
    _strncpy(norm, hash, (int)sizeof(norm));
    trim_inplace(norm);
  }
  hash_password(password, computed_hash);
  return _strcmp(computed_hash, norm) == 0;
}

// Find user by username
struct user_entry *user_find(const char *username) {
  if (!users_loaded) {
    user_load_from_file();
  }
  
  for (int i = 0; i < MAX_USERS; i++) {
    if (users[i].active && _strcmp(users[i].username, username) == 0) {
      return &users[i];
    }
  }
  return NULL;
}

// Add new user
int user_add(const char *username, const char *password) {
  if (!users_loaded) {
    user_load_from_file();
  }
  
  // Check if user already exists
  if (user_find(username)) {
    log_writestring("[USER] User already exists: ");
    log_writestring(username);
    log_putchar('\n');
    return 0;
  }
  
  // Find free slot
  int slot = -1;
  for (int i = 0; i < MAX_USERS; i++) {
    if (!users[i].active) {
      slot = i;
      break;
    }
  }
  
  if (slot == -1) {
    log_writestring("[USER] User database full\n");
    return 0;
  }
  
  // Validate username
  int username_len = _strlen(username);
  if (username_len == 0 || username_len >= 32) {
    log_writestring("[USER] Invalid username\n");
    return 0;
  }
  
  // Create user entry
  _kmemset(&users[slot], 0, sizeof(struct user_entry));
  _strncpy(users[slot].username, username, 32);
  hash_password(password, users[slot].password_hash);
  users[slot].uid = next_uid++;
  users[slot].gid = 0; // All users in group 0 for now
  _strncpy(users[slot].home, "/", 64);
  _strncpy(users[slot].shell, "/bin/sh", 64);
  users[slot].active = 1;
  
  // Save to file
  user_save_to_file();
  
  log_writestring("[USER] User added: ");
  log_writestring(username);
  log_writestring(" (UID: ");
  log_write_u32(users[slot].uid);
  log_writestring(")\n");
  
  return 1;
}

// Delete user
int user_del(const char *username) {
  if (!users_loaded) {
    user_load_from_file();
  }
  
  struct user_entry *user = user_find(username);
  if (!user) {
    log_writestring("[USER] User not found: ");
    log_writestring(username);
    log_putchar('\n');
    return 0;
  }
  
  user->active = 0;
  user_save_to_file();
  
  log_writestring("[USER] User deleted: ");
  log_writestring(username);
  log_putchar('\n');
  
  return 1;
}

// Change password
int user_change_password(const char *username, const char *old_pass, const char *new_pass) {
  if (!users_loaded) {
    user_load_from_file();
  }
  
  struct user_entry *user = user_find(username);
  if (!user) {
    log_writestring("[USER] User not found\n");
    return 0;
  }
  
  // Verify old password
  if (!verify_password(old_pass, user->password_hash)) {
    log_writestring("[USER] Incorrect password\n");
    return 0;
  }
  
  // Set new password
  hash_password(new_pass, user->password_hash);
  user_save_to_file();
  
  log_writestring("[USER] Password changed for: ");
  log_writestring(username);
  log_putchar('\n');
  
  return 1;
}

// Check password (used by auth system)
int user_check_password(const char *username, const char *password) {
  char ubuf[64];
  char pbuf[64];
  _kmemset(ubuf, 0, sizeof(ubuf));
  _kmemset(pbuf, 0, sizeof(pbuf));
  if (username)
    _strncpy(ubuf, username, (int)sizeof(ubuf));
  if (password)
    _strncpy(pbuf, password, (int)sizeof(pbuf));
  trim_inplace(ubuf);
  trim_inplace(pbuf);

#ifdef AJOS_SERIAL_ONLY
  /* `make run-console` / mkfat12.py stock account. Dev console only (see
   * Makefile). Use explicit bytes so stray NUL-adjacent RAM cannot break
   * strcmp on tiny rodata literals. */
  if (ubuf[0] == 'u' && ubuf[1] == 's' && ubuf[2] == 'e' && ubuf[3] == 'r' &&
      ubuf[4] == '\0' && pbuf[0] == 'p' && pbuf[1] == 'a' && pbuf[2] == 's' &&
      pbuf[3] == 's' && pbuf[4] == '\0')
    return 1;
#endif

  if (!users_loaded) {
    user_load_from_file();
  }

  struct user_entry *user = user_find(ubuf);
  if (!user) {
    log_writestring("[LOGIN] unknown user\n");
    return 0;
  }

  if (!verify_password(pbuf, user->password_hash)) {
    log_writestring("[LOGIN] bad password\n");
    return 0;
  }
  return 1;
}

// List all users
void user_list(void) {
  if (!users_loaded) {
    user_load_from_file();
  }
  
  log_writestring("USERNAME    UID    GID    HOME    SHELL\n");
  int count = 0;
  for (int i = 0; i < MAX_USERS; i++) {
    if (users[i].active) {
      log_writestring(users[i].username);
      // Pad username to 12 chars
      int pad = 12 - _strlen(users[i].username);
      for (int j = 0; j < pad; j++) {
        log_putchar(' ');
      }
      log_write_u32(users[i].uid);
      log_putchar(' ');
      log_write_u32(users[i].gid);
      log_putchar(' ');
      log_writestring(users[i].home);
      log_putchar(' ');
      log_writestring(users[i].shell);
      log_putchar('\n');
      count++;
    }
  }
  if (count == 0) {
    log_writestring("(No users)\n");
  }
}

// Load users from PASSWD file
// Format: username:password_hash:uid:gid:home:shell (one per line)
int user_load_from_file(void) {
  uint8_t *buf = NULL;
  uint32_t size = 0;
  /* Prefer root PASSWD (floppy images from mkfat12); then etc/passwd. */
  if (!fat12_read_file_to_ram(PASSWD_FILE, &buf, &size) &&
      !fat12_read_file_to_ram("etc/passwd", &buf, &size)) {
    seed_default_user();
    return 1;
  }
  // Parse file
  _kmemset(users, 0, sizeof(users));
  next_uid = DEFAULT_UID_START;
  
  const char *line_start = (const char *)buf;
  const char *ptr = line_start;
  const char *end = (const char *)buf + size;
  int user_idx = 0;
  
  while (ptr < end && user_idx < MAX_USERS) {
    // Find end of line
    const char *line_end = ptr;
    while (line_end < end && *line_end != '\n' && *line_end != '\r') {
      line_end++;
    }
    
    int line_len = line_end - ptr;
    if (line_len > 0 && *ptr != '#') { // Skip comments and empty lines
      // Parse line: username:hash:uid:gid:home:shell
      char line[256] = {0};
      int copy = line_len;
      if (copy > 255) copy = 255;
      for (int i = 0; i < copy; i++) {
        line[i] = ptr[i];
      }
      
      // Split by colons
      char *fields[6];
      int field_idx = 0;
      fields[0] = line;
      for (int i = 0; i < copy && field_idx < 5; i++) {
        if (line[i] == ':') {
          line[i] = '\0';
          fields[++field_idx] = &line[i + 1];
        }
      }
      
      if (field_idx >= 5) {
        // Parse fields
        _strncpy(users[user_idx].username, fields[0], 32);
        _kmemset(users[user_idx].password_hash, 0,
                 sizeof(users[user_idx].password_hash));
        _strncpy(users[user_idx].password_hash, fields[1], 64);
        
        // Parse UID
        uint32_t uid = 0;
        const char *uid_str = fields[2];
        while (*uid_str >= '0' && *uid_str <= '9') {
          uid = uid * 10 + (*uid_str - '0');
          uid_str++;
        }
        users[user_idx].uid = uid;
        if (uid >= next_uid) next_uid = uid + 1;
        
        // Parse GID
        uint32_t gid = 0;
        const char *gid_str = fields[3];
        while (*gid_str >= '0' && *gid_str <= '9') {
          gid = gid * 10 + (*gid_str - '0');
          gid_str++;
        }
        users[user_idx].gid = gid;
        
        _strncpy(users[user_idx].home, fields[4], 64);
        _strncpy(users[user_idx].shell, fields[5], 64);
        users[user_idx].active = 1;
        user_idx++;
      }
    }
    
    /* Advance to next line (was missing: ptr never moved past content). */
    ptr = line_end;
    while (ptr < end && (*ptr == '\n' || *ptr == '\r')) {
      ptr++;
    }
  }
  
  kfree(buf);
  users_loaded = 1;
  if (user_idx == 0) {
    log_writestring("[USER] PASSWD parse yielded no users; using defaults\n");
    seed_default_user();
    return 1;
  }
  log_writestring("[USER] Loaded ");
  log_write_u32(user_idx);
  log_writestring(" users from PASSWD\n");
  return 1;
}

// Save users to PASSWD file
int user_save_to_file(void) {
  if (!user_db_persist_enabled) {
    log_writestring("[USER] PASSWD persistence deferred\n");
    return 1;
  }
  char *file_buf = (char *)kmalloc(8192);
  if (!file_buf) return 0;
  _kmemset(file_buf, 0, 8192);
  int pos = 0;
  
  for (int i = 0; i < MAX_USERS && pos < 8000; i++) {
    if (users[i].active) {
      // Format: username:hash:uid:gid:home:shell\n
      int username_len = _strlen(users[i].username);
      int hash_len = _strlen(users[i].password_hash);
      int home_len = _strlen(users[i].home);
      int shell_len = _strlen(users[i].shell);
      
      if (pos + username_len + hash_len + home_len + shell_len + 50 > 8000) {
        break; // File too large
      }
      
      // Copy username
      for (int j = 0; j < username_len; j++) {
        file_buf[pos++] = users[i].username[j];
      }
      file_buf[pos++] = ':';
      
      // Copy hash
      for (int j = 0; j < hash_len; j++) {
        file_buf[pos++] = users[i].password_hash[j];
      }
      file_buf[pos++] = ':';
      
      // Write UID
      uint32_t uid = users[i].uid;
      char uid_str[16];
      int uid_len = 0;
      if (uid == 0) {
        uid_str[uid_len++] = '0';
      } else {
        uint32_t temp = uid;
        char uid_rev[16];
        int rev_len = 0;
        while (temp > 0) {
          uid_rev[rev_len++] = '0' + (temp % 10);
          temp /= 10;
        }
        for (int j = rev_len - 1; j >= 0; j--) {
          uid_str[uid_len++] = uid_rev[j];
        }
      }
      for (int j = 0; j < uid_len; j++) {
        file_buf[pos++] = uid_str[j];
      }
      file_buf[pos++] = ':';
      
      // Write GID
      uint32_t gid = users[i].gid;
      char gid_str[16];
      int gid_len = 0;
      if (gid == 0) {
        gid_str[gid_len++] = '0';
      } else {
        uint32_t temp = gid;
        char gid_rev[16];
        int rev_len = 0;
        while (temp > 0) {
          gid_rev[rev_len++] = '0' + (temp % 10);
          temp /= 10;
        }
        for (int j = rev_len - 1; j >= 0; j--) {
          gid_str[gid_len++] = gid_rev[j];
        }
      }
      for (int j = 0; j < gid_len; j++) {
        file_buf[pos++] = gid_str[j];
      }
      file_buf[pos++] = ':';
      
      // Copy home
      for (int j = 0; j < home_len; j++) {
        file_buf[pos++] = users[i].home[j];
      }
      file_buf[pos++] = ':';
      
      // Copy shell
      for (int j = 0; j < shell_len; j++) {
        file_buf[pos++] = users[i].shell[j];
      }
      file_buf[pos++] = '\n';
    }
  }
  
  /* Try root PASSWD first - etc/ may not exist on first boot */
  int ok = 0;
  if (fat12_write_file(PASSWD_FILE, (const uint8_t *)file_buf, pos) ||
      fat12_write_file("etc/passwd", (const uint8_t *)file_buf, pos)) {
    ok = 1;
  } else {
    log_writestring("[USER] Failed to save PASSWD file\n");
  }
  kfree(file_buf);
  return ok;
}

// Initialize user system
void user_init(void) {
  _kmemset(users, 0, sizeof(users));
  next_uid = DEFAULT_UID_START;
  users_loaded = 0;
  user_load_from_file();
  // Suppress verbose initialization message
}
