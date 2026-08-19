#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>

// Session Management
void auth_init(void);
int auth_check_credentials(const char *user, const char *pass);
void auth_set_authenticated(uint32_t ip);
int auth_is_authenticated(uint32_t ip);
void auth_logout(uint32_t ip);
void auth_stat(void);

#endif // AUTH_H
