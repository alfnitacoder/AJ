// Network configuration file format:
// Each line contains a configuration directive
// Lines starting with # are comments
//
// Example network.cfg:
// # AJOS Network Configuration
// ip 10.0.2.100
// dns 8.8.8.8
// gateway 10.0.2.2
//
// If this file doesn't exist or ip is not set, DHCP will be used

#include "net.h"
#include <stddef.h>
#include <stdint.h>

extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void arp_set_ajos_ip(uint32_t ip);
extern void dns_set_server(uint32_t ip);
extern void ip4_set_netmask(uint32_t mask);
extern void ip4_set_gateway(uint32_t gw);
extern void dhcpd_reinit(void);
extern void httpd_update_listener_ip(uint32_t ip);
extern void httpd_auto_start(void);

static int netcfg_parse_ip(const char *str, uint32_t *ip_out) {
  uint32_t ip = 0;
  uint32_t part;
  const char *s = str;

  for (int i = 0; i < 4; i++) {
    part = 0;
    if (*s < '0' || *s > '9')
      return 0;
    while (*s >= '0' && *s <= '9') {
      part = part * 10 + (*s - '0');
      s++;
    }
    if (part > 255)
      return 0;
    ip = (ip << 8) | part;
    if (i < 3) {
      if (*s != '.')
        return 0;
      s++;
    }
  }

  *ip_out = ip;
  return 1;
}

static int netcfg_strncmp(const char *a, const char *b, int n) {
  for (int i = 0; i < n; i++) {
    if (a[i] != b[i])
      return 1;
    if (a[i] == '\0')
      return 0;
  }
  return 0;
}

static const char *skip_whitespace(const char *s) {
  while (*s == ' ' || *s == '\t')
    s++;
  return s;
}

// Load network configuration from a buffer
// Returns 1 if DHCP should be used, 0 if static configuration
int netcfg_load_from_buffer(const char *buf, int len) {
  int has_static_ip = 0;
  const char *line_start = buf;
  const char *ptr = buf;
  const char *end = buf + len;

  while (ptr < end) {
    // Find end of line
    while (ptr < end && *ptr != '\n' && *ptr != '\r')
      ptr++;

    int line_len = ptr - line_start;

    // Skip empty lines and comments
    if (line_len > 0 && *line_start != '#') {
      // Parse "dhcp on/off"
      if (line_len > 5 && netcfg_strncmp(line_start, "dhcp ", 5) == 0) {
        const char *value = skip_whitespace(line_start + 5);
        if (netcfg_strncmp(value, "off", 3) == 0) {
          log_writestring("[NetCfg] DHCP: Disabled\n");
          // Continue parsing for static config
        } else {
          log_writestring("[NetCfg] DHCP: Enabled\n");
          return 2; // Use DHCP, ignore other settings
        }
      }
      // Parse "ip <address>"
      else if (line_len > 3 && netcfg_strncmp(line_start, "ip ", 3) == 0) {
        uint32_t ip;
        if (netcfg_parse_ip(line_start + 3, &ip)) {
          arp_set_ajos_ip(ip);
          has_static_ip = 1;
          log_writestring("[NetCfg] IP: ");
          log_write_u32((ip >> 24) & 0xFF);
          log_putchar('.');
          log_write_u32((ip >> 16) & 0xFF);
          log_putchar('.');
          log_write_u32((ip >> 8) & 0xFF);
          log_putchar('.');
          log_write_u32(ip & 0xFF);
          log_putchar('\n');
          // Reinitialize DHCP server with new IP
          dhcpd_reinit();
          // Update HTTP listener IP if service is running, or auto-start it
          httpd_update_listener_ip(ip);
          // Auto-start HTTP service if not already running
          extern void httpd_auto_start(void);
          httpd_auto_start();
          // Update SSH listener IP as well
          extern void sshd_update_listener_ip(uint32_t ip);
          sshd_update_listener_ip(ip);
        }
      }
      // Parse "netmask <address>"
      else if (line_len > 8 && netcfg_strncmp(line_start, "netmask ", 8) == 0) {
        uint32_t netmask;
        if (netcfg_parse_ip(line_start + 8, &netmask)) {
          ip4_set_netmask(netmask);
          log_writestring("[NetCfg] Netmask: ");
          log_write_u32((netmask >> 24) & 0xFF);
          log_putchar('.');
          log_write_u32((netmask >> 16) & 0xFF);
          log_putchar('.');
          log_write_u32((netmask >> 8) & 0xFF);
          log_putchar('.');
          log_write_u32(netmask & 0xFF);
          log_putchar('\n');
        }
      }
      // Parse "gateway <address>"
      else if (line_len > 8 && netcfg_strncmp(line_start, "gateway ", 8) == 0) {
        uint32_t gateway;
        if (netcfg_parse_ip(line_start + 8, &gateway)) {
          ip4_set_gateway(gateway);
          log_writestring("[NetCfg] Gateway: ");
          log_write_u32((gateway >> 24) & 0xFF);
          log_putchar('.');
          log_write_u32((gateway >> 16) & 0xFF);
          log_putchar('.');
          log_write_u32((gateway >> 8) & 0xFF);
          log_putchar('.');
          log_write_u32(gateway & 0xFF);
          log_putchar('\n');
        }
      }
      // Parse "dns <address>"
      else if (line_len > 4 && netcfg_strncmp(line_start, "dns ", 4) == 0) {
        uint32_t dns;
        if (netcfg_parse_ip(line_start + 4, &dns)) {
          dns_set_server(dns);
          log_writestring("[NetCfg] DNS Server: ");
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
    }

    // Skip to next line
    while (ptr < end && (*ptr == '\n' || *ptr == '\r'))
      ptr++;
    line_start = ptr;
  }

  return has_static_ip ? 1 : 0;
}
