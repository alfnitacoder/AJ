#include "http.h"
#include "auth.h"
#include "net.h"
#include <stddef.h>

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern struct tcp_pcb *tcp_get_free_pcb(void);
extern int tcp_send_data(struct tcp_pcb *pcb, const uint8_t *data,
                         uint16_t len);

static int _strlen(const char *s) {
  int len = 0;
  while (s[len])
    len++;
  return len;
}

// Static HTML content for captive portal
static const char *html_login_page =
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "  <title>WiFi Login</title>\n"
    "  <style>\n"
    "    body { font-family: Arial; text-align: center; padding: 50px; }\n"
    "    h1 { color: #333; }\n"
    "    form { margin: 20px auto; max-width: 300px; }\n"
    "    input { width: 100%; padding: 10px; margin: 5px 0; }\n"
    "    button { width: 100%; padding: 10px; background: #007bff; color: "
    "white; border: none; cursor: pointer; }\n"
    "  </style>\n"
    "</head>\n"
    "<body>\n"
    "  <h1>Welcome to WiFi</h1>\n"
    "  <p>Please log in to access the internet</p>\n"
    "  <form method=\"POST\" action=\"/auth\">\n"
    "    <input type=\"text\" name=\"username\" placeholder=\"Username\" "
    "required>\n"
    "    <input type=\"password\" name=\"password\" placeholder=\"Password\" "
    "required>\n"
    "    <button type=\"submit\">Connect</button>\n"
    "  </form>\n"
    "</body>\n"
    "</html>";

static const char *html_success_page =
    "HTTP/1.0 200 OK\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head>\n"
    "  <title>Connected</title>\n"
    "  <style>\n"
    "    body { font-family: Arial; text-align: center; padding: 50px; }\n"
    "    h1 { color: #28a745; }\n"
    "  </style>\n"
    "</head>\n"
    "<body>\n"
    "  <h1>You are now connected!</h1>\n"
    "  <p>Enjoy your internet access.</p>\n"
    "</body>\n"
    "</html>";

static const char *html_not_found =
    "HTTP/1.0 404 Not Found\r\n"
    "Content-Type: text/html\r\n"
    "Connection: close\r\n"
    "\r\n"
    "<!DOCTYPE html>\n"
    "<html>\n"
    "<head><title>404 Not Found</title></head>\n"
    "<body>\n"
    "  <h1>404 - Page Not Found</h1>\n"
    "</body>\n"
    "</html>";

// Helper function to find string in buffer
static const char *http_strstr(const char *haystack, const char *needle,
                               int haystack_len) {
  int needle_len = 0;
  while (needle[needle_len])
    needle_len++;

  for (int i = 0; i <= haystack_len - needle_len; i++) {
    int match = 1;
    for (int j = 0; j < needle_len; j++) {
      if (haystack[i + j] != needle[j]) {
        match = 0;
        break;
      }
    }
    if (match)
      return &haystack[i];
  }
  return NULL;
}

// Helper to copy string until delimiter
static int http_copy_until(char *dest, const char *src, char delim,
                           int max_len) {
  int i = 0;
  while (i < max_len - 1 && src[i] && src[i] != delim) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
  return i;
}

// Initialize HTTP server
void http_init(void) {
  // Get a free PCB for listening
  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb) {
    log_writestring("[HTTP] ERROR: No free PCBs for listening\n");
    return;
  }

  // Set up listener on port 80
  // Use 0.0.0.0 (all interfaces) instead of calling arp_get_ajos_ip()
  // which might not be ready yet during early initialization
  extern uint32_t arp_get_ajos_ip(void);
  pcb->local_port = HTTP_PORT;
  pcb->local_ip = 0; // 0 = listen on all interfaces (safer during init)
  pcb->state = TCP_LISTEN;

  log_writestring("[HTTP] Server listening on port 80\n");
}

// Parse HTTP request
int http_parse_request(const char *data, int len, struct http_request *req) {
  if (len < 14)
    return 0; // Minimum: "GET / HTTP/1.0"

  // Clear request structure
  req->method = 0;
  req->uri[0] = '\0';
  req->host[0] = '\0';
  req->method = 0;
  req->uri[0] = '\0';
  req->host[0] = '\0';
  req->content_length = 0;
  req->body[0] = '\0';

  // Find Content-Length
  const char *cl = http_strstr(data, "Content-Length: ", len);
  if (cl) {
    int clen = 0;
    const char *p = cl + 16;
    while (*p >= '0' && *p <= '9') {
      clen = clen * 10 + (*p - '0');
      p++;
    }
    req->content_length = clen;
  }

  // Find Body (after double CRLF)
  const char *body_start = http_strstr(data, "\r\n\r\n", len);
  if (body_start) {
    body_start += 4;
    int max_body = 255;
    int i = 0;
    // Copy body
    while (i < max_body && body_start[i] && (body_start + i < data + len)) {
      req->body[i] = body_start[i];
      i++;
    }
    req->body[i] = 0;
  }

  // Parse method
  if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
    req->method = HTTP_METHOD_GET;
    data += 4; // Skip "GET "
  } else if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' &&
             data[3] == 'T') {
    req->method = HTTP_METHOD_POST;
    data += 5; // Skip "POST "
  } else {
    return 0; // Unknown method
  }

  // Parse URI
  int uri_len = http_copy_until(req->uri, data, ' ', HTTP_MAX_URI_LEN);
  if (uri_len == 0)
    return 0;

  // Parse Host header (optional but useful)
  const char *host_header = http_strstr(data, "Host: ", len);
  if (host_header) {
    host_header += 6; // Skip "Host: "
    http_copy_until(req->host, host_header, '\r', HTTP_MAX_HOST_LEN);
  }

  // For POST, parse Content-Length and body
  if (req->method == HTTP_METHOD_POST) {
    const char *cl_header = http_strstr(data, "Content-Length: ", len);
    if (cl_header) {
      cl_header += 16; // Skip "Content-Length: "
      req->content_length = 0;
      while (cl_header < data + len && *cl_header >= '0' && *cl_header <= '9') {
        req->content_length = req->content_length * 10 + (*cl_header - '0');
        cl_header++;
      }
    }

    // Find body (after \r\n\r\n)
    const char *body_start = http_strstr(data, "\r\n\r\n", len);
    if (body_start) {
      body_start += 4;
      int body_len = len - (body_start - data);
      // Use Content-Length if available, otherwise use available data
      if (req->content_length > 0 && body_len > req->content_length) {
        body_len = req->content_length;
      }
      if (body_len > 0 && body_len < HTTP_MAX_BODY_LEN) {
        for (int i = 0; i < body_len; i++) {
          req->body[i] = body_start[i];
        }
        req->body[body_len] = '\0';
      } else if (body_len == 0 && req->content_length == 0) {
        // Empty body is OK
        req->body[0] = '\0';
      }
    }
  }

  return 1; // Success
}

// Send HTTP response
void http_send_response(struct tcp_pcb *pcb, struct http_response *resp) {
  // For now, we'll use pre-built responses
  // In the future, we can build dynamic responses here
  (void)pcb;
  (void)resp;
}

// Serve login page
void http_serve_login_page(struct tcp_pcb *pcb) {
  int len = 0;
  const char *p = html_login_page;
  while (p[len])
    len++;

  tcp_send_data(pcb, (const uint8_t *)html_login_page, len);
  log_writestring("[HTTP] Served login page\n");
}

// Serve success page
void http_serve_success_page(struct tcp_pcb *pcb) {
  int len = 0;
  const char *p = html_success_page;
  while (p[len])
    len++;

  tcp_send_data(pcb, (const uint8_t *)html_success_page, len);
  log_writestring("[HTTP] Served success page\n");
}

// Serve 404 page
void http_serve_not_found(struct tcp_pcb *pcb) {
  int len = 0;
  const char *p = html_not_found;
  while (p[len])
    len++;

  tcp_send_data(pcb, (const uint8_t *)html_not_found, len);
  log_writestring("[HTTP] Served 404 page\n");
}

// Handle authentication POST
void http_handle_auth(struct tcp_pcb *pcb, struct http_request *req) {
  // For now, accept any credentials
  // TODO: Implement actual authentication
  log_writestring("[HTTP] Auth request: ");
  log_writestring(req->body);
  log_putchar('\n');

  // Redirect to success page
  http_serve_success_page(pcb);
}

// Handle incoming HTTP connection
void http_handle_connection(struct tcp_pcb *pcb, const uint8_t *data, int len) {
  struct http_request req;

  log_writestring("[HTTP] Request received (");
  log_write_u32(len);
  log_writestring(" bytes)\n");

  if (!http_parse_request((const char *)data, len, &req)) {
    log_writestring("[HTTP] Failed to parse request\n");
    http_serve_not_found(pcb);
    return;
  }

  log_writestring("[HTTP] ");
  log_writestring(req.method == HTTP_METHOD_GET ? "GET" : "POST");
  log_writestring(" ");
  log_writestring(req.uri);
  log_putchar('\n');

  // Route request
  if (req.method == HTTP_METHOD_POST && req.uri[0] == '/' &&
      req.uri[1] == 'a' && req.uri[2] == 'u' && req.uri[3] == 't' &&
      req.uri[4] == 'h') {

    // Parse body: "username=user&password=pass"
    char user[32] = {0};
    char pass[32] = {0};

    const char *u_ptr = http_strstr(req.body, "username=", 256);
    const char *p_ptr = http_strstr(req.body, "password=", 256);

    if (u_ptr)
      http_copy_until(user, u_ptr + 9, '&', 32);
    if (p_ptr)
      http_copy_until(pass, p_ptr + 9, '&', 32); // Assuming & or end

    if (auth_check_credentials(user, pass)) {
      auth_set_authenticated(pcb->remote_ip);

      const char *redir = "HTTP/1.0 302 Found\r\nLocation: /success\r\n\r\n";
      tcp_send_data(pcb, (const uint8_t *)redir, _strlen(redir));
      return;
    } else {
      const char *redir = "HTTP/1.0 302 Found\r\nLocation: /?error=1\r\n\r\n";
      tcp_send_data(pcb, (const uint8_t *)redir, _strlen(redir));
      return;
    }
  } else if (req.uri[0] == '/' &&
             (req.uri[1] == '\0' ||
              (req.uri[1] == 'l' && req.uri[2] == 'o' && req.uri[3] == 'g' &&
               req.uri[4] == 'i' && req.uri[5] == 'n'))) {
    http_serve_login_page(pcb);
  } else if (req.uri[0] == '/' && req.uri[1] == 's' && req.uri[2] == 'u' &&
             req.uri[3] == 'c') {
    http_serve_success_page(pcb);
  } else {
    // For captive portal, redirect everything to login
    http_serve_login_page(pcb);
  }
}
