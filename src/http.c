#include "http.h"
#include "auth.h"
#include "fat.h"
#include "net.h"
#include <stddef.h>

// External functions
extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern struct tcp_pcb *tcp_get_free_pcb(void);
extern int tcp_send_data(struct tcp_pcb *pcb, const uint8_t *data,
                         uint16_t len);
extern int tcp_send(struct tcp_pcb *pcb, const uint8_t *data,
                  uint16_t len);
extern void kfree(void *ptr);

static int _strlen(const char *s) {
  int len = 0;
  while (s[len])
    len++;
  return len;
}

// Static HTML content for captive portal (bodies only; headers are added
// by http_send_page so Content-Length is always correct)
static const char *html_login_page =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
    "<title>AJOS - Sign in</title>\n"
    "<style>\n"
    "*{box-sizing:border-box;margin:0;padding:0}\n"
    "body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a,#1e293b 55%,#155e75);font-family:-apple-system,\"Segoe UI\",Roboto,Arial,sans-serif;color:#e2e8f0;padding:24px}\n"
    ".card{width:100%;max-width:340px;background:rgba(15,23,42,.85);border:1px solid rgba(148,163,184,.25);border-radius:16px;padding:30px 26px;text-align:center;box-shadow:0 24px 60px rgba(2,6,23,.55)}\n"
    ".logo{width:54px;height:54px;margin:0 auto 14px;border-radius:14px;background:linear-gradient(135deg,#22d3ee,#0e7490);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:19px;color:#062a33}\n"
    "h1{font-size:20px;color:#f1f5f9;margin-bottom:6px}\n"
    ".sub{font-size:13px;color:#94a3b8;margin-bottom:20px}\n"
    ".err{display:none;background:rgba(220,38,38,.14);border:1px solid rgba(248,113,113,.45);color:#fca5a5;padding:9px 11px;border-radius:9px;font-size:12.5px;margin-bottom:16px;text-align:left}\n"
    "form{display:flex;flex-direction:column;gap:12px}\n"
    "input{width:100%;padding:12px 13px;border-radius:10px;border:1px solid rgba(148,163,184,.3);background:rgba(2,6,23,.6);color:#f1f5f9;font-size:14px;outline:none}\n"
    "input:focus{border-color:#22d3ee}\n"
    "button{padding:12px;border:0;border-radius:10px;background:linear-gradient(135deg,#22d3ee,#0891b2);color:#052e36;font-weight:700;font-size:14px;cursor:pointer}\n"
    "button:hover{filter:brightness(1.08)}\n"
    ".ft{margin-top:18px;font-size:11px;color:#64748b}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class=\"card\">\n"
    "<div class=\"logo\">AJ</div>\n"
    "<h1>Welcome to AJOS</h1>\n"
    "<p class=\"sub\">Sign in to continue</p>\n"
    "<div class=\"err\" id=\"err\">Wrong username or password. Try again.</div>\n"
    "<form method=\"POST\" action=\"/auth\">\n"
    "<input name=\"username\" placeholder=\"Username\" autocomplete=\"username\" required>\n"
    "<input type=\"password\" name=\"password\" placeholder=\"Password\" autocomplete=\"current-password\" required>\n"
    "<button type=\"submit\">Sign in</button>\n"
    "</form>\n"
    "<p class=\"ft\">AJOS 1.0 - captive portal</p>\n"
    "</div>\n"
    "<script>if(location.search.indexOf(\"error=1\")>-1)document.getElementById(\"err\").style.display=\"block\";</script>\n"
    "</body>\n"
    "</html>\n"
"";

static const char *html_success_page =
    "<!DOCTYPE html>\n"
    "<html lang=\"en\">\n"
    "<head>\n"
    "<meta charset=\"utf-8\">\n"
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
    "<title>Connected - AJOS</title>\n"
    "<style>\n"
    "*{box-sizing:border-box;margin:0;padding:0}\n"
    "body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a,#1e293b 55%,#155e75);font-family:-apple-system,\"Segoe UI\",Roboto,Arial,sans-serif;color:#e2e8f0;padding:24px}\n"
    ".card{width:100%;max-width:340px;background:rgba(15,23,42,.85);border:1px solid rgba(148,163,184,.25);border-radius:16px;padding:34px 26px;text-align:center;box-shadow:0 24px 60px rgba(2,6,23,.55)}\n"
    ".ok{width:56px;height:56px;margin:0 auto 16px;border-radius:50%;background:rgba(34,197,94,.14);border:1px solid rgba(74,222,128,.5);display:flex;align-items:center;justify-content:center;font-size:26px;color:#4ade80}\n"
    "h1{font-size:20px;color:#f1f5f9;margin-bottom:8px}\n"
    ".sub{font-size:13px;color:#94a3b8}\n"
    ".ft{margin-top:20px;font-size:11px;color:#64748b}\n"
    "</style>\n"
    "</head>\n"
    "<body>\n"
    "<div class=\"card\">\n"
    "<div class=\"ok\">&#10003;</div>\n"
    "<h1>You are connected!</h1>\n"
    "<p class=\"sub\">Welcome online - enjoy your session.</p>\n"
    "<p class=\"ft\">AJOS 1.0 - captive portal</p>\n"
    "</div>\n"
    "</body>\n"
    "</html>\n"
"";

static const char *html_not_found =
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

/* Send a complete response with correct Content-Length and close the
 * connection. Without Content-Length + FIN, clients block waiting for the
 * body to end. */
static void http_send_page_buf(struct tcp_pcb *pcb, const char *status,
                               const char *body, int blen) {
  char hdr[160];
  int n = 0;
  const char *s = status;
  while (*s && n < (int)sizeof(hdr) - 1)
    hdr[n++] = *s++;
  const char *cl = "Content-Type: text/html\r\nCache-Control: no-store\r\nContent-Length: ";
  s = cl;
  while (*s && n < (int)sizeof(hdr) - 1)
    hdr[n++] = *s++;
  // append decimal length
  char digits[12];
  int d = 0;
  if (blen == 0)
    digits[d++] = '0';
  int t = blen;
  while (t > 0) {
    digits[d++] = (char)('0' + t % 10);
    t /= 10;
  }
  while (d > 0 && n < (int)sizeof(hdr) - 1)
    hdr[n++] = digits[--d];
  const char *tail = "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
  s = tail;
  while (*s && n < (int)sizeof(hdr) - 1)
    hdr[n++] = *s++;

  tcp_send_data(pcb, (const uint8_t *)hdr, (uint16_t)n);
  if (blen > 0)
    /* tcp_send segments to MSS; tcp_send_data silently drops bodies that
     * would exceed the e1000 frame limit (one un-segmented frame). */
    tcp_send(pcb, (const uint8_t *)body, (uint16_t)blen);
  tcp_close(pcb);
}

static void http_send_page(struct tcp_pcb *pcb, const char *status,
                           const char *body) {
  http_send_page_buf(pcb, status, body, _strlen(body));
}

/* Serve var/www/<name> if present, else the compiled-in fallback.
 * Reads prefer the IDE-disk copy (/mnt/var/www/...) -- floppy reads inside
 * the network dispatch can wedge the kernel in QEMU. */
extern int vfs_read_file_ram(const char *path, uint8_t **out_buf,
                             uint32_t *out_len);
static void http_serve_web_file(struct tcp_pcb *pcb, const char *status,
                                const char *www_name, const char *fallback) {
  uint8_t *buf = 0;
  uint32_t size = 0;
  {
    char mnt[96];
    const char *pre = "/mnt/var/www/";
    int mi = 0;
    while (pre[mi]) { mnt[mi] = pre[mi]; mi++; }
    int wi = 0;
    while (www_name[wi] && mi < 90) { mnt[mi++] = www_name[wi++]; }
    mnt[mi] = 0;
    if (vfs_read_file_ram(mnt, &buf, &size) && buf && size > 0) {
      http_send_page_buf(pcb, status, (const char *)buf, (int)size);
      kfree(buf);
      return;
    }
    if (buf)
      kfree(buf);
  }
  if (fat12_read_file_to_ram(www_name, &buf, &size)) {
    http_send_page_buf(pcb, status, (const char *)buf, (int)size);
    kfree(buf);
    return;
  }
  http_send_page(pcb, status, fallback);
}

/* Send a 302 redirect with an empty body and close. */
static void http_send_redirect(struct tcp_pcb *pcb, const char *location) {
  char hdr[192];
  int n = 0;
  const char *prefix = "HTTP/1.0 302 Found\r\nLocation: ";
  const char *s = prefix;
  while (*s && n < (int)sizeof(hdr) - 1)
    hdr[n++] = *s++;
  s = location;
  while (*s && n < (int)sizeof(hdr) - 1)
    hdr[n++] = *s++;
  const char *tail = "\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
  s = tail;
  while (*s && n < (int)sizeof(hdr) - 1)
    hdr[n++] = *s++;
  tcp_send_data(pcb, (const uint8_t *)hdr, (uint16_t)n);
  tcp_close(pcb);
}

// Serve login page (var/www/index.html, compiled-in fallback)
void http_serve_login_page(struct tcp_pcb *pcb) {
  http_serve_web_file(pcb, "HTTP/1.0 200 OK\r\n", "var/www/index.html",
                      html_login_page);
  log_writestring("[HTTP] Served login page\n");
}

// Serve success page (var/www/success.html, compiled-in fallback)
void http_serve_success_page(struct tcp_pcb *pcb) {
  http_serve_web_file(pcb, "HTTP/1.0 200 OK\r\n", "var/www/success.html",
                      html_success_page);
  log_writestring("[HTTP] Served success page\n");
}

// Serve 404 page (var/www/404.html, compiled-in fallback)
void http_serve_not_found(struct tcp_pcb *pcb) {
  http_serve_web_file(pcb, "HTTP/1.0 404 Not Found\r\n", "var/www/404.html",
                      html_not_found);
  log_writestring("[HTTP] Served 404 page\n");
}

// Handle authentication POST
void http_handle_auth(struct tcp_pcb *pcb, struct http_request *req) {
  // Parse body: "username=user&password=pass"
  char user[32] = {0};
  char pass[32] = {0};

  const char *u_ptr = http_strstr(req->body, "username=", 256);
  const char *p_ptr = http_strstr(req->body, "password=", 256);

  if (u_ptr)
    http_copy_until(user, u_ptr + 9, '&', 32);
  if (p_ptr)
    http_copy_until(pass, p_ptr + 9, '&', 32);

  if (auth_check_credentials(user, pass)) {
    auth_set_authenticated(pcb->remote_ip);
    http_send_redirect(pcb, "/success");
  } else {
    http_send_redirect(pcb, "/?error=1");
  }
}

static void http_handle_webapp(struct tcp_pcb *pcb, struct http_request *req);
static void http_handle_raw_app(struct tcp_pcb *pcb, struct http_request *req);

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
    http_handle_auth(pcb, &req);
  } else if (req.uri[0] == '/' &&
             (req.uri[1] == '\0' ||
              (req.uri[1] == 'l' && req.uri[2] == 'o' && req.uri[3] == 'g' &&
               req.uri[4] == 'i' && req.uri[5] == 'n'))) {
    http_serve_login_page(pcb);
  } else if (req.uri[0] == '/' && req.uri[1] == 's' && req.uri[2] == 'u' &&
             req.uri[3] == 'c') {
    http_serve_success_page(pcb);
  } else if (req.uri[0] == '/' && req.uri[1] == 'r' && req.uri[2] == 'a' &&
             req.uri[3] == 'w' && req.uri[4] == '/') {
    // App Store: serve the raw webapp script so other AJOS boxes can
    // `appinstall` it: GET /raw/<name> -> webapp/<name>.aj (text/plain)
    http_handle_raw_app(pcb, &req);
  } else if (req.uri[0] == '/' && req.uri[1] == 'a' && req.uri[2] == 'p' &&
             req.uri[3] == 'p' && req.uri[4] == '/') {
    // ajlangweb: /app/<script> -> webapp/<script>.aj via the interpreter
    http_handle_webapp(pcb, &req);
  } else {
    // For captive portal, redirect everything to login
    http_serve_login_page(pcb);
  }
}

/* ---- ajlangweb: serve /app/<script> through the AJLang interpreter ---- */
extern int ajlang_run_webapp(const char *script_path, const char *method,
                             const char *uri, const char *body, char *out,
                             int outcap, char *redirect, int redcap);
/* App Store: GET /raw/<name> -> serve webapp/<name>.aj as text/plain so a
 * remote AJOS box can install it with `appinstall <ip> <name>`. */
static void http_handle_raw_app(struct tcp_pcb *pcb, struct http_request *req)
{
  static uint8_t rawbuf[16384];
  const char *u = req->uri + 5; /* skip "/raw/" */
  char name[64];
  int i = 0;
  while (u[i] && u[i] != '?' && i < 60)
  {
    char c = u[i];
    if (c == '/' || c == '\\')
    {
      http_serve_not_found(pcb);
      return;
    }
    name[i] = c;
    i++;
  }
  name[i] = 0;
  if (i == 0)
  {
    http_serve_not_found(pcb);
    return;
  }

  /* First check the RAM registry (apps installed at runtime are shareable) */
  {
    extern int webreg_lookup(const char *name, const char **out_text, int *out_len);
    const char *text = 0;
    int tlen = 0;
    if (webreg_lookup(name, &text, &tlen) && text && tlen > 0)
    {
      /* Status line only - http_send_page_buf appends its own
       * Content-Type/Content-Length headers. Passing a full header block
       * here produced double headers and broke appinstall parsing. */
      http_send_page_buf(pcb, "HTTP/1.0 200 OK\r\n", text, tlen);
      return;
    }
  }

  char script[96];
  int si = 0;
  const char *pre = "webapp/";
  while (pre[si]) { script[si] = pre[si]; si++; }
  int q = 0;
  while (name[q] && si < 92) { script[si++] = name[q++]; }
  const char *ext = ".aj";
  while (*ext && si < 92) { script[si++] = *ext++; }
  script[si] = 0;

  extern int vfs_read_file_ram(const char *path, uint8_t **out_buf, uint32_t *out_len);
  extern int fat12_read_file_to_ram(const char *path, uint8_t **out_buf, uint32_t *out_len);
  uint8_t *buf = 0;
  uint32_t blen = 0;
  int ok = 0;
  {
    char mnt_path[128];
    int mi = 0;
    const char *mntpre = "/mnt/";
    while (mntpre[mi]) { mnt_path[mi] = mntpre[mi]; mi++; }
    int wi = 0;
    while (script[wi] && mi < 126) { mnt_path[mi++] = script[wi++]; }
    mnt_path[mi] = 0;
    if (vfs_read_file_ram(mnt_path, &buf, &blen))
      ok = 1;
    else if (fat12_read_file_to_ram(script, &buf, &blen))
      ok = 1;
  }
  if (!ok || !buf || blen == 0 || blen > sizeof(rawbuf))
  {
    http_serve_not_found(pcb);
    if (buf)
      kfree(buf);
    return;
  }
  for (uint32_t k = 0; k < blen; k++)
    rawbuf[k] = buf[k];
  kfree(buf);

  http_send_page_buf(pcb, "HTTP/1.0 200 OK\r\n", (const char *)rawbuf, (int)blen);
}

static void http_handle_webapp(struct tcp_pcb *pcb, struct http_request *req)
{
  static char out[8192];
  static char redirect[160];
  const char *u = req->uri + 5; /* skip "/app/" */
  char name[64];
  int i = 0;
  while (u[i] && u[i] != '?' && i < 60)
  {
    name[i] = u[i];
    i++;
  }
  name[i] = 0;
  if (i == 0)
  {
    http_serve_not_found(pcb);
    return;
  }

  /* RAM registry (App Store installs) takes precedence over the boot image */
  {
    extern int webreg_lookup(const char *name, const char **out_text, int *out_len);
    extern int ajlang_run_webapp_buf(const char *text, uint32_t slen,
                                     const char *method, const char *uri,
                                     const char *body, char *out, int outcap,
                                     char *redirect, int redcap);
    const char *text = 0;
    int tlen = 0;
    if (webreg_lookup(name, &text, &tlen) && text && tlen > 0)
    {
      int rb = ajlang_run_webapp_buf(text, (uint32_t)tlen,
                                     req->method == HTTP_METHOD_POST ? "POST" : "GET",
                                     req->uri, req->body, out, (int)sizeof(out),
                                     redirect, (int)sizeof(redirect));
      if (rb == -2)
        http_send_redirect(pcb, redirect);
      else if (rb < 0)
        http_serve_not_found(pcb);
      else
        http_send_page_buf(pcb, "HTTP/1.0 200 OK\r\n", out, rb);
      return;
    }
  }

  char script[96];
  int si = 0;
  const char *pre = "webapp/";
  while (pre[si]) { script[si] = pre[si]; si++; }
  int ni = 0;
  while (name[ni] && si < 88) { script[si++] = name[ni++]; }
  const char *ext = ".aj";
  while (*ext && si < 92) { script[si++] = *ext++; }
  script[si] = 0;

  int r = ajlang_run_webapp(script,
                            req->method == HTTP_METHOD_POST ? "POST" : "GET",
                            req->uri, req->body, out, (int)sizeof(out),
                            redirect, (int)sizeof(redirect));
  if (r == -2)
    http_send_redirect(pcb, redirect);
  else if (r < 0)
    http_serve_not_found(pcb);
  else
    http_send_page_buf(pcb, "HTTP/1.0 200 OK\r\n", out, r);
}
