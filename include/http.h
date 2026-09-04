#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

// HTTP server port
#define HTTP_PORT 80

// HTTPS (TLS) server port — served by the TLS 1.2 server in src/tls.c
#define HTTPS_PORT 443

// HTTP methods
#define HTTP_METHOD_GET 1
#define HTTP_METHOD_POST 2

// HTTP status codes
#define HTTP_STATUS_OK 200
#define HTTP_STATUS_REDIRECT 302
#define HTTP_STATUS_NOT_FOUND 404

// Maximum sizes
#define HTTP_MAX_URI_LEN 128
#define HTTP_MAX_HOST_LEN 64
#define HTTP_MAX_HEADER_LEN 512
#define HTTP_MAX_BODY_LEN 1024

// HTTP request structure
struct http_request {
  uint8_t method; // HTTP_METHOD_GET or HTTP_METHOD_POST
  char uri[HTTP_MAX_URI_LEN];
  char host[HTTP_MAX_HOST_LEN];
  int content_length;
  char body[HTTP_MAX_BODY_LEN];
};

// HTTP response structure
struct http_response {
  int status_code;
  const char *content_type;
  const char *body;
  int body_len;
  const char *location; // For redirects
};

// Forward declaration
struct tcp_pcb;

// HTTP server functions
void http_init(void);
void http_handle_connection(struct tcp_pcb *pcb, const uint8_t *data, int len);
int http_parse_request(const char *data, int len, struct http_request *req);
void http_send_response(struct tcp_pcb *pcb, struct http_response *resp);

// HTTP page handlers
void http_serve_login_page(struct tcp_pcb *pcb);
void http_serve_success_page(struct tcp_pcb *pcb);
void http_serve_not_found(struct tcp_pcb *pcb);
void http_handle_auth(struct tcp_pcb *pcb, struct http_request *req);

#endif // HTTP_H
