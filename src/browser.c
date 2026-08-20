/* Text-mode web browser (lynx-style): fetch a page over HTTP and render
 * it as plain text on the VGA console with a scrollable pager.
 *
 *   browser example.com            -> http://example.com/
 *   browser http://host/path?q=1
 */
#include "keyboard.h"
#include "net.h"
#include <stddef.h>
#include <stdint.h>

extern void log_writestring(const char *s);
extern void log_write_u32(uint32_t v);
extern void log_putchar(char c);
extern void terminal_clear(void);
extern int input_getkey(void);
extern void sleep_ms(uint32_t ms);
extern volatile uint32_t pit_ticks;
#define PIT_HZ 100u

extern struct tcp_pcb *tcp_get_free_pcb(void);
extern int tcp_connect(struct tcp_pcb *pcb, ip_addr_t remote_ip,
                       uint16_t port);
extern int tcp_send(struct tcp_pcb *pcb, const uint8_t *data, uint16_t len);
extern int tcp_close(struct tcp_pcb *pcb);
extern void dns_lookup(const char *name);
extern volatile int dns_got_reply;
extern volatile uint32_t dns_last_ip;

#define PAGE_MAX 4096
#define LINE_MAX 90
#define LINES_MAX 400
#define VIEW_ROWS 23

static char page_body[PAGE_MAX];
static uint32_t page_body_len = 0;
static int page_status = 0;
static char page_location[160];
static char lines[LINES_MAX][LINE_MAX];
static int n_lines = 0;

static int streq(const char *a, const char *b) {
  while (*a && *b) {
    if (*a++ != *b++)
      return 0;
  }
  return *a == *b;
}

/* Fetch http://host/path into page_body. Returns 1 on success. */
static int browser_fetch(const char *host, const char *path) {
  /* Resolve the host first */
  dns_lookup(host);
  uint32_t start = pit_ticks;
  while (!dns_got_reply && (pit_ticks - start) < PIT_HZ * 4u)
    sleep_ms(50);
  if (!dns_got_reply || dns_last_ip == 0) {
    log_writestring("browser: DNS lookup failed for ");
    log_writestring(host);
    log_putchar('\n');
    return 0;
  }
  uint32_t ip = dns_last_ip;

  struct tcp_pcb *pcb = tcp_get_free_pcb();
  if (!pcb) {
    log_writestring("browser: no free pcb\n");
    return 0;
  }

  log_writestring("browser: connecting to ");
  log_write_u32((ip >> 24) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 16) & 0xFF);
  log_putchar('.');
  log_write_u32((ip >> 8) & 0xFF);
  log_putchar('.');
  log_write_u32(ip & 0xFF);
  log_writestring("...\n");

  int connected = 0;
  for (int attempt = 0; attempt < 2 && !connected; attempt++) {
    tcp_connect(pcb, ip, 80);
    start = pit_ticks;
    while ((pit_ticks - start) < PIT_HZ * 6u) {
      if (pcb->state == TCP_ESTABLISHED) {
        connected = 1;
        break;
      }
      if (pcb->state == TCP_CLOSED)
        break;
      sleep_ms(50);
    }
    if (!connected) {
      pcb->state = TCP_CLOSED;
      sleep_ms(100);
    }
  }
  if (!connected) {
    log_writestring("browser: connect timeout\n");
    return 0;
  }

  pcb->app_rx_len = 0;

  /* Build and send the GET request */
  char req[256];
  int n = 0;
  const char *parts[] = {"GET ", path, " HTTP/1.0\r\nHost: ", host,
                         "\r\nUser-Agent: AJOS-browser/1.0\r\n\r\n"};
  for (int i = 0; i < 5 && n < (int)sizeof(req) - 1; i++)
    for (int j = 0; parts[i][j] && n < (int)sizeof(req) - 1; j++)
      req[n++] = parts[i][j];
  tcp_send(pcb, (const uint8_t *)req, (uint16_t)n);

  /* Wait for the response body to settle */
  int found_header_end = 0;
  uint16_t last_len = 0;
  uint32_t stable_since = 0;
  start = pit_ticks;
  while ((pit_ticks - start) < PIT_HZ * 10u) {
    sleep_ms(100);
    uint16_t len = pcb->app_rx_len;
    if (!found_header_end) {
      for (uint16_t i = 0; i + 3 < len; i++) {
        if (pcb->app_rx_buf[i] == '\r' && pcb->app_rx_buf[i + 1] == '\n' &&
            pcb->app_rx_buf[i + 2] == '\r' && pcb->app_rx_buf[i + 3] == '\n') {
          found_header_end = 1;
          break;
        }
      }
    }
    if (found_header_end) {
      if (len == last_len) {
        if (stable_since == 0)
          stable_since = pit_ticks;
        else if ((pit_ticks - stable_since) > 150u) /* ~1.5s at 100Hz */
          break; /* no new data for 1.5s: page complete */
      } else {
        stable_since = 0;
        last_len = len;
      }
      if (len >= TCP_APP_RX_MAX - 64)
        break; /* buffer full */
    }
  }

  if (!found_header_end || pcb->app_rx_len == 0) {
    log_writestring("browser: no response\n");
    tcp_close(pcb);
    return 0;
  }

  /* Locate body */
  uint16_t hdr_end = 0;
  for (uint16_t i = 0; i + 3 < pcb->app_rx_len; i++) {
    if (pcb->app_rx_buf[i] == '\r' && pcb->app_rx_buf[i + 1] == '\n' &&
        pcb->app_rx_buf[i + 2] == '\r' && pcb->app_rx_buf[i + 3] == '\n') {
      hdr_end = (uint16_t)(i + 4);
      break;
    }
  }
  /* Parse status code and Location header from the response head */
  page_status = 0;
  page_location[0] = '\0';
  for (uint16_t i = 5; i + 1 < hdr_end && page_status == 0; i++) {
    if (pcb->app_rx_buf[i] == ' ') {
      for (uint16_t j = i + 1;
           j < hdr_end && pcb->app_rx_buf[j] >= '0' &&
           pcb->app_rx_buf[j] <= '9';
           j++)
        page_status = page_status * 10 + (pcb->app_rx_buf[j] - '0');
      break;
    }
  }
  for (uint16_t i = 0; i + 9 < hdr_end; i++) {
    if ((pcb->app_rx_buf[i] == 'L' || pcb->app_rx_buf[i] == 'l') &&
        pcb->app_rx_buf[i + 1] == 'o' && pcb->app_rx_buf[i + 2] == 'c' &&
        pcb->app_rx_buf[i + 3] == 'a' && pcb->app_rx_buf[i + 4] == 't' &&
        pcb->app_rx_buf[i + 5] == 'i' && pcb->app_rx_buf[i + 6] == 'o' &&
        pcb->app_rx_buf[i + 7] == 'n' && pcb->app_rx_buf[i + 8] == ':' &&
        pcb->app_rx_buf[i + 9] == ' ') {
      uint16_t j = i + 10;
      int k = 0;
      while (j < hdr_end && k < (int)sizeof(page_location) - 1 &&
             pcb->app_rx_buf[j] != '\r' && pcb->app_rx_buf[j] != '\n')
        page_location[k++] = (char)pcb->app_rx_buf[j++];
      page_location[k] = '\0';
      break;
    }
  }

  page_body_len = 0;
  for (uint16_t i = hdr_end; i < pcb->app_rx_len && page_body_len < PAGE_MAX;
       i++)
    page_body[page_body_len++] = (char)pcb->app_rx_buf[i];
  page_body[page_body_len] = '\0';

  tcp_close(pcb);
  return 1;
}

/* Case-insensitive tag name compare at buf[i] (buf[i]=='<'). */
static int tag_is(const char *buf, uint32_t i, uint32_t len, const char *name) {
  i++; /* skip '<' */
  if (i < len && (buf[i] == '/'))
    i++;
  for (int j = 0; name[j]; j++) {
    if (i >= len)
      return 0;
    char a = buf[i];
    char b = name[j];
    if (a >= 'A' && a <= 'Z')
      a += 32;
    if (a != b)
      return 0;
    i++;
  }
  if (i >= len)
    return 1;
  char c = buf[i];
  return c == ' ' || c == '>' || c == '\t' || c == '\n' || c == '\r' || c == '/';
}

static void find_close_tag(const char *buf, uint32_t len, const char *name,
                           uint32_t *i) {
  /* skip until </name> */
  while (*i + 1 < len) {
    if (buf[*i] == '<' && buf[*i + 1] == '/' &&
        tag_is(buf, *i, len, name)) {
      while (*i < len && buf[*i] != '>')
        (*i)++;
      if (*i < len)
        (*i)++;
      return;
    }
    (*i)++;
  }
}

static void push_line(const char *text, int len) {
  if (n_lines >= LINES_MAX)
    return;
  if (len >= LINE_MAX)
    len = LINE_MAX - 1;
  for (int i = 0; i < len; i++)
    lines[n_lines][i] = text[i];
  lines[n_lines][len] = '\0';
  n_lines++;
}

/* Very small HTML-to-text: drops script/style, tags -> nothing (block tags
 * break lines), decodes the common entities, word-wraps to 78 columns. */
static void html_to_lines(void) {
  n_lines = 0;
  char word[LINE_MAX];
  char line[LINE_MAX];
  int wl = 0;
  int llen = 0;
  int col = 0;

  for (uint32_t i = 0; i < page_body_len;) {
    char c = page_body[i];

    if (c == '<') {
      if (tag_is(page_body, i, page_body_len, "script")) {
        find_close_tag(page_body, page_body_len, "script", &i);
        continue;
      }
      if (tag_is(page_body, i, page_body_len, "style")) {
        find_close_tag(page_body, page_body_len, "style", &i);
        continue;
      }
      /* block tags force a line break */
      const char *blocks[] = {"p",  "br", "div", "tr", "li", "h1", "h2",
                              "h3", "h4", "h5",  "h6",  "ul",  "ol", 0};
      for (int b = 0; blocks[b]; b++) {
        if (tag_is(page_body, i, page_body_len, blocks[b])) {
          if (col > 0 || wl > 0) {
            if (wl > 0) {
              if (col > 0 && llen < LINE_MAX - 1)
                line[llen++] = ' ';
              for (int k = 0; k < wl && llen < LINE_MAX - 1; k++)
                line[llen++] = word[k];
              wl = 0;
            }
            push_line(line, llen);
            llen = 0;
            col = 0;
          }
          break;
        }
      }
      /* skip to tag end */
      while (i < page_body_len && page_body[i] != '>')
        i++;
      if (i < page_body_len)
        i++;
      continue;
    }

    if (c == '&') {
      /* decode entity */
      if (page_body_len - i >= 5 && page_body[i + 1] == 'a' &&
          page_body[i + 2] == 'm' && page_body[i + 3] == 'p' &&
          page_body[i + 4] == ';') {
        c = '&';
        i += 5;
      } else if (page_body_len - i >= 4 && page_body[i + 1] == 'l' &&
                 page_body[i + 2] == 't' && page_body[i + 3] == ';') {
        c = '<';
        i += 4;
      } else if (page_body_len - i >= 4 && page_body[i + 1] == 'g' &&
                 page_body[i + 2] == 't' && page_body[i + 3] == ';') {
        c = '>';
        i += 4;
      } else if (page_body_len - i >= 6 && page_body[i + 1] == 'q' &&
                 page_body[i + 2] == 'u' && page_body[i + 3] == 'o' &&
                 page_body[i + 4] == 't' && page_body[i + 5] == ';') {
        c = '"';
        i += 6;
      } else if (page_body_len - i >= 6 && page_body[i + 1] == 'n' &&
                 page_body[i + 2] == 'b' && page_body[i + 3] == 's' &&
                 page_body[i + 4] == 'p' && page_body[i + 5] == ';') {
        c = ' ';
        i += 6;
      } else {
        c = '&';
        i++;
      }
    } else if (c == '\r' || c == '\t') {
      c = ' ';
      i++;
    } else if (c == '\n') {
      /* newline in source: treat as a space (block tags handle breaks) */
      c = ' ';
      i++;
    } else {
      i++;
    }

    if (c == ' ') {
      if (wl > 0) {
        /* append word to the current line, wrapping when needed */
        if (col > 0 && col + 1 + wl > 78) {
          push_line(line, llen);
          llen = 0;
          col = 0;
        }
        if (col > 0 && llen < LINE_MAX - 1)
          line[llen++] = ' ';
        for (int k = 0; k < wl && llen < LINE_MAX - 1; k++)
          line[llen++] = word[k];
        col += wl + (col > 0 ? 1 : 0);
        wl = 0;
      }
      continue;
    }

    if (wl < LINE_MAX - 1)
      word[wl++] = c;
    else {
      /* single very long word: hard wrap */
      if (col > 0) {
        push_line(line, llen);
        llen = 0;
        col = 0;
      }
      push_line(word, wl);
      wl = 0;
    }
  }
  if (wl > 0) {
    if (col > 0 && llen < LINE_MAX - 1)
      line[llen++] = ' ';
    for (int k = 0; k < wl && llen < LINE_MAX - 1; k++)
      line[llen++] = word[k];
  }
  if (llen > 0)
    push_line(line, llen);
}

static void browser_render(int scroll) {
  terminal_clear();
  log_writestring(" AJOS browser - q: quit, up/down: scroll\n");
  for (int r = 0; r < VIEW_ROWS && scroll + r < n_lines; r++) {
    log_writestring(" ");
    log_writestring(lines[scroll + r]);
    log_writestring("\n");
  }
  log_writestring(" [");
  log_write_u32((uint32_t)(scroll + 1));
  log_writestring("-");
  log_write_u32((uint32_t)(scroll + VIEW_ROWS < n_lines ? scroll + VIEW_ROWS
                                                         : n_lines));
  log_writestring("] of ");
  log_write_u32((uint32_t)n_lines);
  log_writestring(" lines\n");
}

void cmd_browser(const char *args) {
  const char *s = args;
  while (*s == ' ')
    s++;
  if (!*s) {
    log_writestring("Usage: browser <host>[/path]\n");
    log_writestring("Example: browser example.com\n");
    return;
  }

  /* strip http:// */
  if (s[0] == 'h' && s[1] == 't' && s[2] == 't' && s[3] == 'p' && s[4] == ':' &&
      s[5] == '/' && s[6] == '/')
    s += 7;

  char host[64];
  int hl = 0;
  while (*s && *s != '/' && hl < (int)sizeof(host) - 1)
    host[hl++] = *s++;
  host[hl] = '\0';
  const char *path = (*s == '/') ? s : "/";

  if (!host[0]) {
    log_writestring("browser: empty host\n");
    return;
  }

  /* Fetch, following up to 3 http redirects */
  for (int hop = 0; hop < 4; hop++) {
    if (!browser_fetch(host, path)) {
      return;
    }
    if (page_status >= 300 && page_status < 400 && page_location[0]) {
      if (page_location[0] == 'h' && page_location[1] == 't' &&
          page_location[2] == 't' && page_location[3] == 'p' &&
          page_location[4] == 's') {
        log_writestring("browser: redirect to ");
        log_writestring(page_location);
        log_writestring("\nbrowser: HTTPS is not supported (no TLS)\n");
        return;
      }
      const char *loc = page_location;
      if (loc[0] == 'h' && loc[1] == 't' && loc[2] == 't' && loc[3] == 'p' &&
          loc[4] == ':' && loc[5] == '/' && loc[6] == '/')
        loc += 7;
      int hl = 0;
      while (*loc && *loc != '/' && hl < (int)sizeof(host) - 1)
        host[hl++] = *loc++;
      host[hl] = '\0';
      path = (*loc == '/') ? loc : "/";
      if (!host[0]) {
        log_writestring("browser: bad redirect target\n");
        return;
      }
      log_writestring("browser: redirected to ");
      log_writestring(host);
      log_writestring(path);
      log_putchar('\n');
      continue;
    }
    break;
  }

  html_to_lines();
  if (n_lines == 0) {
    log_writestring("browser: page has no text content (");
    log_write_u32(page_body_len);
    log_writestring(" bytes)\n");
    return;
  }

  int scroll = 0;
  int need_render = 1;
  for (;;) {
    if (need_render) {
      browser_render(scroll);
      need_render = 0;
    }
    int key = input_getkey();
    if (key == 'q' || key == 'Q' || key == 27)
      break;
    int ns = scroll;
    if (key == KEY_UP)
      ns--;
    else if (key == KEY_DOWN)
      ns++;
    else if (key == KEY_PAGEUP)
      ns -= VIEW_ROWS;
    else if (key == KEY_PAGEDOWN)
      ns += VIEW_ROWS;
    else if (key == 'g')
      ns = 0;
    else if (key == 'G')
      ns = n_lines - VIEW_ROWS;
    /* only redraw when the view actually moved (key repeat would
     * otherwise reflash identical screens) */
    if (ns > n_lines - VIEW_ROWS)
      ns = n_lines - VIEW_ROWS;
    if (ns < 0)
      ns = 0;
    if (ns != scroll) {
      scroll = ns;
      need_render = 1;
    }
  }
  terminal_clear();
}
