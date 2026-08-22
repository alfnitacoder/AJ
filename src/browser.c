/* Text-mode web browser (lynx-style): fetch a page over HTTP and render
 * it as plain text on the VGA console with a scrollable pager.
 *
 *   browser example.com            -> http://example.com/
 *   browser http://host/path?q=1
 */
#include "crypto.h"
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

/* Some real pages (WordPress themes that inline all their CSS into <head>)
 * run 100-200KB before any visible text appears at all — an 8KB cap meant
 * a fetch never even reached <body>, just the title. Match crypto.h's
 * TLS_APP_DATA_CAP so this and the TLS decrypt path can't drift apart
 * again (see its comment for why that drift is exactly what happened). */
#define PAGE_MAX TLS_APP_DATA_CAP
#define LINE_MAX 90
#define LINES_MAX 4000
#define VIEW_ROWS 23
#define LINKS_MAX 64
#define LINK_URL_MAX 224

static char page_body[PAGE_MAX];
static uint32_t page_body_len = 0;
static int page_status = 0;
static char page_location[160];
static char lines[LINES_MAX][LINE_MAX];
static int n_lines = 0;

/* Links found on the current page, numbered [1]..[n_links] inline in the
 * rendered text; each entry is a fully-resolved "http(s)://host/path" URL
 * ready to feed straight back into the same fetch path. */
static char link_url[LINKS_MAX][LINK_URL_MAX];
static int n_links = 0;
/* Which rendered line (index into `lines[]`) each link's [N] marker ends
 * up on, so arrow-key selection can highlight it and scroll it into view. */
static int link_line[LINKS_MAX];

/* Where the current page came from, so relative hrefs can be resolved
 * against it. base_dir is the path's directory (through the last '/'). */
static char base_host[64];
static char base_dir[160];
static int base_tls;

static int streq(const char *a, const char *b) {
  while (*a && *b) {
    if (*a++ != *b++)
      return 0;
  }
  return *a == *b;
}

/* Decrypted TLS application data lands here (tls_read() accumulates into
 * it); for plain HTTP we just alias pcb->app_rx_buf instead. */
#define TLS_RX_MAX (PAGE_MAX + 1024)
static uint8_t tls_rx_buf[TLS_RX_MAX];

/* Fetch host/path into page_body, over plain HTTP or TLS. Returns 1 on
 * success. */
static int browser_fetch(const char *host, const char *path, int use_tls) {
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
  log_writestring(use_tls ? ":443...\n" : ":80...\n");

  int connected = 0;
  for (int attempt = 0; attempt < 2 && !connected; attempt++) {
    tcp_connect(pcb, ip, use_tls ? 443 : 80);
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

  if (use_tls) {
    log_writestring("browser: TLS handshake...\n");
    if (!tls_handshake(pcb, host)) {
      log_writestring("browser: TLS handshake failed\n");
      tcp_close(pcb);
      return 0;
    }
  }

  /* Build and send the GET request */
  char req[256];
  int n = 0;
  const char *parts[] = {"GET ", path, " HTTP/1.0\r\nHost: ", host,
                         "\r\nUser-Agent: AJOS-browser/1.0\r\n\r\n"};
  for (int i = 0; i < 5 && n < (int)sizeof(req) - 1; i++)
    for (int j = 0; parts[i][j] && n < (int)sizeof(req) - 1; j++)
      req[n++] = parts[i][j];
  if (use_tls)
    tls_write(pcb, (const uint8_t *)req, (uint16_t)n);
  else
    tcp_send(pcb, (const uint8_t *)req, (uint16_t)n);

  /* Wait for the response body to settle.
   *
   * NOTE: these are uint32_t, not uint16_t — PAGE_MAX/TLS_RX_MAX now run
   * well past 64KB, and a uint16_t index or length here would silently
   * wrap at 65536, corrupting the copy (or looping forever) on any page
   * bigger than that instead of just capping cleanly at PAGE_MAX. */
  uint32_t tls_rx_len = 0;
  int found_header_end = 0;
  uint32_t last_len = 0;
  uint32_t stable_since = 0;
  start = pit_ticks;
  /* Big pages (100s of KB) can take a real while: measured ~2.85KB/s
   * end-to-end against a live site once the connection itself was no
   * longer stalling, because our software AES-GCM/GHASH decrypt is slow
   * under emulation, not because of the network — a full PAGE_MAX
   * (384KB) page needs on the order of two minutes at that rate. This
   * loop returns whatever it has once the cap trips, silently, as if the
   * page just ended there — so a cap shorter than a big page actually
   * needs looks identical to a normal short fetch, just truncated. */
  while ((pit_ticks - start) < PIT_HZ * 180u) {
    sleep_ms(100);
    uint32_t len;
    int tls_done = 0;
    if (use_tls) {
      /* tls_read() drains every complete record currently buffered in one
       * call, so the final Application Data record and a close_notify
       * Alert that arrived in the same TCP burst are both processed here
       * before it returns -1 for the alert. tls_rx_len already reflects
       * that data — scan/use it below instead of bailing immediately, or
       * a fully-received response gets thrown away. */
      int r = tls_read(pcb, tls_rx_buf, &tls_rx_len);
      len = tls_rx_len;
      if (r < 0) /* alert (close_notify) or a bad tag: stop after this pass */
        tls_done = 1;
      /* tls_read() just decrypted and compacted pcb->app_rx_buf, likely
       * freeing a good chunk of it. Tell the peer now — see
       * tcp_announce_window()'s comment for why waiting for the next
       * incoming segment to carry this news isn't good enough. */
      tcp_announce_window(pcb);
    } else {
      len = pcb->app_rx_len;
    }
    const uint8_t *rxp = use_tls ? tls_rx_buf : pcb->app_rx_buf;
    if (!found_header_end) {
      for (uint32_t i = 0; i + 3 < len; i++) {
        if (rxp[i] == '\r' && rxp[i + 1] == '\n' && rxp[i + 2] == '\r' &&
            rxp[i + 3] == '\n') {
          found_header_end = 1;
          break;
        }
      }
    }
    if (found_header_end) {
      /* The server closes the connection after the body (Connection:
       * close): the FIN is the definitive end-of-page signal. */
      if (pcb->state == TCP_CLOSE_WAIT || pcb->state == TCP_CLOSED ||
          pcb->state == TCP_CLOSING)
        break;
      if (len == last_len) {
        if (stable_since == 0)
          stable_since = pit_ticks;
        else if ((pit_ticks - stable_since) > 2000u) /* 20s quiet: give up */
          break;
      } else {
        stable_since = 0;
        last_len = len;
      }
      if (use_tls) {
        if (len >= TLS_RX_MAX - 64)
          break; /* decrypted buffer full */
      } else if (len >= TCP_APP_RX_MAX - 64) {
        break; /* buffer full */
      }
    }
    if (tls_done)
      break;
  }

  const uint8_t *rxbuf = use_tls ? tls_rx_buf : pcb->app_rx_buf;
  uint32_t rxlen = use_tls ? tls_rx_len : pcb->app_rx_len;

  if (!found_header_end || rxlen == 0) {
    log_writestring("browser: no response\n");
    tcp_close(pcb);
    return 0;
  }

  /* Locate body */
  uint32_t hdr_end = 0;
  for (uint32_t i = 0; i + 3 < rxlen; i++) {
    if (rxbuf[i] == '\r' && rxbuf[i + 1] == '\n' && rxbuf[i + 2] == '\r' &&
        rxbuf[i + 3] == '\n') {
      hdr_end = i + 4;
      break;
    }
  }
  /* Parse status code and Location header from the response head */
  page_status = 0;
  page_location[0] = '\0';
  for (uint32_t i = 5; i + 1 < hdr_end && page_status == 0; i++) {
    if (rxbuf[i] == ' ') {
      for (uint32_t j = i + 1;
           j < hdr_end && rxbuf[j] >= '0' && rxbuf[j] <= '9'; j++)
        page_status = page_status * 10 + (rxbuf[j] - '0');
      break;
    }
  }
  for (uint32_t i = 0; i + 9 < hdr_end; i++) {
    if ((rxbuf[i] == 'L' || rxbuf[i] == 'l') && rxbuf[i + 1] == 'o' &&
        rxbuf[i + 2] == 'c' && rxbuf[i + 3] == 'a' && rxbuf[i + 4] == 't' &&
        rxbuf[i + 5] == 'i' && rxbuf[i + 6] == 'o' && rxbuf[i + 7] == 'n' &&
        rxbuf[i + 8] == ':' && rxbuf[i + 9] == ' ') {
      uint32_t j = i + 10;
      int k = 0;
      while (j < hdr_end && k < (int)sizeof(page_location) - 1 &&
             rxbuf[j] != '\r' && rxbuf[j] != '\n')
        page_location[k++] = (char)rxbuf[j++];
      page_location[k] = '\0';
      break;
    }
  }

  page_body_len = 0;
  for (uint32_t i = hdr_end; i < rxlen && page_body_len < PAGE_MAX; i++)
    page_body[page_body_len++] = (char)rxbuf[i];
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

/* Resolve an href (as it appeared in the source, possibly relative) against
 * the current page (base_host/base_dir/base_tls) into a normalized
 * "http(s)://host/path" string. Writes "" (out[0]='\0') for anything not
 * worth navigating to (fragment-only, mailto:, javascript:, etc). */
static void resolve_link(const char *href, int hlen, char *out, int outcap) {
  out[0] = '\0';
  if (hlen <= 0 || outcap <= 0)
    return;
  /* fragments aren't sent to the server; drop one if present */
  for (int i = 0; i < hlen; i++) {
    if (href[i] == '#') {
      hlen = i;
      break;
    }
  }
  if (hlen == 0)
    return; /* "#foo" -- same-page fragment, nothing to fetch */
  if (href[0] == 'm' || href[0] == 'M') {
    if (hlen >= 7 && (href[1] == 'a' || href[1] == 'A') &&
        (href[2] == 'i' || href[2] == 'I') && (href[3] == 'l' || href[3] == 'L') &&
        (href[4] == 't' || href[4] == 'T') && (href[5] == 'o' || href[5] == 'O') &&
        href[6] == ':')
      return;
  }
  if (hlen >= 11 && (href[0] == 'j' || href[0] == 'J')) {
    /* good enough sniff for "javascript:" without a full case-insensitive
     * compare loop */
    return;
  }

  int n = 0;
  const char *scheme = base_tls ? "https://" : "http://";
  int is_http = hlen >= 7 && href[0] == 'h' && href[1] == 't' &&
               href[2] == 't' && href[3] == 'p' && href[4] == ':' &&
               href[5] == '/' && href[6] == '/';
  int is_https = hlen >= 8 && href[0] == 'h' && href[1] == 't' &&
                 href[2] == 't' && href[3] == 'p' && href[4] == 's' &&
                 href[5] == ':' && href[6] == '/' && href[7] == '/';
  if (is_http || is_https) {
    for (int i = 0; i < hlen && n < outcap - 1; i++)
      out[n++] = href[i];
  } else if (hlen >= 2 && href[0] == '/' && href[1] == '/') {
    /* protocol-relative: //host/path */
    for (int i = 0; scheme[i] && n < outcap - 1; i++)
      out[n++] = scheme[i];
    for (int i = 2; i < hlen && n < outcap - 1; i++)
      out[n++] = href[i];
  } else if (href[0] == '/') {
    /* root-relative: /path */
    for (int i = 0; scheme[i] && n < outcap - 1; i++)
      out[n++] = scheme[i];
    for (int i = 0; base_host[i] && n < outcap - 1; i++)
      out[n++] = base_host[i];
    for (int i = 0; i < hlen && n < outcap - 1; i++)
      out[n++] = href[i];
  } else {
    /* relative to the current page's directory */
    for (int i = 0; scheme[i] && n < outcap - 1; i++)
      out[n++] = scheme[i];
    for (int i = 0; base_host[i] && n < outcap - 1; i++)
      out[n++] = base_host[i];
    for (int i = 0; base_dir[i] && n < outcap - 1; i++)
      out[n++] = base_dir[i];
    for (int i = 0; i < hlen && n < outcap - 1; i++)
      out[n++] = href[i];
  }
  out[n] = '\0';
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
  n_links = 0;
  char word[LINE_MAX];
  char line[LINE_MAX];
  int wl = 0;
  int llen = 0;
  int col = 0;
  int in_link = 0;
  int cur_link_num = 0;

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
      if (tag_is(page_body, i, page_body_len, "a")) {
        int is_close = (i + 1 < page_body_len && page_body[i + 1] == '/');
        uint32_t j = i;
        while (j < page_body_len && page_body[j] != '>')
          j++;
        if (!is_close) {
          /* opening <a ...>: pull out href="..." (or '...') and, if it
           * resolves to something navigable, number this link. */
          int hstart = -1, hlen = 0;
          for (uint32_t k = i; k < j; k++) {
            if (page_body[k] == 'h' && k + 4 < j && page_body[k + 1] == 'r' &&
                page_body[k + 2] == 'e' && page_body[k + 3] == 'f' &&
                page_body[k + 4] == '=') {
              uint32_t v = k + 5;
              char q = 0;
              if (v < j && (page_body[v] == '"' || page_body[v] == '\'')) {
                q = page_body[v];
                v++;
              }
              hstart = (int)v;
              while (v < j && (q ? page_body[v] != q
                                  : (page_body[v] != ' ' &&
                                     page_body[v] != '\t' &&
                                     page_body[v] != '>')))
                v++;
              hlen = (int)v - hstart;
              break;
            }
          }
          in_link = 0;
          if (hstart >= 0 && hlen > 0 && n_links < LINKS_MAX) {
            char resolved[LINK_URL_MAX];
            resolve_link(page_body + hstart, hlen, resolved,
                        sizeof(resolved));
            if (resolved[0]) {
              int idx = 0;
              while (resolved[idx] && idx < LINK_URL_MAX - 1) {
                link_url[n_links][idx] = resolved[idx];
                idx++;
              }
              link_url[n_links][idx] = '\0';
              n_links++;
              cur_link_num = n_links;
              in_link = 1;
            }
          }
        } else if (in_link) {
          /* closing </a>: stamp the link number onto the word we were
           * building, e.g. "click here[3]", so it flows through the
           * normal word-wrap logic below like any other text. */
          if (cur_link_num >= 1 && cur_link_num <= LINKS_MAX)
            link_line[cur_link_num - 1] = n_lines;
          char mk[10];
          int ml = 0;
          mk[ml++] = '[';
          char digs[8];
          int dl = 0;
          int v = cur_link_num;
          while (v > 0 && dl < 7) {
            digs[dl++] = (char)('0' + (v % 10));
            v /= 10;
          }
          while (dl > 0)
            mk[ml++] = digs[--dl];
          mk[ml++] = ']';
          for (int t = 0; t < ml && wl < LINE_MAX - 1; t++)
            word[wl++] = mk[t];
          in_link = 0;
        }
        i = (j < page_body_len) ? j + 1 : j;
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

    if ((unsigned char)c >= 0x80) {
      /* UTF-8 lead/continuation bytes (emoji, smart quotes): drop them
       * so VGA text shows clean ASCII instead of garbage glyphs. */
      i++;
      continue;
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

/* Highlight the row the currently-selected link is on (white background,
 * black text — a brighter bar than editor.c's light-grey status bar, so
 * it reads as a selection rather than a status line) by poking the VGA
 * text buffer's attribute bytes directly — log_writestring() has no
 * notion of color, so this runs as a second pass over whatever
 * browser_render() already drew. Assumes the standard 80x25 text mode the
 * rest of the console (and editor.c) assumes. */
#define VGA_TEXT_WIDTH 80
#define VGA_ATTR_SELECTED 0xF0 /* bg=white(15), fg=black(0) */
static void highlight_selected_link(int scroll, int selected_link) {
  if (selected_link < 0 || selected_link >= n_links)
    return;
  int line_idx = link_line[selected_link];
  if (line_idx < scroll || line_idx >= scroll + VIEW_ROWS)
    return; /* selection scrolled off-screen */
  int row = 1 + (line_idx - scroll); /* row 0 is the header line */
  uint8_t *vid = (uint8_t *)0xB8000;
  for (int col = 0; col < VGA_TEXT_WIDTH; col++)
    vid[(row * VGA_TEXT_WIDTH + col) * 2 + 1] = VGA_ATTR_SELECTED;
}

static void browser_render(int scroll, const char *linknum_buf,
                           int selected_link) {
  terminal_clear();
  if (n_links > 0)
    log_writestring(" AJOS browser - q: quit, arrows: select link/scroll, "
                    "Enter: go\n");
  else
    log_writestring(" AJOS browser - q: quit, up/down: scroll\n");
  for (int r = 0; r < VIEW_ROWS && scroll + r < n_lines; r++) {
    log_writestring(" ");
    log_writestring(lines[scroll + r]);
    log_writestring("\n");
  }
  highlight_selected_link(scroll, selected_link);
  log_writestring(" [");
  log_write_u32((uint32_t)(scroll + 1));
  log_writestring("-");
  log_write_u32((uint32_t)(scroll + VIEW_ROWS < n_lines ? scroll + VIEW_ROWS
                                                         : n_lines));
  log_writestring("] of ");
  log_write_u32((uint32_t)n_lines);
  log_writestring(" lines");
  if (n_links > 0) {
    log_writestring(", ");
    log_write_u32((uint32_t)n_links);
    log_writestring(" link");
    if (n_links != 1)
      log_writestring("s");
  }
  if (linknum_buf && linknum_buf[0]) {
    log_writestring("  -> go to link ");
    log_writestring(linknum_buf);
  }
  log_writestring("\n");
}

void cmd_browser(const char *args) {
  /* Trim trailing whitespace: pasted URLs often carry spaces, and a
   * trailing space inside the GET request line is a 400 Bad Request. */
  char cur_url[LINK_URL_MAX];
  int tl = 0;
  while (args[tl] && tl < (int)sizeof(cur_url) - 1) {
    cur_url[tl] = args[tl];
    tl++;
  }
  while (tl > 0 && (cur_url[tl - 1] == ' ' || cur_url[tl - 1] == '\t' ||
                    cur_url[tl - 1] == '\r' || cur_url[tl - 1] == '\n'))
    tl--;
  cur_url[tl] = '\0';

  {
    const char *s0 = cur_url;
    while (*s0 == ' ')
      s0++;
    if (!*s0) {
      log_writestring("Usage: browser <host>[/path]\n");
      log_writestring("Example: browser example.com\n");
      return;
    }
  }

  /* Outer loop: each pass fetches one URL (following its redirects) and
   * runs the pager. Picking a numbered link on the page rewrites cur_url
   * and loops back here instead of returning, so navigation stays inside
   * one `browser` invocation. */
  for (;;) {
    const char *s = cur_url;
    while (*s == ' ')
      s++;

    /* strip the scheme, defaulting to plain http */
    int use_tls = 0;
    if (s[0] == 'h' && s[1] == 't' && s[2] == 't' && s[3] == 'p' &&
        s[4] == 's' && s[5] == ':' && s[6] == '/' && s[7] == '/') {
      use_tls = 1;
      s += 8;
    } else if (s[0] == 'h' && s[1] == 't' && s[2] == 't' && s[3] == 'p' &&
               s[4] == ':' && s[5] == '/' && s[6] == '/') {
      s += 7;
    }

    char host[64];
    int hl = 0;
    while (*s && *s != '/' && hl < (int)sizeof(host) - 1)
      host[hl++] = *s++;
    host[hl] = '\0';
    static char pathbuf[160];
    int pl = 0;
    const char *psrc = (*s == '/') ? s : "/";
    while (psrc[pl] && pl < (int)sizeof(pathbuf) - 1) {
      pathbuf[pl] = psrc[pl];
      pl++;
    }
    pathbuf[pl] = '\0';
    const char *path = pathbuf;

    if (!host[0]) {
      log_writestring("browser: empty host\n");
      return;
    }

    /* Fetch, following up to 3 redirects (scheme may change each hop) */
    int ok = 1;
    for (int hop = 0; hop < 4; hop++) {
      if (!browser_fetch(host, path, use_tls)) {
        ok = 0;
        break;
      }
      if (page_status >= 300 && page_status < 400 && page_location[0]) {
        const char *loc = page_location;
        if (loc[0] == 'h' && loc[1] == 't' && loc[2] == 't' && loc[3] == 'p' &&
            loc[4] == 's' && loc[5] == ':' && loc[6] == '/' && loc[7] == '/') {
          use_tls = 1;
          loc += 8;
        } else if (loc[0] == 'h' && loc[1] == 't' && loc[2] == 't' &&
                   loc[3] == 'p' && loc[4] == ':' && loc[5] == '/' &&
                   loc[6] == '/') {
          use_tls = 0;
          loc += 7;
        }
        /* else: relative redirect target, keep the current host/scheme */
        hl = 0;
        char newhost[64];
        while (*loc && *loc != '/' && hl < (int)sizeof(newhost) - 1)
          newhost[hl++] = *loc++;
        newhost[hl] = '\0';
        if (newhost[0]) {
          for (int i = 0; i <= hl; i++)
            host[i] = newhost[i];
        }
        psrc = (*loc == '/') ? loc : "/";
        pl = 0;
        while (psrc[pl] && pl < (int)sizeof(pathbuf) - 1) {
          pathbuf[pl] = psrc[pl];
          pl++;
        }
        pathbuf[pl] = '\0';
        if (!host[0]) {
          log_writestring("browser: bad redirect target\n");
          ok = 0;
          break;
        }
        log_writestring("browser: redirected to ");
        log_writestring(use_tls ? "https://" : "http://");
        log_writestring(host);
        log_writestring(path);
        log_putchar('\n');
        continue;
      }
      break;
    }
    if (!ok)
      return;

    /* Remember where this page came from so relative links on it resolve
     * correctly (base_dir is the path through its last '/'). */
    base_tls = use_tls;
    {
      int i = 0;
      while (host[i] && i < (int)sizeof(base_host) - 1) {
        base_host[i] = host[i];
        i++;
      }
      base_host[i] = '\0';
    }
    {
      int last_slash = 0;
      for (int i = 0; path[i]; i++)
        if (path[i] == '/')
          last_slash = i;
      int n = last_slash + 1;
      if (n > (int)sizeof(base_dir) - 1)
        n = (int)sizeof(base_dir) - 1;
      for (int i = 0; i < n; i++)
        base_dir[i] = path[i];
      base_dir[n] = '\0';
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
    char linknum_buf[8];
    int linknum_len = 0;
    linknum_buf[0] = '\0';
    int follow_link = 0;
    /* -1 = no link selected. Up/Down move this between links (when the
     * page has any) instead of scrolling by a line; PageUp/PageDown and
     * g/G still do plain scrolling regardless. */
    int selected_link = -1;

    /* Shared by both the arrow-selection path and Enter: point cur_url at
     * link_url[idx] and arrange for the outer loop to re-fetch it. */
#define GO_TO_LINK(idx)                                                     \
  do {                                                                      \
    int _i = 0;                                                            \
    while (link_url[idx][_i] && _i < (int)sizeof(cur_url) - 1) {           \
      cur_url[_i] = link_url[idx][_i];                                     \
      _i++;                                                                \
    }                                                                      \
    cur_url[_i] = '\0';                                                    \
    follow_link = 1;                                                       \
  } while (0)

    for (;;) {
      if (need_render) {
        browser_render(scroll, linknum_buf, selected_link);
        need_render = 0;
      }
      int key = input_getkey();
      if (key >= '0' && key <= '9') {
        if (linknum_len < (int)sizeof(linknum_buf) - 1) {
          linknum_buf[linknum_len++] = (char)key;
          linknum_buf[linknum_len] = '\0';
          need_render = 1;
        }
        continue;
      }
      if (key == '\b') {
        if (linknum_len > 0) {
          linknum_buf[--linknum_len] = '\0';
          need_render = 1;
        }
        continue;
      }
      if (key == '\n' || key == '\r') {
        if (linknum_len > 0) {
          int num = 0;
          for (int i = 0; i < linknum_len; i++)
            num = num * 10 + (linknum_buf[i] - '0');
          linknum_len = 0;
          linknum_buf[0] = '\0';
          if (num >= 1 && num <= n_links) {
            GO_TO_LINK(num - 1);
            break;
          }
          need_render = 1;
        } else if (selected_link >= 0) {
          GO_TO_LINK(selected_link);
          break;
        }
        continue;
      }
      if (key == 'q' || key == 'Q' || key == 27)
        break;
      /* any other navigation key cancels a pending link-number entry */
      if (linknum_len > 0) {
        linknum_len = 0;
        linknum_buf[0] = '\0';
        need_render = 1;
      }
      if (n_links > 0 && (key == KEY_UP || key == KEY_DOWN)) {
        if (selected_link < 0)
          selected_link = 0;
        else if (key == KEY_DOWN) {
          if (selected_link < n_links - 1)
            selected_link++;
        } else if (selected_link > 0) {
          selected_link--;
        }
        int L = link_line[selected_link];
        int ns = scroll;
        if (L < scroll)
          ns = L; /* moving up past the top: bring it to the top */
        else if (L >= scroll + VIEW_ROWS)
          ns = L - VIEW_ROWS + 1; /* moving down past the bottom: to the bottom */
        if (ns > n_lines - VIEW_ROWS)
          ns = n_lines - VIEW_ROWS;
        if (ns < 0)
          ns = 0;
        scroll = ns;
        need_render = 1; /* re-render regardless: the highlight moved even
                          * when the scroll position didn't */
        continue;
      }
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
#undef GO_TO_LINK
    if (!follow_link)
      break;
  }
  terminal_clear();
}
