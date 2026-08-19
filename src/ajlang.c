/*
 * AJLang interpreter for AJOS - runs .aj scripts inside the kernel
 * Supports: print, let, if/then/else/end, while/do/end, for/to/do/end,
 *           def/return/call, input, dns(hostname), arithmetic and comparison
 */

#include "ajlang.h"
#include "kernel.h"
#include "net.h"

#include <stddef.h>
#include <stdint.h>

extern int input_getkey(void);
extern void sleep_ms(uint32_t ms);
extern volatile uint32_t pit_ticks;
extern volatile int dns_got_reply;
extern volatile uint32_t dns_last_ip;

#ifndef AJLANG_PIT_HZ
#define AJLANG_PIT_HZ 100u
#endif

/* Format IPv4 as dotted decimal into out (null-terminated). */
static void format_ipv4(uint32_t ip, char *out, int maxlen)
{
  int pos = 0;
  for (int octet = 0; octet < 4; octet++)
  {
    uint8_t v = (uint8_t)((ip >> (24 - octet * 8)) & 0xFF);
    char tmp[3];
    int n = 0;
    if (v >= 100)
      tmp[n++] = (char)('0' + v / 100);
    if (v >= 10)
      tmp[n++] = (char)('0' + (v / 10) % 10);
    tmp[n++] = (char)('0' + v % 10);
    for (int i = 0; i < n && pos < maxlen - 1; i++)
      out[pos++] = tmp[i];
    if (octet < 3 && pos < maxlen - 1)
      out[pos++] = '.';
  }
  out[pos < maxlen ? pos : maxlen - 1] = 0;
}

/* Resolve hostname via kernel DNS; returns 1 and dotted IP, or 0 and "". */
static int builtin_dns_lookup(const char *name, char *out, int maxlen)
{
  if (!name || !name[0] || !out || maxlen < 8)
  {
    if (out && maxlen > 0)
      out[0] = 0;
    return 0;
  }
  out[0] = 0;

  for (int attempt = 0; attempt < 2; attempt++)
  {
    dns_lookup(name);
    uint32_t start = pit_ticks;
    uint32_t spins = 0;
    /* Avoid netdev_napi_poll (can re-enter interpreter). IRQs deliver RX. */
    while ((pit_ticks - start) < (AJLANG_PIT_HZ * 3u) && spins < 50000u)
    {
      if (dns_got_reply)
      {
        format_ipv4(dns_last_ip, out, maxlen);
        return 1;
      }
      sleep_ms(50);
      spins++;
    }
  }
  return 0;
}

#define TOK_EOF      0
#define TOK_NUMBER   1
#define TOK_STRING   2
#define TOK_IDENT    3
#define TOK_PRINT    4
#define TOK_LET      5
#define TOK_IF       6
#define TOK_THEN     7
#define TOK_ELSE     8
#define TOK_END      9
#define TOK_WHILE   10
#define TOK_FOR     11
#define TOK_TO      12
#define TOK_DO      13
#define TOK_DEF     14
#define TOK_RETURN  15
#define TOK_INPUT   16
#define TOK_TRUE    17
#define TOK_FALSE   18
#define TOK_AND     19
#define TOK_OR      20
#define TOK_NOT     21
#define TOK_PLUS    22
#define TOK_MINUS   23
#define TOK_STAR    24
#define TOK_SLASH   25
#define TOK_PERCENT 26
#define TOK_EQ      27
#define TOK_EQEQ    28
#define TOK_BANG    29
#define TOK_BANGEQ  30
#define TOK_LT      31
#define TOK_LE      32
#define TOK_GT      33
#define TOK_GE      34
#define TOK_LPAREN  35
#define TOK_RPAREN  36
#define TOK_COMMA   37
#define TOK_NEWLINE 38

#define MAX_TOKENS   512
#define MAX_IDENT    32
#define MAX_VARS     64
#define MAX_FUNCS    16
#define MAX_PARAMS   8
#define MAX_BODY     64
#define STR_BUF_SIZE 256

extern size_t kstrlen(const char *s);

struct Token {
  int type;
  int64_t num_val;
  char str_val[STR_BUF_SIZE];
};

struct Var {
  char name[MAX_IDENT];
  int is_num;
  int64_t num_val;
  char str_val[STR_BUF_SIZE];
};

struct Func {
  char name[MAX_IDENT];
  int nparams;
  char params[MAX_PARAMS][MAX_IDENT];
  int body_start;   /* token index */
  int body_len;
};

static const char *g_source;
static size_t g_pos;
static int g_line;
static volatile int g_ntokens;  /* before g_tokens to avoid potential overflow corruption */
static struct Token g_tokens[MAX_TOKENS];
static int g_tok_pos;
static struct Var g_vars[MAX_VARS];
static int g_nvars;
static struct Func g_funcs[MAX_FUNCS];
static int g_nfuncs;
static int g_return_flag;
static int64_t g_return_val;
static char g_return_str[STR_BUF_SIZE];
static int g_return_is_str;
static int g_define_pass;  /* 1 = first pass, only register defs; 0 = execute all */

static char peek(void) {
  if (!g_source || g_pos > 65535)
    return 0;
  return g_source[g_pos] ? g_source[g_pos] : 0;
}

static char peek_ahead(int offset) {
  if (!g_source || g_pos + offset > 65535)
    return 0;
  return g_source[g_pos + offset] ? g_source[g_pos + offset] : 0;
}

static char advance(void) {
  char c = g_source[g_pos];
  if (c) {
    g_pos++;
    if (c == '\n') g_line++;
  }
  return c;
}

static void skip_comment(void) {
  while (peek() && peek() != '\n') advance();
}

static void skip_whitespace(void) {
  while (peek() == ' ' || peek() == '\t' || peek() == '\r') advance();
}

static void add_token(int type, int64_t num_val, const char *str_val, int *pn) {
  if (*pn >= MAX_TOKENS) return;
  struct Token *t = &g_tokens[(*pn)++];
  t->type = type;
  t->num_val = num_val;
  if (str_val) {
    size_t i = 0;
    while (i < STR_BUF_SIZE - 1 && str_val[i]) {
      t->str_val[i] = str_val[i];
      i++;
    }
    t->str_val[i] = 0;
  } else {
    t->str_val[0] = 0;
  }
  g_ntokens = *pn;
}

static void lex_number(int *pn) {
  int64_t v = 0;
  int neg = 0;
  if (peek() == '-') { neg = 1; advance(); }
  while (peek() >= '0' && peek() <= '9') {
    v = v * 10 + (advance() - '0');
  }
  if (peek() == '.') {
    advance();
    while (peek() >= '0' && peek() <= '9') advance();
  }
  add_token(TOK_NUMBER, neg ? -v : v, 0, pn);
}

static void lex_string(char quote, int *pn) {
  static char buf[STR_BUF_SIZE];
  int i = 0;
  advance();
  while (peek() != quote && peek() && i < STR_BUF_SIZE - 1) {
    char c = advance();
    if (c == '\\') {
      char e = advance();
      if (e == 'n') buf[i++] = '\n';
      else if (e == 't') buf[i++] = '\t';
      else if (e == '\\') buf[i++] = '\\';
      else if (e == quote) buf[i++] = quote;
      else buf[i++] = e;
    } else {
      buf[i++] = c;
    }
  }
  if (peek() == quote) advance();
  buf[i] = 0;
  add_token(TOK_STRING, 0, buf, pn);
}

static void lex_ident(int *pn) {
  static char buf[MAX_IDENT];
  int i = 0;
  while ((peek() >= 'a' && peek() <= 'z') || (peek() >= 'A' && peek() <= 'Z') ||
         (peek() >= '0' && peek() <= '9') || peek() == '_') {
    if (i < MAX_IDENT - 1) buf[i++] = advance();
    else advance();
  }
  buf[i] = 0;
  if (kstrcmp_n(buf, "print", 5) == 0) add_token(TOK_PRINT, 0, 0, pn);
  else if (kstrcmp_n(buf, "let", 4) == 0) add_token(TOK_LET, 0, 0, pn);
  else if (kstrcmp_n(buf, "if", 3) == 0) add_token(TOK_IF, 0, 0, pn);
  else if (kstrcmp_n(buf, "then", 5) == 0) add_token(TOK_THEN, 0, 0, pn);
  else if (kstrcmp_n(buf, "else", 5) == 0) add_token(TOK_ELSE, 0, 0, pn);
  else if (kstrcmp_n(buf, "end", 4) == 0) add_token(TOK_END, 0, 0, pn);
  else if (kstrcmp_n(buf, "while", 6) == 0) add_token(TOK_WHILE, 0, 0, pn);
  else if (kstrcmp_n(buf, "for", 4) == 0) add_token(TOK_FOR, 0, 0, pn);
  else if (kstrcmp_n(buf, "to", 3) == 0) add_token(TOK_TO, 0, 0, pn);
  else if (kstrcmp_n(buf, "do", 3) == 0) add_token(TOK_DO, 0, 0, pn);
  else if (kstrcmp_n(buf, "def", 4) == 0) add_token(TOK_DEF, 0, 0, pn);
  else if (kstrcmp_n(buf, "return", 7) == 0) add_token(TOK_RETURN, 0, 0, pn);
  else if (kstrcmp_n(buf, "input", 6) == 0) add_token(TOK_INPUT, 0, 0, pn);
  else if (kstrcmp_n(buf, "true", 5) == 0) add_token(TOK_TRUE, 0, 0, pn);
  else if (kstrcmp_n(buf, "false", 6) == 0) add_token(TOK_FALSE, 0, 0, pn);
  else if (kstrcmp_n(buf, "and", 4) == 0) add_token(TOK_AND, 0, 0, pn);
  else if (kstrcmp_n(buf, "or", 3) == 0) add_token(TOK_OR, 0, 0, pn);
  else if (kstrcmp_n(buf, "not", 4) == 0) add_token(TOK_NOT, 0, 0, pn);
  else add_token(TOK_IDENT, 0, buf, pn);
}

/* Returns token count (>=1) on success, 0 on failure. */
static int lex(void) {
  int n = 0;
  g_ntokens = 0;
  g_pos = 0;
  g_line = 1;
  while (n < MAX_TOKENS) {
    skip_whitespace();
    char c = peek();
    if (!c) { add_token(TOK_EOF, 0, 0, &n); break; }
    if (c == '\n') { advance(); add_token(TOK_NEWLINE, 0, 0, &n); continue; }
    if (c == '/' && peek_ahead(1) == '/') { skip_comment(); continue; }
    if (c >= '0' && c <= '9') { lex_number(&n); continue; }
    if (c == '-' && peek_ahead(1) >= '0' && peek_ahead(1) <= '9') {
      lex_number(&n); continue;
    }
    if (c == '"' || c == '\'') { lex_string(c, &n); continue; }
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
      lex_ident(&n); continue;
    }
    if (c == '=' && peek_ahead(1) == '=') {
      advance(); advance(); add_token(TOK_EQEQ, 0, 0, &n); continue;
    }
    if (c == '!' && peek_ahead(1) == '=') {
      advance(); advance(); add_token(TOK_BANGEQ, 0, 0, &n); continue;
    }
    if (c == '<' && peek_ahead(1) == '=') {
      advance(); advance(); add_token(TOK_LE, 0, 0, &n); continue;
    }
    if (c == '>' && peek_ahead(1) == '=') {
      advance(); advance(); add_token(TOK_GE, 0, 0, &n); continue;
    }
    if (c == '+') { advance(); add_token(TOK_PLUS, 0, 0, &n); continue; }
    if (c == '-') { advance(); add_token(TOK_MINUS, 0, 0, &n); continue; }
    if (c == '*') { advance(); add_token(TOK_STAR, 0, 0, &n); continue; }
    if (c == '/') { advance(); add_token(TOK_SLASH, 0, 0, &n); continue; }
    if (c == '%') { advance(); add_token(TOK_PERCENT, 0, 0, &n); continue; }
    if (c == '=') { advance(); add_token(TOK_EQ, 0, 0, &n); continue; }
    if (c == '!') { advance(); add_token(TOK_BANG, 0, 0, &n); continue; }
    if (c == '<') { advance(); add_token(TOK_LT, 0, 0, &n); continue; }
    if (c == '>') { advance(); add_token(TOK_GT, 0, 0, &n); continue; }
    if (c == '(') { advance(); add_token(TOK_LPAREN, 0, 0, &n); continue; }
    if (c == ')') { advance(); add_token(TOK_RPAREN, 0, 0, &n); continue; }
    if (c == ',') { advance(); add_token(TOK_COMMA, 0, 0, &n); continue; }
    advance();
  }
  /* Ensure we always have at least EOF so caller gets a valid token stream */
  if (n == 0)
    add_token(TOK_EOF, 0, 0, &n);
  g_ntokens = n;
  return n;
}

static void skip_newlines(void) {
  while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type == TOK_NEWLINE)
    g_tok_pos++;
}

static struct Token *peek_tok(void) {
  skip_newlines();
  if (g_ntokens <= 0)
    return &g_tokens[0]; /* guard: never &g_tokens[-1] */
  if (g_tok_pos >= g_ntokens)
    return &g_tokens[g_ntokens - 1];
  return &g_tokens[g_tok_pos];
}

static struct Token *advance_tok(void) {
  skip_newlines();
  if (g_ntokens <= 0)
    return &g_tokens[0];
  if (g_tok_pos >= g_ntokens)
    return &g_tokens[g_ntokens - 1];
  return &g_tokens[g_tok_pos++];
}

static struct Var *find_var(const char *name) {
  for (int i = 0; i < g_nvars; i++)
    if (kstrcmp_n(g_vars[i].name, name, MAX_IDENT) == 0)
      return &g_vars[i];
  return 0;
}

static struct Var *get_or_add_var(const char *name) {
  struct Var *v = find_var(name);
  if (v) return v;
  if (g_nvars >= MAX_VARS) return 0;
  v = &g_vars[g_nvars++];
  size_t i = 0;
  while (i < MAX_IDENT - 1 && name[i]) { v->name[i] = name[i]; i++; }
  v->name[i] = 0;
  v->is_num = 1;
  v->num_val = 0;
  v->str_val[0] = 0;
  return v;
}

static struct Func *find_func(const char *name) {
  for (int i = 0; i < g_nfuncs; i++)
    if (kstrcmp_n(g_funcs[i].name, name, MAX_IDENT) == 0)
      return &g_funcs[i];
  return 0;
}

static void num_to_str(int64_t n, char *buf, int maxlen) {
  if (n < 0) { *buf++ = '-'; maxlen--; n = -n; }
  char tmp[24];
  int i = 0;
  do { tmp[i++] = (char)('0' + (n % 10)); n /= 10; } while (n && i < 23);
  int j = 0;
  while (i > 0 && j < maxlen - 1) buf[j++] = tmp[--i];
  buf[j] = 0;
}

static int is_truthy(int is_num, int64_t n, const char *s) {
  if (!is_num) return s[0] != 0;
  return n != 0;
}

/* Forward declaration */
static void parse_expr(int *out_is_num, int64_t *out_num, char *out_str, int maxlen);

static void eval_expr(int *out_is_num, int64_t *out_num, char *out_str, int maxlen);

static void parse_primary(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  struct Token *t = advance_tok();
  if (t->type == TOK_NUMBER) {
    *out_is_num = 1;
    *out_num = t->num_val;
    out_str[0] = 0;
    return;
  }
  if (t->type == TOK_STRING) {
    *out_is_num = 0;
    *out_num = 0;
    size_t i = 0;
    while (i < (size_t)(maxlen - 1) && t->str_val[i]) {
      out_str[i] = t->str_val[i]; i++;
    }
    out_str[i] = 0;
    return;
  }
  if (t->type == TOK_TRUE) {
    *out_is_num = 1;
    *out_num = 1;
    out_str[0] = 0;
    return;
  }
  if (t->type == TOK_FALSE) {
    *out_is_num = 1;
    *out_num = 0;
    out_str[0] = 0;
    return;
  }
  if (t->type == TOK_IDENT) {
    if (peek_tok()->type == TOK_LPAREN) {
      advance_tok();
      /* Builtin: dns(hostname) -> dotted IPv4 string, or "" on failure */
      if (t->str_val[0] == 'd' && t->str_val[1] == 'n' && t->str_val[2] == 's' &&
          t->str_val[3] == 0)
      {
        int arg_is_num;
        int64_t arg_num;
        char arg_str[STR_BUF_SIZE];
        arg_str[0] = 0;
        if (peek_tok()->type != TOK_RPAREN)
          eval_expr(&arg_is_num, &arg_num, arg_str, STR_BUF_SIZE);
        if (peek_tok()->type == TOK_RPAREN)
          advance_tok();
        *out_is_num = 0;
        *out_num = 0;
        out_str[0] = 0;
        if (!g_define_pass)
        {
          const char *host = arg_is_num ? "" : arg_str;
          builtin_dns_lookup(host, out_str, maxlen > 0 ? maxlen : STR_BUF_SIZE);
        }
        return;
      }
      struct Func *f = find_func(t->str_val);
      if (!f) {
        log_writestring("ajlang: undefined function ");
        log_writestring(t->str_val);
        log_putchar('\n');
        *out_is_num = 1;
        *out_num = 0;
        return;
      }
      int args_is_num[MAX_PARAMS];
      int64_t args_num[MAX_PARAMS];
      char args_str[MAX_PARAMS][STR_BUF_SIZE];
      int nargs = 0;
      while (peek_tok()->type != TOK_RPAREN && nargs < MAX_PARAMS) {
        eval_expr(&args_is_num[nargs], &args_num[nargs], args_str[nargs], STR_BUF_SIZE);
        nargs++;
        if (peek_tok()->type == TOK_COMMA) advance_tok();
      }
      if (peek_tok()->type == TOK_RPAREN) advance_tok();
      if (g_define_pass) {
        /* Define pass only registers defs; do not execute calls. */
        *out_is_num = 1;
        *out_num = 0;
        out_str[0] = 0;
        return;
      }
      if (nargs != f->nparams) {
        log_writestring("ajlang: wrong arg count\n");
        *out_is_num = 1;
        *out_num = 0;
        return;
      }
      int old_pos = g_tok_pos;
      g_return_flag = 0;
      for (int i = 0; i < f->nparams; i++) {
        struct Var *pv = get_or_add_var(f->params[i]);
        if (pv) {
          pv->is_num = args_is_num[i];
          pv->num_val = args_num[i];
          size_t j = 0;
          while (j < STR_BUF_SIZE - 1 && args_str[i][j]) {
            pv->str_val[j] = args_str[i][j]; j++;
          }
          pv->str_val[j] = 0;
        }
      }
      g_tok_pos = f->body_start;
      while (g_tok_pos < f->body_start + f->body_len && !g_return_flag) {
        int d1, d2; int64_t d3; char d4[STR_BUF_SIZE];
        if (peek_tok()->type == TOK_EOF || peek_tok()->type == TOK_END) break;
        if (peek_tok()->type == TOK_PRINT) {
          advance_tok();
          eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
          if (d1) { log_write_u32((uint32_t)d3); log_putchar('\n'); }
          else { log_writestring(d4); log_putchar('\n'); }
        } else if (peek_tok()->type == TOK_LET) {
          advance_tok();
          struct Token *tn = advance_tok();
          if (tn->type != TOK_IDENT) break;
          advance_tok();
          eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
          struct Var *v = get_or_add_var(tn->str_val);
          if (v) { v->is_num = d1; v->num_val = d3; mem_copy(v->str_val, d4, STR_BUF_SIZE); }
        } else if (peek_tok()->type == TOK_IF) {
          advance_tok();
          eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
          int cond = is_truthy(d1, d3, d4);
          advance_tok();
          int depth = 1;
          int then_len = 0;
          while (depth > 0 && g_tok_pos < g_ntokens) {
            if (g_tokens[g_tok_pos].type == TOK_IF) depth++;
            else if (g_tokens[g_tok_pos].type == TOK_END) { depth--; if (depth == 0) break; }
            else if (g_tokens[g_tok_pos].type == TOK_ELSE && depth == 1) break;
            then_len++;
            g_tok_pos++;
          }
          int saved = g_tok_pos;
          if (cond) {
            g_tok_pos = saved - then_len;
            for (int k = 0; k < then_len; k++) {
              if (g_tokens[g_tok_pos].type == TOK_PRINT) {
                g_tok_pos++;
                eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
                if (d1) { log_write_u32((uint32_t)d3); log_putchar('\n'); }
                else { log_writestring(d4); log_putchar('\n'); }
              } else if (g_tokens[g_tok_pos].type == TOK_LET) {
                g_tok_pos++;
                struct Token *tn2 = &g_tokens[g_tok_pos++];
                g_tok_pos++;
                eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
                struct Var *v = get_or_add_var(tn2->str_val);
                if (v) { v->is_num = d1; v->num_val = d3; mem_copy(v->str_val, d4, STR_BUF_SIZE); }
              } else g_tok_pos++;
            }
          }
          while (g_tok_pos < g_ntokens && (g_tokens[g_tok_pos].type != TOK_ELSE || depth != 1))
            g_tok_pos++;
          if (g_tokens[g_tok_pos].type == TOK_ELSE && depth == 1) {
            g_tok_pos++;
            int else_len = 0;
            depth = 1;
            while (depth > 0 && g_tok_pos < g_ntokens) {
              if (g_tokens[g_tok_pos].type == TOK_IF) depth++;
              else if (g_tokens[g_tok_pos].type == TOK_END) { depth--; if (depth == 0) break; }
              else_len++;
              g_tok_pos++;
            }
            if (!cond) {
              g_tok_pos = g_tok_pos - else_len;
              for (int k = 0; k < else_len; k++) {
                if (g_tokens[g_tok_pos].type == TOK_PRINT) {
                  g_tok_pos++;
                  eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
                  if (d1) { log_write_u32((uint32_t)d3); log_putchar('\n'); }
                  else { log_writestring(d4); log_putchar('\n'); }
                } else if (g_tokens[g_tok_pos].type == TOK_LET) {
                  g_tok_pos++;
                  struct Token *tn2 = &g_tokens[g_tok_pos++];
                  g_tok_pos++;
                  eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
                  struct Var *v = get_or_add_var(tn2->str_val);
                  if (v) { v->is_num = d1; v->num_val = d3; mem_copy(v->str_val, d4, STR_BUF_SIZE); }
                } else g_tok_pos++;
              }
            }
          }
          while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type != TOK_END) g_tok_pos++;
          if (g_tok_pos < g_ntokens) g_tok_pos++;
        } else if (peek_tok()->type == TOK_RETURN) {
          advance_tok();
          if (peek_tok()->type != TOK_NEWLINE && peek_tok()->type != TOK_END && peek_tok()->type != TOK_EOF) {
            eval_expr(&g_return_is_str, &g_return_val, g_return_str, STR_BUF_SIZE);
            g_return_is_str = !g_return_is_str;
          } else {
            g_return_is_str = 1;
            g_return_val = 0;
            g_return_str[0] = 0;
          }
          g_return_flag = 1;
        } else {
          eval_expr(&d1, &d3, d4, STR_BUF_SIZE);
        }
      }
      g_tok_pos = old_pos;
      *out_is_num = !g_return_is_str;  /* g_return_is_str=1 means string, so out_is_num=0 */
      *out_num = g_return_val;
      mem_copy(out_str, g_return_str, maxlen);
      return;
    }
    struct Var *v = find_var(t->str_val);
    if (v) {
      *out_is_num = v->is_num;
      *out_num = v->num_val;
      size_t i = 0;
      while (i < (size_t)(maxlen - 1) && v->str_val[i]) { out_str[i] = v->str_val[i]; i++; }
      out_str[i] = 0;
    } else {
      *out_is_num = 1;
      *out_num = 0;
      out_str[0] = 0;
    }
    return;
  }
  if (t->type == TOK_LPAREN) {
    eval_expr(out_is_num, out_num, out_str, maxlen);
    if (peek_tok()->type == TOK_RPAREN) advance_tok();
    return;
  }
  *out_is_num = 1;
  *out_num = 0;
  out_str[0] = 0;
}

static void parse_unary(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  if (peek_tok()->type == TOK_BANG || peek_tok()->type == TOK_NOT) {
    advance_tok();
    parse_unary(out_is_num, out_num, out_str, maxlen);
    *out_is_num = 1;
    *out_num = is_truthy(*out_is_num, *out_num, out_str) ? 0 : 1;
    out_str[0] = 0;
    return;
  }
  if (peek_tok()->type == TOK_MINUS) {
    advance_tok();
    parse_unary(out_is_num, out_num, out_str, maxlen);
    if (*out_is_num) *out_num = -(*out_num);
    return;
  }
  parse_primary(out_is_num, out_num, out_str, maxlen);
}

static void parse_factor(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_unary(out_is_num, out_num, out_str, maxlen);
  while (peek_tok()->type == TOK_STAR || peek_tok()->type == TOK_SLASH || peek_tok()->type == TOK_PERCENT) {
    int op = advance_tok()->type;
    int r_is_num;
    int64_t r_num;
    char r_str[STR_BUF_SIZE];
    parse_unary(&r_is_num, &r_num, r_str, STR_BUF_SIZE);
    if (op == TOK_STAR) {
      *out_num = (*out_num) * r_num;
    } else if (op == TOK_SLASH) {
      if (r_num == 0) { log_writestring("ajlang: div by zero\n"); return; }
      *out_num = (*out_num) / r_num;
    } else {
      if (r_num == 0) { log_writestring("ajlang: mod by zero\n"); return; }
      *out_num = (*out_num) % r_num;
    }
    *out_is_num = 1;
    out_str[0] = 0;
  }
}

static void parse_term(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_factor(out_is_num, out_num, out_str, maxlen);
  while (peek_tok()->type == TOK_PLUS || peek_tok()->type == TOK_MINUS) {
    int op = advance_tok()->type;
    int r_is_num;
    int64_t r_num;
    char r_str[STR_BUF_SIZE];
    parse_factor(&r_is_num, &r_num, r_str, STR_BUF_SIZE);
    if (op == TOK_PLUS) {
      if (!(*out_is_num) || !r_is_num) {
        static char cat[STR_BUF_SIZE];
        char a[STR_BUF_SIZE], b[STR_BUF_SIZE];
        if (*out_is_num) num_to_str(*out_num, a, STR_BUF_SIZE);
        else { size_t i = 0; while (i < STR_BUF_SIZE - 1 && out_str[i]) { a[i] = out_str[i]; i++; } a[i] = 0; }
        if (r_is_num) num_to_str(r_num, b, STR_BUF_SIZE);
        else { size_t i = 0; while (i < STR_BUF_SIZE - 1 && r_str[i]) { b[i] = r_str[i]; i++; } b[i] = 0; }
        size_t i = 0;
        while (i < STR_BUF_SIZE - 1 && a[i]) { cat[i] = a[i]; i++; }
        size_t j = 0;
        while (i < STR_BUF_SIZE - 1 && b[j]) { cat[i++] = b[j++]; }
        if (i >= STR_BUF_SIZE) i = STR_BUF_SIZE - 1;
        cat[i] = 0;
        *out_is_num = 0;
        *out_num = 0;
        i = 0;
        while (i < maxlen - 1 && cat[i]) { out_str[i] = cat[i]; i++; }
        out_str[i] = 0;
      } else {
        *out_num = *out_num + r_num;
      }
    } else {
      *out_num = *out_num - r_num;
      *out_is_num = 1;
      out_str[0] = 0;
    }
  }
}

static void parse_comparison(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_term(out_is_num, out_num, out_str, maxlen);
  int op = peek_tok()->type;
  if (op == TOK_LT || op == TOK_LE || op == TOK_GT || op == TOK_GE) {
    advance_tok();
    int r_is_num;
    int64_t r_num;
    char r_str[STR_BUF_SIZE];
    parse_term(&r_is_num, &r_num, r_str, STR_BUF_SIZE);
    int cmp = 0;
    if (*out_is_num && r_is_num) {
      if (*out_num < r_num) cmp = -1;
      else if (*out_num > r_num) cmp = 1;
    }
    if (op == TOK_LT) *out_num = (cmp < 0) ? 1 : 0;
    else if (op == TOK_LE) *out_num = (cmp <= 0) ? 1 : 0;
    else if (op == TOK_GT) *out_num = (cmp > 0) ? 1 : 0;
    else *out_num = (cmp >= 0) ? 1 : 0;
    *out_is_num = 1;
    out_str[0] = 0;
  }
}

static void parse_equality(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_comparison(out_is_num, out_num, out_str, maxlen);
  int op = peek_tok()->type;
  if (op == TOK_EQEQ || op == TOK_BANGEQ) {
    advance_tok();
    int r_is_num;
    int64_t r_num;
    char r_str[STR_BUF_SIZE];
    parse_comparison(&r_is_num, &r_num, r_str, STR_BUF_SIZE);
    int eq = (*out_is_num == r_is_num && *out_num == r_num);
    if (*out_is_num == 0 && r_is_num == 0) {
      eq = 1;
      size_t i = 0;
      while (out_str[i] && r_str[i] && out_str[i] == r_str[i]) i++;
      if (out_str[i] != r_str[i]) eq = 0;
    }
    *out_num = (op == TOK_EQEQ) ? (eq ? 1 : 0) : (eq ? 0 : 1);
    *out_is_num = 1;
    out_str[0] = 0;
  }
}

static void parse_and(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_equality(out_is_num, out_num, out_str, maxlen);
  while (peek_tok()->type == TOK_AND) {
    advance_tok();
    int r_is_num;
    int64_t r_num;
    char r_str[STR_BUF_SIZE];
    parse_equality(&r_is_num, &r_num, r_str, STR_BUF_SIZE);
    *out_num = (is_truthy(*out_is_num, *out_num, out_str) && is_truthy(r_is_num, r_num, r_str)) ? 1 : 0;
    *out_is_num = 1;
    out_str[0] = 0;
  }
}

static void parse_or(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_and(out_is_num, out_num, out_str, maxlen);
  while (peek_tok()->type == TOK_OR) {
    advance_tok();
    int r_is_num;
    int64_t r_num;
    char r_str[STR_BUF_SIZE];
    parse_and(&r_is_num, &r_num, r_str, STR_BUF_SIZE);
    *out_num = (is_truthy(*out_is_num, *out_num, out_str) || is_truthy(r_is_num, r_num, r_str)) ? 1 : 0;
    *out_is_num = 1;
    out_str[0] = 0;
  }
}

static void eval_expr(int *out_is_num, int64_t *out_num, char *out_str, int maxlen) {
  parse_or(out_is_num, out_num, out_str, maxlen);
}

static int is_block_open_tok(int t)
{
  return t == TOK_IF || t == TOK_WHILE || t == TOK_FOR || t == TOK_DEF;
}

static void run_statement(void) {
  if (peek_tok()->type == TOK_EOF) return;
  if (peek_tok()->type == TOK_PRINT) {
    advance_tok();
    int is_num;
    int64_t n;
    char s[STR_BUF_SIZE];
    s[0] = 0;
    s[STR_BUF_SIZE - 1] = 0;
    eval_expr(&is_num, &n, s, STR_BUF_SIZE);
    if (!g_define_pass) {
      s[STR_BUF_SIZE - 1] = 0;
      if (is_num) {
        log_write_u32((uint32_t)n);
        log_putchar('\n');
      } else {
        log_writestring(s);
        log_putchar('\n');
      }
    }
    return;
  }
  if (peek_tok()->type == TOK_INPUT) {
    advance_tok();
    struct Token *tn = advance_tok();
    if (tn->type != TOK_IDENT) return;
    if (peek_tok()->type == TOK_STRING || peek_tok()->type == TOK_IDENT) {
      int d1; int64_t d2; char d3[STR_BUF_SIZE];
      eval_expr(&d1, &d2, d3, STR_BUF_SIZE);
      if (!g_define_pass) log_writestring(d3);
    }
    if (g_define_pass) { /* skip input in define pass */ return; }
    static char line[256];
    int i = 0;
    for (;;) {
      int k = input_getkey();
      if (k == '\n' || k == '\r' || k == TOK_EOF) break;
      if (k >= 32 && k < 127 && i < 255) line[i++] = (char)k;
    }
    line[i] = 0;
    int64_t parsed = 0;
    int neg = 0;
    int j = 0;
    if (line[0] == '-') { neg = 1; j = 1; }
    while (line[j] >= '0' && line[j] <= '9')
      parsed = parsed * 10 + (line[j++] - '0');
    struct Var *v = get_or_add_var(tn->str_val);
    if (v) {
      if (j > 0 && (line[j] == 0 || line[j] == '.')) {
        v->is_num = 1;
        v->num_val = neg ? -parsed : parsed;
        v->str_val[0] = 0;
      } else {
        v->is_num = 0;
        v->num_val = 0;
        j = 0;
        while (j < STR_BUF_SIZE - 1 && line[j]) { v->str_val[j] = line[j]; j++; }
        v->str_val[j] = 0;
      }
    }
    return;
  }
  if (peek_tok()->type == TOK_LET) {
    advance_tok();
    struct Token *tn = advance_tok();
    if (tn->type != TOK_IDENT) return;
    advance_tok();
    int is_num;
    int64_t n;
    char s[STR_BUF_SIZE];
    eval_expr(&is_num, &n, s, STR_BUF_SIZE);
    if (!g_define_pass) {
      struct Var *v = get_or_add_var(tn->str_val);
      if (v) {
        v->is_num = is_num;
        v->num_val = n;
        mem_copy(v->str_val, s, STR_BUF_SIZE);
      }
    }
    return;
  }
  if (peek_tok()->type == TOK_IF) {
    advance_tok();
    int cond_is_num, dummy_i;
    int64_t cond_n;
    char cond_s[STR_BUF_SIZE];
    eval_expr(&cond_is_num, &cond_n, cond_s, STR_BUF_SIZE);
    int cond = is_truthy(cond_is_num, cond_n, cond_s);
    if (peek_tok()->type != TOK_THEN) return;
    advance_tok();
    int depth = 1;
    int then_end = g_tok_pos;
    while (depth > 0 && then_end < g_ntokens) {
      if (g_tokens[then_end].type == TOK_IF) depth++;
      else if (g_tokens[then_end].type == TOK_END) { depth--; if (depth == 0) break; }
      else if (g_tokens[then_end].type == TOK_ELSE && depth == 1) break;
      then_end++;
    }
    int else_start = then_end;
    if (g_tokens[then_end].type == TOK_ELSE) {
      else_start++;
      depth = 1;
      while (depth > 0 && else_start < g_ntokens) {
        if (g_tokens[else_start].type == TOK_IF) depth++;
        else if (g_tokens[else_start].type == TOK_END) { depth--; if (depth == 0) break; }
        else_start++;
      }
    }
    int saved_pos = g_tok_pos;
    if (g_define_pass) {
      g_tok_pos = saved_pos;
      while (g_tok_pos < then_end) run_statement();
      if (g_tokens[then_end].type == TOK_ELSE) {
        g_tok_pos = else_start;
        while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type != TOK_END)
          run_statement();
      }
      g_tok_pos = then_end;
    } else if (cond) {
      while (g_tok_pos < then_end) run_statement();
    } else if (g_tokens[then_end].type == TOK_ELSE) {
      g_tok_pos = else_start;
      while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type != TOK_END)
        run_statement();
    }
    if (!g_define_pass) g_tok_pos = (cond ? then_end : g_ntokens);
    while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type != TOK_END) g_tok_pos++;
    if (g_tok_pos < g_ntokens) g_tok_pos++;
    return;
  }
  if (peek_tok()->type == TOK_WHILE) {
    advance_tok();
    int cond_start = g_tok_pos;
    int cond_is_num, dummy_i;
    int64_t cond_n;
    char cond_s[STR_BUF_SIZE];
    eval_expr(&cond_is_num, &cond_n, cond_s, STR_BUF_SIZE);
    if (peek_tok()->type != TOK_DO) return;
    advance_tok();
    int body_start = g_tok_pos;
    int depth = 1;
    while (depth > 0 && g_tok_pos < g_ntokens) {
      int t = g_tokens[g_tok_pos].type;
      if (is_block_open_tok(t)) depth++;
      else if (t == TOK_END) { depth--; if (depth == 0) break; }
      g_tok_pos++;
    }
    int body_end = g_tok_pos++;
    if (!g_define_pass) {
      for (;;) {
        g_tok_pos = cond_start;
        eval_expr(&cond_is_num, &cond_n, cond_s, STR_BUF_SIZE);
        if (!is_truthy(cond_is_num, cond_n, cond_s)) break;
        g_tok_pos = body_start;
        while (g_tok_pos < body_end) {
          run_statement();
          if (g_return_flag) return;
        }
      }
    }
    return;
  }
  if (peek_tok()->type == TOK_FOR) {
    advance_tok();
    struct Token *var_tok = advance_tok();
    if (var_tok->type != TOK_IDENT) return;
    advance_tok();
    int s_is_num, e_is_num;
    int64_t start_val, end_val;
    char dummy[STR_BUF_SIZE];
    eval_expr(&s_is_num, &start_val, dummy, STR_BUF_SIZE);
    if (peek_tok()->type != TOK_TO) return;
    advance_tok();
    eval_expr(&e_is_num, &end_val, dummy, STR_BUF_SIZE);
    if (peek_tok()->type != TOK_DO) return;
    advance_tok();
    int body_start = g_tok_pos;
    int depth = 1;
    while (depth > 0 && g_tok_pos < g_ntokens) {
      int t = g_tokens[g_tok_pos].type;
      if (is_block_open_tok(t)) depth++;
      else if (t == TOK_END) { depth--; if (depth == 0) break; }
      g_tok_pos++;
    }
    int body_end = g_tok_pos++;
    if (!g_define_pass) {
      for (int64_t i = start_val; i <= end_val; i++) {
        struct Var *v = get_or_add_var(var_tok->str_val);
        if (v) { v->is_num = 1; v->num_val = i; v->str_val[0] = 0; }
        g_tok_pos = body_start;
        while (g_tok_pos < body_end) {
          run_statement();
          if (g_return_flag) return;
        }
      }
    }
    return;
  }
  if (peek_tok()->type == TOK_DEF) {
    if (!g_define_pass) {
      /* Skip def in second pass - already registered */
      advance_tok(); /* consume DEF */
      int depth = 1;
      while (depth > 0 && g_tok_pos < g_ntokens) {
        int t = advance_tok()->type;
        if (is_block_open_tok(t)) depth++;
        else if (t == TOK_END) depth--;
      }
      return;
    }
    advance_tok();
    struct Token *name_tok = advance_tok();
    if (name_tok->type != TOK_IDENT) return;
    if (g_nfuncs >= MAX_FUNCS) return;
    struct Func *f = &g_funcs[g_nfuncs++];
    size_t i = 0;
    while (i < MAX_IDENT - 1 && name_tok->str_val[i]) {
      f->name[i] = name_tok->str_val[i]; i++;
    }
    f->name[i] = 0;
    if (peek_tok()->type != TOK_LPAREN) return;
    advance_tok();
    f->nparams = 0;
    while (peek_tok()->type == TOK_IDENT && f->nparams < MAX_PARAMS) {
      struct Token *pt = advance_tok();
      i = 0;
      while (i < MAX_IDENT - 1 && pt->str_val[i]) {
        f->params[f->nparams][i] = pt->str_val[i]; i++;
      }
      f->params[f->nparams][i] = 0;
      f->nparams++;
      if (peek_tok()->type == TOK_COMMA) advance_tok();
    }
    if (peek_tok()->type != TOK_RPAREN) return;
    advance_tok();
    f->body_start = g_tok_pos;
    int depth = 1;
    while (depth > 0 && g_tok_pos < g_ntokens) {
      int t = g_tokens[g_tok_pos].type;
      if (is_block_open_tok(t)) depth++;
      else if (t == TOK_END) { depth--; if (depth == 0) break; }
      g_tok_pos++;
    }
    f->body_len = g_tok_pos - f->body_start;
    g_tok_pos++;
    return;
  }
  if (peek_tok()->type == TOK_RETURN) {
    advance_tok();
    if (peek_tok()->type != TOK_NEWLINE && peek_tok()->type != TOK_END && peek_tok()->type != TOK_EOF) {
      eval_expr(&g_return_is_str, &g_return_val, g_return_str, STR_BUF_SIZE);
      g_return_is_str = !g_return_is_str;
    } else {
      g_return_is_str = 1;
      g_return_val = 0;
      g_return_str[0] = 0;
    }
    g_return_flag = 1;
    return;
  }
  if (peek_tok()->type == TOK_IDENT) {
    int is_num;
    int64_t n;
    char s[STR_BUF_SIZE];
    eval_expr(&is_num, &n, s, STR_BUF_SIZE);
    return;
  }
  /* Skip unknown/stray tokens (e.g. unmatched end) so we never spin forever */
  if (peek_tok()->type != TOK_EOF)
    advance_tok();
}

int ajlang_run(const char *source) {
  if (!source)
    return 0;
  g_source = source;
  g_nvars = 0;
  g_nfuncs = 0;
  g_return_flag = 0;

  if (!lex()) return 0;
  g_tok_pos = 0;

  /* First pass: register function definitions only; skip other statements */
  g_define_pass = 1;
  while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type != TOK_EOF) {
    skip_newlines();
    if (g_tok_pos >= g_ntokens || g_tokens[g_tok_pos].type == TOK_EOF) break;
    run_statement();
  }
  g_tok_pos = 0;
  g_return_flag = 0;

  /* Second pass: execute all statements except DEF (already registered) */
  g_define_pass = 0;
  while (g_tok_pos < g_ntokens && g_tokens[g_tok_pos].type != TOK_EOF) {
    skip_newlines();
    if (g_tok_pos >= g_ntokens || g_tokens[g_tok_pos].type == TOK_EOF) break;
    run_statement();
  }
  return 1;
}
