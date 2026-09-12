/* ajlang64.c - AJLang interpreter (language subset) for the x86-64 port.
 * Tree-walking evaluator built on the kernel heap (kmalloc64). Supports:
 *   var x = expr        print expr            name = expr
 *   if (cond) { } else { }                    while (cond) { }
 *   expr: numbers, "strings", idents, + - * / %, == != < > <= >=,
 *         str_len(s), str_cat(a,b), num(s), file_read("NAME.TXT")
 * Comments: # to end of line. One statement per line or separated by ';'.
 * Scripts are read from the FAT disk (fat64) by the shell: aj FILE. */

typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef unsigned long long u64;

extern void *kmalloc64(unsigned long long n);
extern int fat64_read_file(const char *name, void *out, unsigned int cap);
extern int tcp64_http_get_body(unsigned int ip, unsigned short port,
                               const char *path, char *out, unsigned short cap);

#define COM1 0x3F8
static inline void outb(u16 port, u8 val)
{
    __asm__ __volatile__("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline u8 inb(u16 port)
{
    u8 v;
    __asm__ __volatile__("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static void ser_putc(char c)
{
    int spins = 100000;
    while (!(inb(COM1 + 5) & 0x20)) {
        if (--spins <= 0) return;
    }
    outb(COM1, (u8)c);
}
static void ser_puts(const char *s)
{
    while (*s) {
        if (*s == '\n') ser_putc('\r');
        ser_putc(*s++);
    }
}
static void ser_put_dec(unsigned long long v)
{
    char buf[21];
    int i = 0;
    if (!v) { ser_putc('0'); return; }
    while (v) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i) ser_putc(buf[--i]);
}

/* ---- lexer ---- */
#define MAXTOK 512
typedef struct {
    int kind;            /* 0 num, 1 str, 2 ident, 3 op/punct */
    long num;
    char str[64];
    char op;
    int line;
} tok_t;

static tok_t toks[MAXTOK];
static int ntok;
static int aj_err;

static void lex(const char *src)
{
    int i = 0, line = 1;
    ntok = 0;
    aj_err = 0;
    while (src[i] && ntok < MAXTOK) {
        char c = src[i];
        if (c == '\n') { line++; i++; continue; }
        if (c == ' ' || c == '\t' || c == '\r') { i++; continue; }
        if (c == '#') { while (src[i] && src[i] != '\n') i++; continue; }
        if (c >= '0' && c <= '9') {
            long v = 0;
            while (src[i] >= '0' && src[i] <= '9') {
                v = v * 10 + (src[i] - '0');
                i++;
            }
            toks[ntok].kind = 0;
            toks[ntok].num = v;
            toks[ntok].line = line;
            ntok++;
            continue;
        }
        if (c == '"') {
            int n = 0;
            i++;
            while (src[i] && src[i] != '"' && n < 62) {
                toks[ntok].str[n++] = src[i++];
            }
            if (src[i] == '"') i++;
            toks[ntok].str[n] = 0;
            toks[ntok].kind = 1;
            toks[ntok].line = line;
            ntok++;
            continue;
        }
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_') {
            int n = 0;
            while (((src[i] >= 'a' && src[i] <= 'z') ||
                    (src[i] >= 'A' && src[i] <= 'Z') ||
                    (src[i] >= '0' && src[i] <= '9') || src[i] == '_') && n < 62) {
                toks[ntok].str[n++] = src[i++];
            }
            toks[ntok].str[n] = 0;
            toks[ntok].kind = 2;
            toks[ntok].line = line;
            ntok++;
            continue;
        }
        if ((c == '=' && src[i + 1] == '=') ||
            (c == '!' && src[i + 1] == '=') ||
            (c == '<' && src[i + 1] == '=') ||
            (c == '>' && src[i + 1] == '=')) {
            toks[ntok].kind = 3;
            toks[ntok].op = (char)(c == '=' ? 'E' : c == '!' ? 'N' :
                                   c == '<' ? 'L' : 'G');
            toks[ntok].line = line;
            ntok++;
            i += 2;
            continue;
        }
        if (c == ';' || c == '(' || c == ')' || c == '{' || c == '}' || c == ',' ||
            c == '+' || c == '-' || c == '*' || c == '/' || c == '%' ||
            c == '=' || c == '<' || c == '>') {
            toks[ntok].kind = 3;
            toks[ntok].op = c;
            toks[ntok].line = line;
            ntok++;
            i++;
            continue;
        }
        aj_err = line;      /* unknown char */
        return;
    }
    toks[ntok].kind = 9;    /* EOF sentinel */
    toks[ntok].line = line;
}

/* ---- AST ---- */
typedef enum { N_NUM, N_STR, N_VAR, N_BIN, N_STRLEN, N_STRCAT, N_NUMCVT,
               N_FREAD, N_HTTPGET, N_STRFIND, N_STRSUB } ntype;

typedef struct node {
    ntype t;
    long num;
    char *str;
    struct node *l, *r;
    struct node *a1, *a2;
} node;

typedef struct stmt {
    int kind;               /* 0 print, 1 assign, 2 if, 3 while, 4 block */
    node *expr;             /* print / assign-value / if / while cond */
    char *name;             /* assign target */
    struct stmt *body, *els;
    struct stmt *next;
} stmt;

typedef struct { long num; char *str; int is_str; } val_t;

static int strcmp64(const char *a, const char *b);

#define MAXVAR 32
static struct { char name[32]; val_t v; } vars[MAXVAR];
static int nvars;

static val_t v_num(long n)  { val_t v; v.is_str = 0; v.num = n; v.str = 0; return v; }
static val_t v_str(char *s) { val_t v; v.is_str = 1; v.num = 0; v.str = s; return v; }

static val_t *var_lookup(const char *name)
{
    int i;
    for (i = 0; i < nvars; i++)
        if (!strcmp64(vars[i].name, name)) return &vars[i].v;
    return 0;
}

/* small strcmp local (freestanding) */
static int strcmp64(const char *a, const char *b)
{
    while (*a && *a == *b) { a++; b++; }
    return (u8)*a - (u8)*b;
}

static char *str_dup64(const char *s)
{
    int n = 0;
    char *d;
    while (s[n]) n++;
    d = (char *)kmalloc64((u64)n + 1);
    {
        int i;
        for (i = 0; i <= n; i++) d[i] = s[i];
    }
    return d;
}

/* ---- parser ---- */
static int tp;               /* token pointer */

static node *parse_expr(void);

static node *node_new(ntype t)
{
    node *n = (node *)kmalloc64(sizeof(node));
    n->t = t;
    n->num = 0;
    n->str = 0;
    n->l = n->r = n->a1 = n->a2 = 0;
    return n;
}

static node *parse_primary(void)
{
    tok_t *t = &toks[tp];
    if (t->kind == 9) { aj_err = t->line; return 0; }
    if (t->kind == 0) {
        node *n = node_new(N_NUM);
        n->num = t->num;
        tp++;
        return n;
    }
    if (t->kind == 1) {
        node *n = node_new(N_STR);
        n->str = str_dup64(t->str);
        tp++;
        return n;
    }
    if (t->kind == 2) {
        if (!strcmp64(t->str, "str_len") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_STRLEN);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        if (!strcmp64(t->str, "str_cat") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_STRCAT);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ',') tp++;
            n->r = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        if (!strcmp64(t->str, "num") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_NUMCVT);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        if (!strcmp64(t->str, "file_read") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_FREAD);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        if (!strcmp64(t->str, "http_get") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_HTTPGET);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        if (!strcmp64(t->str, "str_find") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_STRFIND);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ',') tp++;
            n->r = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        if (!strcmp64(t->str, "str_sub") && toks[tp + 1].kind == 3 &&
            toks[tp + 1].op == '(') {
            node *n = node_new(N_STRSUB);
            tp += 2;
            n->l = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ',') tp++;
            n->r = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ',') tp++;
            n->a1 = parse_expr();
            if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
            return n;
        }
        {
            node *n = node_new(N_VAR);
            n->str = str_dup64(t->str);
            tp++;
            return n;
        }
    }
    if (t->kind == 3 && t->op == '(') {
        node *n;
        tp++;
        n = parse_expr();
        if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
        return n;
    }
    aj_err = t->line;
    return 0;
}

static node *parse_term(void)
{
    node *l = parse_primary();
    while (toks[tp].kind == 3 && (toks[tp].op == '*' || toks[tp].op == '/' ||
                                  toks[tp].op == '%')) {
        node *n = node_new(N_BIN);
        n->num = toks[tp].op;
        tp++;
        n->l = l;
        n->r = parse_primary();
        l = n;
    }
    return l;
}

static node *parse_expr(void)
{
    node *l = parse_term();
    while (toks[tp].kind == 3 && (toks[tp].op == '+' || toks[tp].op == '-')) {
        node *n = node_new(N_BIN);
        n->num = toks[tp].op;
        tp++;
        n->l = l;
        n->r = parse_term();
        l = n;
    }
    return l;
}

static node *parse_cond(void)
{
    node *l = parse_expr();
    if (toks[tp].kind == 3 && (toks[tp].op == 'E' || toks[tp].op == 'N' ||
                               toks[tp].op == 'L' || toks[tp].op == 'G' ||
                               toks[tp].op == '<' || toks[tp].op == '>')) {
        node *n = node_new(N_BIN);
        n->num = (toks[tp].op == '<' || toks[tp].op == '>') ? toks[tp].op : toks[tp].op;
        tp++;
        n->l = l;
        n->r = parse_expr();
        return n;
    }
    return l;
}

static stmt *parse_block(void);

static stmt *stmt_new(int kind)
{
    stmt *st = (stmt *)kmalloc64(sizeof(stmt));
    st->kind = kind;
    st->expr = 0;
    st->name = 0;
    st->body = st->els = st->next = 0;
    return st;
}

static stmt *parse_stmt(void)
{
    tok_t *t = &toks[tp];
    if (t->kind == 9) return 0;
    if (t->kind == 3 && t->op == ';') { tp++; return parse_stmt(); }
    if (t->kind == 2 && !strcmp64(t->str, "print")) {
        stmt *st = stmt_new(0);
        tp++;
        st->expr = parse_expr();
        return st;
    }
    if (t->kind == 2 && !strcmp64(t->str, "var") && toks[tp + 1].kind == 2) {
        stmt *st = stmt_new(1);
        st->name = str_dup64(toks[tp + 1].str);
        tp += 2;
        if (toks[tp].kind == 3 && toks[tp].op == '=') {
            tp++;
            st->expr = parse_expr();
        }
        return st;
    }
    if (t->kind == 2 && !strcmp64(t->str, "if")) {
        stmt *st = stmt_new(2);
        tp++;
        if (toks[tp].kind == 3 && toks[tp].op == '(') tp++;
        st->expr = parse_cond();
        if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
        st->body = parse_block();
        if (toks[tp].kind == 2 && !strcmp64(toks[tp].str, "else")) {
            tp++;
            st->els = parse_block();
        }
        return st;
    }
    if (t->kind == 2 && !strcmp64(t->str, "while")) {
        stmt *st = stmt_new(3);
        tp++;
        if (toks[tp].kind == 3 && toks[tp].op == '(') tp++;
        st->expr = parse_cond();
        if (toks[tp].kind == 3 && toks[tp].op == ')') tp++;
        st->body = parse_block();
        return st;
    }
    if (t->kind == 2 && toks[tp + 1].kind == 3 && toks[tp + 1].op == '=') {
        stmt *st = stmt_new(1);
        st->name = str_dup64(t->str);
        tp += 2;
        st->expr = parse_expr();
        return st;
    }
    aj_err = t->line;
    return 0;
}

static stmt *parse_block(void)
{
    stmt *head = 0, *tail = 0;
    if (toks[tp].kind == 3 && toks[tp].op == '{') tp++;
    while (!(toks[tp].kind == 9 || (toks[tp].kind == 3 && toks[tp].op == '}'))) {
        stmt *st = parse_stmt();
        if (!st) break;
        if (tail) tail->next = st;
        else head = st;
        tail = st;
        if (toks[tp].kind == 3 && toks[tp].op == ';') tp++;
    }
    if (toks[tp].kind == 3 && toks[tp].op == '}') tp++;
    return head;
}

/* ---- evaluator ---- */
#define MAXSTR 256

static val_t eval(node *n, int depth)
{
    val_t r = v_num(0);
    if (!n || depth > 100) return r;
    switch (n->t) {
    case N_NUM:  return v_num(n->num);
    case N_STR:  return v_str(n->str);
    case N_VAR: {
        val_t *v = var_lookup(n->str);
        return v ? *v : v_num(0);
    }
    case N_STRLEN: {
        val_t a = eval(n->l, depth + 1);
        long len = 0;
        if (a.is_str) while (a.str[len]) len++;
        return v_num(len);
    }
    case N_STRCAT: {
        val_t a = eval(n->l, depth + 1);
        val_t b = eval(n->r, depth + 1);
        char *d = (char *)kmalloc64(MAXSTR);
        int i = 0, k = 0;
        char tmp[24];
        const char *sa, *sb;
        if (a.is_str) sa = a.str;
        else {
            long x = a.num; int neg = 0; char buf[24]; int bi = 0;
            if (!x) buf[bi++] = '0';
            if (x < 0) { neg = 1; x = -x; }
            while (x) { buf[bi++] = (char)('0' + (x % 10)); x /= 10; }
            if (neg) tmp[k++] = '-';
            while (bi) tmp[k++] = buf[--bi];
            tmp[k] = 0;
            sa = tmp;
        }
        if (b.is_str) sb = b.str;
        else {
            long x = b.num; int neg = 0; char buf[24]; int bi = 0;
            if (!x) buf[bi++] = '0';
            if (x < 0) { neg = 1; x = -x; }
            while (x) { buf[bi++] = (char)('0' + (x % 10)); x /= 10; }
            if (neg) tmp[k++] = '-';
            while (bi) tmp[k++] = buf[--bi];
            tmp[k] = 0;
            sb = tmp;
        }
        while (sa[i] && i < MAXSTR - 2) { d[i] = sa[i]; i++; }
        while (sb[k] && i < MAXSTR - 2) { d[i++] = sb[k++]; }
        d[i] = 0;
        return v_str(d);
    }
    case N_NUMCVT: {
        val_t a = eval(n->l, depth + 1);
        if (a.is_str) {
            long v = 0;
            const char *s = a.str;
            while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
            return v_num(v);
        }
        return v_num(a.num);
    }
    case N_FREAD: {
        val_t a = eval(n->l, depth + 1);
        static char fb[512];
        if (a.is_str) {
            int n = fat64_read_file(a.str, fb, sizeof(fb) - 1);
            if (n < 0) n = 0;
            fb[n] = 0;
            return v_str(fb);
        }
        return r;
    }
    case N_HTTPGET: {
        val_t a = eval(n->l, depth + 1);
        static char hb[1024];
        u32 target = *(volatile u32 *)0x74000u;
        if (!target) target = 0x0202000Au;
        if (a.is_str) {
            int code = tcp64_http_get_body(target, 8130, a.str, hb, sizeof(hb));
            if (code == 200) return v_str(hb);
        }
        return v_str((char *)"");
    }
    case N_STRFIND: {
        val_t a = eval(n->l, depth + 1);
        val_t b = eval(n->r, depth + 1);
        long idx = -1;
        if (a.is_str && b.is_str) {
            long i, j;
            for (i = 0; a.str[i]; i++) {
                for (j = 0; b.str[j] && a.str[i + j] == b.str[j]; j++) { }
                if (!b.str[j]) { idx = i; break; }
            }
        }
        return v_num(idx);
    }
    case N_STRSUB: {
        val_t a = eval(n->l, depth + 1);
        val_t b = eval(n->r, depth + 1);
        val_t c = eval(n->a1, depth + 1);
        char *d = (char *)kmalloc64(MAXSTR);
        long i, k = 0;
        long start = b.num, len = c.num;
        for (i = 0; i < MAXSTR - 1; i++) d[i] = 0;
        if (a.is_str && start >= 0 && len >= 0) {
            for (i = start; a.str[i] && i < start + len && k < MAXSTR - 1; i++)
                d[k++] = a.str[i];
        }
        d[k] = 0;
        return v_str(d);
    }
    case N_BIN: {
        val_t a = eval(n->l, depth + 1);
        val_t b = eval(n->r, depth + 1);
        char op = (char)n->num;
        if (op == '+') {
            if (a.is_str || b.is_str) {
                /* string concat via + too */
                node tmpn;
                node l2 = *n->l, r2 = *n->r;
                (void)l2; (void)r2;
                {
                    /* reuse STRCAT path */
                    char *d = (char *)kmalloc64(MAXSTR);
                    int i = 0, k = 0;
                    char t1[24], t2[24];
                    const char *sa, *sb;
                    if (a.is_str) sa = a.str;
                    else {
                        long x = a.num; char buf[24]; int bi = 0;
                        if (!x) buf[bi++] = '0';
                        while (x) { buf[bi++] = (char)('0' + (x % 10)); x /= 10; }
                        while (bi) t1[i++] = buf[--bi];
                        t1[i] = 0; sa = t1; i = 0;
                    }
                    if (b.is_str) sb = b.str;
                    else {
                        long x = b.num; char buf[24]; int bi = 0;
                        if (!x) buf[bi++] = '0';
                        while (x) { buf[bi++] = (char)('0' + (x % 10)); x /= 10; }
                        while (bi) t2[k++] = buf[--bi];
                        t2[k] = 0; sb = t2;
                    }
                    while (sa[i] && i < MAXSTR - 2) { d[i] = sa[i]; i++; }
                    while (sb[k] && i < MAXSTR - 2) { d[i++] = sb[k++]; }
                    d[i] = 0;
                    return v_str(d);
                }
            }
            return v_num(a.num + b.num);
        }
        if (op == '-') return v_num(a.num - b.num);
        if (op == '*') return v_num(a.num * b.num);
        if (op == '/') return v_num(b.num ? a.num / b.num : 0);
        if (op == '%') return v_num(b.num ? a.num % b.num : 0);
        if (op == 'E') return v_num(!a.is_str == !b.is_str && a.num == b.num &&
                                    (a.is_str ? !strcmp64(a.str, b.str) : 1));
        if (op == 'N') return v_num(a.is_str != b.is_str || a.num != b.num ||
                                    (a.is_str ? strcmp64(a.str, b.str) : 0));
        if (op == '<') return v_num(a.num < b.num);
        if (op == '>') return v_num(a.num > b.num);
        if (op == 'L') return v_num(a.num <= b.num);
        if (op == 'G') return v_num(a.num >= b.num);
        return r;
    }
    }
    return r;
}

static void print_val(val_t v)
{
    if (v.is_str) {
        const char *s = v.str;
        while (*s) ser_putc(*s++);
    } else {
        ser_put_dec((u64)v.num);
    }
    ser_puts("\n");
}

static void exec_stmts(stmt *head, int depth);

static void exec_stmt(stmt *st, int depth)
{
    if (!st || depth > 200) return;
    switch (st->kind) {
    case 0:
        print_val(eval(st->expr, depth));
        break;
    case 1: {
        val_t v = eval(st->expr, depth);
        val_t *slot = var_lookup(st->name);
        if (!slot && nvars < MAXVAR) {
            int i = 0;
            while (st->name[i] && i < 31) { vars[nvars].name[i] = st->name[i]; i++; }
            vars[nvars].name[i] = 0;
            slot = &vars[nvars].v;
            slot->is_str = 0;
            slot->num = 0;
            slot->str = 0;
            nvars++;
        }
        if (slot) *slot = v;
        break;
    }
    case 2: {
        val_t c = eval(st->expr, depth);
        if (c.is_str ? c.str[0] != 0 : c.num != 0) exec_stmts(st->body, depth + 1);
        else exec_stmts(st->els, depth + 1);
        break;
    }
    case 3: {
        int guard = 0;
        while (guard++ < 100000) {
            val_t c = eval(st->expr, depth);
            if (c.is_str ? c.str[0] == 0 : c.num == 0) break;
            exec_stmts(st->body, depth + 1);
        }
        break;
    }
    }
}

static void exec_stmts(stmt *head, int depth)
{
    stmt *s;
    for (s = head; s; s = s->next)
        exec_stmt(s, depth);
}

/* ---- entry: run a script from the FAT disk ---- */
static u8 aj_src[4096];
static u8 aj_out[4096];

int ajlang64_run(const char *name)
{
    int n, i, out = 0;
    n = fat64_read_file(name, aj_src, sizeof(aj_src) - 1);
    if (n < 0) {
        ser_puts(" aj: script not found\n");
        return -1;
    }
    aj_src[n] = 0;
    lex((const char *)aj_src);
    if (aj_err) {
        ser_puts(" aj: lex error at line ");
        ser_put_dec((u64)aj_err);
        ser_puts("\n");
        return -2;
    }
    nvars = 0;
    tp = 0;
    {
        stmt *prog = parse_block();
        if (aj_err) {
            ser_puts(" aj: parse error at line ");
            ser_put_dec((u64)aj_err);
            ser_puts("\n");
            return -3;
        }
        (void)out;
        (void)aj_out;
        exec_stmts(prog, 0);
    }
    return 0;
}
