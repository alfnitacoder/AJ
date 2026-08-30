#ifndef AJLANG_H
#define AJLANG_H

/* Run an AJLang .aj source file. Returns 1 on success, 0 on error. */
int ajlang_run(const char *source);

/* ---- ajlangweb: request context + output capture (used by http.c via
 * ajlang_run_webapp in kernel.c) ---- */
void webreq_begin(const char *method, const char *path, const char *query,
                  const char *body);
void webreq_end(void);
int webreq_take_redirect(char *out, int cap);
void ajlang_capture_begin(char *buf, int cap);
int ajlang_capture_len(void);

#endif
