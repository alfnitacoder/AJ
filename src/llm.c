/**
 * LLM (Large Language Model) offline inference for AJOS.
 *
 * Port of llama2.c: load checkpoint + tokenizer (BPE), run inference.
 * stories260K etc. need TOK512.BIN + correct BPE encode (not raw bytes).
 */
#include "llm.h"
#include "fat.h"
#include "kernel.h"
#include "llm_inference.h"
#include "vfs.h"
#include <stddef.h>
#include <stdint.h>

extern void log_writestring(const char *s);
extern void log_putchar(char c);
extern float expf(float x);
extern int kstreq(const char *a, const char *b);

#define BOS 1
#define EOS 2
#define MAX_PROMPT 256
#define MAX_PROMPT_TOKENS 512
#define MAX_STEPS 64

static unsigned int random_u32(uint64_t *state) {
  *state ^= *state >> 12;
  *state ^= *state << 25;
  *state ^= *state >> 27;
  return (unsigned int)((*state * 0x2545F4914F6CDD1DULL) >> 32);
}

static float random_f32(uint64_t *state) {
  return (float)(random_u32(state) >> 8) / 16777216.0f;
}

static int sample_argmax(const float *logits, int n) {
  int max_i = 0;
  float max_p = logits[0];
  for (int i = 1; i < n; i++) {
    if (logits[i] > max_p) {
      max_i = i;
      max_p = logits[i];
    }
  }
  return max_i;
}

static int sample_mult(const float *probs, int n, float coin) {
  float cdf = 0.0f;
  for (int i = 0; i < n; i++) {
    cdf += probs[i];
    if (coin < cdf)
      return i;
  }
  return n - 1;
}

/* Byte-level: apply temp to logits, softmax in-place, sample. */
static int sample(float *logits, int vocab_size, float temperature,
                  uint64_t *rng) {
  if (temperature <= 0.0f)
    return sample_argmax(logits, vocab_size);
  for (int q = 0; q < vocab_size; q++)
    logits[q] /= temperature;
  /* softmax in-place */
  float max_val = logits[0];
  for (int i = 1; i < vocab_size; i++)
    if (logits[i] > max_val)
      max_val = logits[i];
  float sum = 0.0f;
  for (int i = 0; i < vocab_size; i++) {
    logits[i] = expf(logits[i] - max_val);
    sum += logits[i];
  }
  for (int i = 0; i < vocab_size; i++)
    logits[i] /= sum;
  float coin = random_f32(rng);
  return sample_mult(logits, vocab_size, coin);
}

/* Single-byte strings for <0xHH> decode (llama2.c). */
static unsigned char g_byte_piece[512];
static uint32_t tokenizer_max_len = 0;
static char **vocab_strs = 0;
static float *vocab_scores = 0;
static int vocab_loaded = 0;

/* Fallback when no tokenizer: BOS + raw bytes (256-vocab byte models only). */
static int encode_prompt_byte(const char *text, int *tokens, int max_tokens) {
  int n = 0;
  if (n < max_tokens)
    tokens[n++] = BOS;
  for (const char *c = text; *c && n < max_tokens; c++)
    tokens[n++] = (unsigned char)*c;
  return n;
}

static int str_lookup_id(const char *str, int vocab_size) {
  if (!vocab_strs)
    return -1;
  for (int i = 0; i < vocab_size; i++)
    if (kstreq(str, vocab_strs[i]))
      return i;
  return -1;
}

static void str_cat_vocab(char *dst, uint32_t cap, const char *a,
                          const char *b) {
  uint32_t o = 0;
  while (o + 1u < cap && a && *a)
    dst[o++] = (unsigned char)*a++;
  while (o + 1u < cap && b && *b)
    dst[o++] = (unsigned char)*b++;
  dst[o] = '\0';
}

/* llama2.c encode(): BPE + UTF-8, optional dummy " " after BOS. */
static int encode_prompt_bpe(const char *text, int *tokens, int max_tokens,
                             int vocab_size) {
  uint32_t mtl = tokenizer_max_len;
  if (mtl < 1u)
    mtl = 256u;
  uint32_t buf_sz = mtl * 2u + 32u;
  char *str_buffer = (char *)kmalloc(buf_sz);
  if (!str_buffer)
    return -1;

  int n_tokens = 0;
  if (n_tokens < max_tokens)
    tokens[n_tokens++] = BOS;

  if (text[0] != '\0') {
    int dummy = str_lookup_id(" ", vocab_size);
    if (dummy >= 0 && n_tokens < max_tokens)
      tokens[n_tokens++] = dummy;
  }

  size_t str_len = 0;
  for (const char *c = text; *c != '\0'; c++) {
    if (((unsigned char)*c & 0xC0u) != 0x80u)
      str_len = 0;
    if (str_len + 1u >= buf_sz) {
      kfree(str_buffer);
      return -1;
    }
    str_buffer[str_len++] = *c;
    str_buffer[str_len] = '\0';

    if (((unsigned char)c[1] & 0xC0u) == 0x80u && str_len < 4u)
      continue;

    int id = str_lookup_id(str_buffer, vocab_size);
    if (id != -1) {
      if (n_tokens >= max_tokens) {
        kfree(str_buffer);
        return -1;
      }
      tokens[n_tokens++] = id;
    } else {
      for (size_t i = 0; i < str_len; i++) {
        if (n_tokens >= max_tokens) {
          kfree(str_buffer);
          return -1;
        }
        tokens[n_tokens++] = (int)((unsigned char)str_buffer[i] + 3u);
      }
    }
    str_len = 0;
  }

  while (1) {
    float best_score = -1e10f;
    int best_id = -1;
    int best_idx = -1;
    for (int i = 0; i < n_tokens - 1; i++) {
      str_cat_vocab(str_buffer, buf_sz, vocab_strs[tokens[i]],
                    vocab_strs[tokens[i + 1]]);
      int id = str_lookup_id(str_buffer, vocab_size);
      if (id != -1 && vocab_scores[id] > best_score) {
        best_score = vocab_scores[id];
        best_id = id;
        best_idx = i;
      }
    }
    if (best_idx < 0)
      break;
    tokens[best_idx] = best_id;
    for (int i = best_idx + 1; i < n_tokens - 1; i++)
      tokens[i] = tokens[i + 1];
    n_tokens--;
  }

  kfree(str_buffer);
  return n_tokens;
}

static int encode_prompt(const char *text, int *tokens, int max_tokens,
                         int vocab_size) {
  if (vocab_loaded && vocab_strs)
    return encode_prompt_bpe(text, tokens, max_tokens, vocab_size);
  return encode_prompt_byte(text, tokens, max_tokens);
}

static uint8_t *load_file_vfs(const char *path, uint32_t *out_size) {
  struct vfs_ctx *vfs = vfs_get_global();
  uint32_t size = 0;
  if (!vfs_stat(vfs, path, &size))
    return 0;
  uint8_t *buf = (uint8_t *)kmalloc(size ? size : 1);
  if (!buf)
    return 0;
  int fd = vfs_open(vfs, path, VFS_FD_READ);
  if (fd < 0) {
    kfree(buf);
    return 0;
  }
  int read = vfs_read(vfs, fd, buf, size);
  vfs_close(vfs, fd);
  if (read < (int)size) {
    kfree(buf);
    return 0;
  }
  *out_size = size;
  return buf;
}

static void load_tokenizer(int vocab_size) {
  if (vocab_loaded)
    return;
  uint8_t *buf = 0;
  uint32_t size = 0;
  const char *paths[] = {"/mnt/TOK32K.BIN", "/mnt/TOK.BIN", "/TOK32K.BIN",
                         "/TOK512.BIN",     "TOK.BIN",      0};
  for (int i = 0; paths[i]; i++) {
    buf = load_file_vfs(paths[i], &size);
    if (buf)
      break;
  }
  if (!buf)
    return;

  char **vs = (char **)kmalloc((uint32_t)vocab_size * sizeof(char *));
  float *vsc = (float *)kmalloc((uint32_t)vocab_size * sizeof(float));
  if (!vs || !vsc) {
    if (vs)
      kfree(vs);
    if (vsc)
      kfree(vsc);
    kfree(buf);
    return;
  }
  vocab_strs = vs;
  vocab_scores = vsc;

  for (int bi = 0; bi < 256; bi++) {
    g_byte_piece[(unsigned)bi * 2u] = (unsigned char)bi;
    g_byte_piece[(unsigned)bi * 2u + 1u] = '\0';
  }

  uint8_t *ptr = buf;
  {
    int32_t mtl = *(int32_t *)ptr;
    tokenizer_max_len = (mtl > 0 && mtl <= 8192) ? (uint32_t)mtl : 256u;
  }
  ptr += 4;
  for (int i = 0; i < vocab_size; i++) {
    vocab_scores[i] = *(float *)ptr;
    ptr += 4;
    int len = *(int *)ptr;
    ptr += 4;
    if (len < 0 || len > 65536) {
      for (int j = 0; j < i; j++)
        kfree(vocab_strs[j]);
      kfree(vocab_strs);
      kfree(vocab_scores);
      vocab_strs = 0;
      vocab_scores = 0;
      kfree(buf);
      return;
    }
    vocab_strs[i] = (char *)kmalloc((uint32_t)len + 1u);
    if (!vocab_strs[i]) {
      for (int j = 0; j < i; j++)
        kfree(vocab_strs[j]);
      kfree(vocab_strs);
      kfree(vocab_scores);
      vocab_strs = 0;
      vocab_scores = 0;
      kfree(buf);
      return;
    }
    mem_copy(vocab_strs[i], ptr, (size_t)len);
    vocab_strs[i][len] = '\0';
    ptr += len;
  }
  vocab_loaded = 1;
  kfree(buf);
}

static void free_tokenizer(int vocab_size) {
  if (!vocab_loaded)
    return;
  for (int i = 0; i < vocab_size; i++)
    kfree(vocab_strs[i]);
  kfree(vocab_strs);
  kfree(vocab_scores);
  vocab_strs = 0;
  vocab_scores = 0;
  vocab_loaded = 0;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F')
    return 10 + (c - 'A');
  return -1;
}

/* llama2.c decode(): strip leading space after BOS; handle <0xHH> raw bytes. */
static void llm_print_piece(int prev_token, int token, int vocab_size) {
  if (token < 0 || token >= vocab_size || !vocab_strs)
    return;
  const char *piece = vocab_strs[token];
  if (prev_token == BOS && piece[0] == ' ')
    piece++;
  if (piece[0] == '<' && piece[1] == '0' && piece[2] == 'x') {
    int hi = hex_nibble(piece[3]);
    int lo = hex_nibble(piece[4]);
    if (hi >= 0 && lo >= 0 && piece[5] == '>') {
      unsigned v = (unsigned)(hi * 16 + lo);
      if (v < 256u)
        piece = (const char *)&g_byte_piece[v * 2u];
    }
  }
  for (int i = 0; piece[i]; i++) {
    unsigned char u = (unsigned char)piece[i];
    if ((u >= 32u && u < 127u) || u == '\n' || u == '\t')
      log_putchar(piece[i]);
  }
}

void cmd_llm(const char *args) {
  uint8_t *model_buf = 0;
  uint32_t model_size = 0;
  int found = 0;
  int from_slot = 0; /* 1 = pointer from file_slot_peek; do not kfree */

  /* Use pre-loaded model from slot without copying (saves ~400KB heap for run
   * buffer) */
  if (file_slot_peek("_llm_model", &model_buf, &model_size) == 1 && model_buf &&
      model_size > 0) {
    found = 1;
    from_slot = 1;
  }
  if (!found && file_slot_read("_llm_model", &model_buf, &model_size) == 1 &&
      model_buf && model_size > 0)
    found = 1;
  if (!found) {
    const char *paths[] = {"/mnt/STORIES42.BIN", "/mnt/STORIES4.BIN",
                           "/mnt/STORIES.BIN",   "/STORIES42.BIN",
                           "/STORIES4.BIN",      "/STORIES.BIN",
                           "STORIES.BIN",        0};
    for (int i = 0; paths[i]; i++) {
      model_buf = load_file_vfs(paths[i], &model_size);
      if (model_buf) {
        found = 1;
        log_writestring("[LLM] Loaded model from ");
        log_writestring(paths[i]);
        log_putchar('\n');
        break;
      }
    }
  }
  if (!found) {
    log_writestring(
        "LLM: model not found globally or on /mnt. Put STORIES.BIN on disk.\n");
    return;
  }

  llm_transformer_t t;
  int load_ret = llm_load(&t, model_buf, model_size);
  /* If we used slot and load failed (e.g. slot corrupted), try reading from
   * disk */
  if (load_ret != 0 && from_slot) {
    uint8_t *disk_buf = 0;
    uint32_t disk_size = 0;
    const char *fallback_paths[] = {"/mnt/STORIES42.BIN", "/mnt/STORIES4.BIN",
                                    "/mnt/STORIES.BIN",   "/STORIES42.BIN",
                                    "/STORIES4.BIN",      "/STORIES.BIN",
                                    "STORIES.BIN",        0};
    for (int i = 0; fallback_paths[i]; i++) {
      disk_buf = load_file_vfs(fallback_paths[i], &disk_size);
      if (disk_buf && disk_size > 0) {
        load_ret = llm_load(&t, disk_buf, disk_size);
        if (load_ret == 0) {
          model_buf = disk_buf;
          model_size = disk_size;
          from_slot = 0;
          break;
        }
        kfree(disk_buf);
        disk_buf = 0;
      }
    }
  }
  if (load_ret != 0) {
    if (load_ret == -1)
      log_writestring("LLM: load failed -1 (bad args or size)\n");
    else if (load_ret == -2)
      log_writestring("LLM: load failed -2 (wrong format / config)\n");
    else if (load_ret == -3)
      log_writestring("LLM: load failed -3 (OOM)\n");
    else
      log_writestring("LLM: failed to load model (wrong format or OOM)\n");
    if (!from_slot && model_buf)
      kfree(model_buf);
    return;
  }

  /* Prompt from args */
  char prompt[MAX_PROMPT];
  int plen = 0;
  if (args) {
    while (*args == ' ')
      args++;
    while (*args && plen < MAX_PROMPT - 1)
      prompt[plen++] = *args++;
  }
  prompt[plen] = '\0';
  if (plen == 0) {
    const char *def = "Once upon a time";
    while (*def && plen < MAX_PROMPT - 1)
      prompt[plen++] = *def++;
    prompt[plen] = '\0';
  }

  load_tokenizer(t.config.vocab_size);
  if (!vocab_loaded)
    log_writestring(
        "[LLM] No tokenizer (TOK512.BIN etc.); BPE encode disabled.\n");

  int prompt_tokens[MAX_PROMPT_TOKENS];
  int num_prompt =
      encode_prompt(prompt, prompt_tokens, MAX_PROMPT_TOKENS, t.config.vocab_size);
  if (num_prompt < 1) {
    log_writestring("LLM: encode failed (prompt too long?)\n");
    llm_free(&t);
    free_tokenizer(t.config.vocab_size);
    if (!from_slot)
      kfree(model_buf);
    return;
  }

  int token = prompt_tokens[0];
  int pos = 0;
  uint64_t rng = 0x123456789ABCDEFULL;
  int steps = 128; /* longer for real stories */

  while (pos < steps) {
    float *logits = llm_forward(&t, token, pos);
    int next;
    if (pos < num_prompt - 1)
      next = prompt_tokens[pos + 1];
    else
      next = sample(logits, t.config.vocab_size, 0.8f, &rng);
    int prev = token;
    pos++;
    if (next == EOS || next == BOS)
      break;
    /* Only print generated continuation (not teacher-forced prompt). */
    if (pos >= num_prompt)
      llm_print_piece(prev, next, t.config.vocab_size);
    token = next;
  }

  log_putchar('\n');
  log_writestring("LLM: done\n");
  free_tokenizer(t.config.vocab_size);
  llm_free(&t);
  if (!from_slot)
    kfree(model_buf);
}
