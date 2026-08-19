/**
 * Llama2.c inference port for AJOS.
 * No libc: kmalloc/kfree, mem_copy/memset, fat12_read_file_to_ram.
 */
#include "llm_inference.h"
#include "kernel.h"
#include <stddef.h>

extern void mem_copy(void *dest, const void *src, size_t n);
extern void *memset(void *s, int c, size_t n);

/* Fallback run buffer when kmalloc fails (e.g. fragmented heap). 128KB. */
#define LLM_STATIC_RUN_FLOATS (32u * 1024u)
static float llm_static_run_buf[LLM_STATIC_RUN_FLOATS];

float sqrtf(float x);
float expf(float x);
float cosf(float x);
float sinf(float x);
float powf(float base, float exp);

static void rmsnorm(float *o, const float *x, const float *weight, int size) {
  float ss = 0.0f;
  for (int j = 0; j < size; j++)
    ss += x[j] * x[j];
  ss /= (float)size;
  ss += 1e-5f;
  ss = 1.0f / sqrtf(ss);
  for (int j = 0; j < size; j++)
    o[j] = weight[j] * (ss * x[j]);
}

static void softmax(float *x, int size) {
  float max_val = x[0];
  for (int i = 1; i < size; i++)
    if (x[i] > max_val)
      max_val = x[i];
  float sum = 0.0f;
  for (int i = 0; i < size; i++) {
    x[i] = expf(x[i] - max_val);
    sum += x[i];
  }
  for (int i = 0; i < size; i++)
    x[i] /= sum;
}

static void matmul(float *xout, const float *x, const float *w, int n, int d) {
  for (int i = 0; i < d; i++) {
    float val = 0.0f;
    for (int j = 0; j < n; j++)
      val += w[i * n + j] * x[j];
    xout[i] = val;
  }
}

static void memory_map_weights(llm_weights_t *w, const llm_config_t *p,
                               float *ptr, int shared_weights) {
  int head_size = p->dim / p->n_heads;
  uint32_t n_layers = (uint32_t)p->n_layers;
  uint32_t dim = (uint32_t)p->dim;
  uint32_t kv_dim = (dim * (uint32_t)p->n_kv_heads) / (uint32_t)p->n_heads;
  uint32_t hidden_dim = (uint32_t)p->hidden_dim;

  w->token_embedding_table = ptr;
  ptr += p->vocab_size * dim;
  w->rms_att_weight = ptr;
  ptr += n_layers * dim;
  w->wq = ptr;
  ptr += n_layers * dim * (uint32_t)(p->n_heads * head_size);
  w->wk = ptr;
  ptr += n_layers * dim * kv_dim;
  w->wv = ptr;
  ptr += n_layers * dim * kv_dim;
  w->wo = ptr;
  ptr += n_layers * (uint32_t)(p->n_heads * head_size) * dim;
  w->rms_ffn_weight = ptr;
  ptr += n_layers * dim;
  w->w1 = ptr;
  ptr += n_layers * dim * hidden_dim;
  w->w2 = ptr;
  ptr += n_layers * hidden_dim * dim;
  w->w3 = ptr;
  ptr += n_layers * dim * hidden_dim;
  w->rms_final_weight = ptr;
  ptr += dim;
  ptr += (uint32_t)(p->seq_len * head_size / 2);
  ptr += (uint32_t)(p->seq_len * head_size / 2);
  w->wcls = shared_weights ? w->token_embedding_table : ptr;
}

int llm_load(llm_transformer_t *t, uint8_t *data, uint32_t size) {
  if (!t || !data || size < sizeof(llm_config_t))
    return -1;

  mem_copy(&t->config, data, sizeof(llm_config_t));
  llm_config_t *p = &t->config;
  /* In llama2.c format, sign of vocab_size indicates shared output weights;
   * normalize for check */
  int shared = p->vocab_size > 0 ? 1 : 0;
  if (p->vocab_size < 0)
    p->vocab_size = -p->vocab_size;
  if (p->vocab_size > 32768)
    return -2; /* cap vocab at 32768 for AJOS */
  /* Reject invalid/corrupt config so run_size cannot overflow or be huge */
  if (p->dim <= 0 || p->dim > 4096 || p->hidden_dim <= 0 ||
      p->hidden_dim > 16384 || p->n_layers <= 0 || p->n_layers > 64 ||
      p->n_heads <= 0 || p->n_heads > 64 || p->n_kv_heads <= 0 ||
      p->n_kv_heads > 64 || p->seq_len <= 0 || p->seq_len > 2048)
    return -2;

  t->data = (float *)(data + sizeof(llm_config_t));
  t->data_len = size;
  memory_map_weights(&t->weights, p, t->data, shared);

  int kv_dim = (p->dim * p->n_kv_heads) / p->n_heads;
  size_t run_size = 0;
  run_size += (size_t)p->dim * 4; /* x, xb, xb2, q */
  run_size += (size_t)p->hidden_dim * 2;
  run_size += (size_t)p->n_layers * p->seq_len * kv_dim * 2;
  run_size += (size_t)p->n_heads * p->seq_len;
  run_size += (size_t)p->vocab_size;
  run_size *= sizeof(float);
  if (run_size > (256u * 1024u * 1024u)) /* cap 256MB */
    return -3;

  float *run = (float *)kmalloc((uint32_t)run_size);
  if (!run) {
    /* Fallback to static buffer if small enough (avoids OOM when heap
     * fragmented) */
    if (run_size <= sizeof(llm_static_run_buf))
      run = llm_static_run_buf;
    else
      return -3;
  }
  memset(run, 0, run_size);
  float *rp = run;
  t->x = rp;
  rp += p->dim;
  t->xb = rp;
  rp += p->dim;
  t->xb2 = rp;
  rp += p->dim;
  t->q = rp;
  rp += p->dim;
  t->hb = rp;
  rp += p->hidden_dim;
  t->hb2 = rp;
  rp += p->hidden_dim;
  t->key_cache = rp;
  rp += (size_t)p->n_layers * p->seq_len * kv_dim;
  t->value_cache = rp;
  rp += (size_t)p->n_layers * p->seq_len * kv_dim;
  t->att = rp;
  rp += (size_t)p->n_heads * p->seq_len;
  t->logits = rp;

  return 0;
}

void llm_free(llm_transformer_t *t) {
  if (!t)
    return;
  /* Run state is one contiguous block: x is the base. Don't kfree static
   * fallback. */
  if (t->x && t->x != llm_static_run_buf)
    kfree(t->x);
  t->x = 0;
  /* Model data was passed in - caller (cmd_llm) frees it via kfree. */
  t->data = 0;
}

float *llm_forward(llm_transformer_t *t, int token, int pos) {
  llm_config_t *p = &t->config;
  llm_weights_t *w = &t->weights;
  float *x = t->x;
  int dim = p->dim;
  int kv_dim = (dim * p->n_kv_heads) / p->n_heads;
  int kv_mul = p->n_heads / p->n_kv_heads;
  int head_size = dim / p->n_heads;
  int hidden_dim = p->hidden_dim;

  float *content_row = w->token_embedding_table + token * dim;
  mem_copy(x, content_row, (size_t)dim * sizeof(float));

  for (int l = 0; l < p->n_layers; l++) {
    rmsnorm(t->xb, x, w->rms_att_weight + l * dim, dim);
    int loff = l * p->seq_len * kv_dim;
    float *k = t->key_cache + loff + pos * kv_dim;
    float *v = t->value_cache + loff + pos * kv_dim;

    matmul(t->q, t->xb, w->wq + l * dim * dim, dim, dim);
    matmul(k, t->xb, w->wk + l * dim * kv_dim, dim, kv_dim);
    matmul(v, t->xb, w->wv + l * dim * kv_dim, dim, kv_dim);

    for (int i = 0; i < dim; i += 2) {
      int head_dim = i % head_size;
      float freq = 1.0f / powf(10000.0f, (float)head_dim / (float)head_size);
      float val = (float)pos * freq;
      float fcr = cosf(val);
      float fci = sinf(val);
      int rotn = (i < kv_dim) ? 2 : 1;
      for (int vv = 0; vv < rotn; vv++) {
        float *vec = (vv == 0) ? t->q : k;
        float v0 = vec[i];
        float v1 = vec[i + 1];
        vec[i] = v0 * fcr - v1 * fci;
        vec[i + 1] = v0 * fci + v1 * fcr;
      }
    }

    for (int h = 0; h < p->n_heads; h++) {
      float *qh = t->q + h * head_size;
      float *att = t->att + h * p->seq_len;
      for (int tt = 0; tt <= pos; tt++) {
        float *kh =
            t->key_cache + loff + tt * kv_dim + (h / kv_mul) * head_size;
        float score = 0.0f;
        for (int i = 0; i < head_size; i++)
          score += qh[i] * kh[i];
        score /= sqrtf((float)head_size);
        att[tt] = score;
      }
      softmax(att, pos + 1);

      float *xb = t->xb + h * head_size;
      memset(xb, 0, (size_t)head_size * sizeof(float));
      for (int tt = 0; tt <= pos; tt++) {
        float *vh =
            t->value_cache + loff + tt * kv_dim + (h / kv_mul) * head_size;
        float a = att[tt];
        for (int i = 0; i < head_size; i++)
          xb[i] += a * vh[i];
      }
    }

    matmul(t->xb2, t->xb, w->wo + l * dim * dim, dim, dim);
    for (int i = 0; i < dim; i++)
      x[i] += t->xb2[i];

    rmsnorm(t->xb, x, w->rms_ffn_weight + l * dim, dim);
    matmul(t->hb, t->xb, w->w1 + l * dim * hidden_dim, dim, hidden_dim);
    matmul(t->hb2, t->xb, w->w3 + l * dim * hidden_dim, dim, hidden_dim);

    for (int i = 0; i < hidden_dim; i++) {
      float val = t->hb[i];
      val *= (1.0f / (1.0f + expf(-val)));
      val *= t->hb2[i];
      t->hb[i] = val;
    }

    matmul(t->xb, t->hb, w->w2 + l * hidden_dim * dim, hidden_dim, dim);
    for (int i = 0; i < dim; i++)
      x[i] += t->xb[i];
  }

  rmsnorm(x, x, w->rms_final_weight, dim);
  matmul(t->logits, x, w->wcls, dim, p->vocab_size);
  return t->logits;
}
