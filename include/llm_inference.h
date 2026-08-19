#ifndef LLM_INFERENCE_H
#define LLM_INFERENCE_H

#include <stdint.h>

/* Llama2.c-compatible model config and inference.
 * Byte-level vocab (256): no tokenizer.bin needed.
 */

typedef struct {
  int32_t dim;
  int32_t hidden_dim;
  int32_t n_layers;
  int32_t n_heads;
  int32_t n_kv_heads;
  int32_t vocab_size;
  int32_t seq_len;
} llm_config_t;

typedef struct {
  float *token_embedding_table;
  float *rms_att_weight;
  float *rms_ffn_weight;
  float *wq, *wk, *wv, *wo;
  float *w1, *w2, *w3;
  float *rms_final_weight;
  float *wcls;
} llm_weights_t;

typedef struct {
  llm_config_t config;
  llm_weights_t weights;
  float *data;       /* raw model data (owned) */
  uint32_t data_len; /* bytes */
  float *x, *xb, *xb2, *hb, *hb2, *q;
  float *key_cache, *value_cache;
  float *att;
  float *logits;
} llm_transformer_t;

/* Load model from buffer (Config + weights). data is taken ownership of. */
int llm_load(llm_transformer_t *t, uint8_t *data, uint32_t size);

/* Free model and run state. */
void llm_free(llm_transformer_t *t);

/* Forward pass: token at pos -> logits. */
float *llm_forward(llm_transformer_t *t, int token, int pos);

#endif /* LLM_INFERENCE_H */
