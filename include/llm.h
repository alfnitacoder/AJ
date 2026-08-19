#ifndef LLM_H
#define LLM_H

/* Run LLM inference on prompt. Offline - loads model from disk.
 * Phase 1: stub - reports status. Phase 2: integrate llama.cpp/ggml. */
void cmd_llm(const char *args);

#endif /* LLM_H */
