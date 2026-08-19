# Offline LLM Integration for AJOS

## Current implementation (Phase 2)

- `llm` shell command – loads llama2.c model and runs inference
- Inference engine: `src/llm_inference.c`, `src/llm_math.c` (minimal expf, sqrtf, cosf, sinf, powf)
- Uses x87 FPU (LLM modules compiled without `-msoft-float` for compatibility)
- Model: llama2.c checkpoint (Config + float weights), vocab 256 (byte-level)
- Files: `STORIES.BIN` (weights) on floppy or `/mnt`; optional `TOK512.BIN` / `TOK32K.BIN` for tokenizer-backed decode
- Memory: `kmalloc`/`kfree`, `fat12_read_file_to_ram`

**Usage:** `llm [prompt]`  
(default prompt: "Once upon a time")

## Model requirements

- Format: llama2.c checkpoint (run.c compatible)
- vocab_size: 256 (byte-level only; no tokenizer.bin)
- Example: stories15M.bin from [llama2.c](https://github.com/karpathy/llama2.c)

## Minimal test model

Run `make build/ajos.img` – if `data/model.bin` is missing, `tools/mkminimodel.py` generates a ~400KB minimal model (dim=64, 2 layers). Output will be gibberish but validates the pipeline. To use a real model, replace `data/model.bin` with a llama2.c checkpoint, then rebuild.

## Disk layout

- Boot floppy: OS + kernel + files from `data/` (~1.44MB)
- IDE data drive: Also built from `data/` when using `make run-console`
- Floppy: `data/STORIES.BIN` + other small `data/*` files; IDE data disk: `STORIES42.BIN` when built with `$(DATA_IMG)`
