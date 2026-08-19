# Memory and CPU (AJOS kernel)

## Allocators in use

The linked kernel uses **`kernel/mm/slab.c`** for `kmalloc` / `kfree`, not the standalone `kernel/mm/heap.c` (that file is kept for reference but is **not** linked in the default build).

| Request size | Backing |
|--------------|---------|
| `0` | `NULL` |
| `1 … 2048` | Slab caches (32, 64, …, 2048 bytes) inside 4 KiB pages |
| `> 2048` | Buddy **PMM** (`pmm_alloc_page`) — **whole pages** (e.g. each `struct pbuf` is ~2 KiB of struct + 2048 B payload → one or more pages) |

So **network traffic** (many `pbuf`s) and **large buffers** (SSH TX/RX, FAT reads) show up as **PMM page use**, not tiny slab slots.

## Shell: inspect usage

- **`mem`** — PMM free/total pages + kmalloc counters (short).
- **`heap`** — Same PMM picture + explanation and leak-hunting hint.

Counters (since boot):

- **`kmalloc ok`** — successful allocations.
- **`kfree`** — `kfree(ptr)` calls with non-NULL `ptr`.
- **`kmalloc_fail`** — allocation refused (OOM / no slab).

If **`(ok - kfree)`** increases while the system is **idle** (no intentional new objects), suspect a **missing `kfree`** or a path that allocates without a matching free. This is an **indicator**, not a precise “live object count” (e.g. some code paths may allocate more than once per logical object).

## Leak hunting (practical)

1. Boot, log in, run `heap` twice with no workload → note `ok`, `kf`, `ok - kf`.
2. Run a suspect command (SSH session, `ping`, file ops) many times.
3. Run `heap` again → if `ok - kf` jumped and stayed high, grep that feature for `kmalloc` / `pbuf_alloc` and verify every success path calls `kfree` / `pbuf_free`.
4. Watch **`kmalloc_fail`** — if it rises under load, you may be **fragmented** or out of RAM (especially large pbufs).

## CPU while waiting for keys

`input_getkey()` already uses **`hlt`** when neither the keyboard queue nor serial has data, so the shell idle loop is not a tight spin. Timer and device IRQs still run (network, PIT, etc.).

For long **polling** loops in commands, prefer waiting on **`pit_ticks`** or calling **`netdev_napi_poll()`** so the stack keeps moving without burning time.

## Related files

- `kernel/mm/slab.c` — `kmalloc` / `kfree`, `mm_kmalloc_stats()`
- `kernel/mm/pmm.c` — physical buddy allocator
- `kernel/mm/heap.c` — alternate heap (not linked by default)
- `src/pbuf.c` — network buffers
- `include/pbuf.h` — `PBUF_PAYLOAD_CAP` (RX must not overflow `buffer_s[]`)
