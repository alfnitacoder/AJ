# Debugging SSH shell “freezes” on AJOS

## Symptom checklist

| Observation | Likely cause |
|-------------|----------------|
| Wireshark shows TCP payloads on :22, **guest serial has no `[SSH] Encrypted RX`** | Guest not running `tcp_input` / NIC poll (IRQs off, or main loop blocked before poll) |
| **`[SSH] DBG: processing=1, append-only`** every 64 packets | `conn->processing` stuck at 1 forever (handler never returned), or **`shell_execute` ran inside CHANNEL_DATA** before the packet was consumed so nested RX only appended ciphertext |
| **`[SSH] WARN: ssh TX mirror-guard leak`** | Leaked `ssh_suppress_log_mirror_to_session` / guard depth from SSH TX (should not happen); recover on next RX |
| Client disconnect / “Bad packet length” / MAC error | `recv_ctr`/`recv_seq` desync (e.g. decrypting same buffer twice, or partial-packet CTR advance) |
| TCP ESTABLISHED but **seq ≠ rcv_nxt** drops payload | Strict in-order TCP; hole or wrong `rcv_nxt` → data never passed to SSH |

## Where to log (AJOS)

1. **`tcp.c` — `tcp_input_body` ESTABLISHED, port 22**  
   - Log when `data_len > 0` but `seq != pcb->rcv_nxt` (out-of-order / retrans).  
   - Log immediately before `ssh_handle_connection(pcb, payload, data_len)`.

2. **`ssh.c` — `ssh_handle_connection` top**  
   - After `sshbuf_put`: `rx_buf` length.  
   - On `if (conn->processing) return`: already instrumented (rate-limited).  
   - On encrypted path: first 4 bytes of ciphertext + `recv_seq` before decrypt.

3. **`ssh.c` — end of `ssh_handle_connection`**  
   - Confirm `processing` cleared; SSH TX mirror-guard recovery is logged if needed.

4. **Not a separate “SSH reader task” on AJOS**  
   SSH runs **synchronously** inside `tcp_input` → `ssh_handle_connection`. If the **CPU never returns** from a command (`shell_execute` infinite loop) or **interrupts stay off**, you will see **no further SSH logs** even if the host keeps sending TCP segments.

## Network stack + SSH: from connect to “after a command”

AJOS has **no background SSH thread**. The path is always:

1. **NIC** → IRQ / timer `netdev_napi_poll` → IP → **`tcp_input` → `tcp_input_body`**
2. For **port 22**, **ESTABLISHED**, **in-order** payload (`seq == pcb->rcv_nxt`):  
   **`ssh_handle_connection(pcb, payload, data_len)`** appends bytes to `conn->rx_buf`, then parses/decrypts SSH frames and dispatches messages.
3. **`tcp_tick(pit_ticks)`** (timer IRQ) drives **retransmits**, **keepalive-ish** state, and is required for a healthy stack while long commands run.
4. **After the client sends a line** (`CHANNEL_DATA` with `\r`): the server **queues** the shell line and runs **`shell_execute`** only **after** the current SSH record is **`sshbuf_consume`d** (`ssh_flush_pending_shell_commands`), with **`conn->processing = 0`** during the command so **nested** `tcp_input` can still **decrypt** further client packets while e.g. **`ping`** calls **`net_pump_rx`**.

**Implications**

- The **whole network stack** (including **other** sockets) shares the same **non-preemptive** execution: a **buggy infinite loop** inside `shell_execute` blocks **everything** until it returns.
- **`ssh_suppress_log_mirror_to_session`** is raised around **TCP logging** and **SSH TX** so **`log_putchar` → SSH mirror** does not **re-enter** SSH from inside **`tcp_input`** / TX and corrupt buffers.
- **Do not** disable interrupts for long SSH sends; that **freezes `pit_ticks`** and wedges **TCP + ping** (see pitfall §3 in *Pitfalls*).

## RFC 4254 / OpenSSH behaviour (your questions)

### EOF / CLOSE after a normal shell command?

**No.** For an interactive shell, finishing `ping` does **not** require `SSH_MSG_CHANNEL_EOF` (96) or `SSH_MSG_CHANNEL_CLOSE` (97). The session channel stays open; the client keeps sending `CHANNEL_DATA` (94) for keystrokes.

### What should appear when the client types?

Encrypted transport packets whose **plaintext** is mostly **`SSH_MSG_CHANNEL_DATA` (94)** with a small string (often one byte per packet for line discipline). You may also see **`SSH_MSG_CHANNEL_WINDOW_ADJUST` (93)** from the client as it extends **your** send window after reading output.

### PTY master/slave / `read()` blocking?

Classic **Unix sshd** uses a **pipe or pty pair** and **select/poll** between socket and pty. **AJOS** does not use a POSIX PTY in the kernel SSH path: input is **`CHANNEL_DATA` → line buffer → `shell_execute`**. There is **no** blocking `read()` on a PTY master unless you added that yourself elsewhere.

### Channel window

If you never send **`SSH_MSG_CHANNEL_WINDOW_ADJUST`** after consuming inbound `CHANNEL_DATA`, the **client’s** send window can drop to **zero** and it **stops sending** (still ESTABLISHED at TCP). Always **add back** the consumed string length after processing client channel data, and **handle inbound type 93** to extend **your** outbound credit.

## Pitfalls already hit in this codebase

1. **Nested `ssh_handle_connection` on unconsumed `rx_buf`**  
   Decrypts the same ciphertext twice with advanced CTR → garbage length / MAC failure. **Do not** call full `ssh_handle_connection` from inside a handler while the current record is still in `rx_buf`.

2. **Advancing `recv_ctr` before the full SSH packet + MAC is buffered**  
   TCP splits records; early CTR commit desyncs the stream.

3. **`cli` around SSH TX (removed)**  
   Holding **IF=0** for a large `help`/`ping` mirror blocks **PIT + NIC IRQs** → `pit_ticks` stops, `tcp_tick` stalls, `ping` wait loops never complete, **whole network wedges** (even serial console). SSH TX now uses **`ssh_suppress_log_mirror_to_session`** only (see `ssh_tx_irq_enter` in `ssh.c`).

4. **Double guard per `CHANNEL_DATA` chunk**  
   One outer **`ssh_tx_irq_enter`** for the whole multi-chunk send and **`ssh_skip_tx_irq_wrappers`** so inner `ssh_send_packet` does not bump the guard again.

5. **`shell_execute` while `conn->processing == 1` inside one SSH record**  
   Reentrant `ssh_handle_connection` only appends to `rx_buf` and returns, so **no `[SSH] Encrypted RX`** for client keystrokes until the outer handler finishes. Long commands (`ping`) then look “stuck”. **Fix:** queue the shell line and run it **after** `sshbuf_consume` for that packet, with **`processing = 0`** during `shell_execute` so nested TCP/SSH can decrypt and drain the queue (see `shell_pending_*` / `ssh_flush_pending_shell_commands` in `ssh.c`).
