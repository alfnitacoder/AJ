# 64-bit parity plan

The 32-bit kernel is the feature-complete AJOS image (SSH/SFTP, processes, TLS, DHCP/DNS, full AJLang). The 64-bit port (`make test64`, `qemu-system-x86_64`) is a parallel kernel that must reach the same surface before the 32-bit image can be retired. Milestones 1–15 are in the tree. This file is the ordered list of what is still missing and how each step is proven.

`make test64` boots the 64-bit image, curls the guest web server, and greps `build/serial64.log` (and the curl captures). Every milestone below names the string that grep must find. A milestone is done only when that assertion is in the Makefile and the run passes.

## What 64-bit already does (milestones 1–15)

| Milestone | In the 64-bit kernel |
|---|---|
| 1 | Long mode boot, serial banner |
| 2 | IDT, PIC, PIT 100 Hz, bitmap PMM |
| 3 | 4 KB paging, NX, kernel heap |
| 4 | e1000 (polling) + ARP/IPv4/ICMP |
| 5 | One TCP connection, HTTP GET |
| 6 | ATA PIO + read-only FAT12/16 |
| 7 | Serial shell (`ls`/`cat`/`ping`/`http`/…) |
| 8–9, 11, 13–14 | AJLang subset, including `file_read`/`file_write`, `http_get`, `str_find`/`str_sub`, `query` |
| 10 | Ring 3 via `syscall`/`sysret`, TSS, user segments |
| 12–14 | TCP :80, visit counter, guestbook POST |
| 15 | `run FILE.UP` loads a flat binary into the user window (exec-style, no parent) |

## Gap against the 32-bit kernel

Still only on the 32-bit side:

- **Processes.** `fork` / `execve` / `waitpid`, per-process user frames, preemption on the ring-3 timer boundary, `sleep` that blocks, `ps` / `kill` / `wait`, background jobs. (Milestone 16 starts this. The shell `run` command is still the milestone 15 loader.)
- **Address space.** 32-bit tasks each get a private page directory. 64-bit tasks share one user window that is remapped on switch.
- **Images.** 32-bit AJOSBIN programs use a multi-page window. 64-bit user programs are one 4 KB code page and one 4 KB stack.
- **AJLang.** 64-bit has `var`/`print`/`if`/`else`/`while`, arithmetic and comparisons, `str_len`/`str_cat`/`str_find`/`str_sub`, `num`, `file_read`/`file_write`, `http_get`, `query`. 32-bit also has `for`, `def`/`return`, `and`/`or`/`not`, `input`, `import` and `/opt` packages, `dns()`, `http_get_save()`, `edit()`.
- **Network beyond a single TCP connection.** UDP, DHCP client, DNS client, DHCP server, DNS server, a multi-connection TCP stack, TLS 1.2, the HTTP file server, the text browser.
- **SSH and SFTP.** Host key, password auth, a shell session, and the SFTP subsystem used by sshfs.
- **Console.** VGA text output and a keyboard IRQ. The graphical desktop was removed from the 32-bit tree (`5ad3692`) and is not a port target.
- **Accounts and files.** Salted SHA-512 passwords, VFS, directories, long names, `rm`, a current directory. 64-bit FAT is an 8.3 root with read and write.

Not a port target: the LLM module (already dropped from the 32-bit build) and the vendored OpenSSH buffer sources (an SSH implementation detail, not a user-facing feature).

## Why milestone 16 is next

Milestone 15 can place a binary in the user window, but `exit` never returns to a parent and the timer does not switch tasks. That is the hole under every later service that wants a job: a shell that can wait, a background DHCP server, an SSH session that is a process. The SSH server is the feature people miss most, and it also needs the crypto and packet layer (milestones 23–25). Those do not unblock the scheduler. Process semantics do, and they are the unfinished half of milestones 10 and 15.

## Milestone 16 — ring-3 processes (this tree)

Scheduled ring-3 tasks with `fork`, `execve`, `waitpid`, `getpid`, `getppid`, `exit` (code in `rdi`), blocking `sleep`, and a preemptive round-robin on IRQ0. The quantum is 10 PIT ticks (100 ms), the same boundary the 32-bit timer uses: kernel code is not preempted. `fork` copies the code and stack frames. `execve` replaces the caller. `waitpid` reaps a zombie and writes the raw exit code. The boot image runs an embedded `FORKDEMO` (fork, spin so the timer can switch, wait for exit 42, exec `CHILD64`).

Syscall numbers in 64-bit (the 32-bit `int 0x80` register convention is different; both `exit` numbers are accepted):

| rax | Call |
|---|---|
| 1 | `write` (`rsi` = buffer, `rdx` = length) |
| 2 and 5 | `exit` (`rdi` = code) |
| 3 | `sleep` (`rdi` = milliseconds) |
| 6 | `getpid` |
| 7 | `getppid` |
| 8 | `ticks` |
| 16 | `fork` (child gets 0, parent gets the pid) |
| 17 | `execve` (`rdi` = path; embedded name or a FAT file) |
| 18 | `waitpid` (`rdi` = pid or 0, `rsi` = `u64 *` status) |

Deliberately not in this milestone: private CR3s, images bigger than 4 KB, `argv`, COW, shell `ps`/`kill`, and making `run` return to the shell. A process-less `exit` (the milestone 10 demo and `run`) still enters the shell.

**test64:** `FORK-WAIT-OK-16`, `EXECVE-OK-16`, `PREEMPT-OK-16`, `M16-RETURN-OK`, and the banner `LONG MODE MILESTONE 16`.

## Milestone 17 — shell job control

Wire the scheduler into the serial shell. `run FILE` spawns a foreground process and returns to the **same** shell when it exits (today `exit` with no process starts a nested `sh64`). Add `ps`, `kill`, `wait`, and `cmd &`. `sleep` from a program must block in the scheduler instead of spinning.

**test64:** a boot-spawned parent prints `SLEEP-OK-17` after a child blocks in `sleep` for at least 200 ms, then `WAIT-BG-OK-17` from `waitpid` of that child. Serial also contains a `ps` line `PS-OK-17` taken while the child is still alive.

## Milestone 18 — private address spaces

Give each process its own PML4: kernel mappings shared, user window private, `CR3` switched in the scheduler. The milestone 16 remap of one global window cannot hold two resident user mappings, so it cannot prove isolation under a stale TLB.

**test64:** the kernel prints two different CR3 values and `CR3-SWITCH-OK-18`. The parent plants a canary in its window, the child writes a different one at the same virtual address, and the parent prints `AS-ISOLATED-18` after `waitpid` when its canary is unchanged.

## Milestone 19 — multi-page programs

Raise the user image limit past 4 KB (code) and 4 KB (stack). Add a `brk` syscall so a program can grow its heap. Load the bytes from FAT the way milestone 15 loads a single page.

**test64:** a disk image larger than 4 KB prints `BIGIMAGE-OK-19` from an address past the first page, then grows the break and prints `BRK-OK-19`.

## Milestone 20 — AJLang parity

Bring `ajlang64` up to the 32-bit language: `for`, `def`/`return`, `and`/`or`/`not`, `true`/`false`, `input`, `import` of `/opt` packages, `dns()`, `http_get_save()`, and `edit()` once the editor exists (the builtin can return a clear "not yet" until milestone 29, but `def` and `dns` must really run).

**test64:** `FULL.TXT` prints `AJLANG-FULL-OK-20` by calling a `def`, looping with `for`, and branching on `and`.

## Milestone 21 — UDP, DHCP client, DNS client

Port UDP and the DHCP client (QEMU user-net is the DHCP server) and the DNS client. Needed before the 64-bit image can configure itself the way the 32-bit image does, and before milestones 22–24 have a transport.

**test64:** serial contains `DHCP-LEASE-OK-21` with a leased address, then `DNS-OK-21` for a name resolved through the slirp DNS (`10.0.2.3`).

## Milestone 22 — DHCP and DNS servers

Port `dhcpd` and `dnsd`. The 32-bit image serves both on the primary interface.

**test64:** an in-kernel DNS query aimed at the local server prints `DNSD-OK-22`. A crafted DHCP discover handled by the local server prints `DHCPD-OK-22`.

## Milestone 23 — TLS 1.2

Port the X25519 + AES-128-GCM server (self-signed cert from the host key, :443, hostfwd). This is the crypto dependency SSH sits on top of.

**test64:** `curl -k` of the forwarded port returns a body containing `TLS-OK-23`.

## Milestone 24 — SSH server

Port the SSH server: banner, key exchange, password auth (`user`/`pass`), and a session that runs a shell command. Sessions should be processes (milestones 16–17), not a second copy of the shell loop.

**test64:** an `ssh` command from the host prints `SSH-OK-24`.

## Milestone 25 — SFTP

Port the SFTP subsystem (`ls` / `get` / `put` on FAT) so sshfs works against the 64-bit image the way `test_sftp.sh` works against the 32-bit image.

**test64:** an sftp batch lists `HELLO.TXT` and the log contains `SFTP-LS-OK-25`.

## Milestone 26 — VGA text and keyboard

Port VGA text output and the keyboard IRQ so the console is not serial-only. No graphical desktop.

**test64:** write a marker to `0xB8000` and read it back; serial contains `VGA-TEXT-OK-26`.

## Milestone 27 — accounts

Port salted SHA-512 password hashing and session expiry. Login on the shell and over SSH checks the same database.

**test64:** a known test vector prints `AUTH-OK-27`, and a bad password prints `AUTH-DENY-27`.

## Milestone 28 — directories and VFS

Port directory create/list/remove, long file names, `rm`, and a current working directory, with the FAT root behind the same path lookup the 32-bit VFS uses.

**test64:** create a file under a new directory, list it, delete it; serial contains `VFS-OK-28`.

## Milestone 29 — editor, browser, syslog, clock

Port the text editor, the text-mode browser, syslog to a log file, and the clock. These are the remaining user-facing tools once the network and the file tree exist.

**test64:** a syslog line written and read back prints `SYSLOG-OK-29`, and the clock prints `DATETIME-OK-29`.

## Retiring the 32-bit kernel

After milestone 29, `make test64` covers the 32-bit surface that `make test-fork`, `make test-net`, `test_ssh_connect.sh`, and `test_sftp.sh` cover today. The 32-bit image stays the default until that run is green; then `make run` can switch to the 64-bit kernel.
