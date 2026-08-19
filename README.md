# AJOS - A Simple Operating System

## Features

- Bootloader (x86 assembly)
- Protected mode switch
- 32-bit C kernel
- VGA text output

## Build & Run

### Prerequisites

- `nasm`, `x86_64-elf-gcc`, `x86_64-elf-ld`, `x86_64-elf-objcopy`, `qemu-system-i386`

### Build

```sh
make clean && make
```

### Run

```sh
make run-console
```

**`make run`** opens the QEMU **VGA window** (same kernel as above, no `AJOS_SERIAL_ONLY`). It uses **`-m 512M -vga std`**: the PMM/navigation code assumes enough guest RAM; **omitting `-m` (QEMU’s small default) used to cause random memory corruption and a screen full of VGA garbage.** If the window still looks wrong on macOS, use `make run-console` or try a locally built QEMU (see below).

If **QEMU segfaults on macOS** (e.g. "Segmentation fault: 11"), especially on **Apple Silicon (M1/M2/M3) with macOS 15.0–15.3**:
- **Option A (recommended):** Build QEMU from source so it matches your OS (takes ~10–20 min): `brew install --build-from-source qemu`, then run `make run-console` again.
- **Option B:** Upgrade macOS to 15.4 or later; the prebuilt QEMU bottle then works.
- **Option C:** Build the image and run elsewhere: `make run-console-img`, copy `build/ajos.run.img` to a Linux machine, then run: `qemu-system-i386 -m 512M -boot a -drive file=ajos.run.img,format=raw,if=floppy -nographic -serial stdio -no-reboot`

**Serial console:** With `make run-console`, the AJOS shell and all kernel output appear in the **terminal** (serial), not in the QEMU window. Log in at the prompt and run `ls` (should list README.TXT, HELLO.AJ, STORIES.BIN, TOK512.BIN, PASSWD, etc.) and `llm hello`.

**Network smoke test (QEMU):** From the repo root, run `make test-net`. This builds with `AJOS_NET_AUTOTEST`, boots in QEMU, runs ARP + `ping 10.0.2.2` + DNS + `ping 1.1.1.1`, then shuts down. Closes other QEMU instances first if you see a disk “lock” error. Log: `build/net-autotest.log`.

### ISO (CD) boot

1. **Build:** `make iso` — requires **xorriso** or **genisoimage** (macOS: `brew install xorriso`). Produces `build/ajos.iso` with El Torito **1.44 MB floppy emulation** (`boot.img` = same image as the floppy).
2. **Check:** `make iso-verify` — prints the El Torito table (expect **BIOS**, **fd1.4**, path `/boot.img`).
3. **QEMU:** `make run-iso` — serial console in the terminal (like `run-console`). Other VMs are killed first so `build/data.img` is not locked.
4. **If the ISO “won’t boot”:**
   - **UEFI / Secure Boot:** This ISO is **legacy BIOS only** (floppy emulation). In VirtualBox/VMware, enable **BIOS** or disable UEFI-only boot.
   - **`Failed to get "write" lock` on `data.img`:** Stop other QEMU/VMs using the AJOS tree, or run from a copy of the repo.
   - **`Error: need xorriso or genisoimage`:** Install xorriso.
   - **Stuck after “Booting from DVD/CD”:** Try **`make run-console`** (floppy); if that works, the problem is CD/firmware-specific.
5. **Easiest path for daily dev:** `make run-console` (floppy) — same kernel as the ISO, fewer moving parts.
6. **Proxmox VE:** Build `make iso`, upload `build/ajos.iso`, use **SeaBIOS** and **Intel E1000** NIC. Full steps: **[docs/PROXMOX.md](docs/PROXMOX.md)**. Shortcut: `make proxmox-iso` (same as `make iso`, prints the ISO path).

## Project Structure

- `asm/` - Assembly sources (bootloader, protected mode, kernel entry)
- `src/` - C kernel
- `include/` - Kernel headers
- `build/` - Build artifacts
- `Makefile` - Build system
- `README.md` - This file
- **`docs/MEMORY.md`** — how `kmalloc`/PMM work, `mem` / `heap` commands, leak hints, CPU idle (`hlt`)
