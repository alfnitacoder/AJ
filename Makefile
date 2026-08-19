CC = x86_64-elf-gcc
AS = nasm
LD = x86_64-elf-ld
OBJCOPY = x86_64-elf-objcopy

SRC_DIR = src
ASM_DIR = asm
INC_DIR = include
BUILD_DIR = build

# Disable SSE/MMX/x87 so the kernel runs on the QEMU i386 CPU model.
CFLAGS = -m32 -march=i386 -mno-sse -mno-sse2 -mno-mmx -mno-80387 -msoft-float -fno-pie -fno-stack-protector -nostdlib -nostdinc -fno-builtin -fno-pic -I$(INC_DIR)
ASFLAGS = -f elf32
LDFLAGS = -m elf_i386 -T $(BUILD_DIR)/linker.ld
# LLM uses x87 FPU (no -msoft-float) - toolchain lacks i386 soft-float libgcc
LLM_CFLAGS = -m32 -march=i386 -mno-sse -mno-sse2 -mno-mmx -fno-pie -fno-stack-protector -nostdlib -nostdinc -fno-builtin -fno-pic -I$(INC_DIR)

BOOT_SRC = $(ASM_DIR)/boot.asm
KERNEL_ENTRY_SRC = $(ASM_DIR)/kernel_entry.asm
ISR_SRC = $(ASM_DIR)/isr.asm
BIOS_SRC = $(ASM_DIR)/bios.asm
GDT_SRC = $(ASM_DIR)/gdt.asm
USER_MODE_SRC = $(ASM_DIR)/user_mode.asm
DEMO_SRC = $(ASM_DIR)/demo_prog.asm
KERNEL_SRC = $(SRC_DIR)/kernel.c
NETDEV_SRC = $(SRC_DIR)/netdev.c
PBUF_SRC = $(SRC_DIR)/pbuf.c
ETH_SRC = $(SRC_DIR)/eth.c
ARP_SRC = $(SRC_DIR)/arp.c
IP4_SRC = $(SRC_DIR)/ip4.c
ICMP_SRC = $(SRC_DIR)/icmp.c
UDP_SRC = $(SRC_DIR)/udp.c
TCP_SRC = $(SRC_DIR)/tcp.c
DHCP_SRC = $(SRC_DIR)/dhcp.c
DNS_SRC = $(SRC_DIR)/dns.c
NETCFG_SRC = $(SRC_DIR)/netcfg.c
HTTP_SRC = $(SRC_DIR)/http.c
SSH_SRC = $(SRC_DIR)/ssh.c
DHCPD_SRC = $(SRC_DIR)/dhcpd.c
DNSD_SRC = $(SRC_DIR)/dnsd.c
AUTH_SRC = $(SRC_DIR)/auth.c
USER_SRC = $(SRC_DIR)/user.c
EDITOR_SRC = $(SRC_DIR)/editor.c
CRYPTO_SRC = $(SRC_DIR)/crypto.c
RAMFS_SRC = $(SRC_DIR)/ramfs.c
VFS_SRC = $(SRC_DIR)/vfs.c
AJLANG_SRC = $(SRC_DIR)/ajlang.c
LLM_SRC = $(SRC_DIR)/llm.c
LLM_MATH_SRC = $(SRC_DIR)/llm_math.c
LLM_INFERENCE_SRC = $(SRC_DIR)/llm_inference.c

# OpenSSH sources
OPENSSH_SRC = $(SRC_DIR)/openssh/sshbuf.c \
              $(SRC_DIR)/openssh/sshbuf-getput-basic.c \
              $(SRC_DIR)/openssh/sshbuf-getput-crypto.c \
              $(SRC_DIR)/openssh/sshbuf-misc.c \
              $(SRC_DIR)/openssh/ssherr.c
OPENSSH_OBJ = $(BUILD_DIR)/openssh_sshbuf.o \
              $(BUILD_DIR)/openssh_sshbuf-getput-basic.o \
              $(BUILD_DIR)/openssh_sshbuf-getput-crypto.o \
              $(BUILD_DIR)/openssh_sshbuf-misc.o \
              $(BUILD_DIR)/openssh_ssherr.o


BOOT_OBJ = $(BUILD_DIR)/boot.bin
BOOT_CD_OBJ = $(BUILD_DIR)/boot_cd.bin
KERNEL_ENTRY_OBJ = $(BUILD_DIR)/kernel_entry.o
ISR_OBJ = $(BUILD_DIR)/isr.o
BIOS_OBJ = $(BUILD_DIR)/bios.o
GDT_OBJ = $(BUILD_DIR)/gdt.o
USER_MODE_OBJ = $(BUILD_DIR)/user_mode.o
MM_SRC = kernel/mm/paging.c kernel/mm/slab.c kernel/mm/pmm.c
MM_OBJ = $(BUILD_DIR)/paging.o $(BUILD_DIR)/slab.o $(BUILD_DIR)/pmm.o
KERNEL_OBJ = $(BUILD_DIR)/kernel.o $(BUILD_DIR)/debug_agent.o $(BUILD_DIR)/pci.o $(BUILD_DIR)/e1000.o $(BUILD_DIR)/disk.o $(BUILD_DIR)/ata.o $(BUILD_DIR)/fat.o $(BUILD_DIR)/fatent_ops.o $(BUILD_DIR)/datetime.o $(BUILD_DIR)/switch.o $(BUILD_DIR)/ramfs.o $(BUILD_DIR)/vfs.o $(MM_OBJ)
NETDEV_OBJ = $(BUILD_DIR)/netdev.o
PBUF_OBJ = $(BUILD_DIR)/pbuf.o
ETH_OBJ = $(BUILD_DIR)/eth.o
ARP_OBJ = $(BUILD_DIR)/arp.o
IP4_OBJ = $(BUILD_DIR)/ip4.o
ICMP_OBJ = $(BUILD_DIR)/icmp.o
UDP_OBJ = $(BUILD_DIR)/udp.o
TCP_OBJ = $(BUILD_DIR)/tcp.o
DHCP_OBJ = $(BUILD_DIR)/dhcp.o
DNS_OBJ = $(BUILD_DIR)/dns.o
NETCFG_OBJ = $(BUILD_DIR)/netcfg.o
HTTP_OBJ = $(BUILD_DIR)/http.o
SSH_OBJ = $(BUILD_DIR)/ssh.o
DHCPD_OBJ = $(BUILD_DIR)/dhcpd.o
DNSD_OBJ = $(BUILD_DIR)/dnsd.o
AUTH_OBJ = $(BUILD_DIR)/auth.o
USER_OBJ = $(BUILD_DIR)/user.o
EDITOR_OBJ = $(BUILD_DIR)/editor.o
VIDEO_OBJ = $(BUILD_DIR)/video.o
MOUSE_OBJ = $(BUILD_DIR)/mouse.o
DESKTOP_OBJ = $(BUILD_DIR)/desktop.o
CRYPTO_OBJ = $(BUILD_DIR)/crypto.o
RAMFS_OBJ = $(BUILD_DIR)/ramfs.o
VFS_OBJ = $(BUILD_DIR)/vfs.o
AJLANG_OBJ = $(BUILD_DIR)/ajlang.o
LLM_OBJ = $(BUILD_DIR)/llm.o $(BUILD_DIR)/llm_math.o $(BUILD_DIR)/llm_inference.o
DEMO_BIN = $(BUILD_DIR)/demo.bin
KERNEL_ELF = $(BUILD_DIR)/kernel.elf
KERNEL_BIN = $(BUILD_DIR)/kernel.bin

OS_IMG = $(BUILD_DIR)/ajos.img
RUN_OS_IMG = $(BUILD_DIR)/ajos.run.img
DATA_IMG = $(BUILD_DIR)/data.img
ISO_IMG = $(BUILD_DIR)/ajos.iso

# Default host port forwards for QEMU user networking (override if port in use):
#   make run-console HOST_HTTP_PORT=9080 HOST_SSH_PORT=9022
HOST_HTTP_PORT ?= 9080
HOST_SSH_PORT ?= 9022

# CD boot: prefer CD over disk; strict=off avoids some firmware refusing multi-drive setups.
QEMU_ISO_BOOT := -m 512M -boot order=d,strict=off

# Line-buffer serial so B/K and boot log appear immediately (optional: brew install coreutils for stdbuf on macOS).
QEMU_RUN := $(if $(shell command -v stdbuf 2>/dev/null),stdbuf -oL ,)qemu-system-i386

# Build the default image. Keep it sequential so a parallel `make -j` does not
# race `force-clean-standard` (which deletes objects) with the compilation/link.
all:
	$(MAKE) force-clean-standard
	$(MAKE) $(OS_IMG)

$(BOOT_OBJ): $(BOOT_SRC)
	$(AS) -f bin $< -o $@

$(BOOT_CD_OBJ): asm/boot_cd.asm
	$(AS) -f bin $< -o $@

$(KERNEL_ENTRY_OBJ): $(KERNEL_ENTRY_SRC)
	$(AS) $(ASFLAGS) $< -o $@

$(ISR_OBJ): $(ISR_SRC)
	$(AS) $(ASFLAGS) $< -o $@

$(BIOS_OBJ): $(BIOS_SRC)
	$(AS) $(ASFLAGS) $< -o $@

$(GDT_OBJ): $(GDT_SRC)
	$(AS) $(ASFLAGS) $< -o $@

$(USER_MODE_OBJ): $(USER_MODE_SRC)
	$(AS) $(ASFLAGS) $< -o $@

$(DEMO_BIN): $(DEMO_SRC)
	$(AS) -f bin $< -o $@

$(BUILD_DIR)/kernel.o: $(KERNEL_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/debug_agent.o: $(SRC_DIR)/debug_agent.c $(INC_DIR)/debug_agent.h $(INC_DIR)/kernel.h
	$(CC) $(CFLAGS) -c $< -o $@

$(NETDEV_OBJ): $(NETDEV_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pci.o: $(SRC_DIR)/pci.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/e1000.o: $(SRC_DIR)/e1000.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/disk.o: $(SRC_DIR)/disk.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/ata.o: $(SRC_DIR)/ata.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fat.o: $(SRC_DIR)/fat.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/fatent_ops.o: $(SRC_DIR)/fatent_ops.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/switch.o: asm/switch.asm
	$(AS) $(ASFLAGS) $< -o $@

$(BUILD_DIR)/protected_mode.o: asm/protected_mode.asm
	$(AS) $(ASFLAGS) $< -o $@

$(BUILD_DIR)/datetime.o: $(SRC_DIR)/datetime.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/paging.o: kernel/mm/paging.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/heap.o: kernel/mm/heap.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/pmm.o: kernel/mm/pmm.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/slab.o: kernel/mm/slab.c
	$(CC) $(CFLAGS) -c $< -o $@

$(PBUF_OBJ): $(PBUF_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(ETH_OBJ): $(ETH_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(ARP_OBJ): $(ARP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(IP4_OBJ): $(IP4_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(ICMP_OBJ): $(ICMP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(UDP_OBJ): $(UDP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(TCP_OBJ): $(TCP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(DHCP_OBJ): $(DHCP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(DNS_OBJ): $(DNS_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(NETCFG_OBJ): $(NETCFG_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(HTTP_OBJ): $(HTTP_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(DHCPD_OBJ): $(DHCPD_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(DNSD_OBJ): $(DNSD_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(AUTH_OBJ): $(AUTH_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(USER_OBJ): $(USER_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(SSH_OBJ): $(SSH_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(EDITOR_OBJ): $(EDITOR_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(VIDEO_OBJ): $(SRC_DIR)/video.c $(INC_DIR)/video.h
	$(CC) $(CFLAGS) -c $< -o $@

$(MOUSE_OBJ): $(SRC_DIR)/mouse.c $(INC_DIR)/mouse.h
	$(CC) $(CFLAGS) -c $< -o $@

$(DESKTOP_OBJ): $(SRC_DIR)/desktop.c $(INC_DIR)/gui.h $(INC_DIR)/video.h $(INC_DIR)/mouse.h
	$(CC) $(CFLAGS) -c $< -o $@

$(CRYPTO_OBJ): $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(RAMFS_OBJ): $(RAMFS_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(VFS_OBJ): $(VFS_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(AJLANG_OBJ): $(AJLANG_SRC)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/llm.o: $(LLM_SRC)
	$(CC) $(LLM_CFLAGS) -c $< -o $@

$(BUILD_DIR)/llm_math.o: $(LLM_MATH_SRC)
	$(CC) $(LLM_CFLAGS) -c $< -o $@

$(BUILD_DIR)/llm_inference.o: $(LLM_INFERENCE_SRC)
	$(CC) $(LLM_CFLAGS) -c $< -o $@

# OpenSSH objects
$(BUILD_DIR)/openssh_sshbuf.o: $(SRC_DIR)/openssh/sshbuf.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/openssh_sshbuf-getput-basic.o: $(SRC_DIR)/openssh/sshbuf-getput-basic.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/openssh_sshbuf-getput-crypto.o: $(SRC_DIR)/openssh/sshbuf-getput-crypto.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/openssh_sshbuf-misc.o: $(SRC_DIR)/openssh/sshbuf-misc.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/openssh_ssherr.o: $(SRC_DIR)/openssh/ssherr.c
	$(CC) $(CFLAGS) -c $< -o $@


# LLM (llm.o llm_math.o llm_inference.o) temporarily not linked — re-add $(LLM_OBJ) to restore.
$(KERNEL_ELF): $(ISR_OBJ) $(BIOS_OBJ) $(GDT_OBJ) $(USER_MODE_OBJ) $(KERNEL_ENTRY_OBJ) $(KERNEL_OBJ) $(NETDEV_OBJ) $(MM_OBJ) $(PBUF_OBJ) $(ETH_OBJ) $(ARP_OBJ) $(IP4_OBJ) $(ICMP_OBJ) $(UDP_OBJ) $(TCP_OBJ) $(DHCP_OBJ) $(DNS_OBJ) $(NETCFG_OBJ) $(HTTP_OBJ) $(SSH_OBJ) $(DHCPD_OBJ) $(DNSD_OBJ) $(AUTH_OBJ) $(USER_OBJ) $(EDITOR_OBJ) $(VIDEO_OBJ) $(MOUSE_OBJ) $(DESKTOP_OBJ) $(CRYPTO_OBJ) $(RAMFS_OBJ) $(VFS_OBJ) $(AJLANG_OBJ) $(OPENSSH_OBJ)
	@echo "Linking kernel.elf (may take 30-60s)..."
	$(LD) $(LDFLAGS) -o $@ $^

$(KERNEL_BIN): $(KERNEL_ELF)
	@echo "Creating kernel.bin..."
	$(OBJCOPY) -O binary $< $@

# Optional LLM assets (not used by default `make` / `make run` — use `make data/STORIES.BIN` if needed).
data/STORIES.BIN:
	@mkdir -p data
	@echo "Downloading Stories-260K model..."
	curl -L https://huggingface.co/karpathy/tinyllamas/resolve/main/stories260K/stories260K.bin -o data/STORIES.BIN

data/TOK512.BIN:
	@mkdir -p data
	@echo "Downloading Stories-260K tokenizer..."
	curl -L https://huggingface.co/karpathy/tinyllamas/resolve/main/stories260K/tok512.bin -o data/TOK512.BIN

data/STORIES42.BIN:
	@mkdir -p data
	@echo "Downloading Stories-42M model (160MB)..."
	curl -L https://huggingface.co/karpathy/tinyllamas/resolve/main/stories42M.bin -o data/STORIES42.BIN

data/TOK32K.BIN:
	@mkdir -p data
	@echo "Downloading standard tokenizer (32K vocab)..."
	curl -L https://huggingface.co/karpathy/tinyllamas/resolve/main/tokenizer.bin -o data/TOK32K.BIN

# Boot floppy: no LLM models (fast build). Optional: data/STORIES*.BIN targets below for manual use.
$(OS_IMG): $(BOOT_OBJ) $(KERNEL_BIN) tools/mkfat12.py
	@mkdir -p data
	@if [ -f examples/hello.aj ]; then cp examples/hello.aj data/; fi
	@if [ ! -f data/hello.aj ]; then echo 'print "test"' > data/hello.aj; fi
	@if [ -f examples/dnscheck.aj ]; then cp examples/dnscheck.aj data/; fi
	python3 tools/mkfat12.py $@ --boot $(BOOT_OBJ) --kernel $(KERNEL_BIN)

# Secondary IDE disk: small empty FAT (no 256MB model copy). Built from empty dir so data/ is not scanned.
$(DATA_IMG): tools/mkfat12.py
	@mkdir -p $(BUILD_DIR)/data_img_staging
	cd $(BUILD_DIR)/data_img_staging && python3 ../../tools/mkfat12.py ../data.img --size-mb 32

$(ISO_IMG): $(OS_IMG)
	mkdir -p $(BUILD_DIR)/iso_staging
	cp $(OS_IMG) $(BUILD_DIR)/iso_staging/boot.img
	# Floppy emulation (1.44MB): full image as virtual floppy. Boot sector uses INT 13h.
	# -iso-level 1 and -pad improve compatibility.
	@if command -v xorriso >/dev/null 2>&1; then \
		xorriso -as mkisofs -V "AJOS" -iso-level 1 -pad \
			-b boot.img -c boot.catalog \
			-o $(ISO_IMG) $(BUILD_DIR)/iso_staging; \
	elif command -v genisoimage >/dev/null 2>&1; then \
		genisoimage -V "AJOS" -iso-level 1 -pad \
			-b boot.img -c boot.catalog \
			-o $(ISO_IMG) $(BUILD_DIR)/iso_staging; \
	else \
		echo "Error: need xorriso or genisoimage for ISO build"; exit 1; \
	fi
	rm -rf $(BUILD_DIR)/iso_staging

iso:
	$(MAKE) force-clean-standard
	$(MAKE) $(ISO_IMG)

# Same image as iso; reminds output path for Proxmox upload (see docs/PROXMOX.md)
proxmox-iso: iso
	@echo "Proxmox: upload this file as a CD/ISO: $(ISO_IMG)"

# Show El Torito boot catalog (needs xorriso). Expect: BIOS, fd1.4, /boot.img
iso-verify: $(ISO_IMG)
	@command -v xorriso >/dev/null 2>&1 || { echo "install xorriso (brew install xorriso)"; exit 1; }
	xorriso -indev $(ISO_IMG) -report_el_torito plain 2>&1 | head -25

clean:
	rm -f $(BOOT_OBJ) $(BOOT_CD_OBJ) $(BUILD_DIR)/ajos_cd.img $(KERNEL_ENTRY_OBJ) $(ISR_OBJ) $(BIOS_OBJ) $(GDT_OBJ) $(USER_MODE_OBJ) $(KERNEL_OBJ) $(PBUF_OBJ) $(ETH_OBJ) $(ARP_OBJ) $(IP4_OBJ) $(ICMP_OBJ) $(UDP_OBJ) $(TCP_OBJ) $(DHCP_OBJ) $(DEMO_BIN) $(KERNEL_ELF) $(KERNEL_BIN) $(OS_IMG) $(RUN_OS_IMG) $(DATA_IMG) $(ISO_IMG)


# GUI QEMU: needs >=512M RAM — kernel PMM maps up to ~480M from 8M; default
# QEMU -m (~128M) causes bogus physical frames and VGA/memory corruption.
# zoom-to-fit: drag-resize the window (or View → Zoom In / ⌘+) to scale VGA text.
# Fullscreen: make run FULLSCREEN=1
ifeq ($(FULLSCREEN),1)
QEMU_DISPLAY = -display cocoa,zoom-to-fit=on,full-screen=on
else
QEMU_DISPLAY = -display cocoa,zoom-to-fit=on
endif
run:
	$(MAKE) force-clean-standard
	$(MAKE) $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	@echo "Tip: resize the QEMU window to enlarge text, or View → Zoom In (⌘+)."
	$(QEMU_RUN) -m 512M -vga std $(QEMU_DISPLAY) -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -serial none

# Same as run, but also mirrors the console to this Terminal via -serial stdio.
run-mirror:
	$(MAKE) force-clean-standard
	$(MAKE) $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	$(QEMU_RUN) -m 512M -vga std $(QEMU_DISPLAY) -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -serial stdio

# VGA via VNC (keyboard works when the QEMU cocoa window ignores keys).
# Connect with macOS Screen Sharing (Finder → Go → Connect to Server):
#   vnc://localhost:5900
run-vnc:
	$(MAKE) force-clean-standard
	$(MAKE) $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	@echo "Connect with Screen Sharing: vnc://localhost:5900"
	$(QEMU_RUN) -m 512M -vga std -display none -vnc 127.0.0.1:0 -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -serial none

# VGA text rendered in this Terminal (curses); type directly in the Terminal.
# Text modes only — the GUI desktop won't render.
run-curses:
	$(MAKE) force-clean-standard
	$(MAKE) $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	$(QEMU_RUN) -m 512M -vga std -display curses -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -serial none

# Build serial-console image only (no QEMU). Use if run-console segfaults; then run QEMU manually.
run-console-img:
	$(MAKE) force-clean-serial
	rm -f $(OS_IMG) $(RUN_OS_IMG)
	@mkdir -p build
	$(MAKE) CFLAGS="$(CFLAGS) -DAJOS_SERIAL_ONLY" $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	@echo "Built $(RUN_OS_IMG). Run QEMU manually if needed: make run-console-qemu"

# Run QEMU with the serial-console image (builds image if missing).
# On some macOS builds QEMU segfaults with -nographic; try: make run-console-qemu-alt
run-console-qemu: run-console-img
	-pkill -9 qemu-system-i386 2>/dev/null || true
	sleep 1
	$(QEMU_RUN) -m 512M -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot

# Alternative: -display none (use if -nographic segfaults on macOS).
run-console-qemu-alt: run-console-img
	-pkill -9 qemu-system-i386 2>/dev/null || true
	sleep 1
	$(QEMU_RUN) -m 512M -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -display none -monitor none -serial stdio -no-reboot

# Use default GUI + serial in terminal. Use if run-console (nographic) segfaults on macOS.
# If you see no boot output (B/K) in this terminal, use instead: make run-console (no GUI, all output here).
run-console-qemu-gui: run-console-img
	-pkill -9 qemu-system-i386 2>/dev/null || true
	sleep 1
	@echo "Console is in this terminal (look for B then K then boot log). QEMU window may stay black."
	$(QEMU_RUN) -m 512M -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -monitor none -serial stdio -no-reboot

# Minimal QEMU: one floppy, no network, no data drive. Try if full run shows no output or segfaults.
run-console-qemu-minimal: run-console-img
	-pkill -9 qemu-system-i386 2>/dev/null || true
	sleep 1
	@echo "Minimal: one floppy, no data drive. Look for B then K in this terminal."
	$(QEMU_RUN) -m 128M -boot a -drive file=$(RUN_OS_IMG),format=raw,if=floppy -monitor none -serial stdio -no-reboot -nographic

# Serial console: build then run QEMU. Console appears in this terminal (no separate window).
# If you see no output (B/K), try: make run-console-qemu-minimal
# If QEMU segfaults on macOS 15.0-15.3 (ARM): run once: make install-qemu-mac
run-console: run-console-img
	$(MAKE) run-console-qemu

# One-time fix for QEMU segfault on macOS 15.0-15.3 (Apple Silicon): build QEMU from source.
# Takes ~10-20 min. Then run: make run-console
install-qemu-mac:
	@echo "Building QEMU from source (fixes segfault on macOS 15.0-15.3 ARM)..."
	brew install --build-from-source qemu
	@echo "Done. Run: make run-console"

force-clean-serial:
	rm -f $(KERNEL_OBJ) $(BUILD_DIR)/kernel_entry.o $(BUILD_DIR)/fat.o $(EDITOR_OBJ) $(VIDEO_OBJ) $(MOUSE_OBJ) $(DESKTOP_OBJ) $(CRYPTO_OBJ) $(SSH_OBJ) $(AJLANG_OBJ) $(BUILD_DIR)/llm.o $(BUILD_DIR)/llm_math.o $(BUILD_DIR)/llm_inference.o

# Standard targets should also clean potentially serial-polluted objects
force-clean-standard:
	rm -f $(KERNEL_OBJ) $(EDITOR_OBJ) $(VIDEO_OBJ) $(MOUSE_OBJ) $(DESKTOP_OBJ) $(BIOS_OBJ)

# Run with ATA hard disk (for Phase 5 verification - no BIOS thunks)
run-ata:
	$(MAKE) force-clean-serial
	$(MAKE) CFLAGS="$(CFLAGS) -DAJOS_SERIAL_ONLY" $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	# Use ATA hard disk instead of floppy to test native ATA driver
	qemu-system-i386 -boot c -drive file=$(RUN_OS_IMG),format=raw,if=ide,index=0 -drive file=$(DATA_IMG),format=raw,if=ide,index=1 -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot

run-iso:
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	$(MAKE) force-clean-serial
	$(MAKE) CFLAGS="$(CFLAGS) -DAJOS_SERIAL_ONLY" $(ISO_IMG) $(DATA_IMG)
	$(QEMU_RUN) $(QEMU_ISO_BOOT) -cdrom $(ISO_IMG) -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot

# Run ISO and wait for GDB on localhost:1234 (use: x86_64-elf-gdb -ex "target remote :1234" build/kernel.elf)
run-iso-debug:
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	$(MAKE) force-clean-serial
	$(MAKE) CFLAGS="$(CFLAGS) -DAJOS_SERIAL_ONLY -g" $(ISO_IMG) $(DATA_IMG)
	$(QEMU_RUN) $(QEMU_ISO_BOOT) -cdrom $(ISO_IMG) -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot -S -s

# ISO with VGA window (Mac Cocoa may show black - use make run-iso for terminal)
run-iso-vga:
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	$(MAKE) force-clean-standard
	$(MAKE) $(ISO_IMG) $(DATA_IMG)
	$(QEMU_RUN) $(QEMU_ISO_BOOT) -cdrom $(ISO_IMG) -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0 -vga std -no-reboot -serial stdio

# ISO with VGA build, serial in terminal (-display none = no window; use when Cocoa is black)
run-iso-vga-tty:
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	$(MAKE) force-clean-standard
	$(MAKE) $(ISO_IMG) $(DATA_IMG)
	$(QEMU_RUN) $(QEMU_ISO_BOOT) -cdrom $(ISO_IMG) -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0 -display none -serial stdio -vga std -no-reboot

# ISO with VGA in terminal (curses) - use when Cocoa window is black
run-iso-curses:
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	$(MAKE) force-clean-standard
	$(MAKE) $(ISO_IMG) $(DATA_IMG)
	$(QEMU_RUN) $(QEMU_ISO_BOOT) -cdrom $(ISO_IMG) -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0 -vga std -no-reboot -display curses

# ISO with VGA via VNC - use when Cocoa shows black screen (connect to vnc://localhost:5900)
run-iso-vnc:
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	$(MAKE) force-clean-standard
	$(MAKE) $(ISO_IMG) $(DATA_IMG)
	@echo "Connect to vnc://localhost:5900 (Screen Sharing or VNC client) to see VGA output"
	$(QEMU_RUN) $(QEMU_ISO_BOOT) -cdrom $(ISO_IMG) -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0 -device e1000,netdev=n0 -serial stdio -vga std -no-reboot -display none -vnc :0

# Test crypto error path: first rsa_sign() kmalloc fails; SSH KEX will fail.
# In QEMU console you should see: [CRYPTO] ERROR: kmalloc failed for padded
run-console-test-crypto-fail:
	$(MAKE) force-clean-serial
	$(MAKE) CFLAGS="$(CFLAGS) -DAJOS_SERIAL_ONLY -DCRYPTO_TEST_KMALLOC_FAIL" $(OS_IMG) $(DATA_IMG)
	qemu-system-i386 -boot a -drive file=$(OS_IMG),format=raw,if=floppy -drive file=$(DATA_IMG),format=raw,if=ide -netdev user,id=n0,hostfwd=tcp::$(HOST_HTTP_PORT)-10.0.2.15:80,hostfwd=tcp::$(HOST_SSH_PORT)-10.0.2.15:22 -device e1000,netdev=n0 -nographic -monitor none -serial stdio -no-reboot

# Host KDF selftest (no QEMU): verifies RFC 4253 KDF known-answer
CC_HOST ?= gcc
test-kdf: tools/kdf_selftest_host.c
	@mkdir -p build
	$(CC_HOST) -o build/kdf_selftest tools/kdf_selftest_host.c && ./build/kdf_selftest

# QEMU user-net: ping 10.0.2.2 should work; ping to public IPs often times out (ICMP not forwarded).
test-net: force-clean-serial
	-pkill -9 qemu-system-i386 2>/dev/null || true
	@sleep 1
	rm -f $(OS_IMG) $(RUN_OS_IMG)
	@mkdir -p build
	$(MAKE) CFLAGS="$(CFLAGS) -DAJOS_SERIAL_ONLY -DAJOS_NET_AUTOTEST" $(OS_IMG) $(DATA_IMG)
	cp $(OS_IMG) $(RUN_OS_IMG)
	@echo "--- Running network autotest in QEMU (see kernel AJOS_NET_AUTOTEST) ---"
	python3 tools/net_autotest.py

.PHONY: all clean run run-console run-console-img run-console-qemu run-console-qemu-alt run-console-qemu-gui run-console-qemu-minimal install-qemu-mac iso proxmox-iso iso-verify run-iso run-iso-vga run-iso-vga-tty run-iso-curses run-iso-vnc run-console-test-crypto-fail test-kdf test-net force-clean-serial force-clean-standard