# AJOS ISO Boot

## Quick Start (works on all platforms)

```bash
make run-iso
```

Boots from ISO with output in the terminal. Log in: **user** / **pass**.

## Build

```bash
make iso            # Build ajos.iso + data.img
make run-iso        # Run in QEMU (terminal, recommended)
make run-iso-vga    # Run with VGA window + serial
```

## Fixes for Black Screen

1. **Removed KBC A20 gate** – The keyboard controller method can hang on CD/VM boot. Now using fast A20 (port 0x92) only.
2. **INT 13h geometry retry** – If get-geometry fails with the BIOS-provided drive number, retry with drive 0.
3. **Floppy emulation** – Standard 1.44MB El Torito floppy emulation (no-emul with 2880 sectors isn’t widely supported).

4. **VGA mode 3 re-set** - Boot sector re-sets VGA to 80x25 before PM.
5. **Early kernel VGA** - Kernel writes "KM" at entry (run-iso-vga).
6. **-vga std** - run-iso-vga uses standard VGA.

## Other Fixes

- **-iso-level 1** – Better compatibility with older CD hardware
- **-pad** – Pads ISO to improve CD readability
- **genisoimage fallback** – Use `genisoimage` if `xorriso` fails

## If VGA Window Is Black (macOS/QEMU Cocoa)

QEMU Cocoa on Mac often shows a black screen that fullscreen/VNC do not fix. **Use another VM**:

- **UTM** (Mac App Store, free) – Uses QEMU with a native GUI; VGA typically works. Create a new VM, add the CD (build/ajos.iso), set boot to CD, add the data drive (build/data.img).
- **VirtualBox** (virtualbox.org) – Create VM, attach ajos.iso as CD, add data.img as second disk; VGA works.

For terminal-only (no graphical display): **`make run-iso`**

## ISO Not Booting / Not Working

1. **Verify with `make run-iso`** – If this works (boot messages in terminal), the ISO is fine. Issue is display/VM config.
2. **UTM / VirtualBox**: Add **both** drives:
   - CD: `build/ajos.iso`
   - Disk: `build/data.img` (IDE, second disk)
   - Boot order: CD first
3. **Port in use**: If you see "Could not set up host forwarding", use: `make run-iso HOST_SSH_PORT=2227` (or another free port)
4. **Real hardware**: BIOS → boot from CD before HDD
