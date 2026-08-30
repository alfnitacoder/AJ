# Installing AJOS onto a server from ISO

AJOS installs onto a machine's own disk (IDE/HDD) so it boots standalone - no
floppy, no live ISO. The flow: boot the install medium, run one command,
reboot from disk.

## 1. Build the install medium

```bash
cd AJOS && make && make iso      # build/ajos.iso (El Torito, legacy BIOS)
```

## 2. Boot it on the server

- **Proxmox VE**: upload `build/ajos.iso` to the node's ISO storage, create a
  VM (SeaBIOS, IDE disk, Intel E1000 NIC), boot from the ISO.
- **QEMU**: `qemu-system-i386 -m 512M -cdrom build/ajos.iso -drive file=disk.img,format=raw,if=ide -nographic -serial stdio`
- **Physical machine**: burn the ISO to a CD-R (legacy BIOS boot).

Log in at the console: **user / pass**.

## 3. Install to disk

At the shell (serial console recommended - the installer's BIOS floppy reads
can disrupt an active SSH session):

```
installdisk
```

This mirrors the boot medium (bootloader -> MBR/LBA0, kernel -> LBA 1..,
filesystem) onto the primary ATA disk - 2880 sectors, ~1-3 minutes. It ends
with `[INSTALL] SUCCESS` and verifies the boot signature.

## 4. Boot the installed system

Set the VM's boot order to disk-first (Proxmox: detach the ISO; QEMU:
`AJOS_BOOT_ORDER=c ./run_aj.sh start` or `launchctl setenv AJOS_BOOT_ORDER c`)
and reboot. AJOS now runs from its own disk: SSH on :22, web on :80 - the
installed system, not a live session.

## Notes & limits

- The installer overwrites the first 1.44 MB of the target disk (the AJOS
  system image); data already on that disk is lost.
- The bootloader is geometry-agnostic: it queries the boot drive's CHS
  geometry via BIOS (int 13h AH=08h), so the same layout boots on floppy,
  IDE and most virtual disks.
- After install, the disk root IS the system filesystem (same layout as the
  boot floppy); kernel updates = re-run the mirror (re-installdisk) or copy
  kernel.bin + files and re-run.
- SSH tip: run the installer from the serial console. The installer's BIOS
  real-mode windows can starve the NIC RX ring and corrupt an active SSH
  stream (bad packet length / MAC errors).
