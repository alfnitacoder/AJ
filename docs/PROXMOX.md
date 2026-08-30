# Running AJOS on Proxmox (ISO)

AJOS ships as a **legacy BIOS** CD image: El Torito **1.44 MB floppy emulation** containing the same `ajos.img` as `make` / floppy boot.

## 1. Build the ISO (on your dev machine or on the PVE host)

```bash
cd AJOS
make iso
```

- **Output:** `build/ajos.iso`
- **Requires:** `xorriso` **or** `genisoimage`
  - Debian/Ubuntu/Proxmox VE: `apt install xorriso`
  - macOS: `brew install xorriso`

Optional check:

```bash
make iso-verify
```

Expect El Torito: **BIOS**, **fd 1.4 MB**, boot image **`/boot.img`**.

## 2. Upload ISO to Proxmox

1. **Datacenter → Storage** (e.g. `local`) → **ISO Images** → **Upload**.
2. Select `build/ajos.iso` (or copy it to `/var/lib/vz/template/iso/` on the node and **Rescan**).

## 3. Create the VM

| Setting | Recommendation |
|--------|----------------|
| **OS** | **Other** (or “Linux” / unspecified — no installer) |
| **BIOS** | **SeaBIOS (default)** — **not** OVMF/UEFI-only |
| **Machine** | **i440fx** or **q35** (either usually works with SeaBIOS) |
| **CPU type** | **host** or **kvm64**; guest is **32-bit x86** |
| **Memory** | **512 MiB** or more (kernel/PMM expect enough RAM) |
| **Display** | **Serial** or default VGA (serial is easiest for the shell if you add a serial port) |
| **CD/DVD** | Use uploaded **`ajos.iso`**, **IDE/SATA** bus is fine |
| **Boot order** | **CD/DVD first** (then disk if you add one) |
| **Network** | **Intel E1000** (AJOS includes an **e1000** driver only — **VirtIO NIC will not work** without adding a driver) |
| **Disk (optional)** | Add a small **virtio** or **SCSI/IDE** disk if you want a second volume (similar to QEMU `data.img` for `/mnt`); not required to boot from CD |

### Serial console (optional, matches `make run-console`)

1. VM **Hardware** → **Add** → **Serial Port** → **Socket** (or redirect to PTY and use `qm terminal`).

## 4. Start the VM

- Open **Console**; you should see SeaBIOS then AJOS boot (floppy/CD path).
- If the guest “hangs” at CD boot, confirm **UEFI is disabled** and the VM is using **SeaBIOS**.

## 4b. Install AJOS to the VM's disk (no live boot)

Since the `installdisk` command exists, a Proxmox VM can run AJOS from its own
disk instead of the live ISO:

1. Add an **IDE disk** to the VM (any size >= 2 MB; the installer writes the
   first 1.44 MB).
2. Boot the ISO, log in (`user` / `pass`).
3. Run **`installdisk`** - mirrors bootloader + kernel + filesystem onto the
   disk (~1-3 min, ends with `[INSTALL] SUCCESS`).
4. **Detach the ISO** (Hardware -> CD/DVD -> Remove) and reboot.
5. The VM now boots AJOS standalone: SSH on :22, web on :80.

> Tip: run `installdisk` from the **serial/console**, not SSH - the installer's
> BIOS real-mode windows can starve the NIC and corrupt an active SSH stream.

## 5. Networking note

AJOS defaults to **10.0.2.15** in `network_auto_setup()` (QEMU user-net style). On Proxmox you will usually use a **real** LAN — set IP/gateway/DNS via **`netcfg`** / **`NETWORK.CFG`** on the FAT image or adjust the kernel’s static setup for your lab.

## Troubleshooting

| Symptom | Check |
|--------|--------|
| No boot from ISO | SeaBIOS not UEFI-only; CD first in boot order |
| No network in guest | NIC model **E1000**, not VirtIO |
| Need same layout as QEMU `run-iso` | Add a second raw disk (~32 MB+) for extra FAT; build `build/data.img` with `make data.img` and attach it |

## File to copy to Proxmox

Only **`build/ajos.iso`** is required for CD boot.
