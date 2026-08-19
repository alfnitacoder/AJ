# AJOS to Minoca OS-style Refactoring Plan

## Overview
Refactor AJOS from a monolithic structure to a modular architecture similar to Minoca OS.

## Target Structure

```
AJOS/
├── kernel/           # Core kernel modules
│   ├── ke/          # Executive (scheduling, timers, events)
│   ├── mm/          # Memory management (heap, paging)
│   ├── io/          # I/O subsystem (serial, terminal, keyboard)
│   ├── ps/          # Process/thread management
│   └── hl/          # Hardware layer (interrupts, GDT, IDT, PIC)
├── drivers/         # Device drivers
│   ├── net/         # Network drivers (e1000, arp, ip4, tcp, udp, etc.)
│   ├── storage/     # Storage drivers (fat, disk)
│   └── pci/         # PCI support
├── apps/            # User applications
│   ├── libc/        # C library
│   └── swiss/       # POSIX tools
├── lib/             # Common libraries
│   ├── rtl/         # Runtime library (printf, memcpy, etc.)
│   └── fatlib/      # FAT filesystem library
├── include/         # Public headers
│   └── minoca/      # Minoca-style public API headers
└── boot/            # Boot code (already exists as asm/)
```

## Module Breakdown from kernel.c

### kernel/mm/ (Memory Management)
- `paging.c` - Paging initialization and MMIO mapping
- `heap.c` - Heap allocator (kmalloc/kfree)

### kernel/io/ (I/O Subsystem)
- `serial.c` - Serial port I/O
- `terminal.c` - Terminal/VGA output
- `keyboard.c` - Keyboard input

### kernel/hl/ (Hardware Layer)
- `interrupts.c` - IDT, PIC, interrupt handlers
- `gdt.c` - GDT management (already in asm/, may need C wrapper)
- `timer.c` - Timer interrupt handler

### kernel/ke/ (Executive)
- `scheduler.c` - Process scheduling
- `timer.c` - System timers
- `events.c` - Event system

### kernel/ps/ (Process/Thread)
- `process.c` - Process management
- `thread.c` - Thread management
- `syscall.c` - System call handler

### drivers/net/
- `e1000.c` - E1000 network card driver
- `arp.c` - ARP protocol
- `ip4.c` - IPv4 protocol
- `tcp.c` - TCP protocol
- `udp.c` - UDP protocol
- `icmp.c` - ICMP protocol
- `dhcp.c` - DHCP client
- `dns.c` - DNS client
- `dhcpd.c` - DHCP server
- `dnsd.c` - DNS server
- `http.c` - HTTP server
- `ssh.c` - SSH server

### drivers/storage/
- `disk.c` - Disk I/O
- `fat.c` - FAT filesystem

### drivers/pci/
- `pci.c` - PCI enumeration and configuration

## Implementation Steps

1. ✅ Create directory structure
2. ⏳ Create kernel module headers and interfaces
3. ⏳ Split kernel.c into modules
4. ⏳ Move drivers to drivers/ directory
5. ⏳ Create driver model/interface
6. ⏳ Update Makefile for modular build
7. ⏳ Create include/minoca/ public headers
8. ⏳ Test boot and functionality

## Driver Model

Minoca OS uses a forward-compatible driver model. We'll create a simple version:

```c
// include/minoca/driver.h
typedef struct DRIVER DRIVER;
typedef struct DEVICE DEVICE;

typedef struct DRIVER_INTERFACE {
    int (*Open)(DEVICE *Device, ...);
    int (*Close)(DEVICE *Device);
    // ... other operations
} DRIVER_INTERFACE;
```

## Notes

- Keep backward compatibility during transition
- Test after each major module move
- Maintain existing functionality
- Gradually improve architecture
