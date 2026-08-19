# Network Configuration File Integration Guide

## Summary
I've created the network configuration system for AJOS. Here's what's been done and what needs to be manually integrated:

## ✅ Completed
1. **Created `/Users/ageorge/AJOS/src/netcfg.c`** - Parser for network config files
2. **Created `/Users/ageorge/AJOS/network.cfg`** - Sample configuration file
3. **Updated `/Users/ageorge/AJOS/include/net.h`** - Added function declaration
4. **Updated `/Users/ageorge/AJOS/Makefile`** - Added netcfg.c to build

## 📝 Manual Integration Needed

### Step 1: Add cmd_netcfg function to kernel.c
Add this function after `cmd_dns` (around line 4177):

```c
static void cmd_netcfg(const char *args) {
  const char *filename = skip_spaces(args);
  if (!*filename) {
    filename = "NETWORK.CFG";
  }
  
  uint8_t *buf = NULL;
  uint32_t size = 0;
  
  if (!fat12_read_file_to_ram(filename, &buf, &size)) {
    log_writestring("[NetCfg] File not found: ");
    log_writestring(filename);
    log_putchar('\n');
    return;
  }
  
  log_writestring("[NetCfg] Loading from ");
  log_writestring(filename);
  log_putchar('\n');
  
  int has_static_ip = netcfg_load_from_buffer((const char *)buf, size);
  kfree(buf);
  
  if (!has_static_ip) {
    log_writestring("[NetCfg] No static IP, use DHCP\n");
  }
}
```

### Step 2: Register command in shell_execute
Add this in the command dispatcher (around line 4660):

```c
  if (cmd_clean_len == 6 && kstrcmp_n(cmd_clean, "netcfg", 6) == 0) {
    cmd_netcfg(rest);
    return;
  }
```

### Step 3: Add to help command
Add this line in `shell_help()` (around line 4540):

```c
  log_writestring("  netcfg [file]   Load network config (default: NETWORK.CFG)\n");
```

### Step 4: (Optional) Auto-load on boot
Add this in `kernel_main()` after network initialization:

```c
  // Try to load network configuration from file
  uint8_t *netcfg_buf = NULL;
  uint32_t netcfg_size = 0;
  if (fat12_read_file_to_ram("NETWORK.CFG", &netcfg_buf, &netcfg_size)) {
    log_writestring("[Boot] Loading network config...\n");
    int has_static = netcfg_load_from_buffer((const char *)netcfg_buf, netcfg_size);
    kfree(netcfg_buf);
    if (!has_static) {
      dhcp_start(); // Auto-start DHCP if no static IP
    }
  }
```

## 📄 Configuration File Format

Create `NETWORK.CFG` on your ramdisk with:

```
# AJOS Network Configuration
ip 10.0.2.100
dns 8.8.8.8
```

## 🎯 Usage

Once integrated, you can:
- `netcfg` - Load NETWORK.CFG
- `netcfg MYNET.CFG` - Load custom config file
- Auto-load on boot (if Step 4 is done)

## 🔧 Build
The Makefile is already updated, just run:
```
make clean && make
```
