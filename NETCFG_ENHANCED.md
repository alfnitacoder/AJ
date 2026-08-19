# Enhanced Network Configuration System

## Summary
Successfully enhanced the AJOS network configuration system to support DHCP toggle, subnet mask, and gateway configuration.

## New Features Added

### 1. DHCP On/Off Toggle
- **Directive**: `dhcp on` or `dhcp off`
- **Behavior**:
  - `dhcp on` (or not specified): Use DHCP, ignore static settings
  - `dhcp off`: Use static configuration from file

### 2. Subnet Mask Support
- **Directive**: `netmask 255.255.255.0`
- **Status**: Parsed and displayed (storage for future routing implementation)

### 3. Gateway Support  
- **Directive**: `gateway 10.0.2.2`
- **Status**: Parsed and displayed (storage for future routing implementation)

## Enhanced Configuration File Format

```
# AJOS Network Configuration
# Set dhcp to 'off' to use static configuration
dhcp off
ip 10.0.2.100
netmask 255.255.255.0
gateway 10.0.2.2
dns 8.8.8.8
```

## Implementation Details

### Modified Files
- **`src/netcfg.c`**: Enhanced parser with new directives
  - Added `skip_whitespace()` helper function
  - Added DHCP on/off parsing
  - Added netmask parsing
  - Added gateway parsing
  - Updated return value logic (0=static, 1=DHCP)

- **`data/NETWORK.CFG`**: Updated sample configuration

### Parser Logic
1. Reads configuration file line by line
2. Skips comments (lines starting with `#`)
3. Parses directives in order:
   - If `dhcp on` found, returns immediately (use DHCP)
   - If `dhcp off` found, continues parsing static config
   - Parses `ip`, `netmask`, `gateway`, `dns` directives
4. Returns 0 for static config, 1 for DHCP

## Usage Examples

### Example 1: DHCP Mode
```
# AJOS Network Configuration
dhcp on
```
Result: Uses DHCP, ignores any other settings

### Example 2: Static Configuration
```
# AJOS Network Configuration
dhcp off
ip 10.0.2.100
netmask 255.255.255.0
gateway 10.0.2.2
dns 8.8.8.8
```
Result: Applies static IP configuration

### Example 3: Minimal Static
```
dhcp off
ip 192.168.1.100
```
Result: Sets static IP only

## Future Enhancements
- Store netmask in network stack for subnet calculations
- Store gateway for IP routing decisions
- Support multiple DNS servers
- Add hostname configuration
- Auto-load on boot option
