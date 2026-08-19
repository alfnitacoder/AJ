# Linux Kernel Boot Initialization Comparison

## Key Differences Found Between Linux Kernel and AJOS

### 1. Serial Port Initialization

**Linux Kernel (`arch/x86/boot/early_serial_console.c`):**
```c
static void early_serial_init(int port, int baud)
{
    outb(0x3, port + LCR);    /* 8n1 */
    outb(0, port + IER);       /* no interrupt */
    outb(0, port + FCR);       /* no fifo */
    outb(0x3, port + MCR);     /* DTR + RTS */
    
    divisor = 115200 / baud;
    c = inb(port + LCR);
    outb(c | DLAB, port + LCR);
    outb(divisor & 0xff, port + DLL);
    outb((divisor >> 8) & 0xff, port + DLH);
    outb(c & ~DLAB, port + LCR);
}
```

**AJOS (Before Fix):**
- Set FCR to 0xC7 (enable FIFO) - **WRONG for early boot**
- Set MCR to 0x0B (more bits set) - **WRONG**
- Different initialization order

**AJOS (After Fix):**
- Matches Linux kernel sequence exactly
- FCR set to 0 (no FIFO during early boot)
- MCR set to 0x3 (DTR + RTS only)
- Same initialization order

### 2. BSS Clearing

**Linux Kernel (`arch/x86/kernel/head_32.S` lines 83-89):**
```asm
cld
xorl %eax,%eax
movl $pa(__bss_start),%edi
movl $pa(__bss_stop),%ecx
subl %edi,%ecx
shrl $2,%ecx
rep stosl
```

**Key Points:**
- Uses `cld` (clear direction flag)
- Uses `rep stosl` (repeat store string long) - clears 4 bytes at a time
- More efficient than byte-by-byte clearing
- Done in assembly, not C

**AJOS:**
- Uses C loop clearing byte-by-byte
- Should be equivalent but less efficient
- May want to optimize to match Linux approach

### 3. Early Boot Sequence

**Linux Kernel (`arch/x86/kernel/head_32.S`):**
1. Set segments to known values
2. Set up stack pointer
3. **Clear BSS** (assembly, 4 bytes at a time)
4. Copy boot parameters
5. Create early page tables
6. Continue with initialization

**AJOS:**
1. Clear BSS (C, byte-by-byte)
2. Initialize serial port
3. Initialize heap
4. Continue with initialization

### 4. Memory Initialization

**Linux Kernel:**
- Uses E820 BIOS calls to detect memory
- Sets up memory maps early
- Initializes page tables before most other code

**AJOS:**
- Uses simpler memory model
- May need to verify memory initialization order

## Changes Applied

1. **Serial Port Initialization:**
   - Updated `serial_initialize()` to match Linux kernel sequence
   - Set FCR to 0 (no FIFO) instead of 0xC7
   - Set MCR to 0x3 (DTR + RTS) instead of 0x0B
   - Fixed initialization order to match Linux

2. **Early Serial Setup in kernel_main:**
   - Updated to match Linux kernel `early_serial_init` sequence
   - Proper DLAB handling (read LCR, set DLAB, set divisor, clear DLAB)

## Potential Issues Identified

1. **FIFO Enable (FCR = 0xC7):**
   - Linux disables FIFO during early boot (FCR = 0)
   - Enabling FIFO too early may cause hangs
   - **FIXED:** Now matches Linux (FCR = 0)

2. **MCR Settings:**
   - Linux uses 0x3 (DTR + RTS only)
   - AJOS was using 0x0B (more bits)
   - **FIXED:** Now matches Linux (MCR = 0x3)

3. **Initialization Order:**
   - Linux sets LCR first, then IER, FCR, MCR
   - Then sets DLAB and divisor
   - **FIXED:** Now matches Linux order

## Next Steps

1. Test if boot now works with Linux-compatible serial initialization
2. Consider optimizing BSS clearing to use assembly (4 bytes at a time)
3. Verify memory initialization order matches Linux approach
4. Check if other early boot code needs Linux-compatible fixes
