# AJOS GDB init for debugging with QEMU (run: make run-iso-debug, then gdb -x debug.gdbinit build/kernel.elf)
set architecture i386
target remote :1234
add-symbol-file build/kernel.elf 0x100000
# Uncomment to break at kernel entry:
# b kernel_main
# c
