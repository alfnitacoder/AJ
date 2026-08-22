[extern kernel_main]
[extern sbss]
[extern ebss]
[global start]

[bits 32]
section .text.start
start:
    ; Stack at 7MB, clear of the kernel image/.bss (ends ~2.2MB and grows
    ; with every static buffer added) and below where the PMM starts
    ; managing memory (8MB, see PMM_START_ADDR in kernel/mm/pmm.c) — the
    ; old 2MB stack address used to sit *inside* .bss once the kernel grew
    ; past it, silently corrupting whatever static var the linker placed
    ; there as soon as the stack was used at all.
    mov esp, 0x700000
    mov ebp, esp

    mov edi, sbss
    mov ecx, ebss
    sub ecx, edi
    jz .bss_done
    xor eax, eax
    cld
    rep stosb
.bss_done:

    call kernel_main
    jmp $