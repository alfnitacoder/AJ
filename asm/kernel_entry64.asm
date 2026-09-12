; kernel_entry64.asm - 64-bit entry point for the AJOS long-mode kernel.
; Lands here from boot64.asm's far jump; stack at 7MB (same address as the
; i386 entry: above .bss growth, below the 8MB PMM start), clear .bss,
; then call the C kernel64 stub.

[extern kernel_main64]
[extern sbss]
[extern ebss]
[global start]

[bits 64]
section .text.start
start:
    mov esp, 0x700000
    mov ebp, esp

    ; Clear .bss (both symbols are < 4GB, identity-mapped).
    mov rdi, sbss
    mov rcx, ebss
    sub rcx, rdi
    jz .bss_done
    xor eax, eax
    cld
    rep stosb
.bss_done:

    call kernel_main64
.hang:
    hlt
    jmp .hang
