[extern kernel_main]
[extern sbss]
[extern ebss]
[global start]

[bits 32]
section .text.start
start:
    ; Set safe stack at 2MB immediately
    mov esp, 0x200000
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