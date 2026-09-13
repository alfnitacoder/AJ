; userprog.asm - a generic AJOS-64 user program template (ring 3).
; Assembled -f bin, position-independent; loaded from the FAT disk by the
; shell's `run FILE.UP` command (user64_exec). Syscalls: rax=1 write,
; rax=2 exit.

[bits 64]
start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg]
    mov rdx, msglen
    syscall
    mov rax, 2
    xor rdi, rdi
    syscall
.hang:
    hlt
    jmp .hang

msg: db "HELLO-FROM-DISK", 10
msglen equ $ - msg
