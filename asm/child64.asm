; child64.asm - execve target for the milestone 16 fork demo.
; Flat position-independent blob. Prints the success marker and exits 7.

[bits 64]

start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg]
    mov rdx, msglen
    syscall
    mov rax, 2
    mov rdi, 7
    syscall
    jmp start

msg: db "EXECVE-OK-16", 10
msglen equ $ - msg
