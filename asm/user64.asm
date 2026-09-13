; user64.asm - the first AJOS-64 user program (ring 3).
; Two write syscalls then exit: bisects the syscall return path.

[bits 64]
start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg]
    mov rdx, msglen
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg2]
    mov rdx, msg2len
    syscall
    mov rax, 2
    xor rdi, rdi
    syscall
.hang:
    hlt
    jmp .hang

msg: db "HELLO-FROM-RING3", 10
msglen equ $ - msg
msg2: db "SECOND-WRITE-OK", 10
msg2len equ $ - msg2
