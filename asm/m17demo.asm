; m17demo.asm - milestone 17 boot program (position-independent, -f bin).
; Parent forks a child that blocks in sleep(300). Parent sleeps 30ms so the
; child can enter that sleep, asks the kernel to ps (must show the sleeper),
; then waitpid. The wait covers the rest of the 300ms.

[bits 64]

start:
    mov rax, 16                 ; fork
    syscall
    test rax, rax
    jz .child
    cmp rax, -1
    je .bad
    mov [rel child_pid], rax

    mov rax, 3                  ; sleep 30ms — child runs and blocks
    mov rdi, 30
    syscall

    mov rax, 19                 ; ps
    syscall

    mov rax, 8                  ; ticks
    syscall
    mov r12, rax

    mov rax, 18                 ; waitpid(child)
    mov rdi, [rel child_pid]
    lea rsi, [rel status]
    syscall
    mov r13, rax

    mov rax, 8
    syscall
    sub rax, r12
    cmp rax, 20                 ; >= 200ms at 100Hz
    jb .bad

    lea rsi, [rel msg_sleep]
    mov rdx, msg_sleep_len
    call write

    cmp r13, [rel child_pid]
    jne .bad
    lea rsi, [rel msg_wait]
    mov rdx, msg_wait_len
    call write

    mov rax, 2
    xor rdi, rdi
    syscall

.child:
    mov rax, 3                  ; sleep 300ms, blocking in the scheduler
    mov rdi, 300
    syscall
    mov rax, 2
    xor rdi, rdi
    syscall

.bad:
    mov rax, 2
    mov rdi, 1
    syscall
    jmp .bad

write:
    mov rax, 1
    mov rdi, 1
    syscall
    ret

msg_sleep: db "SLEEP-OK-17", 10
msg_sleep_len equ $ - msg_sleep
msg_wait:  db "WAIT-BG-OK-17", 10
msg_wait_len equ $ - msg_wait

align 8
child_pid: dq 0
status:    dq 0
