; forkdemo64.asm - milestone 16 ring-3 test (position-independent, -f bin).
; Parent forks, both spin so the timer can preempt, parent waitpid's the
; child (exit 42), then execve's CHILD64. Syscall ABI (rax):
;   1 write (rsi=buf, rdx=len)   2 exit (rdi=code)
;   6 getpid   7 getppid   8 ticks
;   16 fork    17 execve (rdi=path)   18 waitpid (rdi=pid, rsi=&status)

[bits 64]

start:
    lea rsi, [rel msg_start]
    mov rdx, msg_start_len
    call write

    mov rax, 16                 ; fork
    syscall
    test rax, rax
    jz .child
    cmp rax, -1
    je .bad
    mov [rel child_pid], rax

    lea rsi, [rel msg_parent]
    mov rdx, msg_parent_len
    call write
    call spin40

    mov rax, 18                 ; waitpid(child, &status)
    mov rdi, [rel child_pid]
    lea rsi, [rel status]
    syscall
    cmp rax, [rel child_pid]
    jne .bad
    cmp qword [rel status], 42
    jne .bad

    lea rsi, [rel msg_ok]
    mov rdx, msg_ok_len
    call write

    mov rax, 17                 ; execve("CHILD64")
    lea rdi, [rel child_path]
    xor rsi, rsi
    syscall

.bad:
    mov rax, 2
    mov rdi, 1
    syscall
    jmp .bad

.child:
    lea rsi, [rel msg_child]
    mov rdx, msg_child_len
    call write
    mov rax, 6                  ; getpid
    syscall
    mov r12, rax
    mov rax, 7                  ; getppid
    syscall
    test rax, rax
    jz .bad
    cmp rax, r12
    je .bad
    call spin40
    lea rsi, [rel msg_cx]
    mov rdx, msg_cx_len
    call write
    mov rax, 2
    mov rdi, 42
    syscall
    jmp .bad

; rsi = buffer, rdx = length. Kernel preserves both.
write:
    mov rax, 1
    mov rdi, 1
    syscall
    ret

; Busy-wait until the PIT has advanced 40 ticks (~400ms). The inner burn
; keeps us in ring 3 long enough for the 100ms quantum to fire.
spin40:
    mov rax, 8
    syscall
    lea r12, [rax + 40]
.spin:
    mov ecx, 200000
.burn:
    dec ecx
    jnz .burn
    mov rax, 8
    syscall
    cmp rax, r12
    jb .spin
    ret

msg_start:  db "FORKDEMO64: start", 10
msg_start_len equ $ - msg_start
msg_parent: db "FORKDEMO64: parent", 10
msg_parent_len equ $ - msg_parent
msg_child:  db "FORKDEMO64: child", 10
msg_child_len equ $ - msg_child
msg_cx:     db "FORKDEMO64: child-exit", 10
msg_cx_len equ $ - msg_cx
msg_ok:     db "FORK-WAIT-OK-16", 10
msg_ok_len equ $ - msg_ok
child_path: db "CHILD64", 0

align 8
child_pid:  dq 0
status:     dq 0
