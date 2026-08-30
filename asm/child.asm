; CHILD.BIN - execve() target for FORKDEMO.BIN
; Entry stack (built by the kernel): [esp]=argc, [esp+4..]=argv[] pointers.

[bits 32]
[org 0]

db 'AJOSBIN'
db 1
dd entry
dd 0
dd 0

%include "asm/ajos_syscall.inc"

entry:
    call .next
.next:
    pop ebp
    sub ebp, .next

    lea ebx, [ebp + msg1]
    call puts

    lea ebx, [ebp + msg_argc]
    call puts
    mov eax, [esp]             ; argc
    call print_u32
    lea ebx, [ebp + msg_argv0]
    call puts
    mov ebx, [esp + 4]         ; argv[0]
    call puts
    lea ebx, [ebp + msg_argv1]
    call puts
    mov ebx, [esp + 8]         ; argv[1]
    test ebx, ebx
    jz .no_arg1
    call puts
.no_arg1:
    lea ebx, [ebp + msg_nl]
    call puts

    mov eax, SYSCALL_SLEEP
    mov ebx, 200
    int 0x80

    lea ebx, [ebp + msg_exit]
    call puts

    mov eax, SYSCALL_EXIT
    mov ebx, 7
    int 0x80
    jmp $

; ---- puts: ebx = NUL-terminated string ----
puts:
    push ecx
    push edx
    mov ecx, ebx
.len:
    cmp byte [ecx], 0
    je .go
    inc ecx
    jmp .len
.go:
    sub ecx, ebx
    mov eax, SYSCALL_WRITE
    int 0x80
    pop edx
    pop ecx
    ret

; ---- print_u32: eax = value (decimal) ----
print_u32:
    push eax
    push ebx
    push ecx
    push edx
    push esi
    lea esi, [ebp + numbuf_end]
    mov byte [esi], 0
    dec esi
    mov ebx, 10
.loop:
    xor edx, edx
    div ebx
    add dl, '0'
    mov [esi], dl
    dec esi
    test eax, eax
    jnz .loop
    inc esi
    mov ecx, ebp
    add ecx, numbuf_end
    sub ecx, esi
    mov eax, SYSCALL_WRITE
    mov ebx, esi
    int 0x80
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

; ---------------- data ----------------
msg1:      db 'CHILD.BIN: running via execve', 0x0D, 0x0A, 0
msg_argc:  db 'CHILD.BIN: argc=', 0
msg_argv0: db ' argv0=', 0
msg_argv1: db ' argv1=', 0
msg_nl:    db 0x0D, 0x0A, 0
msg_exit:  db 'CHILD.BIN: exiting 7', 0x0D, 0x0A, 0

numbuf:    times 16 db 0
numbuf_end:
