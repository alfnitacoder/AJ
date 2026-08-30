; FORKDEMO.BIN - exercises real fork()/waitpid()/execve() (AJOSBIN flat binary)
;
; Flow:
;   parent: print pid, fork()
;     child : print pid/ppid, sleep 300ms, exit(42)
;     parent: waitpid(child) -> prints reaped pid + status 42
;             execve("CHILD.BIN", ["CHILD.BIN", "hello-from-parent"], 0)
;   (image replaced; CHILD.BIN prints its argc/argv and exits 7)

[bits 32]
[org 0]

db 'AJOSBIN'
db 1
dd entry
dd 0
dd 0

%include "asm/ajos_syscall.inc"

USER_EFLAGS_IF equ 0x202

entry:
    ; Position-independent base (image is loaded at 0x300000)
    call .next
.next:
    pop ebp
    sub ebp, .next

    ; ---- parent & child both start here ----
    lea ebx, [ebp + msg_start]
    call puts
    mov eax, SYSCALL_GETPID
    int 0x80
    call print_u32
    lea ebx, [ebp + msg_nl]
    call puts

    mov eax, SYSCALL_FORK
    int 0x80
    test eax, eax
    jnz .parent

; ---------------- child ----------------
.child:
    lea ebx, [ebp + msg_child]
    call puts
    mov eax, SYSCALL_GETPID
    int 0x80
    call print_u32
    lea ebx, [ebp + msg_child2]
    call puts
    mov eax, SYSCALL_GETPPID
    int 0x80
    call print_u32
    lea ebx, [ebp + msg_close]
    call puts
    lea ebx, [ebp + msg_nl]
    call puts

    mov eax, SYSCALL_SLEEP
    mov ebx, 300
    int 0x80

    lea ebx, [ebp + msg_child_exit]
    call puts

    mov eax, SYSCALL_EXIT
    mov ebx, 42
    int 0x80
    jmp $                       ; unreachable

; ---------------- parent ----------------
.parent:
    mov [ebp + child_pid], eax
    lea ebx, [ebp + msg_parent]
    call puts
    mov eax, [ebp + child_pid]
    call print_u32
    lea ebx, [ebp + msg_nl]
    call puts

    mov eax, SYSCALL_WAITPID
    mov ebx, [ebp + child_pid]
    lea ecx, [ebp + status_v]
    xor edx, edx
    int 0x80
    mov [ebp + reaped_v], eax

    lea ebx, [ebp + msg_reaped]
    call puts
    mov eax, [ebp + reaped_v]
    call print_u32
    lea ebx, [ebp + msg_status]
    call puts
    mov eax, [ebp + status_v]
    call print_u32
    lea ebx, [ebp + msg_nl]
    call puts

    ; Build argv for execve in our own data area.
    lea eax, [ebp + arg0]
    mov [ebp + exec_argv + 0], eax
    lea eax, [ebp + arg1]
    mov [ebp + exec_argv + 4], eax
    mov dword [ebp + exec_argv + 8], 0

    lea ebx, [ebp + child_path]
    lea ecx, [ebp + exec_argv]
    xor edx, edx
    mov eax, SYSCALL_EXECVE
    int 0x80

    ; Only reached if execve failed
    lea ebx, [ebp + msg_execfail]
    call puts
    mov eax, SYSCALL_EXIT
    mov ebx, 1
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
    sub ecx, ebx                ; length
    mov eax, SYSCALL_WRITE
    int 0x80                    ; ebx=ptr, ecx=len
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
    sub ecx, esi                ; length
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
msg_start:      db 'FORKDEMO: start, pid=', 0
msg_nl:         db 0x0D, 0x0A, 0
msg_child:      db 'FORKDEMO: child (pid=', 0
msg_child2:     db ', ppid=', 0
msg_close:      db ')', 0
msg_child_exit: db 'FORKDEMO: child done sleeping, exiting 42', 0x0D, 0x0A, 0
msg_parent:     db 'FORKDEMO: parent, child pid=', 0
msg_reaped:     db 'FORKDEMO: parent reaped pid=', 0
msg_status:     db ', status=', 0
msg_execfail:   db 'FORKDEMO: execve FAILED', 0x0D, 0x0A, 0
child_path:     db 'CHILD.BIN', 0
arg0:           db 'CHILD.BIN', 0
arg1:           db 'hello-from-parent', 0

exec_argv:      dd 0, 0, 0     ; filled at runtime
child_pid:      dd 0
status_v:       dd 0
reaped_v:       dd 0
numbuf:         times 16 db 0
numbuf_end:
