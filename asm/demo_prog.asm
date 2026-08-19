[bits 32]
[org 0]

; AJOS demo program (flat binary with tiny header)
; Header (16 bytes):
;  - magic[7] = "AJOSBIN"
;  - version  = 1
;  - entry_offset (u32) = offset of entry from file start
;  - flags (u32) = 0

db 'AJOSBIN'
db 1
dd entry
dd 0

%include "asm/ajos_syscall.inc"

entry:
    ; Compute runtime base address (position-independent addressing)
    call .next
.next:
    pop ebp
    sub ebp, .next

    ; syscall write(banner, len)
    mov eax, SYSCALL_WRITE
    lea ebx, [ebp + banner]
    mov ecx, banner_len
    int 0x80

    ; Wait for a key (returns ASCII or KEY_* constants)
    ; Ignore leftover newlines from the shell input.
.wait_key:
    mov eax, SYSCALL_GETKEY
    int 0x80
    ; If special key (>= 0x100), print special message
    cmp eax, 0x100
    jae .special_key

    ; Ignore control chars + space; wait for a visible printable ASCII.
    cmp al, '!'
    jb .wait_key
    cmp al, '~'
    ja .wait_key

    jmp .print_char

.special_key:
    mov eax, SYSCALL_WRITE
    lea ebx, [ebp + special]
    mov ecx, special_len
    int 0x80
    jmp .sleep_and_return

.print_char:
    mov [ebp + one_char], al
    mov eax, SYSCALL_WRITE
    lea ebx, [ebp + pressed]
    mov ecx, pressed_len
    int 0x80

    mov eax, SYSCALL_WRITE
    lea ebx, [ebp + one_char]
    mov ecx, 1
    int 0x80

    mov eax, SYSCALL_WRITE
    lea ebx, [ebp + crlf]
    mov ecx, 2
    int 0x80

.sleep_and_return:
    ; sleep 500ms so you can see output
    mov eax, SYSCALL_SLEEP
    mov ebx, 500
    int 0x80

    ; Exit back to kernel (needed for run3)
    mov eax, SYSCALL_EXIT
    int 0x80

    hlt
    jmp $

banner db 'DEMO.BIN: sys_write/sys_getkey/sys_sleep demo', 0x0D, 0x0A, 'Press any key...', 0x0D, 0x0A, 0
banner_len equ ($ - banner) - 1

pressed db 'You pressed: ', 0
pressed_len equ ($ - pressed) - 1

special db 'You pressed a special key.', 0x0D, 0x0A, 0
special_len equ ($ - special) - 1

crlf db 0x0D, 0x0A
one_char db 0

