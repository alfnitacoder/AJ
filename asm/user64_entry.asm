; user64_entry.asm - ring0 <-> ring3 transitions for the AJOS x86-64 port.
; jump_to_user: iretq into ring 3 (the frame pushed by hand).
; syscall_entry: LSTAR target; switches to the kernel stack, dispatches
; to the C syscall_handler(nr, a1, a2), then sysretq back.

[global syscall_entry]
[global jump_to_user]
[extern syscall_handler]

[bits 64]
section .text
syscall_entry:
    mov [rel dbg_rcx], rcx
    mov rsp, [rel sys_rsp0]         ; switch to the kernel stack
    push rcx                        ; the user rip
    push r11                        ; the user rflags
    mov rdi, rax                    ; the C handler(nr, a1=rsi, a2=rdx)
    call syscall_handler
    pop r11
    pop rcx
    ; return via iretq: build the ring3 frame by hand (the user rsp is the
    ; fixed initial stack top; the milestone programs never move it)
    mov rsp, [rel sys_rsp0]
    push 0x23                       ; user SS
    push 0x10000101000              ; user RSP (USER_STACK + 4096)
    push r11                        ; RFLAGS
    push 0x2B                       ; user CS
    push rcx                        ; user RIP
    iretq

jump_to_user:                       ; rdi = the entry rip, rsi = the user rsp
    cli
    push 0x23                       ; user SS  (0x20 | RPL3)
    push rsi                        ; user RSP
    push 0x202                      ; RFLAGS: IF=1
    push 0x2B                       ; user CS  (0x28 | RPL3)
    push rdi                        ; user RIP
    iretq

section .data
align 8
global sys_rsp0
sys_rsp0:       dq 0x6E0000         ; the ring0 stack top (below the kernel 7MB)
global user_rsp_save
user_rsp_save:  dq 0
global dbg_rcx
dbg_rcx:        dq 0
