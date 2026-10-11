; user64_entry.asm - ring0 <-> ring3 transitions for the AJOS x86-64 port.
; jump_to_user: iretq into ring 3 (the frame pushed by hand).
; syscall_entry: LSTAR target. Snapshots the user register file into
; proc64_snap (syscall clobbers rcx/r11; rsp is still the user stack),
; switches to the kernel stack, and calls syscall_handler. A normal
; return iretqs back with the real user RSP. fork/wait/exit may instead
; iretq into a different process and never return here.

[global syscall_entry]
[global jump_to_user]
[extern syscall_handler]
[extern proc64_snap]

[bits 64]
section .text
syscall_entry:
    ; uctx slots: see proc64.c / proc64_iret_user. rcx = return RIP, r11 = RFLAGS.
    mov [rel proc64_snap + 56], rsp
    mov [rel proc64_snap + 128], rcx
    mov [rel proc64_snap + 136], r11
    mov [rel proc64_snap + 0], rax
    mov [rel proc64_snap + 8], rbx
    mov [rel proc64_snap + 16], rcx
    mov [rel proc64_snap + 24], rdx
    mov [rel proc64_snap + 32], rsi
    mov [rel proc64_snap + 40], rdi
    mov [rel proc64_snap + 48], rbp
    mov [rel proc64_snap + 64], r8
    mov [rel proc64_snap + 72], r9
    mov [rel proc64_snap + 80], r10
    mov [rel proc64_snap + 88], r11
    mov [rel proc64_snap + 96], r12
    mov [rel proc64_snap + 104], r13
    mov [rel proc64_snap + 112], r14
    mov [rel proc64_snap + 120], r15
    mov rsp, [rel sys_rsp0]
    mov rdi, rax                    ; syscall_handler(nr); args live in the snap
    call syscall_handler
    ; rax = return value. Restore every other GPR from the snap so a
    ; syscall preserves the user register file (rcx/r11 are the iretq vehicles).
    mov rbx, [rel proc64_snap + 8]
    mov rdx, [rel proc64_snap + 24]
    mov rsi, [rel proc64_snap + 32]
    mov rdi, [rel proc64_snap + 40]
    mov rbp, [rel proc64_snap + 48]
    mov r8,  [rel proc64_snap + 64]
    mov r9,  [rel proc64_snap + 72]
    mov r10, [rel proc64_snap + 80]
    mov r12, [rel proc64_snap + 96]
    mov r13, [rel proc64_snap + 104]
    mov r14, [rel proc64_snap + 112]
    mov r15, [rel proc64_snap + 120]
    mov rcx, [rel proc64_snap + 128]    ; user RIP
    mov r11, [rel proc64_snap + 136]    ; user RFLAGS
    mov rsp, [rel sys_rsp0]
    push qword 0x23                     ; user SS
    push qword [rel proc64_snap + 56]   ; user RSP
    push r11
    push qword 0x2B                     ; user CS
    push rcx
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
