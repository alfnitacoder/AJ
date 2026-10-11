; proc64.asm - kernel context save/restore and iretq into a user uctx.
; proc_save_kernel returns 0. proc_restore_kernel resumes that call with eax=1
; (setjmp-style), which is how the scheduler hands control back to kernel_main
; once no ring-3 process is runnable.

[bits 64]

[extern sys_rsp0]

section .text

global proc_save_kernel
proc_save_kernel:
    mov [rel kctx_rsp], rsp
    mov [rel kctx_rbx], rbx
    mov [rel kctx_rbp], rbp
    mov [rel kctx_r12], r12
    mov [rel kctx_r13], r13
    mov [rel kctx_r14], r14
    mov [rel kctx_r15], r15
    xor eax, eax
    ret

global proc_restore_kernel
proc_restore_kernel:
    mov rsp, [rel kctx_rsp]
    mov rbx, [rel kctx_rbx]
    mov rbp, [rel kctx_rbp]
    mov r12, [rel kctx_r12]
    mov r13, [rel kctx_r13]
    mov r14, [rel kctx_r14]
    mov r15, [rel kctx_r15]
    mov eax, 1
    ret

; void proc64_iret_user(struct uctx *ctx) __attribute__((noreturn));
; uctx layout (8-byte slots):
;   0 rax, 8 rbx, 16 rcx, 24 rdx, 32 rsi, 40 rdi, 48 rbp, 56 rsp,
;   64 r8 .. 120 r15, 128 rip, 136 rflags
; void sh64_switch_stack(void *top, void (*fn)(void));
; The serial shell runs on its own stack so a foreground process can reuse
; the syscall/IRQ stack (sys_rsp0) without clobbering the shell frame.
global sh64_switch_stack
sh64_switch_stack:
    mov rsp, rdi
    call rsi
.hang:
    cli
    hlt
    jmp .hang

global proc64_iret_user
proc64_iret_user:
    cli
    mov rsp, [rel sys_rsp0]
    mov rax, [rdi + 56]         ; user RSP
    mov rcx, [rdi + 128]        ; user RIP
    mov r11, [rdi + 136]        ; user RFLAGS
    push qword 0x23             ; SS  (user data | RPL3)
    push rax
    push r11
    push qword 0x2B             ; CS  (user code | RPL3)
    push rcx
    mov rax, [rdi + 0]
    mov rbx, [rdi + 8]
    mov rcx, [rdi + 16]
    mov rdx, [rdi + 24]
    mov rsi, [rdi + 32]
    mov rbp, [rdi + 48]
    mov r8,  [rdi + 64]
    mov r9,  [rdi + 72]
    mov r10, [rdi + 80]
    mov r11, [rdi + 88]
    mov r12, [rdi + 96]
    mov r13, [rdi + 104]
    mov r14, [rdi + 112]
    mov r15, [rdi + 120]
    mov rdi, [rdi + 40]
    iretq

section .data
align 8
kctx_rsp: dq 0
kctx_rbx: dq 0
kctx_rbp: dq 0
kctx_r12: dq 0
kctx_r13: dq 0
kctx_r14: dq 0
kctx_r15: dq 0
