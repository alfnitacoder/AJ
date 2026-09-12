; isr64.asm - 64-bit exception/IRQ stubs for the AJOS long-mode kernel.
; SysV x86-64: rdi=vector, rsi=error code, rdx=faulting RIP -> C dispatch.
; Exceptions are fatal (halt) except vec 3 (breakpoint), which returns.
; IRQ stubs dispatch to irq64_dispatch(vector-32).

[global isr64_stub_table]
[extern isr64_dispatch]
[extern irq64_dispatch]

; The C dispatchers follow the SysV ABI and may clobber the volatile
; registers, so every stub saves/restores them. 9 pushes (72 bytes) +
; the 24-byte CPU frame also leaves rsp 16-aligned for the call.
%macro PUSHVOL 0
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
%endmacro

%macro POPVOL 0
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax
%endmacro

%macro ISR64_NOERR 1
isr64_stub_%1:
    PUSHVOL
    mov edi, %1
    xor esi, esi
    mov rdx, [rsp+72]       ; pushed RIP (above the 9 saved regs)
    cld
    call isr64_dispatch
    POPVOL
    iretq
%endmacro

%macro ISR64_ERR 1
isr64_stub_%1:
    PUSHVOL
    mov edi, %1
    mov esi, [rsp+72]       ; CPU-pushed error code
    mov rdx, [rsp+80]       ; pushed RIP
    cld
    call isr64_dispatch
    POPVOL
    add rsp, 8              ; drop error code
    iretq
%endmacro

%macro ISR64_IRQ 1
isr64_stub_%1:
    PUSHVOL
    mov edi, %1 - 32
    cld
    call irq64_dispatch
    POPVOL
    iretq
%endmacro

section .text

; Exceptions without an error code
ISR64_NOERR 0
ISR64_NOERR 1
ISR64_NOERR 2
ISR64_NOERR 3
ISR64_NOERR 4
ISR64_NOERR 5
ISR64_NOERR 6
ISR64_NOERR 7
; 8 (DF) has error code(s); treated as ERR - fatal anyway
ISR64_ERR 8
ISR64_NOERR 9
ISR64_ERR 10
ISR64_ERR 11
ISR64_ERR 12
ISR64_ERR 13
ISR64_ERR 14
ISR64_NOERR 15
ISR64_NOERR 16
ISR64_ERR 17
ISR64_NOERR 18
ISR64_NOERR 19
ISR64_NOERR 20
ISR64_ERR 21
ISR64_NOERR 22
ISR64_NOERR 23
ISR64_NOERR 24
ISR64_NOERR 25
ISR64_NOERR 26
ISR64_NOERR 27
ISR64_NOERR 28
ISR64_NOERR 29
ISR64_NOERR 30
ISR64_NOERR 31

; IRQs 0..15 -> vectors 32..47
ISR64_IRQ 32
ISR64_IRQ 33
ISR64_IRQ 34
ISR64_IRQ 35
ISR64_IRQ 36
ISR64_IRQ 37
ISR64_IRQ 38
ISR64_IRQ 39
ISR64_IRQ 40
ISR64_IRQ 41
ISR64_IRQ 42
ISR64_IRQ 43
ISR64_IRQ 44
ISR64_IRQ 45
ISR64_IRQ 46
ISR64_IRQ 47

; Any other vector: quiet iretq (should not happen with a full IDT).
isr64_stub_spurious:
    iretq

section .data
align 8
isr64_stub_table:
    %assign v 0
    %rep 32
        dq isr64_stub_ %+ v
    %assign v v+1
    %endrep
    %assign v 32
    %rep 16
        dq isr64_stub_ %+ v
    %assign v v+1
    %endrep
    dq isr64_stub_spurious
