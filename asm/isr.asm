[bits 32]

; Loads the IDT: void idt_load(void* idt_ptr)
[global idt_load]
idt_load:
    mov eax, [esp + 4]
    lidt [eax]
    ret

; Common ISR stub calls into C: void isr_handler(struct regs* r)
[extern isr_handler]
[extern user_mode_exit_flag]
[extern user_mode_kernel_esp]
[extern user_mode_kernel_eip]

; Resume path for freshly built user task stacks: enters with ESP pointing at
; the four segment dwords (gs,fs,es,ds), then the pusha block, then
; int_no/err_code, then the iret frame. Same layout the stub pops below.
[global isr_user_exit]

isr_common_stub:
    pusha
    ; Push segment selectors as 32-bit values so the C regs struct matches.
    xor eax, eax
    mov ax, ds
    push eax
    xor eax, eax
    mov ax, es
    push eax
    xor eax, eax
    mov ax, fs
    push eax
    xor eax, eax
    mov ax, gs
    push eax

    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    push esp
    call isr_handler
    add esp, 4

    ; If a user-mode program requested exit via syscall, jump back to the
    ; saved kernel context (set by enter_user_mode). We only do this for
    ; syscalls (int 0x80) where no PIC EOI is needed.
    cmp dword [user_mode_exit_flag], 0
    je .no_user_exit
    mov dword [user_mode_exit_flag], 0
    mov esp, [user_mode_kernel_esp]
    jmp dword [user_mode_kernel_eip]
.no_user_exit:

isr_user_exit:
    pop eax
    mov gs, ax
    pop eax
    mov fs, ax
    pop eax
    mov es, ax
    pop eax
    mov ds, ax
    popa

    add esp, 8          ; pop int_no and err_code
    iretd

%macro ISR_NOERR 1
    [global isr%1]
isr%1:
    push dword 0
    push dword %1
    jmp isr_common_stub
%endmacro

%macro ISR_ERR 1
    [global isr%1]
isr%1:
    push dword %1
    jmp isr_common_stub
%endmacro

; CPU exceptions (0..31). Error-code exceptions: 8,10,11,12,13,14,17
ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_NOERR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_NOERR 30
ISR_NOERR 31

; IRQs after PIC remap (32..47)
ISR_NOERR 32
ISR_NOERR 33
ISR_NOERR 34
ISR_NOERR 35
ISR_NOERR 36
ISR_NOERR 37
ISR_NOERR 38
ISR_NOERR 39
ISR_NOERR 40
ISR_NOERR 41
ISR_NOERR 42
ISR_NOERR 43
ISR_NOERR 44
ISR_NOERR 45
ISR_NOERR 46
ISR_NOERR 47

; Syscall interrupt
ISR_NOERR 128

