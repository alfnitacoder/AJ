[bits 32]

[global enter_user_mode]

[extern user_mode_kernel_esp]
[extern user_mode_kernel_eip]

%define USER_CS 0x1B
%define USER_DS 0x23

; void enter_user_mode(uint32_t user_eip, uint32_t user_esp)
; Enters CPL3 via iret. Returns to caller when the kernel's syscall handler
; requests exit (isr stub jumps back to user_mode_kernel_eip/esp).
enter_user_mode:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    pushfd

    mov [user_mode_kernel_esp], esp
    mov eax, .return_from_user
    mov [user_mode_kernel_eip], eax

    ; Set user data segments before dropping privilege
    mov ax, USER_DS
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Build iret frame: SS, ESP, EFLAGS, CS, EIP
    push USER_DS
    mov eax, [ebp + 12]     ; user_esp
    push eax
    pushfd
    pop eax
    or eax, 0x200           ; IF=1
    push eax
    push USER_CS
    mov eax, [ebp + 8]      ; user_eip
    push eax
    iretd

.return_from_user:
    popfd
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret

