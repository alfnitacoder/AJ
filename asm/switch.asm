; Cooperative context switch (i386, cdecl).
; void switch_to(uint32_t *old_esp, uint32_t new_esp);
; Saves callee-saved regs + frame on current stack, stores ESP in *old_esp,
; loads new_esp, pops the frame the other task saved, and ret's to its PC.

bits 32
section .text

global switch_to

switch_to:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi

    mov eax, [ebp+8]     ; old_esp
    mov edx, [ebp+12]    ; new_esp
    mov [eax], esp       ; *old_esp = saved stack pointer
    mov esp, edx

    pop edi
    pop esi
    pop ebx
    pop ebp
    ret
