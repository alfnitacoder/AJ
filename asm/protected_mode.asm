[bits 16]

[global pm_start]
[global gdt_descriptor]
pm_start:
    ; Still in real mode here (jumped from bootloader). Print a marker so we
    ; can distinguish "kernel not reached" from "protected mode switch failed".
    mov si, pm_start_msg
    call rm_print_string

    cli
    lgdt [gdt_descriptor]

    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp 0x08:protected_mode_entry

rm_print_string:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0e
    int 0x10
    jmp rm_print_string
.done:
    ret

pm_start_msg db 'PM stub reached, switching modes...', 0x0d, 0x0a, 0

gdt_start:
gdt_null:      dq 0
gdt_code:      dw 0xFFFF, 0x0000, 0x9A00, 0x00CF
gdt_data:      dw 0xFFFF, 0x0000, 0x9200, 0x00CF
; BOSS segments for real-mode transitions (needed by BIOS thunk)
; 16-bit code: base=0x70000 limit=0xFFFF
gdt_boss_code: dw 0xFFFF, 0x0000, 0x9A07, 0x0000
; 16-bit data: base=0x70000 limit=0xFFFF
gdt_boss_data: dw 0xFFFF, 0x0000, 0x9207, 0x0000
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

[bits 32]
protected_mode_entry:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x90000
    mov ebp, esp
    cld

    ; Call the kernel entry point (start)
    extern start
    call start

    hlt
    jmp $ 