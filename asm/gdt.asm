[bits 32]

; Kernel GDT:
;  - 0x00: null
;  - 0x08: kernel code
;  - 0x10: kernel data
;  - 0x18: user code (ring3)
;  - 0x20: user data (ring3)
;  - 0x28: TSS (ring0 stack for CPL transitions)
;
; Used by:
;  - BIOS thunk (restore protected-mode state after real-mode calls)
;  - run3/user mode (CPL3)

[global gdt_descriptor]
[global gdt_start]
[global tss_entry]
[global gdt_install_and_tss]
[global tss_set_esp0]
[global tss_runtime_base]

%define KERNEL_CS 0x08
%define KERNEL_DS 0x10
%define USER_CS   0x1B    ; 0x18 | RPL3
%define USER_DS   0x23    ; 0x20 | RPL3
%define RM_CODE_SEL 0x28
%define RM_DATA_SEL 0x30
%define TSS_SEL     0x38

section .data
align 4

; 32-bit TSS (104 bytes)
tss_entry:
    dd 0                ; prev_tss
    dd 0x001ff000       ; esp0 — matches tss_set_esp0() after GDT install
    dd KERNEL_DS        ; ss0
    dd 0                ; esp1
    dd 0                ; ss1
    dd 0                ; esp2
    dd 0                ; ss2
    dd 0                ; cr3
    dd 0                ; eip
    dd 0                ; eflags
    dd 0                ; eax
    dd 0                ; ecx
    dd 0                ; edx
    dd 0                ; ebx
    dd 0                ; esp
    dd 0                ; ebp
    dd 0                ; esi
    dd 0                ; edi
    dd 0                ; es
    dd 0                ; cs
    dd 0                ; ss
    dd 0                ; ds
    dd 0                ; fs
    dd 0                ; gs
    dd 0                ; ldt
    dw 0                ; trap
    dw tss_end - tss_entry ; iomap_base
tss_end:

; Runtime address of TSS (kernel runs at 0x100000; descriptor and tss_set_esp0 use this)
tss_runtime_base: dd 0

gdt_start:
    dq 0
    ; kernel code: base=0 limit=4GiB, present, ring0, exec/read
    ; Use same format as bootloader's working GDT (word-packed)
    dw 0xFFFF, 0x0000, 0x9A00, 0x00CF
    ; kernel data: base=0 limit=4GiB, present, ring0, read/write
    ; Use same format as bootloader's working GDT (word-packed)
    dw 0xFFFF, 0x0000, 0x9200, 0x00CF
    ; user code: base=0 limit=4GiB, present, ring3, exec/read
    dw 0xFFFF      ; limit low
    dw 0x0000      ; base low
    db 0x00        ; base mid
    db 0xFA        ; access: present(1) DPL(11) S(1) type(1010=exec/read)
    db 0xCF        ; limit high + flags
    db 0x00        ; base high
    ; user data: base=0 limit=4GiB, present, ring3, read/write
    dw 0xFFFF      ; limit low
    dw 0x0000      ; base low
    db 0x00        ; base mid
    db 0xF2        ; access: present(1) DPL(11) S(1) type(0010=read/write)
    db 0xCF        ; limit high + flags
    db 0x00        ; base high
    ; 16-bit code: base=0x70000 limit=0xFFFF (BOSS segment for RM transition)
    dw 0xFFFF      ; limit low
    dw 0x0000      ; base low (bits 0-15 of 0x70000 = 0x0000)
    db 0x07        ; base mid (bits 16-23 of 0x70000 = 0x07)
    db 0x9A        ; access: present, ring0, exec/read
    db 0x00        ; limit high + flags (16-bit, no granularity)
    db 0x00        ; base high (bits 24-31 of 0x70000 = 0x00)
    ; 16-bit data: base=0x70000 limit=0xFFFF (BOSS segment for RM transition)
    dw 0xFFFF      ; limit low
    dw 0x0000      ; base low
    db 0x07        ; base mid
    db 0x92        ; access: present, ring0, read/write
    db 0x00        ; limit high + flags
    db 0x00        ; base high
    ; TSS descriptor (base is patched at runtime in gdt_install_and_tss)
gdt_tss:
    dw (tss_end - tss_entry - 1)      ; limit low
    dw 0x0000                         ; base low (patched)
    db 0x00                           ; base mid (patched)
    db 0x89                           ; access: present, ring0, 32-bit available TSS
    db 0x00                           ; limit high=0 (TSS < 256 bytes), flags=0
    db 0x00                           ; base high (patched)
gdt_end:

gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; Far jump pointer for CS refresh (offset, segment)
far_jump_ptr:
    dd 0        ; offset (will be patched)
    dw 0x08    ; segment

section .text

; void gdt_install_and_tss(void)
gdt_install_and_tss:
    cli

    ; Patch TSS descriptor with the real VMA of tss_entry. Do not use
    ; (tss_entry - .pic): NASM emits R_386_PC32 .data + tiny addend; the linker
    ; then produces a wrong base (~0x200 short) and ltr faults.
    mov eax, tss_entry
    mov [tss_runtime_base], eax
    mov word [gdt_tss + 2], ax        ; base low
    shr eax, 16
    mov byte [gdt_tss + 4], al        ; base mid
    mov byte [gdt_tss + 7], ah        ; base high

    ; Copy GDT to 0x8000 and point GDTR there. In-image lgdt + ljmp left GDTR
    ; corrupted in QEMU (see int log: bogus GDT base ~0x13b10c68); low-RAM copy
    ; matches the bootloader-tested layout for the first 3 descriptors.
    mov dword [0x8000], 0
    mov dword [0x8004], 0
    mov dword [0x8008], 0x0000ffff
    mov dword [0x800c], 0x00cf9a00
    mov dword [0x8010], 0x0000ffff
    mov dword [0x8014], 0x00cf9200
    xor eax, eax
    mov ax, KERNEL_DS
    mov ds, ax
    mov esi, gdt_start
    add esi, 24
    mov edi, 0x8018
    mov ecx, 8
.copy_mid:
    mov eax, [esi]
    mov [edi], eax
    add esi, 4
    add edi, 4
    loop .copy_mid
    mov esi, gdt_tss
    mov edi, 0x8038
    mov eax, [esi]
    mov [edi], eax
    mov eax, [esi + 4]
    mov [edi + 4], eax
    mov word [gdt_descriptor], gdt_end - gdt_start - 1
    mov dword [gdt_descriptor + 2], 0x8000
    lgdt [gdt_descriptor]

    ; Reload CS first (far jump), then data segments — loading DS/SS from the
    ; new GDT before CS is refreshed faulted on QEMU with the old sequence.
    jmp KERNEL_CS:.flush
.flush:
    ; Reload data + stack segments (clear EAX so high 16 bits are zero).
    xor eax, eax
    mov ax, KERNEL_DS
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    xor eax, eax
    mov ax, TSS_SEL
    ; In [bits 32], bare `ltr ax` encodes as LTR r/m32 and #GPs; need 16-bit form.
    ; QEMU still #GPs on o16 ltr with selector 0x38 (error code 0x38) despite a
    ; valid TSS descriptor at 0x8038; load TR from C after IDT is up (ltr_load).
    ret

; void tss_set_esp0(uint32_t esp0)
tss_set_esp0:
    mov eax, [esp + 4]                 ; esp0 value
    mov ebx, [tss_runtime_base]        ; TSS in running image (0x100000 + offset)
    mov [ebx + 4], eax
    ret

; uint32_t tss_get_esp0(void)
[global tss_get_esp0]
tss_get_esp0:
    mov ebx, [tss_runtime_base]
    mov eax, [ebx + 4]
    ret

; Load task register (call after GDT + IDT are valid; see gdt_install_and_tss).
[global ltr_load]
ltr_load:
    xor eax, eax
    mov ax, TSS_SEL
    o16 ltr ax
    ret

