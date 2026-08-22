[org 0x7c00]
[bits 16]

jmp short start
nop
times 59 db 0

start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    cld
    mov [boot_drive], dl
    sti

    ; Enable A20 via BIOS
    mov ax, 0x2401
    int 0x15
    in al, 0x92
    or al, 0x02
    out 0x92, al

    mov dl, [boot_drive]
    mov [0x0500], dl

    ; Get Geometry
    mov ah, 0x08
    int 0x13
    jnc .geom_ok
    mov cx, 18
    mov dh, 1
.geom_ok:
    and cx, 0x3F
    mov [spt], cx
    movzx ax, dh
    inc ax
    mov [heads], ax
    mov word [0x0501], 2880

    ; Load Kernel to 0x10000 (staging). Must relocate to 1MB BEFORE loading
    ; the disk cache at 0x51000 — with KERNEL_SECTORS=800 staging ends at
    ; 0x74000 and would be overwritten by the cache (corrupting .data, e.g.
    ; fat12_cwd_path → garbage shell prompt).
    %define KERNEL_SECTORS 800
    mov ax, 0x1000
    mov es, ax
    xor bx, bx
    mov si, KERNEL_SECTORS
    mov ax, 1 ; Start LBA
.lk:
    call rs
    inc ax
    add bx, 512
    jnc .ns
    mov dx, es
    add dx, 0x1000
    mov es, dx
.ns:
    dec si
    jnz .lk

    ; Enter PM, copy kernel to 1MB, return to real mode, then load cache.
    cli
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:pm_reloc32

[bits 32]
pm_reloc32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x700000

    mov esi, 0x10000
    mov edi, 0x100000
    mov ecx, (KERNEL_SECTORS * 512) / 4
    rep movsd

    ; Drop back to 16-bit protected mode then real mode for BIOS disk I/O.
    jmp 0x38:pm16_down   ; gdt_code16: 16-bit code, base 0

[bits 16]
pm16_down:
    mov ax, 0x40         ; gdt_data16
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov eax, cr0
    and eax, ~1
    mov cr0, eax
    jmp 0:real_after_reloc

real_after_reloc:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    sti

    ; Load cache to 0x51000 (632*512 ends at 0xA0000, below VGA).
    ; Must cover full FAT12 root (often LBA ~560+32) so SSH/edit does not
    ; fall back to slow INT 13h during an active network session.
    ; Safe now: kernel already lives at 1MB.
    %define CACHE_SECTORS 632
    mov ax, 0x5100
    mov es, ax
    xor bx, bx
    mov si, CACHE_SECTORS
    mov ax, 0 ; Sector 0 (re-read boot)
.lc:
    call rs
    inc ax
    add bx, 512
    jnc .nsc
    mov dx, es
    add dx, 0x1000
    mov es, dx
.nsc:
    dec si
    jnz .lc

    ; Switch to PM for good and enter the kernel
    cli
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:pm_entry32

[bits 32]
pm_entry32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x700000
    mov ebp, esp

    mov eax, 0x100000
    call eax
    jmp $

[bits 16]
rs: ; Read Sector LBA
    push ax
    push bx
    push cx
    push dx
    xor dx, dx
    div word [spt]
    inc dl
    mov cl, dl
    xor dx, dx
    div word [heads]
    mov ch, al
    mov dh, dl
    mov dl, [boot_drive]
    mov ax, 0x0201
    int 0x13
    jnc .ok
    jmp $ ; Hang on error
.ok:
    pop dx
    pop cx
    pop bx
    pop ax
    ret

boot_drive db 0
spt dw 18
heads dw 2

gdt_start:
gdt_null: dq 0
gdt_code: dw 0xFFFF, 0x0000, 0x9A00, 0x00CF
gdt_data: dw 0xFFFF, 0x0000, 0x9200, 0x00CF
gdt_user_code: dw 0xFFFF, 0x0000, 0xFA00, 0x00CF
gdt_user_data: dw 0xFFFF, 0x0000, 0xF200, 0x00CF
gdt_boss_code: dw 0xFFFF, 0x0000, 0x9A07, 0x0000
gdt_boss_data: dw 0xFFFF, 0x0000, 0x9207, 0x0000
; 16-bit segments (base 0) for protected→real transition
gdt_code16: dw 0xFFFF, 0x0000, 0x9A00, 0x0000
gdt_data16: dw 0xFFFF, 0x0000, 0x9200, 0x0000
gdt_end:
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

times 510-($-$$) db 0
dw 0xAA55
