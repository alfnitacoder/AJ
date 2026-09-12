; boot64.asm - AJOS x86-64 bring-up boot sector.
; Fork of asm/boot.asm, simplified: loads kernel64.bin, relocates to 1MB in
; protected mode, then transitions straight to IA-32e long mode (no second
; real-mode phase - the 64-bit stub does not need the FAT disk cache).
; Page tables: 0x1000 PML4 -> 0x2000 PDPT with four 1GB identity pages
; (0..4GB). 64-bit GDT: 0x08 code (L=1), 0x10 data.

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

    mov ax, 0x2401      ; A20 via BIOS
    int 0x15
    in al, 0x92
    or al, 0x02
    out 0x92, al

    mov ah, 0x08        ; geometry
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

    %define KERNEL_SECTORS 800
    mov ax, 0x1000      ; stage kernel at 0x10000
    mov es, ax
    xor bx, bx
    mov si, KERNEL_SECTORS
    mov ax, 1           ; start LBA
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

    cli
    lgdt [gdt_descriptor]
    mov eax, cr0
    or eax, 1           ; PE
    mov cr0, eax
    jmp 0x08:pm_entry32

[bits 32]
pm_entry32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov esp, 0x700000

    mov esi, 0x10000    ; relocate kernel to 1MB
    mov edi, 0x100000
    mov ecx, (KERNEL_SECTORS * 512) / 4
    rep movsd

    ; ---- Identity page tables: 0..4GB with 1GB pages ----
    mov edi, 0x1000     ; PML4: zero 2 pages (PML4 + PDPT)
    xor eax, eax
    mov ecx, 1024
    rep stosd
    mov dword [0x1000], 0x2003          ; PML4[0] = 0x2000 | P|W
    mov dword [0x2000], 0x00000083      ; 1GB @ 0
    mov dword [0x2008], 0x40000083      ; 1GB @ 0x40000000
    mov dword [0x2010], 0x80000083      ; 1GB @ 0x80000000
    mov dword [0x2018], 0xC0000083      ; 1GB @ 0xC0000000

    mov eax, 0x1000     ; CR3 = PML4
    mov cr3, eax
    mov eax, cr4
    or eax, (1 << 5)    ; PAE
    mov cr4, eax
    mov ecx, 0xC0000080 ; IA32_EFER
    rdmsr
    or eax, (1 << 8)    ; LME
    wrmsr
    mov eax, cr0
    or eax, (1 << 31)   ; PG -> long mode active
    mov cr0, eax

    lgdt [gdt64_descriptor]
    jmp 0x08:lm_entry64

[bits 64]
lm_entry64:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov rax, 0x100000   ; kernel_entry64 start
    jmp rax

[bits 16]
rs: ; Read Sector LBA -> CHS INT 13h
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
    jmp $               ; hang on error
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
gdt_end:
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

align 8
gdt64_start:
gdt64_null: dq 0                    ; selector 0x00
gdt64_code: dq 0x00AF9A000000FFFF   ; selector 0x08, L=1, P|S|RX
gdt64_data: dq 0x00CF92000000FFFF   ; selector 0x10, P|S|W
gdt64_end:
gdt64_descriptor:
    dw gdt64_end - gdt64_start - 1
    dd gdt64_start

times 510-($-$$) db 0
dw 0xAA55
