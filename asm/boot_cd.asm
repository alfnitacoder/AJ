; CD no-emulation boot: BIOS loads full 1.44MB image to 0x7C00.
; We copy kernel and cache from memory - no INT 13h needed.
; Use with: xorriso ... -no-emul-boot -boot-load-size 4 -boot-info-table
;           (boot-load-size 4 loads only first sector - we need full image)
; Actually: use -boot-load-size 2880 to load entire 1.44MB image to 0x7C00.
; Then this stub runs (at 0x7C00), kernel at 0x7E00, we copy to 0x100000 and 0x51000.

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

    ; A20
    in al, 0x92
    or al, 0x02
    and al, 0xFE
    out 0x92, al

    ; Clear screen and print
    mov ax, 0x0003
    int 0x10
    mov si, boot_msg
cd_print_loop:
    lodsb
    or al, al
    jz cd_print_done
    mov ah, 0x0e
    int 0x10
    jmp cd_print_loop
cd_print_done:

    ; Boot drive = 0 (use cache, no BIOS disk)
    mov byte [0x0500], 0
    mov word [0x0501], 2880

    ; Copy disk cache: 600 sectors from 0x7C00 to 0x51000 (must stay below 0xA0000)
    mov ax, 0x7C0
    mov ds, ax
    xor si, si
    mov ax, 0x5100
    mov es, ax
    xor di, di
    mov bx, 600 * 2       ; 600 sectors = 1200 x 256 bytes
cd_cache_loop:
    mov cx, 256 / 2
    rep movsw
    dec bx
    jnz cd_cache_loop

    ; Copy kernel: 500 sectors from 0x7E00 to 0x100000
    xor ax, ax
    mov ds, ax
    mov ax, 0x7E0
    mov ds, ax
    xor si, si
    mov ax, 0xF000
    mov es, ax
    mov di, 0x1000
    mov bx, 500 * 2       ; 500 sectors = 1000 x 256 bytes
cd_kernel_loop:
    mov cx, 256 / 2
    rep movsw
    dec bx
    jnz cd_kernel_loop

    xor ax, ax
    mov ds, ax

    ; Switch to protected mode
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

    mov eax, 0x100000
    call eax
    jmp $

[bits 16]
boot_msg db 'AJOS (CD)...', 0

gdt_start:
gdt_null: dq 0
gdt_code: dw 0xFFFF, 0x0000, 0x9A00, 0x00CF
gdt_data: dw 0xFFFF, 0x0000, 0x9200, 0x00CF
gdt_end:
gdt_descriptor:
    dw gdt_end - gdt_start - 1
    dd gdt_start

times 510-($-$$) db 0
dw 0xAA55
