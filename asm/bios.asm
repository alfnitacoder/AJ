; BIOS INT 13h thunk for protected mode
; ------------------------------------
; int bios_int13_read_chs(uint32_t drive, uint32_t cyl, uint32_t head, uint32_t sect,
;                         uint32_t seg, uint32_t off);
;
; Returns 0 on success, non-zero on error.
;
; Copies a small real-mode trampoline to 0x7000:0x0000 and uses it to call BIOS.

[bits 32]
[global bios_int13_read_chs]
[global bios_int13_write_chs]
[global bios_vga_set_mode]
[global bios_vbe_set_mode]
[global bios_vbe_get_mode_info]
[extern gdt_descriptor]

%define TRAMP_SEG 0x7000
%define TRAMP_OFF 0x0000
%define TRAMP_PHYS 0x70000
; Params must NOT overlap the runtime GDT at 0x8000 (see gdt_install_and_tss).
; Using 0x8000 previously corrupted kernel descriptors and triple-faulted on
; floppy writes (touch/create → QEMU reboot → login prompt).
%define PARAM_PHYS 0x8400
%define GDT_COPY_PHYS 0x8100
%define IDT_COPY_PHYS 0x8200
%define PM_IDT_COPY_PHYS 0x8300

section .data
align 4
rm_idtr:
    dw 0x3FF    ; Limit
    dd 0        ; Base

section .bss
align 4
pm_saved_esp:     resd 1
tramp_inited:     resd 1

section .text

; -------------------------
; Protected-mode entrypoint
; -------------------------
bios_int13_read_chs:
    push ebp
    mov ebp, esp
    mov dword [PARAM_PHYS + 28], 0x0201 ; AH=02 (read), AL=01 (count)
    jmp bios_int13_common

bios_int13_write_chs:
    push ebp
    mov ebp, esp
    mov dword [PARAM_PHYS + 28], 0x0301 ; AH=03 (write), AL=01 (count)
    jmp bios_int13_common

bios_int13_common:
    pushad

    cli
    mov [pm_saved_esp], esp
    
    ; Save current Interrupt Mask Registers (IMR) to low memory
    in al, 0x21
    mov [PARAM_PHYS + 32], al
    in al, 0xA1
    mov [PARAM_PHYS + 33], al
    
    ; CRITICAL FIX: Mask unsafe interrupts (e.g. Network IRQ11) before Real Mode!
    ; Real Mode IDT is not set up for E1000 interrupts, causing crashes if they fire.
    
    ; Mask Slave interrupts: Enable IRQ14/15 (IDE). Mask IRQ11 (E1000).
    ; 0x3F = 0011 1111. Bits 6,7 are 0 (Enabled). Bit 3 (IRQ11) is 1 (Masked).
    mov al, 0x3F
    out 0xA1, al
    
    ; Mask Master interrupts: Enable IRQ0(Timer), IRQ1(Kbd), IRQ2(Cascade), IRQ6(Floppy)
    ; 0xB8 = 1011 1000. Bit 2 (Cascade) is 0 (Enabled).
    mov al, 0xB8
    out 0x21, al

    ; mov esi, idtp
    ; Initialize trampoline EVERY TIME for safety
    ; cmp dword [tramp_inited], 1
    ; je .tramp_ok
    mov esi, rm_tramp_start
    mov edi, TRAMP_PHYS
    mov ecx, rm_tramp_end - rm_tramp_start
    cld
    rep movsb
    mov dword [tramp_inited], 1
.tramp_ok:

    ; Stage params into low memory block (fixed physical address)
    mov eax, [ebp + 8]     ; drive
    mov [PARAM_PHYS + 0], eax
    mov eax, [ebp + 12]    ; cyl
    mov [PARAM_PHYS + 4], eax
    mov eax, [ebp + 16]    ; head
    mov [PARAM_PHYS + 8], eax
    mov eax, [ebp + 20]    ; sect
    mov [PARAM_PHYS + 12], eax
    mov eax, [ebp + 24]    ; seg
    mov [PARAM_PHYS + 16], eax
    mov eax, [ebp + 28]    ; off
    mov [PARAM_PHYS + 20], eax
    mov dword [PARAM_PHYS + 24], 0   ; status out

    ; Copy GDT & IDT descriptors into low memory
    mov esi, gdt_descriptor
    mov edi, GDT_COPY_PHYS
    mov ecx, 6
    rep movsb
    mov esi, rm_idtr
    mov edi, IDT_COPY_PHYS
    mov ecx, 6
    rep movsb

    extern idtp
    mov esi, idtp
    mov edi, PM_IDT_COPY_PHYS
    mov ecx, 6
    rep movsb

    ; Flush PM state before switch
    mov eax, cr0
    and eax, 0x7FFFFFFF ; Clear PG (bit 31)
    mov cr0, eax
    
    ; Far jump to BOSS segment (0x28:0 lands at trampoline 0x70000)
    ; The BOSS segment 0x28 has base 0x70000.
    jmp 0x28:0

; -------------------------
; Return point (protected mode)
; -------------------------
[bits 32]
pm_return:
    mov ax, 0x10 ; KERNEL_DS
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, [pm_saved_esp]

    mov eax, [PARAM_PHYS + 24]
    popad
    pop ebp
    sti
    ret

; -------------------------
; Real-mode trampoline blob
; -------------------------
[bits 16]
rm_tramp_start:
    ; Offset 0 (Accessed via Selector 0x28:0 from PM)
    ; This code runs in 16-bit Protected Mode initially.
    mov ax, 0x30 ; Selector 0x30 (16-bit data BOSS)
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov eax, cr0
    and eax, 0xFFFFFFFE ; Clear PE (bit 0)
    mov cr0, eax

    ; Now in Real Mode. Refresh CS and jump to the rest of the tramp.
    jmp TRAMP_SEG:(.rm_entry - rm_tramp_start)

.rm_entry:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x9000

    xor ax, ax
    mov es, ax
    lidt [IDT_COPY_PHYS]
    cld

    ; Instead of remapping PIC (which is slow and potentially unstable),
    ; we tunnel the remapped IRQs to the BIOS vectors in the IVT at 0.
    ; IRQ 0 (Timer) is at 0x20 in AJOS. BIOS expects it at 0x08.
    ; IRQ 1 (Keyboard) is at 0x21 in AJOS. BIOS expects it at 0x09.
    ; IRQ 6 (Floppy) is at 0x26 in AJOS. BIOS expects it at 0x0E.

    xor ax, ax
    mov es, ax
    ; Set [0x20*4] to [0x08*4]
    mov eax, [es:0x08*4]
    mov [es:0x20*4], eax
    ; Set [0x21*4] to [0x09*4]
    mov eax, [es:0x09*4]
    mov [es:0x21*4], eax
    ; Set [0x26*4] to [0x0E*4]
    mov eax, [es:0x0E*4]
    mov [es:0x26*4], eax

    ; IRQ 14 (IDE Primary): 0x2E -> 0x76 (BIOS)
    mov eax, [es:0x76*4]
    mov [es:0x2E*4], eax

    ; IRQ 15 (IDE Secondary): 0x2F -> 0x77 (BIOS)
    mov eax, [es:0x77*4]
    mov [es:0x2F*4], eax

    ; Do NOT unmask everything here. Rely on masks set before jumping.
    ; (Removing unsafe 'out 0x21, 0' which enabled UARTs/etc)

    ; Stage 3: Parameter Setup
    mov dl, byte [PARAM_PHYS + 0] ; Drive

    ; Reset drive removed (redundant and potentially clobbers DL)
    ; xor ax, ax
    ; int 0x13

    ; CH = cylinder low 8 bits
    mov ax, [PARAM_PHYS + 4]      ; cyl
    mov ch, al
    ; CL = sector (1..18)
    mov al, byte [PARAM_PHYS + 12] ; sect
    mov cl, al
    ; DH = head
    mov al, byte [PARAM_PHYS + 8]  ; head
    mov dh, al

    ; ES:BX = buffer (seg/off)
    mov ax, [PARAM_PHYS + 16]      ; seg
    mov es, ax
    mov bx, [PARAM_PHYS + 20]      ; off

    ; Op/Count
    mov ax, [PARAM_PHYS + 28]      ; AH=op, AL=count

    ; Execute BIOS INT 13h
    sti
    int 0x13
    cli

    mov [PARAM_PHYS + 24], ax ; Store AH (status) and AL (count)

    jmp .to_pm

.to_pm:
    ; Restore PIC remap for protected mode (IRQs 0..15 -> 0x20..0x2F)
    mov al, 0x11
    out 0x20, al
    out 0xA0, al
    mov al, 0x20
    out 0x21, al
    mov al, 0x28
    out 0xA1, al
    mov al, 0x04
    out 0x21, al
    mov al, 0x02
    out 0xA1, al
    mov al, 0x01
    out 0x21, al
    out 0xA1, al
    ; Mask everything except IRQ0(Timer), IRQ1(KBD), IRQ3/4(Serial) on master.
    ; CRITICAL FIX: Restore previous interrupt masks instead of hardcoding!
    ; This ensures E1000 (IRQ11) remains enabled if it was enabled before.
    
    ; Restore Master IMR from PARAM_PHYS+32
    mov al, [PARAM_PHYS + 32]
    out 0x21, al
    
    ; Restore Slave IMR from PARAM_PHYS+33
    mov al, [PARAM_PHYS + 33]
    out 0xA1, al

    ; GDT descriptor copy is at physical 0x0640.
    lgdt [GDT_COPY_PHYS]
    lidt [PM_IDT_COPY_PHYS]

    mov eax, cr0
    or eax, 0x00000001 ; Set PE (bit 0)
    mov cr0, eax

    ; Jump to 32-bit PM code (Selector 0x08)
    ; We must use the absolute physical address because Selector 0x08 has base 0.
    jmp dword 0x08:(TRAMP_PHYS + (.pm32_entry - rm_tramp_start))

[bits 32]
.pm32_entry:
    ; Now in 32-bit PM (no paging yet)
    mov ax, 0x10 ; KERNEL_DS
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov eax, cr0
    or eax, 0x80000000 ; Set PG (bit 31)
    mov cr0, eax

    ; Final jump to the high-memory return point
    jmp 0x08:pm_return

rm_tramp_end:

; =============================================================================
; BIOS INT 10h set video mode (AH=0, AL=mode)
; void bios_vga_set_mode(uint32_t mode_al);
; =============================================================================
[bits 32]
bios_vga_set_mode:
    push ebp
    mov ebp, esp
    pushad
    cli
    mov [pm_saved_esp], esp

    in al, 0x21
    mov [PARAM_PHYS + 32], al
    in al, 0xA1
    mov [PARAM_PHYS + 33], al

    ; Same IRQ masks as INT13 path (hide E1000 during RM)
    mov al, 0x3F
    out 0xA1, al
    mov al, 0xB8
    out 0x21, al

    mov esi, rm_vga_tramp_start
    mov edi, TRAMP_PHYS
    mov ecx, rm_vga_tramp_end - rm_vga_tramp_start
    cld
    rep movsb

    mov eax, [ebp + 8]          ; mode (AL)
    and eax, 0xFF
    mov [PARAM_PHYS + 0], eax
    mov dword [PARAM_PHYS + 24], 0

    mov esi, gdt_descriptor
    mov edi, GDT_COPY_PHYS
    mov ecx, 6
    rep movsb
    mov esi, rm_idtr
    mov edi, IDT_COPY_PHYS
    mov ecx, 6
    rep movsb
    extern idtp
    mov esi, idtp
    mov edi, PM_IDT_COPY_PHYS
    mov ecx, 6
    rep movsb

    mov eax, cr0
    and eax, 0x7FFFFFFF
    mov cr0, eax
    jmp 0x28:0

[bits 16]
rm_vga_tramp_start:
    mov ax, 0x30
    mov ds, ax
    mov es, ax
    mov ss, ax

    mov eax, cr0
    and eax, 0xFFFFFFFE
    mov cr0, eax
    jmp TRAMP_SEG:(.vga_rm_entry - rm_vga_tramp_start)

.vga_rm_entry:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x9000

    xor ax, ax
    mov es, ax
    lidt [IDT_COPY_PHYS]
    cld

    ; Tunnel remapped IRQs to BIOS IVT (same as INT13 tramp)
    xor ax, ax
    mov es, ax
    mov eax, [es:0x08*4]
    mov [es:0x20*4], eax
    mov eax, [es:0x09*4]
    mov [es:0x21*4], eax
    mov eax, [es:0x0E*4]
    mov [es:0x26*4], eax
    mov eax, [es:0x76*4]
    mov [es:0x2E*4], eax
    mov eax, [es:0x77*4]
    mov [es:0x2F*4], eax

    mov al, byte [PARAM_PHYS + 0]
    xor ah, ah                  ; AH=0 set mode
    sti
    int 0x10
    cli
    mov [PARAM_PHYS + 24], ax

    ; Restore PIC remap for PM
    mov al, 0x11
    out 0x20, al
    out 0xA0, al
    mov al, 0x20
    out 0x21, al
    mov al, 0x28
    out 0xA1, al
    mov al, 0x04
    out 0x21, al
    mov al, 0x02
    out 0xA1, al
    mov al, 0x01
    out 0x21, al
    out 0xA1, al
    mov al, [PARAM_PHYS + 32]
    out 0x21, al
    mov al, [PARAM_PHYS + 33]
    out 0xA1, al

    lgdt [GDT_COPY_PHYS]
    lidt [PM_IDT_COPY_PHYS]

    mov eax, cr0
    or eax, 0x00000001
    mov cr0, eax
    jmp dword 0x08:(TRAMP_PHYS + (.vga_pm32 - rm_vga_tramp_start))

[bits 32]
.vga_pm32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    jmp 0x08:pm_return

rm_vga_tramp_end:

; =============================================================================
; VBE helpers — PARAM layout:
;   +0  mode (CX for 4F01 / BX low for 4F02)
;   +4  dest_phys for mode info (4F01 only)
;   +8  op: 1 = get mode info, 2 = set mode
;   +24 status (AX return)
; =============================================================================
%define VBE_INFO_PHYS 0x8600

[bits 32]
bios_vbe_get_mode_info:
    push ebp
    mov ebp, esp
    pushad
    cli
    mov [pm_saved_esp], esp
    mov eax, [ebp + 8]
    mov [PARAM_PHYS + 0], eax       ; mode
    mov eax, [ebp + 12]
    mov [PARAM_PHYS + 4], eax       ; dest_phys
    mov dword [PARAM_PHYS + 8], 1   ; op = get info
    jmp bios_vbe_common

bios_vbe_set_mode:
    push ebp
    mov ebp, esp
    pushad
    cli
    mov [pm_saved_esp], esp
    mov eax, [ebp + 8]
    mov [PARAM_PHYS + 0], eax       ; mode
    mov dword [PARAM_PHYS + 8], 2   ; op = set mode
    jmp bios_vbe_common

bios_vbe_common:
    in al, 0x21
    mov [PARAM_PHYS + 32], al
    in al, 0xA1
    mov [PARAM_PHYS + 33], al
    mov al, 0x3F
    out 0xA1, al
    mov al, 0xB8
    out 0x21, al

    mov esi, rm_vbe_tramp_start
    mov edi, TRAMP_PHYS
    mov ecx, rm_vbe_tramp_end - rm_vbe_tramp_start
    cld
    rep movsb

    mov dword [PARAM_PHYS + 24], 0

    mov esi, gdt_descriptor
    mov edi, GDT_COPY_PHYS
    mov ecx, 6
    rep movsb
    mov esi, rm_idtr
    mov edi, IDT_COPY_PHYS
    mov ecx, 6
    rep movsb
    extern idtp
    mov esi, idtp
    mov edi, PM_IDT_COPY_PHYS
    mov ecx, 6
    rep movsb

    mov eax, cr0
    and eax, 0x7FFFFFFF
    mov cr0, eax
    jmp 0x28:0

[bits 16]
rm_vbe_tramp_start:
    mov ax, 0x30
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr0
    and eax, 0xFFFFFFFE
    mov cr0, eax
    jmp TRAMP_SEG:(.vbe_rm_entry - rm_vbe_tramp_start)

.vbe_rm_entry:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x9000
    xor ax, ax
    mov es, ax
    lidt [IDT_COPY_PHYS]
    cld

    xor ax, ax
    mov es, ax
    mov eax, [es:0x08*4]
    mov [es:0x20*4], eax
    mov eax, [es:0x09*4]
    mov [es:0x21*4], eax
    mov eax, [es:0x0E*4]
    mov [es:0x26*4], eax
    mov eax, [es:0x76*4]
    mov [es:0x2E*4], eax
    mov eax, [es:0x77*4]
    mov [es:0x2F*4], eax

    cmp dword [PARAM_PHYS + 8], 1
    jne .vbe_set

    ; AX=4F01 get mode info — ES:DI = dest (phys must be 16-byte aligned)
    mov eax, [PARAM_PHYS + 4]
    mov ebx, eax
    and ebx, 0x000F
    mov di, bx
    shr eax, 4
    mov es, ax
    mov cx, [PARAM_PHYS + 0]
    mov ax, 0x4F01
    sti
    int 0x10
    cli
    mov [PARAM_PHYS + 24], ax
    jmp .vbe_to_pm

.vbe_set:
    mov bx, [PARAM_PHYS + 0]
    or bx, 0x4000          ; use LFB
    mov ax, 0x4F02
    sti
    int 0x10
    cli
    mov [PARAM_PHYS + 24], ax

.vbe_to_pm:
    mov al, 0x11
    out 0x20, al
    out 0xA0, al
    mov al, 0x20
    out 0x21, al
    mov al, 0x28
    out 0xA1, al
    mov al, 0x04
    out 0x21, al
    mov al, 0x02
    out 0xA1, al
    mov al, 0x01
    out 0x21, al
    out 0xA1, al
    mov al, [PARAM_PHYS + 32]
    out 0x21, al
    mov al, [PARAM_PHYS + 33]
    out 0xA1, al
    lgdt [GDT_COPY_PHYS]
    lidt [PM_IDT_COPY_PHYS]
    mov eax, cr0
    or eax, 0x00000001
    mov cr0, eax
    jmp dword 0x08:(TRAMP_PHYS + (.vbe_pm32 - rm_vbe_tramp_start))

[bits 32]
.vbe_pm32:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov eax, cr0
    or eax, 0x80000000
    mov cr0, eax
    jmp 0x08:pm_return

rm_vbe_tramp_end:

