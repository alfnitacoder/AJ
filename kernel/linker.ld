OUTPUT_FORMAT("elf32-i386")
OUTPUT_ARCH(i386)
ENTRY(start)

SECTIONS
{
    . = 0x100000;

    .text : {
        *(.text.start)
        *(.text)
        *(.text.*)
    }

    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    .data : {
        *(.data)
        *(.data.*)
    }

    /* Runtime-zeroed; keep out of kernel.bin so the floppy staging cap fits. */
    sbss = .;
    .bss (NOLOAD) : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    }
    ebss = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.eh_frame.*)
        *(.note.*)
        *(.note.GNU-stack)
    }
}
