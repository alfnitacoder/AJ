OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
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

    /* Runtime-zeroed; keep out of kernel64.bin. */
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
