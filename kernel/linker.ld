/* Linker script for the RunixOS x86_64 kernel */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

PHDRS
{
    null    PT_NULL    FLAGS(0);
    text    PT_LOAD    FLAGS((1 << 0) | (1 << 2)); /* Execute + Read */
    rodata  PT_LOAD    FLAGS((1 << 2));             /* Read */
    data    PT_LOAD    FLAGS((1 << 1) | (1 << 2)); /* Write + Read */
}

SECTIONS
{
    /* The kernel is linked to the high half of the virtual address space */
    . = 0xffffffff80000000;

    .text : {
        *(.text .text.*)
    } :text

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .rodata : {
        *(.rodata .rodata.*)
    } :rodata

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .data : {
        *(.data .data.*)

        /* Limine protocol boot requests must be placed in a contiguous block in the writable data segment */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
    } :data

    . = ALIGN(CONSTANT(MAXPAGESIZE));

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /* Discard sections that are not needed in a bare-metal kernel */
    /DISCARD/ : {
        *(.eh_frame)
        *(.note.gnu.build-id)
    }
}
