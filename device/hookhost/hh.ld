ENTRY(hh_init)
SECTIONS
{
    . = 0;
    /* The kernel enters through the trampolines by offset only, so they are
     * the --gc-sections roots besides the entry point. */
    .text   : { KEEP(*(.text.hh_tramp)) *(.text .text.*) }
    /* Fixed layout: text 0x0, ro 0x7000, data+bss 0x8000..0x10000. The kernel
     * maps these ranges and mesosphere must keep its size (0xc8000), so each
     * part may shrink but never grow, and the image is padded to 0x10000. */
    ASSERT(. <= 0x7000, "hookhost .text exceeds 0x7000")
    . = 0x7000;
    .rodata : { *(.rodata .rodata.*) }
    ASSERT(. <= 0x8000, "hookhost .rodata exceeds 0x1000")
    . = 0x8000;
    .data   : { *(.data .data.*) }
    ASSERT(. <= 0x9000, "hookhost .data exceeds 0x1000")
    . = 0x9000;
    .bss    : { *(.bss .bss.*) *(COMMON) . = 0x7000; }
    ASSERT(. == 0x10000, "hookhost image must end at 0x10000")
    /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame) }
}
