ENTRY(_entry)
SECTIONS
{
    . = 0x100000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) *(.rdata*) }
    .data : { *(.data*) }
    _end_of_file = .;
    .bss : { *(COMMON) *(.bss*) }
    _end_of_bss = .;
}
