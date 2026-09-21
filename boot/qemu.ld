/* qemu.ld - multiboot flat-image layout for the core/boot.S bootstrap.
 * The kernel is linked at 0x100000 where the a.out-kludge multiboot header
 * declares it. _end_of_file / _end_of_bss feed the loader's BSS zero-fill. */
ENTRY(_entry)

SECTIONS
{
    . = 0x100000;

    .text : {
        *(.text*)
    }

    _etext = .;

    .rodata : {
        *(.rodata*)
        *(.rdata*)
    }

    .data : {
        *(.data*)
    }

    _end_of_file = .;

    .bss : {
        *(.bss*)
        *(COMMON)
    }

    _end_of_bss = .;

    /DISCARD/ : {
        *(.pdata*)
        *(.xdata*)
        *(.comment*)
    }
}