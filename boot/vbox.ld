/* vbox.ld - flat image layout for the VirtualBox floppy bootstrap.
 * The kernel is linked at 0x10000 where the 16-bit stage1 bootloader can
 * load it from a floppy with BIOS int13h (real-mode ES:BX addressing),
 * enter 32-bit protected mode, zero the BSS, and jump to qboot_entry.
 * _end_of_file / _end_of_bss are published in the image header longwords. */
ENTRY(_entry)

SECTIONS
{
    . = 0x10000;

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
        *(.reloc*)
    }
}