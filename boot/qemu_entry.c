/* qemu_entry.c - 64-bit multiboot kernel entry for the QEMU test image.
 * boot.S sets up long mode + paging + stack, then calls this with
 * (magic, mbi) in rcx/rdx (MS x64 ABI); we hand off to the same boot
 * sequence the OWX PE would run (_start). */
#include <stdint.h>

extern void _start(void);

void kernel_main64(uint32_t magic_ecx, uint32_t mbi_edx) {
    (void)magic_ecx;
    (void)mbi_edx;
    _start();
}