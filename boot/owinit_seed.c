/* owinit_seed.c - Test-image owinit provisioner.
 * Linked ONLY into the VM test images (the QEMU multiboot flat binary and the
 * VirtualBox/QEMU floppy). It provides the weak OwDiskSeedTestOwinit() hook so
 * the Phase 5c owinit gate finds the Essentials owinit.owx on the freshly formatted
 * in-memory OWFS volume and the boot reaches the interactive shell, where
 * everything can be exercised from the terminal.
 * The openwinkrnl.chk fixture the integrity phase needs lives in
 * boot/owchk_seed.c: it belongs to the volume rather than to this one image,
 * and an image seeded without owinit.owx still has to pass the integrity phase.
 * Production images (openwinkrnl.owx, openwinkrnl.vdi) do not link this file:
 * there the weak hook returns false, nothing is seeded, and the owinit gate
 * keeps its fatal halt. */
#include "../inc/ow_types.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_sentinel.h"
#include "../storage/owdisk.h"
#include "owinit_image.h"
#include <stdint.h>
#include <stdbool.h>

bool OwDiskSeedTestOwinit(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &inode);
    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_owinit_image,
                   OWINIT_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWINIT] test image: seeded Essentials owinit.owx (ino %u)\r\n",
                   (unsigned)inode);
        return true;
    }
    ow_kprintf("[OWINIT] test image: failed to seed owinit.owx (code 0x%X)\r\n",
               (unsigned)st);
    return false;
}
