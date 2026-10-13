/* owargv_seed.c - QEMU argv regression: seed the shell image AS the init.
 *
 * The argv regression boots the real OpenWindows command shell (owsh.owx,
 * built by OpenWindows-Essentials) as PID 1 so that a non-trivial argument
 * vector reaches real Ring 3 code.  The Phase 5c survey selects an init by the
 * volume name OW_INIT_EXEC_NAME ("owinit.owx"), so this object writes the
 * owsh image's bytes under that name: the survey resolves to state 1 and
 * enters what the volume calls the init -- which is the shell under test.
 *
 * It is a separate seed object from boot/owinit_seed.c on purpose.  The two
 * provide the same strong OwDiskSeedTestOwinit() hook with different bytes, so
 * a link line carries exactly one of them and an argv image can never silently
 * fall back to seeding the production init instead of the shell.
 *
 * This object is linked only into the argv test image.  Production kernels and
 * the healthy/emergency/provenance test images never see it. */
#include "../inc/ow_types.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_sentinel.h"
#include "../storage/owdisk.h"
#include "owargv_image.h"
#include <stdint.h>
#include <stdbool.h>

bool OwDiskSeedTestOwinit(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &inode);
    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_owargv_image,
                   OWARGV_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWARGV] test image: seeded owsh.owx as %s (ino %u)\r\n",
                   OW_INIT_EXEC_NAME, (unsigned)inode);
        return true;
    }
    ow_kprintf("[OWARGV] test image: failed to seed %s (code 0x%X)\r\n",
               OW_INIT_EXEC_NAME, (unsigned)st);
    return false;
}
