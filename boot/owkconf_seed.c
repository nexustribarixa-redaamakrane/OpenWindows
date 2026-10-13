/* owkconf_seed.c - QEMU kconfctl regression: seed the config CLI AS the init.
 *
 * The kconfctl regression boots the real OpenWindows configuration control CLI
 * (kconfctl.owx, built by OpenWindows-Essentials) as PID 1 so that a genuine
 * query runs at CPL3 and its output is observed on the serial console.  The
 * Phase 5c survey enters whatever occupies OW_INIT_EXEC_NAME, so this seed
 * writes the kconfctl bytes there; the name is the init slot, the bytes are the
 * program under test.
 *
 * A dedicated seed per image is the existing convention (owinit_seed.c,
 * owinitv_seed.c, owrs_seed.c, owargv_seed.c): each provides its own
 * OwDiskSeedTestOwinit(), and exactly one is linked into any given image, so a
 * boot regression can never silently seed the wrong program.
 *
 * C99 freestanding. */
#include "../inc/ow_kprintf.h"
#include "../inc/ow_sentinel.h"
#include "../storage/owdisk.h"
#include "owkconf_image.h"
#include <stdint.h>
#include <stdbool.h>

bool OwDiskSeedTestOwinit(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &inode);
    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_owkconf_image,
                   OWKCONF_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWKCONF] test image: seeded kconfctl.owx as %s (ino %u)\r\n",
                   OW_INIT_EXEC_NAME, (unsigned)inode);
        return true;
    }
    ow_kprintf("[OWKCONF] test image: failed to seed %s (code 0x%X)\r\n",
               OW_INIT_EXEC_NAME, (unsigned)st);
    return false;
}
