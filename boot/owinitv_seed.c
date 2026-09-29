/* owinitv_seed.c - Test-image owinitv provisioner.
 *
 * Linked ONLY into the emergency test image.  It provides the strong
 * OwDiskSeedTestOwinitv() that overrides the weak default in storage/owdisk.c,
 * so the Phase 5c survey finds owinitv.owx on the freshly formatted volume and
 * the kernel enters it as PID 1.
 *
 * This object is what makes the state-2 test image different from the state-3
 * one.  The two images are built from the same kernel sources and differ only in
 * which seed objects appear on their link lines:
 *
 *   all three seeds   -> state 1, owinit.owx is PID 1 (the normal test image)
 *   these two         -> state 2, owinitv.owx is PID 1 and spawns owrs.owx
 *   none              -> state 3, unrecoverable panic
 *
 * Putting the choice in the link line rather than in a runtime flag means the
 * image a target produces can be read straight off that target's recipe, which
 * is the only way to be sure a test is exercising the state it claims to.
 *
 * Note what this file does NOT do: it does not corrupt or remove owinit.owx.  A
 * corrupt primary is a state-2 input too, and it is the more interesting one, but
 * it is a property of the volume rather than of the link, and a seed that
 * scribbled on a good image would make the two cases indistinguishable in the
 * artifact.  The corruption test drives the classifier directly instead. */
#include "../inc/ow_types.h"
#include "../inc/ow_kprintf.h"
#include "../storage/owdisk.h"
#include "../emergency/owinitv_image.h"
#include <stdint.h>
#include <stdbool.h>

bool OwDiskSeedTestOwinitv(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_INITV_EXEC_NAME, &inode);

    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_INITV_EXEC_NAME, g_owinitv_image,
                           OWINITV_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWINITV] test image: seeded owinitv.owx (ino %u, %u bytes)\r\n",
                   (unsigned)inode, (unsigned)OWINITV_IMAGE_SIZE);
        return true;
    }
    ow_kprintf("[OWINITV] test image: failed to seed owinitv.owx (code 0x%X)\r\n",
               (unsigned)st);
    return false;
}
