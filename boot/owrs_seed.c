/* owrs_seed.c - Test-image owrs provisioner.
 *
 * Linked ONLY into the emergency test image, alongside boot/owinitv_seed.o.  It
 * provides the strong OwDiskSeedTestOwrs() that overrides the weak default in
 * storage/owdisk.c.
 *
 * owrs.owx is the payload of the emergency userspace rather than an entry point:
 * the kernel never enters it, owinitv.owx spawns it through OW_SYS_PS_SPAWN_OWX.
 * It is provisioned by its own hook rather than as a side effect of the owinitv
 * hook so that "the volume has owinitv but not owrs" is a state the build can
 * actually express -- which is the case that has to keep working, because
 * owinitv.owx is a complete init on its own and a missing rescue shell is a
 * degraded rescue shell, not an unrecoverable machine. */
#include "../inc/ow_types.h"
#include "../inc/ow_kprintf.h"
#include "../storage/owdisk.h"
#include "../emergency/owrs_image.h"
#include <stdint.h>
#include <stdbool.h>

bool OwDiskSeedTestOwrs(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_RESCUE_EXEC_NAME, &inode);

    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_RESCUE_EXEC_NAME, g_owrs_image, OWRS_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWRS] test image: seeded owrs.owx (ino %u, %u bytes)\r\n",
                   (unsigned)inode, (unsigned)OWRS_IMAGE_SIZE);
        return true;
    }
    ow_kprintf("[OWRS] test image: failed to seed owrs.owx (code 0x%X)\r\n",
               (unsigned)st);
    return false;
}
