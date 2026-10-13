/*
 * owbh_seed.c - seed banhammer_cli.owx as PID 1 for the Banhammer regression.
 *
 * The Banhammer quote CLI is a real, import-free .owx whose output depends on
 * argv and on the panic-text table, so booting it as PID 1 proves the argument
 * vector reaches a program that computes from it at CPL3.  Each QEMU variant
 * carries its own seed so two cases can never write the same image by accident.
 *
 * C99 freestanding. */
#include "../inc/ow_kprintf.h"
#include "../inc/ow_sentinel.h"
#include "../storage/owdisk.h"
#include "owbh_image.h"
#include <stdint.h>
#include <stdbool.h>

bool OwDiskSeedTestOwinit(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &inode);
    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_owbh_image, OWBH_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWBH] test image: seeded banhammer_cli.owx as %s (ino %u)\r\n",
                   OW_INIT_EXEC_NAME, (unsigned)inode);
        return true;
    }
    ow_kprintf("[OWBH] test image: failed to seed %s (code 0x%X)\r\n",
               OW_INIT_EXEC_NAME, (unsigned)st);
    return false;
}
