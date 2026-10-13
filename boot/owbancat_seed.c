/*
 * owbancat_seed.c - seed bancat.owx as PID 1 plus a protected crash dump.
 *
 * bancat is a real, import-free .owx that reaches the primary OWFS volume
 * through the syscall gateway, so proving it needs two things on the volume: the
 * program itself, seeded under OW_INIT_EXEC_NAME so the boot survey enters it as
 * PID 1, and a .bdmp for it to decode.  Both are written here, by one object --
 * a build that has one without the other would not be a meaningful bancat test,
 * so there is no reason to let them be linked independently.
 *
 * The dump is built with the shipped producer (bdmp_build) and published
 * root-owned, mode 0600, OWFS_SEC_HIDDEN: exactly the protection the real crash
 * path applies, and exactly what an unprivileged process must be refused.  bancat
 * runs as a BOOT-subsystem image, so the same volume that hides the dump from an
 * ordinary process serves it to this one.
 *
 * C99 freestanding. */
#include "../inc/ow_kprintf.h"
#include "../storage/owdisk.h"
#include "bdmp_format.h"
#include "bdmp_core.h"
#include "owfs_types.h"
#include "bancat_image.h"
#include <stdint.h>
#include <stdbool.h>

/* Placeholder primary BANcode.  There is no in-repo BANcode table this build can
 * consult for a fault code it would actually raise, so the fixture uses a fixed,
 * obviously synthetic value in the BANcode diagnostic range rather than
 * inventing one that could be mistaken for a decodable trap.  bancat prints it
 * verbatim. */
#define OWBANCAT_FIXTURE_BANCODE  0x0000BADCu

/* A small, recognizable memory region so the dump carries non-header bytes. */
static uint8_t g_owbancat_mem[32];

/* The dump buffer.  Sized above the fixture (header 256 + frame 176 + 2 traps 48
 * + 32 memory = 512) so a layout change cannot silently overflow. */
static uint8_t g_owbancat_buf[1024];

bool OwDiskSeedTestOwinit(void) {
    uint32_t inode = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &inode);
    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_bancat_image,
                           BANCAT_IMAGE_SIZE);
    }
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWBANCAT] test image: seeded bancat.owx as %s (ino %u)\r\n",
                   OW_INIT_EXEC_NAME, (unsigned)inode);
        return true;
    }
    ow_kprintf("[OWBANCAT] test image: failed to seed %s (code 0x%X)\r\n",
               OW_INIT_EXEC_NAME, (unsigned)st);
    return false;
}

bool OwDiskSeedTestBdmp(void) {
    bdmp_cpu_frame_t frame;
    bdmp_trap_record_t traps[2];
    uint32_t total;
    uint32_t i;
    OW_STATUS st;

    for (i = 0u; i < (uint32_t)sizeof(g_owbancat_mem); ++i) {
        g_owbancat_mem[i] = (uint8_t)(0xA0u + i);
    }

    frame.rax = 0x1122334455667788ULL;
    frame.rbx = 0x00000000DEADBEEFULL;
    frame.rcx = 0x0000000000000003ULL;
    frame.rdx = 0x0000000000000000ULL;
    frame.rsi = 0x0000000000000000ULL;
    frame.rdi = 0x0000000000000000ULL;
    frame.rbp = 0x0000000000400000ULL;
    frame.rsp = 0x000000000041FF00ULL;
    frame.r8  = 0u;
    frame.r9  = 0u;
    frame.r10 = 0u;
    frame.r11 = 0u;
    frame.r12 = 0u;
    frame.r13 = 0u;
    frame.r14 = 0u;
    frame.r15 = 0u;
    frame.rip = 0x0000000000401234ULL;
    frame.rflags = 0x0000000000000202ULL;
    frame.cr0 = 0x0000000080010001ULL;
    frame.cr2 = 0x0000000000000000ULL;
    frame.cr3 = 0x0000000000100000ULL;
    frame.cr4 = 0x0000000000000620ULL;

    traps[0].bancode = OWBANCAT_FIXTURE_BANCODE;
    traps[0].trap_slot = 3u;
    traps[0].timestamp = 0x0000000000001234ULL;
    traps[0].context_ip = 0x0000000000401230ULL;

    traps[1].bancode = OWBANCAT_FIXTURE_BANCODE;
    traps[1].trap_slot = 1u;
    traps[1].timestamp = 0x0000000000000FF0ULL;
    traps[1].context_ip = 0x00000000004011F0ULL;

    total = bdmp_build(g_owbancat_buf, (uint32_t)sizeof(g_owbancat_buf), &frame,
                       traps, 2u, OWBANCAT_FIXTURE_BANCODE, 0u,
                       0x0000000000001234ULL, 0x0000000000000000ULL,
                       g_owbancat_mem, (uint32_t)sizeof(g_owbancat_mem));
    if (total == 0u) {
        ow_kprintf("[OWBANCAT] test fixture: bdmp_build refused\r\n");
        return false;
    }

    st = OwFsOwfsCreateRestricted(
        OW_CRASH_DUMP_NAME,
        (uint16_t)(OWFS_MODE_OWNER_READ | OWFS_MODE_OWNER_WRITE),
        (uint8_t)OWFS_SEC_HIDDEN,
        g_owbancat_buf, total);
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWBANCAT] test fixture: seeded %s, %u bytes, root 0600 hidden\r\n",
                   OW_CRASH_DUMP_NAME, (unsigned)total);
        return true;
    }
    ow_kprintf("[OWBANCAT] test fixture: failed to seed %s (code 0x%X)\r\n",
               OW_CRASH_DUMP_NAME, (unsigned)st);
    return false;
}
