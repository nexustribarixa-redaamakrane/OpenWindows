/* owchk_seed.c - Test-volume openwinkrnl.chk provisioner.
 *
 * This used to live inside owinit_seed.c, which was a mistake of placement rather
 * than of intent.  openwinkrnl.chk is the sentinel's plaintext kernel-checksum
 * file: the kernel-integrity phase (Phase 5c.2) reads it off the primary volume
 * and compares the SHA-256 it names against the running image.  It has nothing
 * to do with owinit.owx, so coupling it to the owinit seed meant every image
 * that was NOT seeded with owinit.owx -- the emergency image above all -- had
 * no checksum fixture at all and halted in that phase with a fatal U+11A001,
 * which reads as a kernel integrity failure and sends whoever sees it looking
 * for tampering rather than for a missing test fixture.
 *
 * So it gets its own hook, and every seeded test image links it.  The value is
 * the same fixed placeholder the previous copy used: the plaintext path accepts
 * a 64-hex-digit digest, and the point of the fixture is that the file EXISTS and
 * is well-formed, not that it matches a particular build.  A real build's digest
 * comes from tools/owx_pack.py, which overwrites this file in the source tree.
 */
#include "../inc/ow_types.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_sentinel.h"
#include "../storage/owdisk.h"
#include <stdint.h>
#include <stdbool.h>

/* Plaintext checksum fallback for the seeded test volume. */
static const char k_owinit_chk_text[] =
    "e925ab4e3f175405000000000000000000000000000000000000000000000000";

bool OwDiskSeedTestChk(void) {
    uint32_t chk_ino = 0;
    OW_STATUS st = OwFsOwfsCreate(OW_KERNEL_CHK_NAME, &chk_ino);
    if (st == OW_SUCCESS) {
        st = OwFsOwfsWrite(OW_KERNEL_CHK_NAME,
                           (const uint8_t*)k_owinit_chk_text,
                           (uint32_t)(sizeof(k_owinit_chk_text) - 1));
    }
    if (st == OW_SUCCESS) {
        return true;
    }
    ow_kprintf("[SENT] test image: failed to seed openwinkrnl.chk (code 0x%X)\r\n",
               (unsigned)st);
    return false;
}
