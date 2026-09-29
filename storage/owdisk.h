/* owdisk.h - OpenWindows-Storage integration (OWFS on primary, USFS on secure) */
#ifndef OWDISK_H
#define OWDISK_H

#include "../inc/ow_types.h"
#include "../inc/ow_userspace.h"
#include <stdint.h>
#include <stdbool.h>

/* ---- The three user-mode images the boot policy resolves over ------------
 *
 * owinit.owx  Tier-3 userspace root orchestrator, the primary init.
 * owinitv.owx Volatile/emergency init.  Stands in for owinit when the primary
 *             is missing or unusable, brings up the minimum userspace, and
 *             spawns owrs.owx.
 * owrs.owx    Rescue shell, spawned by owinitv.
 *
 * A missing primary is NOT automatically fatal any more: the emergency pair is
 * consulted first, and only a volume with neither a usable owinit nor a usable
 * emergency userspace panics. */
#define OW_INIT_EXEC_NAME     "owinit.owx"
#define OW_INITV_EXEC_NAME    "owinitv.owx"
#define OW_RESCUE_EXEC_NAME   "owrs.owx"

/* Ceiling on any single user-mode image read off the primary volume, in bytes.
 *
 * This is simultaneously the boot-time survey's read window and the hand-off's
 * staging pool size, which is the point: an image is classified as available
 * only if it is readable AND loadable within the same bound the loader will
 * actually use.  Surveying with a larger window than the loader has would let
 * the boot call a 100 KiB image "available" and then fail the load, which is
 * the disagreement that turns a diagnosable degraded boot into a silent halt. */
#define OW_USERSPACE_IMAGE_MAX  (64U * 1024U)

/* Longest userspace image name, including the NUL.  Root-catalog entries are
 * bounded by the OWFS catalog, and every kernel-side copy of a name is bounded
 * by this so a caller-supplied name can never drive an unbounded walk. */
#define OW_USERSPACE_NAME_MAX   64U

OW_STATUS OwDiskInitialize(void);        /* auto format+mount OWFS & USFS */

bool OwDiskOwfsMounted(void);
bool OwDiskUsfsMounted(void);

/* OwDiskOwinitPresent: owinit.owx is on the primary volume AND loadable.
 *
 * True presence and true loadability are the same answer here, deliberately:
 * this predicate exists to answer "can the boot enter owinit?", and a file that
 * is present but not loadable cannot be entered.  Use OwDiskProbeUserspace when
 * you need to tell those two apart. */
bool OwDiskOwinitPresent(void);

/* OwDiskProbeUserspace: survey owinit/owinitv/owrs on the primary volume and
 * record, per image, whether it is present and whether it passes the OWX1 load
 * gate.  Never fails: an unmounted volume reports everything absent, which
 * classifies as OW_USERSPACE_ABSENT and panics, exactly as a volume with an
 * empty root catalog does. */
void OwDiskProbeUserspace(OW_USERSPACE_PROBE* out);

OW_STATUS OwFsOwfsFormat(const uint8_t* label, uint32_t label_len);
OW_STATUS OwFsOwfsMount(void);
OW_STATUS OwFsOwfsUnmount(void);
OW_STATUS OwFsOwfsMkdir(const char* name, uint32_t* out_inode);
OW_STATUS OwFsOwfsCreate(const char* name, uint32_t* out_inode);
OW_STATUS OwFsOwfsWrite(const char* name, const uint8_t* data, uint32_t len);
OW_STATUS OwFsOwfsRead(const char* name, uint8_t* buf, uint32_t cap,
                       uint32_t* out_read);
OW_STATUS OwFsOwfsReadOffset(const char* name, uint8_t* buf, uint32_t offset,
                             uint32_t cap, uint32_t* out_read);
OW_STATUS OwFsOwfsList(uint32_t* out_count);
uint32_t  OwFsOwfsFreeBlocks(void);

OW_STATUS OwFsUsfsFormat(const uint8_t* label, uint32_t label_len);
OW_STATUS OwFsUsfsMount(void);
OW_STATUS OwFsUsfsUnmount(void);
uint32_t  OwFsUsfsFreeBlocks(void);

#endif /* OWDISK_H */