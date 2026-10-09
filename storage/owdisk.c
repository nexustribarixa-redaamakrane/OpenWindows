/* owdisk.c - OpenWindows-Storage ecosystem integration
 * OWFS volume on the primary RAM disk, USFS volume on the secure disk. */
#include "../inc/ow_types.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_owx.h"
#include "../inc/ow_string.h"
#include "../inc/ow_kprintf.h"
#include "owdisk.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "owfs.h"
#include "usfs.h"

static owfs_superblock_t g_owfs_sb;
static bool g_owfs_formatted;
static bool g_owfs_mounted;

static usfs_superblock_t g_usfs_sb;
static bool g_usfs_formatted;
static bool g_usfs_mounted;

static OW_STATUS map_owfs(owfs_status_t st) {
    return (OW_STATUS)st;   /* OWFS_OK == 0 == OW_SUCCESS */
}

OW_STATUS OwFsOwfsFormat(const uint8_t* label, uint32_t label_len) {
    htl_device_t* dev;
    owfs_status_t st;
    if (!label) return (OW_STATUS)OWFS_ERR_INVALID_PARAM;
    dev = OwHalGetPrimaryDisk();
    st = owfs_format_volume(dev, dev->total_blocks, label, label_len);
    if (st != OWFS_OK) return (OW_STATUS)st;
    g_owfs_formatted = true;
    g_owfs_mounted = false;
    st = owfs_superblock_read(dev, &g_owfs_sb);
    return map_owfs(st);
}

OW_STATUS OwFsOwfsMount(void) {
    htl_device_t* dev;
    owfs_status_t st;
    if (g_owfs_mounted) return OW_SUCCESS;
    if (!g_owfs_formatted) {
        st = OwFsOwfsFormat((const uint8_t*)"OWINIT", 6);
        if (st != OW_SUCCESS) return st;
    }
    dev = OwHalGetPrimaryDisk();
    st = owfs_mount(dev, &g_owfs_sb);
    if (st != OWFS_OK) return (OW_STATUS)st;
    g_owfs_mounted = true;
    return OW_SUCCESS;
}

OW_STATUS OwFsOwfsUnmount(void) {
    htl_device_t* dev;
    owfs_status_t st;
    if (!g_owfs_mounted) return OW_SUCCESS;
    dev = OwHalGetPrimaryDisk();
    st = owfs_unmount(dev, &g_owfs_sb);
    g_owfs_mounted = false;
    return map_owfs(st);
}

static OW_STATUS owfs_name_to_inode(const char* name, uint32_t* out_inode) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    owfs_status_t st;
    if (!g_owfs_formatted || !g_owfs_mounted) return (OW_STATUS)OWFS_ERR_IO;
    st = owfs_catalog_lookup(dev, &g_owfs_sb, OWFS_ROOT_INODE,
                             (const uint8_t*)name, (size_t)ow_strlen(name),
                             out_inode);
    return map_owfs(st);
}

OW_STATUS OwFsOwfsMkdir(const char* name, uint32_t* out_inode) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    owfs_status_t st;
    if (!g_owfs_formatted || !g_owfs_mounted) return (OW_STATUS)OWFS_ERR_IO;
    st = owfs_catalog_mkdir(dev, &g_owfs_sb, OWFS_ROOT_INODE,
                            (const uint8_t*)name, (size_t)ow_strlen(name),
                            out_inode);
    return map_owfs(st);
}

OW_STATUS OwFsOwfsCreate(const char* name, uint32_t* out_inode) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    owfs_status_t st;
    if (!g_owfs_formatted || !g_owfs_mounted) return (OW_STATUS)OWFS_ERR_IO;
    st = owfs_catalog_create(dev, &g_owfs_sb, OWFS_ROOT_INODE,
                             (const uint8_t*)name, (size_t)ow_strlen(name),
                             out_inode);
    return map_owfs(st);
}

OW_STATUS OwFsOwfsWrite(const char* name, const uint8_t* data, uint32_t len) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    owfs_inode_t inode;
    uint32_t inode_num = 0;
    uint32_t written = 0;
    owfs_status_t st;

    if (!g_owfs_formatted || !g_owfs_mounted) return (OW_STATUS)OWFS_ERR_IO;
    st = owfs_name_to_inode(name, &inode_num);
    if (st != OW_SUCCESS) return st;
    st = owfs_inode_read(dev, &g_owfs_sb, inode_num, &inode);
    if (st != OWFS_OK) return (OW_STATUS)st;
    st = owfs_file_write(dev, &g_owfs_sb, &inode, inode_num,
                         data, 0, len, &written);
    if (st != OWFS_OK) return (OW_STATUS)st;
    return OW_SUCCESS;
}

OW_STATUS OwFsOwfsReadOffset(const char* name, uint8_t* buf, uint32_t offset,
                             uint32_t cap, uint32_t* out_read) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    owfs_inode_t inode;
    uint32_t inode_num = 0;
    owfs_status_t st;

    if (!g_owfs_formatted || !g_owfs_mounted) return (OW_STATUS)OWFS_ERR_IO;
    st = owfs_name_to_inode(name, &inode_num);
    if (st != OW_SUCCESS) return st;
    st = owfs_inode_read(dev, &g_owfs_sb, inode_num, &inode);
    if (st != OWFS_OK) return (OW_STATUS)st;
    st = owfs_file_read(dev, &g_owfs_sb, &inode, buf, offset, cap, out_read);
    return map_owfs(st);
}

OW_STATUS OwFsOwfsRead(const char* name, uint8_t* buf, uint32_t cap,
                       uint32_t* out_read) {
    return OwFsOwfsReadOffset(name, buf, 0, cap, out_read);
}

OW_STATUS OwFsOwfsList(uint32_t* out_count) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    owfs_catalog_entry_t entries[OWFS_ENTRIES_PER_BLOCK];
    uint32_t count = 0;
    uint32_t i;
    owfs_status_t st;

    if (!g_owfs_formatted || !g_owfs_mounted) return (OW_STATUS)OWFS_ERR_IO;
    st = owfs_catalog_list(dev, &g_owfs_sb, OWFS_ROOT_INODE,
                           entries, OWFS_ENTRIES_PER_BLOCK, &count);
    if (st != OWFS_OK) return (OW_STATUS)st;
    for (i = 0; i < count; i++) {
        if (entries[i].entry_type == OWFS_ENTRY_DELETED) continue;
        ow_kprintf("  [%s] %s (ino %u)\r\n",
                   entries[i].entry_type == OWFS_ENTRY_CATALOG ? "DIR " : "FILE",
                   (const char*)entries[i].name, entries[i].inode_number);
    }
    if (out_count) *out_count = count;
    return OW_SUCCESS;
}

uint32_t OwFsOwfsFreeBlocks(void) {
    return g_owfs_formatted ? g_owfs_sb.free_blocks : 0u;
}

OW_STATUS OwFsUsfsFormat(const uint8_t* label, uint32_t label_len) {
    htl_device_t* dev;
    usfs_status_t st;
    if (!label) return (OW_STATUS)USFS_ERR_INVALID_PARAM;
    dev = OwHalGetSecureDisk();
    st = usfs_format_volume(dev, dev->total_blocks, label, label_len);
    if (st != USFS_OK) return (OW_STATUS)st;
    g_usfs_formatted = true;
    g_usfs_mounted = false;
    st = usfs_superblock_read(dev, &g_usfs_sb);
    return (st == USFS_OK) ? OW_SUCCESS : (OW_STATUS)st;
}

OW_STATUS OwFsUsfsMount(void) {
    htl_device_t* dev;
    usfs_status_t st;
    if (g_usfs_mounted) return OW_SUCCESS;
    if (!g_usfs_formatted) {
        st = OwFsUsfsFormat((const uint8_t*)"USFS", 4);
        if (st != OW_SUCCESS) return st;
    }
    dev = OwHalGetSecureDisk();
    st = usfs_mount(dev, &g_usfs_sb);
    if (st != USFS_OK) return (OW_STATUS)st;
    g_usfs_mounted = true;
    return OW_SUCCESS;
}

OW_STATUS OwFsUsfsUnmount(void) {
    htl_device_t* dev;
    usfs_status_t st;
    if (!g_usfs_mounted) return OW_SUCCESS;
    dev = OwHalGetSecureDisk();
    st = usfs_unmount(dev, &g_usfs_sb);
    g_usfs_mounted = false;
    return (st == USFS_OK) ? OW_SUCCESS : (OW_STATUS)st;
}

uint32_t OwFsUsfsFreeBlocks(void) {
    return g_usfs_formatted ? g_usfs_sb.free_blocks : 0u;
}

bool OwDiskOwfsMounted(void) { return g_owfs_mounted; }
bool OwDiskUsfsMounted(void) { return g_usfs_mounted; }

/* ====================================================================== */
/* Test-image userspace provisioners                                     */
/* ====================================================================== */
/* Three separate weak hooks rather than one "seed everything" hook, because
 * the three boot states are told apart by exactly which images a build carries:
 *
 *   owinit + owinitv + owrs   -> state 1, the normal test image
 *   owinitv + owrs only       -> state 2, the emergency image
 *   none                      -> state 3, the validation image
 *
 * A single hook with a mode argument would put that choice in a runtime flag
 * that a build could get wrong silently; three objects put it in the link line,
 * where the image a target produces is readable directly off the target's own
 * recipe.  Each hook creates and writes ONE image into the empty volume and
 * reports whether it did.
 *
 * The normal QEMU multiboot and floppy images link all three.  The production
 * hard-disk image (openwinkrnl.owx / openwinkrnl.vdi) links none, and gets the
 * weak defaults defined below: hooks that exist and do nothing, so a stock
 * volume has no user-mode init and no emergency userspace, which is state 3 and
 * a panic.  The defaults are weak so that linking a real seed object simply
 * overrides them -- the link line, not a runtime flag, is what selects the boot
 * image set. */
__attribute__((weak)) bool OwDiskSeedTestOwinit(void)  { return false; }
__attribute__((weak)) bool OwDiskSeedTestOwinitv(void) { return false; }
__attribute__((weak)) bool OwDiskSeedTestOwrs(void)    { return false; }

/* openwinkrnl.chk is not one of the three userspace images, so it is seeded
 * separately and unconditionally rather than being hung off one of them.  Every
 * seeded test image needs it: the kernel-integrity phase (before the init
 * hand-off) reads it off the volume and halts with a fatal integrity code if it
 * is absent, so a test image that forgets this fixture halts looking like
 * tampering before any userspace runs.  It was previously written by
 * owinit_seed.c, which is why the emergency image -- seeded without owinit.owx
 * -- failed the integrity phase. */
__attribute__((weak)) bool OwDiskSeedTestChk(void)     { return false; }

/* One-shot guard per hook: the provisioner must not rewrite an image that the
 * volume already carries, and a failed seed must not turn into a retry loop
 * inside the survey. */
static bool g_seeded_owinit;
static bool g_seeded_owinitv;
static bool g_seeded_owrs;
static bool g_seeded_chk;

static bool owdisk_run_seed(bool (*hook)(void), bool* already) {
    if (!hook || *already) return false;   /* absent, or attempted once already */
    *already = true;
    return hook();
}

/* ====================================================================== */
/* Userspace image survey                                                 */
/* ====================================================================== */
/* Header survey buffer.  Static, like every other staging pool in this kernel:
 * there is no dynamic heap to allocate from.  It is the same size as the
 * hand-off pool in core/main.c for the reason given on OW_USERSPACE_IMAGE_MAX
 * -- the survey must not be able to read past what the loader can read. */
static uint8_t g_owprobe_pool[OW_USERSPACE_IMAGE_MAX];

/* Survey one image.  `present` and `valid` are reported separately because they
 * answer different questions: "is it on the volume" and "could the loader enter
 * it".  A corrupted owinit.owx must be distinguishable from an absent one, or
 * the boot log cannot tell an operator whether to look for a missing file or a
 * damaged one. */
static void owdisk_probe_image(const char* name, bool (*seed)(void),
                               bool* seeded, bool* present, bool* valid,
                               OW_STATUS* status) {
    uint32_t inode = 0;
    uint32_t len = 0;
    OW_STATUS st;
    const owx_header_t* hdr;

    *present = false;
    *valid = false;
    *status = OW_ERR_NOT_FOUND;

    if (!g_owfs_formatted || !g_owfs_mounted) return;

    /* Catalog presence.  A test build gets one chance to provision the image
     * into the freshly formatted volume before the answer is given. */
    st = owfs_name_to_inode(name, &inode);
    if (st != OW_SUCCESS) {
        if (owdisk_run_seed(seed, seeded)) {
            st = owfs_name_to_inode(name, &inode);
        }
    }
    if (st != OW_SUCCESS) return;
    *present = true;

    /* Usability.  Read the image and hold it to exactly the verdict the
     * hand-off will act on: the loader's own structural gate PLUS the
     * whole-image CRC32c check.  A volume whose owinit is truncated,
     * garbage-filled or bit-rotted is classified unusable HERE, instead of being
     * discovered to be so by a failed hand-off that has already committed to
     * calling this machine healthy. */
    st = OwFsOwfsRead(name, g_owprobe_pool, (uint32_t)sizeof(g_owprobe_pool),
                      &len);
    if (!ow_status_success(st)) {
        *status = st;
        return;
    }
    if (len == 0u) {
        *status = OW_ERR_NOT_FOUND;
        return;
    }
    /* No length check against the pool: owfs_file_read() clamps the request to
     * the inode size and the capacity, so `len` cannot exceed the buffer. */
    if (len < 4u) {
        *status = OW_ERR_CORRUPT;
        ow_kprintf("[OWINIT] %s: %u byte(s) is not an image of any kind\r\n",
                   name, (unsigned)len);
        return;
    }

    hdr = (const owx_header_t*)(const void*)g_owprobe_pool;
    if (!OwOwxImageIsLoadable(hdr, len)) {
        /* Separate the two structural verdicts: "these bytes are not an OWX1
         * image" and "this is an OWX1 image this loader cannot bind" call for
         * completely different repairs, and reporting both as CORRUPT sends the
         * reader to re-flash a perfectly good file. */
        *status = (hdr->magic == OWX_MAGIC) ? OW_ERR_UNSUPPORTED : OW_ERR_CORRUPT;
        ow_kprintf("[OWINIT] %s: unusable image (%s)\r\n", name,
                   (hdr->magic == OWX_MAGIC) ? "OWX1 form this loader cannot bind"
                                             : "not an OWX1 image");
        return;
    }

    /* Structurally fine.  The remaining question is whether the bytes are the
     * bytes the packer wrote, and the packer is the only party that knows: a
     * scrambled payload passes every structural check in the loader and then
     * faults at CPL3 on the instruction it was corrupted in.  OW_ERR_CORRUPT is
     * right here, unlike the verdict above, because these really are the good
     * bytes in the wrong order or the wrong values. */
    if (!OwOwxImageIsUsable(g_owprobe_pool, len)) {
        *status = OW_ERR_CORRUPT;
        ow_kprintf("[OWINIT] %s: %u byte(s) FAILED CRC32c verification\r\n",
                   name, (unsigned)len);
        return;
    }

    *valid = true;
    *status = OW_SUCCESS;
    ow_kprintf("[OWINIT] %s: %u byte(s), entry 0x%llX, verified\r\n", name,
               (unsigned)len, (unsigned long long)hdr->entry_point);
}

void OwDiskProbeUserspace(OW_USERSPACE_PROBE* out) {
    if (!out) return;
    out->PrimaryPresent = false;   out->PrimaryValid = false;
    out->PrimaryStatus = OW_ERR_NOT_FOUND;
    out->EmergencyPresent = false; out->EmergencyValid = false;
    out->EmergencyStatus = OW_ERR_NOT_FOUND;
    out->RescuePresent = false;    out->RescueValid = false;
    out->RescueStatus = OW_ERR_NOT_FOUND;

    owdisk_probe_image(OW_INIT_EXEC_NAME,  OwDiskSeedTestOwinit,  &g_seeded_owinit,
                       &out->PrimaryPresent, &out->PrimaryValid,
                       &out->PrimaryStatus);
    owdisk_probe_image(OW_INITV_EXEC_NAME, OwDiskSeedTestOwinitv, &g_seeded_owinitv,
                       &out->EmergencyPresent, &out->EmergencyValid,
                       &out->EmergencyStatus);
    owdisk_probe_image(OW_RESCUE_EXEC_NAME, OwDiskSeedTestOwrs,   &g_seeded_owrs,
                       &out->RescuePresent, &out->RescueValid,
                       &out->RescueStatus);

    /* The integrity fixture is seeded here rather than by one of the three image
     * hooks because it belongs to the volume, not to any one image.  Doing it
     * first keeps the failure mode sane: if this fails, the kernel-integrity
     * phase will still halt with a fatal integrity code, but the log will
     * already say why, next to the survey line that has just run. */
    if (!g_seeded_chk) {
        g_seeded_chk = true;
        (void)OwDiskSeedTestChk();
    }
}

bool OwDiskOwinitPresent(void) {
    OW_USERSPACE_PROBE probe;

    /* A presence test that reports "present" for an image the loader would
     * reject is worse than no presence test at all: the boot would announce a
     * provisioned orchestrator and then fail to enter it.  This reuses the full
     * survey so the answer is the one the hand-off will act on. */
    OwDiskProbeUserspace(&probe);
    return probe.PrimaryValid;
}

OW_STATUS OwDiskInitialize(void) {
    OW_STATUS st;

    st = OwFsOwfsMount();
    if (st == OW_SUCCESS) {
        ow_kprintf("[OWFS] Primary volume mounted (LBA region %u KiB)\r\n",
                   (unsigned int)(OW_RAMDISK_PRIMARY_BLOCKS / 2));
    } else {
        ow_kprintf("[OWFS] Primary mount failed (0x%X)\r\n", (unsigned int)st);
    }

    st = OwFsUsfsMount();
    if (st == OW_SUCCESS) {
        ow_kprintf("[USFS] Secure volume mounted\r\n");
    } else {
        ow_kprintf("[USFS] Secure mount failed (0x%X)\r\n", (unsigned int)st);
    }
    return OW_SUCCESS;
}