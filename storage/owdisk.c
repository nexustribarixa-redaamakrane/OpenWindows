/* owdisk.c - OpenWindows-Storage ecosystem integration
 * OWFS volume on the primary RAM disk, USFS volume on the secure disk. */
#include "../inc/ow_types.h"
#include "../inc/ow_hal.h"
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

/* Test images (QEMU multiboot flat binary, floppy) link boot/owinit_seed.o,
 * which provides this function and seeds the Essentials owinit.owx onto the freshly
 * formatted in-memory OWFS volume so the boot reaches the interactive shell.
 * Production images do not link it, so the weak reference stays null and the
 * owinit provisioning gate keeps its fatal halt behaviour. */
extern bool OwDiskSeedTestOwinit(void) __attribute__((weak));

bool OwDiskOwinitPresent(void) {
    uint32_t inode = 0;
    OW_STATUS st;
    /* owinit is a Tier-3 userspace .owx executable that must live in the
     * OWFS root catalog. The volume label is NOT the signal: the boot
     * only proceeds when the owinit image itself is provisioned on disk. */
    if (!g_owfs_formatted || !g_owfs_mounted) return false;
    st = owfs_name_to_inode(OW_INIT_EXEC_NAME, &inode);
    if (st != OW_SUCCESS && OwDiskSeedTestOwinit) {
        return OwDiskSeedTestOwinit();
    }
    return (st == OW_SUCCESS);
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