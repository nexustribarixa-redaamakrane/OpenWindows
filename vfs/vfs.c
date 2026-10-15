/* vfs.c - Virtual File System */
#include "../inc/ow_vfs.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_string.h"
#include "../inc/ow_kprintf.h"
#include "../storage/owdisk.h"

static bool g_primary_mounted = false;
static bool g_secure_mounted = false;

/* CRC32c simplified checksum */
uint32_t OwFsChecksumCalc(const void* Data, uint32_t Size) {
    const uint8_t* p = (const uint8_t*)Data;
    uint32_t crc = 0xFFFFFFFF;
    uint32_t i;
    for (i = 0; i < Size; i++) {
        crc ^= (uint32_t)p[i];
        uint32_t j;
        for (j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0x82F63B78U & (-(int32_t)(crc & 1)));
        }
    }
    return ~crc;
}

/* OWFS Superblock Operations */
OW_STATUS OwFsSuperblockRead(htl_device_t* Dev, OW_FS_SUPERBLOCK* Sb) {
    if (!Dev || !Sb) return OW_ERR_NULL_POINTER;
    return htl_read_block(Dev, 0, Sb) == HTL_OK ? OW_SUCCESS : OW_ERR_IO;
}

OW_STATUS OwFsSuperblockWrite(htl_device_t* Dev, const OW_FS_SUPERBLOCK* Sb) {
    if (!Dev || !Sb) return OW_ERR_NULL_POINTER;
    return htl_write_block(Dev, 0, Sb) == HTL_OK ? OW_SUCCESS : OW_ERR_IO;
}

/* OWFS Inode Operations */
OW_STATUS OwFsInodeRead(htl_device_t* Dev, uint32_t InodeNum, OW_FS_INODE* Inode) {
    uint8_t block[4096];
    uint32_t inodes_per_block;
    uint32_t block_num;
    uint32_t offset;
    htl_status_t st;

    if (!Dev || !Inode) return OW_ERR_NULL_POINTER;
    inodes_per_block = Dev->block_size / sizeof(OW_FS_INODE);
    if (inodes_per_block == 0) return OW_ERR_CORRUPT;
    block_num = 1 + (InodeNum / inodes_per_block);
    offset = (InodeNum % inodes_per_block) * sizeof(OW_FS_INODE);

    st = htl_read_block(Dev, block_num, block);
    if (st != HTL_OK) return OW_ERR_IO;

    ow_memcpy(Inode, block + offset, sizeof(OW_FS_INODE));
    return OW_SUCCESS;
}

OW_STATUS OwFsInodeWrite(htl_device_t* Dev, uint32_t InodeNum, const OW_FS_INODE* Inode) {
    uint8_t block[4096];
    uint32_t inodes_per_block;
    uint32_t block_num;
    uint32_t offset;
    htl_status_t st;

    if (!Dev || !Inode) return OW_ERR_NULL_POINTER;
    inodes_per_block = Dev->block_size / sizeof(OW_FS_INODE);
    if (inodes_per_block == 0) return OW_ERR_CORRUPT;
    block_num = 1 + (InodeNum / inodes_per_block);
    offset = (InodeNum % inodes_per_block) * sizeof(OW_FS_INODE);

    st = htl_read_block(Dev, block_num, block);
    if (st != HTL_OK) return OW_ERR_IO;

    ow_memcpy(block + offset, Inode, sizeof(OW_FS_INODE));
    st = htl_write_block(Dev, block_num, block);
    return st == HTL_OK ? OW_SUCCESS : OW_ERR_IO;
}

/* OWFS Block I/O */
OW_STATUS OwFsBlockRead(htl_device_t* Dev, uint32_t BlockNum, void* Buffer) {
    if (!Dev || !Buffer) return OW_ERR_NULL_POINTER;
    return htl_read_block(Dev, BlockNum, Buffer) == HTL_OK ? OW_SUCCESS : OW_ERR_IO;
}

OW_STATUS OwFsBlockWrite(htl_device_t* Dev, uint32_t BlockNum, const void* Buffer) {
    if (!Dev || !Buffer) return OW_ERR_NULL_POINTER;
    return htl_write_block(Dev, BlockNum, Buffer) == HTL_OK ? OW_SUCCESS : OW_ERR_IO;
}

/* OWFS Catalog Operations */
OW_STATUS OwFsCatalogLookup(htl_device_t* Dev, uint32_t ParentInode, const char* Name, OW_FS_CATALOG_ENTRY* OutEntry) {
    OW_FS_INODE parent_inode;
    uint8_t block[4096];
    uint32_t entries_per_block;
    uint32_t i, j;

    if (!Dev || !Name || !OutEntry) return OW_ERR_NULL_POINTER;

    if (!ow_status_success(OwFsInodeRead(Dev, ParentInode, &parent_inode))) return OW_ERR_IO;

    entries_per_block = Dev->block_size / sizeof(OW_FS_CATALOG_ENTRY);

    for (i = 0; i < 12 && parent_inode.DirectBlocks[i]; i++) {
        if (!ow_status_success(OwFsBlockRead(Dev, parent_inode.DirectBlocks[i], block))) continue;
        for (j = 0; j < entries_per_block; j++) {
            OW_FS_CATALOG_ENTRY* e = (OW_FS_CATALOG_ENTRY*)(block + j * sizeof(OW_FS_CATALOG_ENTRY));
            if (e->EntryType != OW_FS_ENTRY_DELETED && ow_strcmp(e->Name, Name) == 0) {
                ow_memcpy(OutEntry, e, sizeof(OW_FS_CATALOG_ENTRY));
                return OW_SUCCESS;
            }
        }
    }
    return OW_ERR_NOT_FOUND;
}

OW_STATUS OwFsCatalogInsert(htl_device_t* Dev, uint32_t ParentInode, const char* Name, uint32_t InodeNum, uint8_t Type) {
    OW_FS_INODE parent_inode;
    uint8_t block[4096];
    uint32_t entries_per_block;
    uint32_t i, j;

    if (!Dev || !Name) return OW_ERR_NULL_POINTER;

    if (!ow_status_success(OwFsInodeRead(Dev, ParentInode, &parent_inode))) return OW_ERR_IO;

    entries_per_block = Dev->block_size / sizeof(OW_FS_CATALOG_ENTRY);

    for (i = 0; i < 12 && parent_inode.DirectBlocks[i]; i++) {
        if (!ow_status_success(OwFsBlockRead(Dev, parent_inode.DirectBlocks[i], block))) continue;
        for (j = 0; j < entries_per_block; j++) {
            OW_FS_CATALOG_ENTRY* e = (OW_FS_CATALOG_ENTRY*)(block + j * sizeof(OW_FS_CATALOG_ENTRY));
            if (e->EntryType == 0 || e->EntryType == OW_FS_ENTRY_DELETED) {
                ow_memset(e, 0, sizeof(OW_FS_CATALOG_ENTRY));
                ow_strncpy(e->Name, Name, 223);
                e->InodeNumber = InodeNum;
                e->EntryType = Type;
                e->SecurityFlags = 0;
                e->Checksum = OwFsChecksumCalc(e, sizeof(OW_FS_CATALOG_ENTRY) - 4);
                return OwFsBlockWrite(Dev, parent_inode.DirectBlocks[i], block);
            }
        }
    }
    return OW_ERR_INSUFFICIENT;
}

/* OWFS Bitmap Operations */
OW_STATUS OwFsBitmapAllocBlock(htl_device_t* Dev, uint32_t* OutBlockNum) {
    uint8_t block[4096];
    uint32_t bitmap_start = 2;
    uint32_t i, j;

    if (!Dev || !OutBlockNum) return OW_ERR_NULL_POINTER;

    for (i = bitmap_start; i < Dev->total_blocks / (Dev->block_size * 8) + bitmap_start; i++) {
        if (htl_read_block(Dev, i, block) != HTL_OK) continue;
        for (j = 0; j < Dev->block_size; j++) {
            if (block[j] != 0xFF) {
                uint8_t bit;
                for (bit = 0; bit < 8; bit++) {
                    if (!(block[j] & (1 << bit))) {
                        block[j] |= (1 << bit);
                        htl_write_block(Dev, i, block);
                        *OutBlockNum = ((i - bitmap_start) * Dev->block_size + j) * 8 + bit;
                        return OW_SUCCESS;
                    }
                }
            }
        }
    }
    return OW_ERR_INSUFFICIENT;
}

OW_STATUS OwFsBitmapFreeBlock(htl_device_t* Dev, uint32_t BlockNum) {
    uint8_t block[4096];
    uint32_t bitmap_start = 2;
    uint32_t byte_idx;
    uint8_t bit_idx;

    if (!Dev) return OW_ERR_NULL_POINTER;

    byte_idx = BlockNum / 8;
    bit_idx = (uint8_t)(BlockNum % 8);
    uint32_t block_num = bitmap_start + (byte_idx / Dev->block_size);
    uint32_t offset = byte_idx % Dev->block_size;

    if (htl_read_block(Dev, block_num, block) != HTL_OK) return OW_ERR_IO;
    block[offset] &= ~(1 << bit_idx);
    return htl_write_block(Dev, block_num, block) == HTL_OK ? OW_SUCCESS : OW_ERR_IO;
}

/* VFS Facade.
 *
 * The facade used to be a second, independent on-disk stack: it wrote an
 * OW_FS_SUPERBLOCK to block 0 and maintained its own inode/catalog/bitmap
 * layout, while the `fs` command, the boot image survey and the OWX loader all
 * spoke the OWFS format on the same disk.  A file created through one was
 * invisible to the other -- exactly the divergence the testing report hit with
 * `write`/`read` versus `fs`.
 *
 * There is now ONE on-disk truth.  The facade is a thin adapter over the real
 * OWFS (primary) and USFS (secure) volumes, so VFS read/write/create/delete and
 * `fs` operate on the same files, and `OwVfsIsPrimaryMounted` reflects the
 * actual mount rather than a private flag.
 *
 * The OwFs* primitives above are retained: OwFsChecksumCalc is the exported
 * CRC32c contract that the crash-dump writer and the packer both pin against,
 * and the block/inode/catalog helpers document the historical layout.  They are
 * no longer reachable from the facade. */
OW_STATUS OwVfsInitialize(void) {
    g_primary_mounted = false;
    g_secure_mounted = false;
    return OW_SUCCESS;
}

OW_STATUS OwVfsMountPrimary(void) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    OW_STATUS st;

    if (!dev) return OW_ERR_NOT_INITIALIZED;

    st = OwFsOwfsMount();
    if (!ow_status_success(st)) return st;

    g_primary_mounted = true;
    ow_kprintf("[VFS] Primary OWFS volume mounted. Blocks: %u, Free: %u\r\n",
               (unsigned)dev->total_blocks, (unsigned)OwFsOwfsFreeBlocks());
    return OW_SUCCESS;
}

OW_STATUS OwVfsMountSecure(void) {
    OW_STATUS st;

    if (!OwHalGetSecureDisk()) return OW_ERR_NOT_INITIALIZED;

    st = OwFsUsfsMount();
    if (!ow_status_success(st)) return st;

    g_secure_mounted = true;
    ow_kprintf("[VFS] Secure USFS volume mounted.\r\n");
    return OW_SUCCESS;
}

OW_STATUS OwVfsCreateFile(const char* Path, uint32_t Attrs) {
    uint32_t inode_num = 0;
    (void)Attrs;

    if (!Path) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    return OwFsOwfsCreate(Path, &inode_num);
}

OW_STATUS OwVfsWriteFile(const char* Path, const uint8_t* Buffer, uint32_t Size) {
    if (!Path || !Buffer) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    return OwFsOwfsWrite(Path, Buffer, Size);
}

uint32_t OwVfsReadFile(const char* Path, uint8_t* Buffer, uint32_t MaxSize) {
    uint32_t got = 0;

    if (!Path || !Buffer || MaxSize == 0) return 0;
    if (!g_primary_mounted) return 0;
    if (!ow_status_success(OwFsOwfsRead(Path, Buffer, MaxSize, &got))) return 0;
    return got;
}

OW_STATUS OwVfsDeleteFile(const char* Path) {
    if (!Path) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    return OwFsOwfsDelete(Path);
}

bool OwVfsIsPrimaryMounted(void) {
    return g_primary_mounted && OwDiskOwfsMounted();
}

bool OwVfsIsSecureMounted(void) {
    return g_secure_mounted && OwDiskUsfsMounted();
}

uint32_t OwVfsSecureFreeBlocks(void) {
    return g_secure_mounted ? OwFsUsfsFreeBlocks() : 0u;
}

OW_STATUS OwVfsSecurePurge(void) {
    htl_device_t* dev = OwHalGetSecureDisk();
    uint32_t i;
    uint8_t block[4096];
    if (!g_secure_mounted || !dev) return OW_ERR_NOT_INITIALIZED;

    ow_memset(block, 0, sizeof(block));
    for (i = 0; i < 16 && i < dev->total_blocks; i++) {
        htl_write_block(dev, i, block);
    }

    ow_kprintf("[VFS] USFS crypto-purge: key slots zeroed.\r\n");
    return OW_SUCCESS;
}
