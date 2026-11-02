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
    ow_skto_name_t admitted;
    skto_status_t sst;

    if (!Dev || !Name || !OutEntry) return OW_ERR_NULL_POINTER;

    sst = OwSktoNameAdmitTrusted(&admitted, Name, sizeof(((OW_FS_CATALOG_ENTRY*)0)->Name));
    if (sst != SKTO_OK) return OW_ERR_INVALID_PARAM;

    if (!ow_status_success(OwFsInodeRead(Dev, ParentInode, &parent_inode))) return OW_ERR_IO;

    entries_per_block = Dev->block_size / sizeof(OW_FS_CATALOG_ENTRY);

    for (i = 0; i < 12 && parent_inode.DirectBlocks[i]; i++) {
        if (!ow_status_success(OwFsBlockRead(Dev, parent_inode.DirectBlocks[i], block))) continue;
        for (j = 0; j < entries_per_block; j++) {
            OW_FS_CATALOG_ENTRY* e = (OW_FS_CATALOG_ENTRY*)(block + j * sizeof(OW_FS_CATALOG_ENTRY));
            if (e->EntryType != OW_FS_ENTRY_DELETED && ow_strcmp(e->Name, OwSktoNameCstr(&admitted)) == 0) {
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
    ow_skto_name_t admitted;
    skto_status_t sst;

    if (!Dev || !Name) return OW_ERR_NULL_POINTER;

    /* Validate candidate name: must be valid SUTF, bounded by catalog field,
     * no silent truncation. */
    sst = OwSktoNameAdmitTrusted(&admitted, Name, sizeof(((OW_FS_CATALOG_ENTRY*)0)->Name));
    if (sst != SKTO_OK) {
        return OW_ERR_INVALID_PARAM;
    }

    if (!ow_status_success(OwFsInodeRead(Dev, ParentInode, &parent_inode))) return OW_ERR_IO;

    entries_per_block = Dev->block_size / sizeof(OW_FS_CATALOG_ENTRY);

    for (i = 0; i < 12 && parent_inode.DirectBlocks[i]; i++) {
        if (!ow_status_success(OwFsBlockRead(Dev, parent_inode.DirectBlocks[i], block))) continue;
        for (j = 0; j < entries_per_block; j++) {
            OW_FS_CATALOG_ENTRY* e = (OW_FS_CATALOG_ENTRY*)(block + j * sizeof(OW_FS_CATALOG_ENTRY));
            if (e->EntryType == 0 || e->EntryType == OW_FS_ENTRY_DELETED) {
                ow_memset(e, 0, sizeof(OW_FS_CATALOG_ENTRY));
                ow_memcpy(e->Name, OwSktoNameCstr(&admitted), OwSktoNameLength(&admitted) + 1);
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
static skto_name_table_t g_vfs_skto_table;
static ow_skto_irq_lock_t g_vfs_skto_lock;
static bool g_vfs_skto_ready = false;

OW_STATUS OwVfsInitialize(void) {
    g_primary_mounted = false;
    g_secure_mounted = false;
    g_vfs_skto_lock.flags = 0;
    if (suas_skto_names_init_locked(&g_vfs_skto_table, OwSktoLockAcquire,
                                    OwSktoLockRelease, &g_vfs_skto_lock) == SKTO_OK) {
        g_vfs_skto_ready = true;
    }
    return OW_SUCCESS;
}

static bool vfs_skto_ensure(void) {
    skto_status_t st;

    if (g_vfs_skto_ready) return true;
    g_vfs_skto_lock.flags = 0;
    st = suas_skto_names_init_locked(&g_vfs_skto_table, OwSktoLockAcquire,
                                     OwSktoLockRelease, &g_vfs_skto_lock);
    if (st != SKTO_OK) return false;
    g_vfs_skto_ready = true;
    return true;
}

OW_STATUS OwVfsPublishName(const ow_skto_name_t* Name, uint32_t* OutGeneration) {
    skto_status_t st;
    if (!Name || !Name->text.bytes) return OW_ERR_INVALID_PARAM;
    if (!vfs_skto_ensure()) return OW_ERR_NOT_INITIALIZED;
    st = suas_skto_publish(&g_vfs_skto_table, &Name->text, NULL, OutGeneration);
    if (st == SKTO_E_BUSY || st == SKTO_E_FULL) return OW_ERR_INSUFFICIENT;
    if (st != SKTO_OK) return OW_ERR_INVALID_PARAM;
    return OW_SUCCESS;
}

/* Withdraw an already-admitted name from the advisory lookup index. This is
 * the teardown half of publication: a successful delete must stop the name
 * from resolving even though a reader may still hold an older snapshot. */
OW_STATUS OwVfsRetireNameSkto(const ow_skto_name_t* Name) {
    skto_status_t st;
    if (!Name || !Name->text.bytes) return OW_ERR_NULL_POINTER;
    if (!g_vfs_skto_ready) return OW_ERR_NOT_INITIALIZED;
    st = suas_skto_retire(&g_vfs_skto_table, &Name->text);
    if (st == SKTO_OK) return OW_SUCCESS;
    if (st == SKTO_E_NOTFOUND) return OW_ERR_NOT_FOUND;
    return OW_ERR_INVALID_PARAM;
}

OW_STATUS OwVfsRetireName(const char* Path) {
    ow_skto_name_t admitted;
    skto_status_t st;
    if (!Path) return OW_ERR_NULL_POINTER;
    st = OwSktoNameAdmitTrusted(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES);
    if (st != SKTO_OK) return OW_ERR_INVALID_PARAM;
    return OwVfsRetireNameSkto(&admitted);
}

OW_STATUS OwVfsReleaseSnapshot(const skto_text_t* Snapshot) {
    skto_status_t st;
    if (!Snapshot || !g_vfs_skto_ready) return OW_ERR_INVALID_PARAM;
    st = suas_skto_name_release(&g_vfs_skto_table, Snapshot);
    return (st == SKTO_OK) ? OW_SUCCESS : OW_ERR_INVALID_PARAM;
}

/* Resolve an already-admitted name against the index. A hit is verified on
 * disk before its snapshot is returned. A miss is verified on disk and then
 * published, so the index follows files that predate this boot. Publication
 * failure (the bounded index is full, or a replacement record is still held)
 * is reported as OW_ERR_INSUFFICIENT; callers treat the index as advisory and
 * continue on the direct path rather than failing the operation. */
OW_STATUS OwVfsLookupSnapshotSkto(const ow_skto_name_t* Name,
                                  skto_text_t* OutSnapshot, uint32_t* OutInode) {
    skto_status_t sst;
    uint32_t gen = 0;
    OW_STATUS ost;
    uint32_t ino = 0;

    if (!Name || !Name->text.bytes || !OutSnapshot) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    if (!vfs_skto_ensure()) return OW_ERR_NOT_INITIALIZED;

    /* Try to resolve an existing published snapshot */
    sst = suas_skto_resolve(&g_vfs_skto_table, &Name->text, &gen, OutSnapshot);
    if (sst == SKTO_OK) {
        /* In table: verify on disk using snapshot */
        ost = OwFsOwfsLookupIn(OwFsOwfsRootInode(), (const char*)OutSnapshot->bytes, &ino, NULL);
        if (!ow_status_success(ost)) {
            suas_skto_name_release(&g_vfs_skto_table, OutSnapshot);
            return ost;
        }
    } else if (sst == SKTO_E_NOTFOUND) {
        /* Not yet in table: verify on primary disk first */
        ost = OwFsOwfsLookupIn(OwFsOwfsRootInode(), OwSktoNameCstr(Name), &ino, NULL);
        if (!ow_status_success(ost)) {
            return ost;
        }
        /* Found on disk: publish to VFS table and acquire snapshot */
        sst = suas_skto_publish(&g_vfs_skto_table, &Name->text, NULL, &gen);
        if (sst != SKTO_OK) {
            return OW_ERR_INSUFFICIENT;
        }
        sst = suas_skto_resolve(&g_vfs_skto_table, &Name->text, &gen, OutSnapshot);
        if (sst != SKTO_OK) {
            return OW_ERR_INSUFFICIENT;
        }
    } else {
        return OW_ERR_INVALID_PARAM;
    }

    if (OutInode) *OutInode = ino;
    return OW_SUCCESS;
}

OW_STATUS OwVfsLookupSnapshot(const char* Path, skto_range_fn Range, void* RangeCtx,
                             skto_text_t* OutSnapshot, uint32_t* OutInode) {
    ow_skto_name_t admitted;
    skto_status_t sst;

    if (!Path || !OutSnapshot) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;

    if (Range != NULL) {
        sst = OwSktoNameAdmitUser(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES, Range, RangeCtx);
    } else {
        sst = OwSktoNameAdmitTrusted(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES);
    }
    if (sst != SKTO_OK) {
        return OW_ERR_INVALID_PARAM;
    }

    return OwVfsLookupSnapshotSkto(&admitted, OutSnapshot, OutInode);
}

OW_STATUS OwVfsCreateFileSkto(const ow_skto_name_t* Name, uint32_t Attrs) {
    uint32_t inode_num = 0;
    OW_STATUS st;
    (void)Attrs;
    if (!Name || !Name->text.bytes) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    st = OwFsOwfsCreate(OwSktoNameCstr(Name), &inode_num);
    /* Publication follows the namespace, not the syscall: any successful
     * create through this facade makes the name resolvable through the
     * advisory index. The index is bounded, so a full table does not fail the
     * create; readers fall back to the direct path. An already-existing name
     * is published on its first read instead. */
    if (ow_status_success(st)) {
        (void)OwVfsPublishName(Name, NULL);
    }
    return st;
}

OW_STATUS OwVfsWriteFileSkto(const ow_skto_name_t* Name, const uint8_t* Buffer, uint32_t Size) {
    if (!Name || !Name->text.bytes || !Buffer) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    return OwFsOwfsWrite(OwSktoNameCstr(Name), Buffer, Size);
}

uint32_t OwVfsReadFileSkto(const ow_skto_name_t* Name, uint8_t* Buffer, uint32_t MaxSize) {
    skto_text_t snapshot;
    uint32_t ino = 0;
    const char* read_name;
    bool have_snapshot = false;
    uint32_t got = 0;
    if (!Name || !Name->text.bytes || !Buffer || MaxSize == 0) return 0;
    if (!g_primary_mounted) return 0;

    /* Consume the publication index when it can resolve the name. A miss or a
     * full table is advisory only: the direct name read below still runs. */
    read_name = OwSktoNameCstr(Name);
    if (ow_status_success(OwVfsLookupSnapshotSkto(Name, &snapshot, &ino))) {
        read_name = (const char*)snapshot.bytes;
        have_snapshot = true;
    }

    if (!ow_status_success(OwFsOwfsRead(read_name, Buffer, MaxSize, &got))) got = 0;
    if (have_snapshot) (void)OwVfsReleaseSnapshot(&snapshot);
    return got;
}

OW_STATUS OwVfsDeleteFileSkto(const ow_skto_name_t* Name) {
    OW_STATUS st;
    if (!Name || !Name->text.bytes) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;
    st = OwFsOwfsDelete(OwSktoNameCstr(Name));
    /* The namespace is the source of truth; the index must not keep resolving
     * a name the disk has already removed. A missing index entry is expected
     * (the file may predate this boot) and is not a delete failure. */
    if (ow_status_success(st)) {
        (void)OwVfsRetireNameSkto(Name);
    }
    return st;
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
    ow_skto_name_t admitted;
    skto_status_t st;
    if (!Path) return OW_ERR_NULL_POINTER;
    st = OwSktoNameAdmitTrusted(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES);
    if (st != SKTO_OK) return OW_ERR_INVALID_PARAM;
    return OwVfsCreateFileSkto(&admitted, Attrs);
}

OW_STATUS OwVfsWriteFile(const char* Path, const uint8_t* Buffer, uint32_t Size) {
    ow_skto_name_t admitted;
    skto_status_t st;
    if (!Path || !Buffer) return OW_ERR_NULL_POINTER;
    st = OwSktoNameAdmitTrusted(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES);
    if (st != SKTO_OK) return OW_ERR_INVALID_PARAM;
    return OwVfsWriteFileSkto(&admitted, Buffer, Size);
}

uint32_t OwVfsReadFile(const char* Path, uint8_t* Buffer, uint32_t MaxSize) {
    ow_skto_name_t admitted;
    skto_status_t st;
    if (!Path || !Buffer || MaxSize == 0) return 0;
    st = OwSktoNameAdmitTrusted(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES);
    if (st != SKTO_OK) return 0;
    return OwVfsReadFileSkto(&admitted, Buffer, MaxSize);
}

OW_STATUS OwVfsDeleteFile(const char* Path) {
    ow_skto_name_t admitted;
    skto_status_t st;
    if (!Path) return OW_ERR_NULL_POINTER;
    st = OwSktoNameAdmitTrusted(&admitted, Path, OW_SKTO_NAME_STORAGE_BYTES);
    if (st != SKTO_OK) return OW_ERR_INVALID_PARAM;
    return OwVfsDeleteFileSkto(&admitted);
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
