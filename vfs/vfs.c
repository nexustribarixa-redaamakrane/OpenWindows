/* vfs.c - Virtual File System */
#include "../inc/ow_vfs.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_string.h"
#include "../inc/ow_kprintf.h"

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

/* VFS Facade */
OW_STATUS OwVfsInitialize(void) {
    g_primary_mounted = false;
    g_secure_mounted = false;
    return OW_SUCCESS;
}

OW_STATUS OwVfsMountPrimary(void) {
    htl_device_t* dev = OwHalGetPrimaryDisk();
    OW_FS_SUPERBLOCK sb;

    if (!dev) return OW_ERR_NOT_INITIALIZED;

    if (!ow_status_success(OwFsSuperblockRead(dev, &sb))) return OW_ERR_IO;

    if (sb.Magic == OW_FS_MAGIC_PRIMARY) {
        g_primary_mounted = true;
        ow_kprintf("[VFS] Primary OWFS volume mounted. Blocks: %u, Free: %u\r\n",
                   (unsigned)sb.TotalBlocks, (unsigned)sb.FreeBlocks);
        return OW_SUCCESS;
    }

    /* No valid superblock - format the volume */
    ow_memset(&sb, 0, sizeof(OW_FS_SUPERBLOCK));
    sb.Magic = OW_FS_MAGIC_PRIMARY;
    sb.Version = 1;
    sb.TotalBlocks = dev->total_blocks;
    sb.FreeBlocks = dev->total_blocks - 4;
    sb.RootInode = 0;
    sb.CreateEpoch = 0;
    sb.ModifyEpoch = 0;
    sb.Checksum = OwFsChecksumCalc(&sb, sizeof(OW_FS_SUPERBLOCK) - 4);

    if (!ow_status_success(OwFsSuperblockWrite(dev, &sb))) return OW_ERR_IO;

    g_primary_mounted = true;
    ow_kprintf("[VFS] Primary OWFS volume formatted and mounted.\r\n");
    return OW_SUCCESS;
}

OW_STATUS OwVfsMountSecure(void) {
    htl_device_t* dev = OwHalGetSecureDisk();
    OW_FS_SUPERBLOCK sb;

    if (!dev) return OW_ERR_NOT_INITIALIZED;

    if (ow_status_success(OwFsSuperblockRead(dev, &sb)) && sb.Magic == OW_FS_MAGIC_SECURE) {
        g_secure_mounted = true;
        ow_kprintf("[VFS] Secure USFS volume mounted.\r\n");
        return OW_SUCCESS;
    }

    /* Format */
    ow_memset(&sb, 0, sizeof(OW_FS_SUPERBLOCK));
    sb.Magic = OW_FS_MAGIC_SECURE;
    sb.Version = 1;
    sb.TotalBlocks = dev->total_blocks;
    sb.FreeBlocks = dev->total_blocks - 4;
    sb.RootInode = 0;
    sb.Checksum = OwFsChecksumCalc(&sb, sizeof(OW_FS_SUPERBLOCK) - 4);

    if (!ow_status_success(OwFsSuperblockWrite(dev, &sb))) return OW_ERR_IO;

    g_secure_mounted = true;
    ow_kprintf("[VFS] Secure USFS volume formatted and mounted.\r\n");
    return OW_SUCCESS;
}

OW_STATUS OwVfsCreateFile(const char* Path, uint32_t Attrs) {
    htl_device_t* dev;
    uint32_t inode_num;
    OW_FS_INODE inode;
    uint32_t data_block;
    (void)Attrs;

    if (!Path) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;

    dev = OwHalGetPrimaryDisk();

    if (ow_status_success(OwFsCatalogLookup(dev, 0, Path, (void*)0))) {
        return OW_ERR_ALREADY_EXISTS;
    }

    if (!ow_status_success(OwFsBitmapAllocBlock(dev, &inode_num))) return OW_ERR_INSUFFICIENT;
    if (!ow_status_success(OwFsBitmapAllocBlock(dev, &data_block))) return OW_ERR_INSUFFICIENT;

    ow_memset(&inode, 0, sizeof(OW_FS_INODE));
    inode.InodeNumber = inode_num;
    inode.Size = 0;
    inode.Permissions = 0x1B6;
    inode.SecurityFlags = 0;
    inode.DirectBlocks[0] = data_block;
    inode.Checksum = OwFsChecksumCalc(&inode, sizeof(OW_FS_INODE) - 4);

    if (!ow_status_success(OwFsInodeWrite(dev, inode_num, &inode))) return OW_ERR_IO;
    if (!ow_status_success(OwFsCatalogInsert(dev, 0, Path, inode_num, OW_FS_ENTRY_FILE))) return OW_ERR_IO;

    return OW_SUCCESS;
}

OW_STATUS OwVfsWriteFile(const char* Path, const uint8_t* Buffer, uint32_t Size) {
    htl_device_t* dev;
    OW_FS_CATALOG_ENTRY cat;
    OW_FS_INODE inode;
    uint8_t block[4096];

    if (!Path || !Buffer) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;

    dev = OwHalGetPrimaryDisk();

    if (!ow_status_success(OwFsCatalogLookup(dev, 0, Path, &cat))) return OW_ERR_NOT_FOUND;
    if (!ow_status_success(OwFsInodeRead(dev, cat.InodeNumber, &inode))) return OW_ERR_IO;

    ow_memset(block, 0, sizeof(block));
    ow_memcpy(block, Buffer, Size < sizeof(block) ? Size : sizeof(block));

    if (!ow_status_success(OwFsBlockWrite(dev, inode.DirectBlocks[0], block))) return OW_ERR_IO;

    inode.Size = Size;
    inode.Checksum = OwFsChecksumCalc(&inode, sizeof(OW_FS_INODE) - 4);
    return OwFsInodeWrite(dev, cat.InodeNumber, &inode);
}

uint32_t OwVfsReadFile(const char* Path, uint8_t* Buffer, uint32_t MaxSize) {
    htl_device_t* dev;
    OW_FS_CATALOG_ENTRY cat;
    OW_FS_INODE inode;
    uint8_t block[4096];
    uint32_t to_read;

    if (!Path || !Buffer || MaxSize == 0) return 0;
    if (!g_primary_mounted) return 0;

    dev = OwHalGetPrimaryDisk();

    if (!ow_status_success(OwFsCatalogLookup(dev, 0, Path, &cat))) return 0;
    if (!ow_status_success(OwFsInodeRead(dev, cat.InodeNumber, &inode))) return 0;
    if (!ow_status_success(OwFsBlockRead(dev, inode.DirectBlocks[0], block))) return 0;

    to_read = inode.Size < MaxSize ? inode.Size : MaxSize;
    ow_memcpy(Buffer, block, to_read);
    return to_read;
}

OW_STATUS OwVfsDeleteFile(const char* Path) {
    htl_device_t* dev;
    OW_FS_CATALOG_ENTRY cat;
    uint8_t block[4096];
    uint32_t entries_per_block;

    if (!Path) return OW_ERR_NULL_POINTER;
    if (!g_primary_mounted) return OW_ERR_NOT_INITIALIZED;

    dev = OwHalGetPrimaryDisk();

    if (!ow_status_success(OwFsCatalogLookup(dev, 0, Path, &cat))) return OW_ERR_NOT_FOUND;

    entries_per_block = dev->block_size / sizeof(OW_FS_CATALOG_ENTRY);
    if (ow_status_success(OwFsBlockRead(dev, 2, block))) {
        uint32_t i;
        for (i = 0; i < entries_per_block; i++) {
            OW_FS_CATALOG_ENTRY* e = (OW_FS_CATALOG_ENTRY*)(block + i * sizeof(OW_FS_CATALOG_ENTRY));
            if (ow_strcmp(e->Name, Path) == 0) {
                e->EntryType = OW_FS_ENTRY_DELETED;
                OwFsBlockWrite(dev, 2, block);
                break;
            }
        }
    }

    return OW_SUCCESS;
}

bool OwVfsIsPrimaryMounted(void) { return g_primary_mounted; }
bool OwVfsIsSecureMounted(void) { return g_secure_mounted; }
uint32_t OwVfsSecureFreeBlocks(void) {
    htl_device_t* dev = OwHalGetSecureDisk();
    OW_FS_SUPERBLOCK sb;
    if (!g_secure_mounted || !dev) return 0;
    if (ow_status_success(OwFsSuperblockRead(dev, &sb))) return sb.FreeBlocks;
    return 0;
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
