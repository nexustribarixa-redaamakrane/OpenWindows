/* ow_vfs.h - Virtual File System */
#ifndef OW_VFS_H
#define OW_VFS_H

#include "ow_types.h"
#include "../lib/ow_htl.h"

#define OW_FS_MAGIC_PRIMARY     0x4F5746535052494DULL
#define OW_FS_MAGIC_SECURE      0x4F57465353454352ULL
#define OW_FS_BLOCK_SIZE        4096U

typedef enum _OW_FS_ENTRY_TYPE {
    OW_FS_ENTRY_FILE    = 0x01U,
    OW_FS_ENTRY_CATALOG = 0x02U,
    OW_FS_ENTRY_DELETED = 0x80U
} OW_FS_ENTRY_TYPE;

typedef struct _OW_FS_SUPERBLOCK {
    uint64_t    Magic;
    uint32_t    Version;
    uint32_t    TotalBlocks;
    uint32_t    FreeBlocks;
    uint32_t    RootInode;
    uint64_t    CreateEpoch;
    uint64_t    ModifyEpoch;
    uint32_t    Checksum;
    uint8_t     Reserved[4060];
} OW_FS_SUPERBLOCK;

typedef struct _OW_FS_INODE {
    uint32_t    InodeNumber;
    uint32_t    Size;
    uint32_t    Permissions;
    uint32_t    SecurityFlags;
    uint64_t    CreatedEpoch;
    uint64_t    ModifiedEpoch;
    uint32_t    DirectBlocks[12];
    uint32_t    IndirectBlock;
    uint32_t    Checksum;
    uint8_t     Reserved[4036];
} OW_FS_INODE;

typedef struct _OW_FS_CATALOG_ENTRY {
    char        Name[224];
    uint32_t    InodeNumber;
    uint8_t     EntryType;
    uint8_t     SecurityFlags;
    uint16_t    Reserved;
    uint32_t    Checksum;
} OW_FS_CATALOG_ENTRY;

OW_STATUS    OwVfsInitialize(void);
OW_STATUS    OwVfsMountPrimary(void);
OW_STATUS    OwVfsMountSecure(void);
OW_STATUS    OwVfsCreateFile(const char* Path, uint32_t Attrs);
OW_STATUS    OwVfsWriteFile(const char* Path, const uint8_t* Buffer, uint32_t Size);
uint32_t     OwVfsReadFile(const char* Path, uint8_t* Buffer, uint32_t MaxSize);
OW_STATUS    OwVfsDeleteFile(const char* Path);
bool         OwVfsIsPrimaryMounted(void);
bool         OwVfsIsSecureMounted(void);
uint32_t     OwVfsSecureFreeBlocks(void);
OW_STATUS    OwVfsSecurePurge(void);

/* OWFS internal */
OW_STATUS    OwFsSuperblockRead(htl_device_t* Dev, OW_FS_SUPERBLOCK* Sb);
OW_STATUS    OwFsSuperblockWrite(htl_device_t* Dev, const OW_FS_SUPERBLOCK* Sb);
OW_STATUS    OwFsInodeRead(htl_device_t* Dev, uint32_t InodeNum, OW_FS_INODE* Inode);
OW_STATUS    OwFsInodeWrite(htl_device_t* Dev, uint32_t InodeNum, const OW_FS_INODE* Inode);
OW_STATUS    OwFsCatalogLookup(htl_device_t* Dev, uint32_t ParentInode, const char* Name, OW_FS_CATALOG_ENTRY* OutEntry);
OW_STATUS    OwFsCatalogInsert(htl_device_t* Dev, uint32_t ParentInode, const char* Name, uint32_t InodeNum, uint8_t Type);
OW_STATUS    OwFsBitmapAllocBlock(htl_device_t* Dev, uint32_t* OutBlockNum);
OW_STATUS    OwFsBitmapFreeBlock(htl_device_t* Dev, uint32_t BlockNum);
OW_STATUS    OwFsBlockRead(htl_device_t* Dev, uint32_t BlockNum, void* Buffer);
OW_STATUS    OwFsBlockWrite(htl_device_t* Dev, uint32_t BlockNum, const void* Buffer);
uint32_t     OwFsChecksumCalc(const void* Data, uint32_t Size);

#endif /* OW_VFS_H */
