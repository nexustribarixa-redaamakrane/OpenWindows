/* ow_memory.h - Memory Manager (PML4 + VAD AVL Tree) */
#ifndef OW_MEMORY_H
#define OW_MEMORY_H

#include "ow_types.h"

#define OW_PAGE_SIZE            4096U
#define OW_PML4_ENTRY_COUNT     512U

typedef struct _OW_PML4_ENTRY {
    uint64_t Present         : 1;
    uint64_t ReadWrite       : 1;
    uint64_t UserSupervisor  : 1;
    uint64_t WriteThrough    : 1;
    uint64_t CacheDisable    : 1;
    uint64_t Accessed        : 1;
    uint64_t Reserved0       : 6;
    uint64_t PageFrameNumber : 40;
    uint64_t Reserved1       : 11;
    uint64_t NoExecute       : 1;
} OW_PML4_ENTRY;

typedef struct _OW_VAD_NODE {
    uint64_t                StartingAddress;
    uint64_t                EndingAddress;
    uint32_t                Protection;
    uint32_t                CommitCharge;
    struct _OW_VAD_NODE*    LeftChild;
    struct _OW_VAD_NODE*    RightChild;
    int32_t                 BalanceFactor;
} OW_VAD_NODE;

OW_STATUS    OwMemInitialize(void);
void*        OwMemAllocatePage(void);
OW_VAD_NODE* OwMemCreateVad(uint64_t Start, uint64_t End, uint32_t Protect);
void         OwMemFreeVad(OW_VAD_NODE* Node);
OW_STATUS    OwMemInsertVad(OW_VAD_NODE** Root, OW_VAD_NODE* Node);
void         OwMemWalkPml4(uint64_t VirtualAddress);
uint32_t     OwMemPagesUsed(void);
uint32_t     OwMemPagesTotal(void);

#endif /* OW_MEMORY_H */
