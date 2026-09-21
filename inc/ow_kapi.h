/* ow_kapi.h - Application-Facing Kernel API (kernel64) */
#ifndef OW_KAPI_H
#define OW_KAPI_H

#include "ow_types.h"

void*        BaseAllocateMemoryHeap(uint64_t Size);
OW_STATUS    BaseCreateFileRecord(const char* Name);
OW_STATUS    BaseWriteFileData(const char* Name, const char* Content);
uint32_t     BaseReadFileData(const char* Name, char* Buffer, uint32_t MaxSize);

#endif /* OW_KAPI_H */
