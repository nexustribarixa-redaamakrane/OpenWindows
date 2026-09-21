/* kernel64.c - Application-Facing Kernel API */
#include "../inc/ow_kapi.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_string.h"
#include "../inc/ow_syscall.h"

void *BaseAllocateMemoryHeap(uint64_t Size) {
  ow_kprintf("[KAPI] Heap alloc request -> Ring 0\r\n");
  return OwApiAllocateMemory(Size);
}

OW_STATUS BaseCreateFileRecord(const char *Name) {
  ow_kprintf("[KAPI] Create '%s' -> VFS\r\n", Name);
  return OwApiCreateFile(Name, 0);
}

OW_STATUS BaseWriteFileData(const char *Name, const char *Content) {
  ow_kprintf("[KAPI] Write '%s' -> VFS\r\n", Name);
  return OwApiWriteFile(Name, (const uint8_t *)Content,
                        (uint32_t)ow_strlen(Content));
}

uint32_t BaseReadFileData(const char *Name, char *Buffer, uint32_t MaxSize) {
  return OwApiReadFile(Name, (uint8_t *)Buffer, MaxSize);
}
