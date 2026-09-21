/* ow_mem.h - Freestanding Memory Operations */
#ifndef OW_MEM_H
#define OW_MEM_H

#include <stdint.h>
#include <stddef.h>

void*       ow_memcpy(void* dst, const void* src, size_t n);
void*       ow_memset(void* dst, int val, size_t n);
int         ow_memcmp(const void* a, const void* b, size_t n);

#endif /* OW_MEM_H */
