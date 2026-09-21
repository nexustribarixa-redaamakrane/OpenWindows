/* kalloc.h - Fixed-Pool Kernel Allocator Interface */
#ifndef KALLOC_H
#define KALLOC_H

#include <stddef.h>

void    kalloc_init(void);
void*   kalloc(size_t size);
void*   kcalloc(size_t count, size_t size);
void*   krealloc(void* ptr, size_t size);
void    kfree(void* ptr);
size_t  kalloc_used(void);

#endif /* KALLOC_H */
