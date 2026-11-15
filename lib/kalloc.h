/* kalloc.h - Fixed-Pool Kernel Allocator Interface */
#ifndef KALLOC_H
#define KALLOC_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Arena entry layout, shared by the allocator and the OWKHeapSan module. */
#define KALLOC_ALIGN       8u
#define KALLOC_HEADER_SIZE KALLOC_ALIGN

void    kalloc_init(void);
void*   kalloc(size_t size);
void*   kcalloc(size_t count, size_t size);
void*   krealloc(void* ptr, size_t size);
void    kfree(void* ptr);
size_t  kalloc_used(void);

/* Read-only hooks consumed by the OWKHeapSan module (Phase 2).
 *
 * OwKAllocWalk walks the packed header chain in [0, g_used) and invokes
 * Callback for every intact block.  The callback receives the block base, the
 * requested size and the payload pointer.  Returning zero stops the walk early
 * (used when a caller has already seen what it needs).  Returns the number of
 * blocks visited.
 *
 * OwKAllocContains reports whether Ptr lies inside the committed part of the
 * arena. */
uint32_t OwKAllocWalk(int (*Callback)(const void* Block, size_t Size,
                                      const void* Payload, void* Ctx),
                      void* Ctx);
bool     OwKAllocContains(const void* Ptr);

#endif /* KALLOC_H */
