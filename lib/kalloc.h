/* kalloc.h - Fixed-Pool Kernel Allocator Interface (free-list + canaries) */
#ifndef KALLOC_H
#define KALLOC_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

/* Arena entry layout, shared by the allocator and the OWKHeapSan module.
 *
 * Each block carries a 16-byte header (requested size, then a tag word), the
 * payload (8-byte aligned) and a 16-byte trailing redzone of 0xA5 bytes:
 *
 *   [size(8)][tag(8)][payload ... aligned to 8][redzone 16 x 0xA5]
 *
 * A live block's tag is KALLOC_MAGIC_LIVE; when freed, the tag becomes
 * KALLOC_MAGIC_FREE and the payload's first 8 bytes hold the free-list link.
 * The walk advance is deterministic from the requested size alone:
 *   KALLOC_HEADER_SIZE + align8(size) + KALLOC_REDZONE */
#define KALLOC_ALIGN        8u
#define KALLOC_HEADER_SIZE  16u
#define KALLOC_REDZONE      16u
#define KALLOC_REDZONE_BYTE 0xA5u
#define KALLOC_POISON_BYTE  0xDDu
#define KALLOC_MAGIC_LIVE   0x4B41554543384C31ull /* arbitrary live tag */
#define KALLOC_MAGIC_FREE   0x4B41554543384C32ull /* arbitrary freed tag */
#define KALLOC_MIN_BLOCK    (KALLOC_HEADER_SIZE + KALLOC_REDZONE + KALLOC_ALIGN)
#define KALLOC_HEAP_SIZE    (8U * 1024U * 1024U)

void    kalloc_init(void);
void*   kalloc(size_t size);
void*   kcalloc(size_t count, size_t size);
void*   krealloc(void* ptr, size_t size);
void    kfree(void* ptr);
size_t  kalloc_used(void);

/* Free-verdict reported to the OWKHeapSan module. */
#define KALLOC_FREE_OK      0u
#define KALLOC_FREE_FOREIGN 1u
#define KALLOC_FREE_DOUBLE  2u

/* Base address of the arena (for shadow mappings in OWKMSan). */
uintptr_t OwKAllocArenaBase(void);

/* Read-only hooks consumed by the OWKHeapSan module (Phase 2).
 *
 * OwKAllocWalk walks the arena's block chain in [0, used) and invokes Callback
 * for every intact block.  Callback receives the block base, the requested
 * size, the payload pointer and the header tag word; returning zero stops the
 * walk early.  Returns the number of blocks visited.
 *
 * OwKAllocContains reports whether Ptr lies inside the committed part of the
 * arena.
 *
 * OwKAllocBlockFind returns the arena block base whose payload starts at
 * Payload, or NULL.  OwKAllocQuarantineCount/At expose a snapshot of the
 * quarantine so the auditor can verify poison integrity.
 * OwKAllocQuarantineLimit/SetLimit expose the runtime quarantine depth knob. */
uint32_t OwKAllocWalk(int (*Callback)(const void* Block, size_t Size,
                                      const void* Payload, uint64_t Magic,
                                      void* Ctx),
                      void* Ctx);
bool     OwKAllocContains(const void* Ptr);
const void* OwKAllocBlockFind(const void* Payload);
uint32_t OwKAllocQuarantineCount(void);
const void* OwKAllocQuarantineAt(uint32_t Index);
uint32_t OwKAllocQuarantineLimit(void);
uint32_t OwKAllocQuarantineSetLimit(uint32_t Limit);

#endif /* KALLOC_H */
