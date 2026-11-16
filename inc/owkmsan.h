/* owkmsan.h - OWKMSan: memory-initialization tracking (Phase 3)
 *
 * Shadow-based tracking of which payload bytes of the kernel heap have been
 * initialized, over the kalloc arena.  One shadow byte per 8 payload bytes;
 * bit i of a shadow byte marks payload byte (8*group+i) as uninitialized.
 *
 * What it detects (when the master switch and the module are enabled):
 *   - reads of payload bytes that were never written (or were freed),
 *   - krealloc copies that propagate initialized data into uninitialized
 *     regions (shadow bookkeeping is propagated exactly),
 *
 * What it does NOT detect:
 *   - reads of uninitialized stack, statics, MMIO or non-heap globals (the
 *     shadow covers the kalloc arena only),
 *   - the moment of an out-of-bounds write (no shadow for statics),
 *   - correctness of caller-initiated writes that mark memory initialized
 *     (initialization is tracked, not proven).
 *
 * Shadow cost: KALLOC_HEAP_SIZE/8 = 1 MiB of static storage, plus the shadow
 * lookup on every tracked operation (single-digit cycles).
 */
#ifndef OW_KMSAN_H
#define OW_KMSAN_H

#include "owksan.h"

/* Register the OWKMSan module with the OWKSan core. */
OW_STATUS OwKMSanRegister(void);

/* Allocator hooks (called from lib/kalloc.c). */
void OwKMSanNoteAlloc(const void* Ptr, size_t Size);
void OwKMSanNoteInit(const void* Ptr, size_t Size);
void OwKMSanNoteCopy(void* Dst, const void* Src, size_t CopyBytes, size_t NewBytes);
void OwKMSanNoteFree(const void* Ptr, size_t Size);

/* Public check/mark APIs for kernel code. */
OW_STATUS OwKMSanCheckRead(const void* Ptr, size_t Size, const char* Label);
void      OwKMSanMarkInit(const void* Ptr, size_t Size);
void      OwKMSanMarkUninit(const void* Ptr, size_t Size);

/* Reset shadow state (module init and tests). */
void OwKMSanReset(void);

#endif /* OW_KMSAN_H */
