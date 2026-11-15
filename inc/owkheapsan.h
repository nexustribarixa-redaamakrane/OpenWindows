/* owkheapsan.h - OWKHeapSan: kernel heap integrity diagnostics (Phase 2)
 *
 * Validates the OpenWindows kernel heap (the fixed-pool bump allocator in
 * lib/kalloc.c): header-chain consistency, payload alignment, accounting
 * invariants, and note-alloc/note-free pairing from the allocator's hooks.
 *
 * What it DOES detect:
 *   - arena header-chain inconsistencies (non-packed chain, payload overflow,
 *     bad sizes),
 *   - payload alignment violations,
 *   - usage accounting that does not match the physical arena pointer,
 *   - kfree() of a pointer that lies outside the kernel arena,
 *   - kfree() of an allocation that was never tracked (bounded registry).
 *
 * What it does NOT detect (do not claim otherwise):
 *   - use-after-free: the allocator is a bump arena and never reuses memory, so
 *     a UAF is indistinguishable from a live allocation without allocator
 *     changes;
 *   - corruption of the payload contents (no canaries are written by kalloc);
 *   - out-of-bounds writes within the arena slack;
 *   - double-free of allocations that overflowed the bounded registry.
 */
#ifndef OW_KHEAPSAN_H
#define OW_KHEAPSAN_H

#include "owksan.h"

#define OW_KHEAPSAN_REGISTRY_MAX 256U

typedef struct _OW_KHEAPSAN_REPORT {
    uint64_t BytesWalked;   /* bytes the header walk accounted for        */
    uint32_t Blocks;        /* intact blocks found on the walk            */
    uint32_t Errors;        /* consistency violations found                */
    uint32_t ForeignFrees;  /* kfree() of pointers outside the arena      */
    uint32_t UntrackedFrees;/* kfree() of never-tracked allocations       */
    uint32_t DoubleFrees;   /* kfree() of an already-freed tracked block  */
} OW_KHEAPSAN_REPORT;

/* Register the OWKHeapSan module with the OWKSan core.  Idempotent-friendly: a
 * second call returns OW_ERR_ALREADY_EXISTS. */
OW_STATUS OwKHeapSanRegister(void);

/* Walk the committed arena and validate every block header.  Findings are
 * reported through the OWKSan core (subject to its master/module switches) and
 * counted in Out.  Returns OW_SUCCESS when the walk completed (findings are in
 * Out->Errors), OW_ERR_NOT_INITIALIZED when the module is not registered, and
 * OW_ERR_INVALID_PARAM when Out is NULL. */
OW_STATUS OwKHeapSanAuditArena(OW_KHEAPSAN_REPORT* Out);

/* True when Ptr is the payload base of a live, packed block on the arena walk. */
bool OwKHeapSanValidateBlock(const void* Ptr);

/* True when Ptr is currently tracked as an allocation. */
bool OwKHeapSanIsTracked(const void* Ptr);

/* Allocator hooks (called from lib/kalloc.c). */
void OwKHeapSanNoteAlloc(const void* Ptr, size_t Size);
void OwKHeapSanNoteFree(const void* Ptr);

/* Reset the live-allocation registry (used by module init and by tests). */
void OwKHeapSanRegistryReset(void);

uint32_t OwKHeapSanTrackedCount(void);

#endif /* OW_KHEAPSAN_H */
