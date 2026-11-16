/* owkheapsan.h - OWKHeapSan: kernel heap integrity diagnostics (Phase 2+)
 *
 * Validates OpenWindows' kernel heap (the free-list allocator in lib/kalloc.c,
 * with per-block magic tags, trailing redzone canaries and poison-on-free).
 *
 * What it detects:
 *   - arena header-chain inconsistencies: walk length mismatch, zero-sized
 *     headers, non-packed chain,
 *   - payload misalignment,
 *   - redzone canary corruption (trailing overflow past the payload),
 *   - header magic corruption (leading overflow, header smash),
 *   - kfree() of a pointer outside the arena,
 *   - kfree() of an already-freed block (double free).
 *
 * What it does NOT detect:
 *   - payload-content corruption that leaves the redzone and header intact,
 *   - arbitrary out-of-bounds writes that land inside a live block (no
 *     shadow, no per-access checking at arbitrary call sites),
 *   - use-after-free reads/writes that never call the allocator or the
 *     checked access APIs (see OWKAsan for the checked-API surface),
 *   - leaks (every block is live until kfree; nothing tracks reachability).
 */
#ifndef OW_KHEAPSAN_H
#define OW_KHEAPSAN_H

#include "owksan.h"

typedef struct _OW_KHEAPSAN_REPORT {
    uint64_t BytesWalked;   /* bytes the header walk accounted for        */
    uint32_t Blocks;        /* intact blocks found on the walk            */
    uint32_t LiveBlocks;    /* blocks whose tag is KALLOC_MAGIC_LIVE      */
    uint32_t FreeBlocks;    /* blocks whose tag is KALLOC_MAGIC_FREE      */
    uint32_t Errors;        /* consistency violations found                */
    uint32_t ForeignFrees;  /* frees outside the arena                    */
    uint32_t DoubleFrees;   /* frees of an already-freed block            */
} OW_KHEAPSAN_REPORT;

/* Register the OWKHeapSan module with the OWKSan core. */
OW_STATUS OwKHeapSanRegister(void);

/* Walk the committed arena and validate every block header and redzone
 * canary.  Findings are reported through the OWKSan core (subject to its
 * master/module switches) and counted in Out. */
OW_STATUS OwKHeapSanAuditArena(OW_KHEAPSAN_REPORT* Out);

/* True when Ptr is the live payload base of a block on the arena walk. */
bool OwKHeapSanValidateBlock(const void* Ptr);

/* True when Ptr is a live (not freed) allocation. */
bool OwKHeapSanIsTracked(const void* Ptr);

/* Reset module counters (module init and tests). */
void OwKHeapSanReset(void);

/* Allocator hook (called from lib/kalloc.c). */
void OwKHeapSanNoteFree(const void* Ptr, uint32_t Verdict);

uint32_t OwKHeapSanLiveCount(void);

#endif /* OW_KHEAPSAN_H */
