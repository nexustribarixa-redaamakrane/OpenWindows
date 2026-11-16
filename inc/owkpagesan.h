/* owkpagesan.h - OWKPageSan: physical/virtual page-management diagnostics (Phase 2)
 *
 * Validates the OpenWindows page-management layer from the outside, with no
 * CPU-dependent state:
 *
 *   - Raw leaf page-table entry structural validation (x86-64, LA48): the
 *     physical-address bit range must not carry reserved bits, the level and
 *     page-size bit must cohere, and a huge-page frame base must be aligned
 *     to its page size.
 *   - Frame-range validation against every arena registered through the
 *     frame-arena registry (alignment, arena membership, no wrap, no overlap
 *     with the non-RAM holes the allocator skips).  Any future arena backing
 *     is validated the moment it registers; the audit knows nothing about the
 *     16 MiB static pool's internals beyond what registration publishes.
 *   - Frame-allocator invariant audit over the registered arenas
 *     (used <= extent, committed <= ceiling, arena alignment).
 *
 * What it does NOT detect:
 *   - CPU walk faults (this module performs no page-table walk);
 *   - page-table sharing or aliasing mistakes between address spaces (no CR3
 *     is visible from this module);
 *   - defects of an arena that never registered itself;
 *   - any virtual-address translation correctness (host builds have no page
 *     tables at all).
 */
#ifndef OW_PAGESAN_H
#define OW_PAGESAN_H

#include "owksan.h"

/* OW_PAGESAN_LEVEL_PT / PD / PDPTE: the level of the entry being validated.
 * For a non-huge entry the level decides the page size (4K/2M/1G). */
#define OW_PAGESAN_LEVEL_PT    1U
#define OW_PAGESAN_LEVEL_PD    2U
#define OW_PAGESAN_LEVEL_PDPTE 3U

typedef struct _OW_PAGESAN_REPORT {
    uint64_t ArenaBytes;    /* sum of extents across the registered arenas  */
    uint32_t ArenaCount;    /* number of registered arenas                  */
    uint32_t TotalPages;    /* total pages across the registered arenas     */
    uint32_t UsedPages;     /* committed pages across the registered arenas */
    uint32_t CommitTotal;
    uint32_t CommitLimit;
    uint32_t Errors;
} OW_PAGESAN_REPORT;

/* Register the OWKPageSan module with the OWKSan core. */
OW_STATUS OwKPageSanRegister(void);

/* Validate a raw leaf page-table entry.
 * Level is one of OW_PAGESAN_LEVEL_PT / PD / PDPTE.  A non-present entry is
 * reported OK (nothing to validate).  Returns OW_SUCCESS when the entry is
 * structurally sound, OW_ERR_CORRUPT otherwise; findings also flow through
 * the OWKSan core with module name "OWKPageSan". */
OW_STATUS OwKPageSanCheckPte(uint64_t Entry, uint32_t Level);

/* Validate a frame range against the registered arenas: alignment, no
 * wraparound, fully inside one registered arena, and no overlap with a
 * non-RAM window.  Returns OW_SUCCESS / OW_ERR_INVALID_PARAM / OW_ERR_CORRUPT
 * (OW_ERR_NOT_INITIALIZED when no arena has registered). */
OW_STATUS OwKPageSanCheckFrameRange(uint64_t Base, uint32_t Pages);

/* Audit every registered arena's public invariants: base alignment, used
 * pages not exceeding the extent, committed charge within the ceiling.
 * Returns OW_SUCCESS, OW_ERR_INVALID_PARAM, OW_ERR_NOT_INITIALIZED or
 * OW_ERR_CORRUPT. */
OW_STATUS OwKPageSanAudit(OW_PAGESAN_REPORT* Out);

#endif /* OW_PAGESAN_H */
