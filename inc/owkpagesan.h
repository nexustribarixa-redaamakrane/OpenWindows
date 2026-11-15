/* owkpagesan.h - OWKPageSan: physical/virtual page-management diagnostics (Phase 2)
 *
 * Validates the OpenWindows page-management layer from the outside, with no
 * CPU-dependent state:
 *
 *   - Raw leaf page-table entry structural validation (x86-64, LA48): the
 *     physical-address bit range must not carry reserved bits, the level and
 *     page-size bit must cohere, and a huge-page frame base must be aligned
 *     to its page size.
 *   - Frame-range validation against the real frame arena (alignment, arena
 *     membership, no overlap with the non-RAM holes the allocator skips).
 *   - Frame-allocator invariant audit (used <= total, committed <= limit).
 *
 * What it does NOT detect:
 *   - CPU walk faults (kSAN has no page walker here);
 *   - page-table sharing or aliasing mistakes between address spaces (no CR3
 *     is visible from this module);
 *   - frames that the bump arena skipped over non-RAM holes: the audit checks
 *     what the arena hands out, not the skip decision itself;
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

/* Architectural leaf address masks (physical address bits [51:12], [51:21],
 * [51:30] respectively, with the level's PS bit set/cleared semantics). */

typedef struct _OW_PAGESAN_REPORT {
    uint32_t Errors;
    uint64_t ArenaBytes;
    uint32_t TotalPages;
    uint32_t UsedPages;
    uint32_t CommitTotal;
    uint32_t CommitLimit;
} OW_PAGESAN_REPORT;

/* Register the OWKPageSan module with the OWKSan core. */
OW_STATUS OwKPageSanRegister(void);

/* Validate a raw leaf page-table entry.
 * Level is one of OW_PAGESAN_LEVEL_PT / PD / PDPTE.  A non-present entry is
 * reported OK (nothing to validate).  Returns OW_SUCCESS when the entry is
 * structurally sound, OW_ERR_CORRUPT otherwise; findings also flow through
 * the OWKSan core with module name "OWKPageSan". */
OW_STATUS OwKPageSanCheckPte(uint64_t Entry, uint32_t Level);

/* Validate a frame range against the frame arena: alignment, no wraparound,
 * fully inside the arena, and no overlap with a non-RAM window.
 * Returns OW_SUCCESS / OW_ERR_INVALID_PARAM / OW_ERR_CORRUPT. */
OW_STATUS OwKPageSanCheckFrameRange(uint64_t Base, uint32_t Pages);

/* Audit the frame allocator's public invariants: arena within bounds, used
 * pages not exceeding the pool, committed charge within the ceiling.
 * Fills Out; returns OW_SUCCESS, OW_ERR_INVALID_PARAM or OW_ERR_CORRUPT. */
OW_STATUS OwKPageSanAudit(OW_PAGESAN_REPORT* Out);

#endif /* OW_PAGESAN_H */
