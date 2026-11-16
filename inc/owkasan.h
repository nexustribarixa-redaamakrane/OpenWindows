/* owkasan.h - OWKAsan: address-access validation (Phase 3)
 *
 * ASan-style, allocator-integrated validation for the kernel heap.  Built on
 * the free-list allocator's metadata (block magic tags, trailing redzones,
 * poison-on-free, bounded quarantine), it validates address accesses at API
 * boundaries and audits the arena for metadata and redzone integrity.
 *
 * What it detects (when the master switch and the module are enabled):
 *   - reads/writes of live-heap memory that was actually freed (use-after-free
 *     at call sites that use the checked APIs),
 *   - trailing buffer overflows that corrupt the redzone canary (at audit
 *     time),
 *   - freed blocks whose payload was modified after free (quarantine poison
 *     verification, at audit time),
 *   - allocation-metadata corruption: block magic tag, chain packing
 *     (delegated to the OWKHeapSan audit path),
 *   - out-of-arena pointer frees (reported via the allocator hook verdict).
 *
 * What it does NOT detect:
 *   - arbitrary out-of-bounds loads/stores that bypass the checked APIs (no
 *     compiler instrumentation exists in this kernel),
 *   - use-after-free through raw pointers that never call the checked APIs,
 *   - overflow of heap blocks whose redzone was already corrupted before the
 *     audit runs (audit is periodic, not per-access),
 *   - stack/global buffer overflows (no redzones exist for those),
 *   - it is NOT ASan-compatible and does not intercept compiler code.
 */
#ifndef OW_KASAN_H
#define OW_KASAN_H

#include "owksan.h"

typedef struct _OW_KASAN_REPORT {
    uint64_t BytesWalked;
    uint32_t Blocks;
    uint32_t LiveBlocks;
    uint32_t FreeBlocks;
    uint32_t QuarantinedBlocks;
    uint32_t Errors;
    uint32_t QuarantinedBytes;
} OW_KASAN_REPORT;

/* Register the OWKAsan module with the OWKSan core. */
OW_STATUS OwKAsanRegister(void);

/* Access checks for kernel call sites.  Heap pointers are validated against
 * the live-block metadata; pointers outside the heap are not this module's
 * business and pass. */
OW_STATUS OwKAsanCheckRead(const void* Ptr, size_t Size, const char* Label);
OW_STATUS OwKAsanCheckWrite(const void* Ptr, size_t Size, const char* Label);

/* Audit the arena and the quarantine: block magic, redzone canaries, freed-
 * payload poison integrity.  Findings flow through the OWKSan core and are
 * counted in Out. */
OW_STATUS OwKAsanAudit(OW_KASAN_REPORT* Out);

/* Quarantine introspection. */
uint32_t OwKAsanQuarantineBlocks(void);

#endif /* OW_KASAN_H */
