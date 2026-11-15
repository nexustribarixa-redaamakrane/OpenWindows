/* owkbounds.h - OWKBoundsSan: index/region/bounds diagnostics (Phase 2)
 *
 * Provides checked index, memory-region and copy primitives for kernel code.
 * These are honest, complete checks against the sizes the caller passes; they
 * do not instrument the compiler's own memory operations.
 *
 * What it detects:
 *   - an index past the declared element count,
 *   - an access span that does not fit its declared base+size,
 *   - a region whose arithmetic wraps,
 *   - a copy whose length exceeds the destination capacity.
 *
 * What it does NOT detect:
 *   - compiler-generated out-of-bounds writes (no -fsanitize=bounds here),
 *   - out-of-bounds reads/writes through raw pointers the caller never
 *     validates,
 *   - bounds validated against a capacity the caller misstates.
 */
#ifndef OW_BOUNDS_H
#define OW_BOUNDS_H

#include "owksan.h"

/* Register the OWKBoundsSan module with the OWKSan core. */
OW_STATUS OwKBoundsSanRegister(void);

/* Index-vs-count check.  Reports and returns OW_ERR_INVALID_PARAM on a hit. */
OW_STATUS OwKBoundsSanCheckIndex(const char* Label, uint32_t Index, uint32_t Count);

/* Access-span check: Access..Access+AccessSize must fit inside Base..Base+Size
 * without wrapping.  Either argument may be NULL with a matching zero size only
 * when the other span is also empty. */
OW_STATUS OwKBoundsSanCheckRegion(const char* Label,
                                  const void* Base, size_t Size,
                                  const void* Access, size_t AccessSize);

/* Capacity-checked copy.  On failure (length past capacity or wrapping) the
 * destination is left untouched.  Returns OW_SUCCESS on success. */
OW_STATUS OwKBoundsSanCopy(void* Dst, size_t DstCapacity,
                           const void* Src, size_t CopyBytes);

#endif /* OW_BOUNDS_H */
