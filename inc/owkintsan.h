/* owkintsan.h - OWKIntSan: integer overflow / arithmetic diagnostics (Phase 4)
 *
 * Overflow-checked arithmetic, prioritizing allocation sizes, pointer offsets
 * and memory-region calculations.  Every function reports through the OWKSan
 * core (module "OWKIntSan") and returns OW_STATUS.
 *
 * IMPLEMENTED (all validated with host-side negative tests):
 *   - add, subtract, multiply on 64-bit unsigned values,
 *   - allocation-size calculation: Count * Size with overflow check,
 *   - pointer offset calculation: Base + Offset with wraparound check,
 *   - scaled index calculation: Base + Index * Scale, both steps checked,
 *   - region span calculation: Base + Size with wraparound check.
 *
 * NOT IMPLEMENTED:
 *   - signed arithmetic (use OWKUbSanSignedAdd/Sub/Mul),
 *   - checked float/double arithmetic (not used by the kernel),
 *   - compiler-inserted arithmetic checks (no instrumentation exists in this
 *     kernel; these are call sites).
 */
#ifndef OW_KINT_SAN_H
#define OW_KINT_SAN_H

#include "owksan.h"

OW_STATUS OwKIntSanRegister(void);

OW_STATUS OwKIntSanAdd(uint64_t A, uint64_t B, uint64_t* Out);
OW_STATUS OwKIntSanSub(uint64_t A, uint64_t B, uint64_t* Out);
OW_STATUS OwKIntSanMul(uint64_t A, uint64_t B, uint64_t* Out);

OW_STATUS OwKIntSanAllocSize(uint64_t Count, uint64_t Size, uint64_t* Out);
OW_STATUS OwKIntSanPointerOffset(uint64_t Base, uint64_t Offset, uint64_t* Out);
OW_STATUS OwKIntSanAddScaled(uint64_t Base, uint64_t Index, uint64_t Scale,
                             uint64_t* Out);
OW_STATUS OwKIntSanRangeSpan(uint64_t Base, uint64_t Size, uint64_t* OutEnd);

#endif /* OW_KINT_SAN_H */
