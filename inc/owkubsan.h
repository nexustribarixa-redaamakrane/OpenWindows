/* owkubsan.h - OWKUbSan: undefined-behavior detection (Phase 4)
 *
 * Deliberately implements a specific, documented set of UB checks.  It is not
 * a drop-in UBSan and it does not instrument the compiler's output.
 *
 * IMPLEMENTED (all validated with host-side negative tests):
 *   - Invalid shifts: shift count >= bit width (integer shift UB).
 *   - Signed integer overflow: add, subtract, multiply (via compiler
 *     intrinsics, no library calls).
 *   - Division by zero; INT64_MIN / -1 (and INT64_MIN % -1) wraparound.
 *   - Misaligned pointer access (address not a multiple of the required
 *     alignment; alignment must itself be a power of two).
 *   - Enum value outside its declared range.
 *   - Null pointer where a non-null pointer is required.
 *
 * NOT IMPLEMENTED (documented, not silently faked):
 *   - Invalid enum casts across types (no type system to consult at runtime),
 *   - vla-size / alignment assumptions introduced by the compiler (no
 *     instrumentation exists in this kernel),
 *   - signed-unsigned comparison UB, object lifetime / type punning UB,
 *     strict-aliasing violations, unsequenced side effects,
 *   - anything triggered by arbitrary generated code; these are checked call
 *     sites only.
 *
 * Every check reports through the OWKSan core (module "OWKUbSan") subject to
 * the master/module switches and returns OW_STATUS.
 */
#ifndef OW_KUB_SAN_H
#define OW_KUB_SAN_H

#include "owksan.h"

OW_STATUS OwKUbSanRegister(void);

OW_STATUS OwKUbSanShiftLeft(uint64_t Value, uint64_t Shift, uint32_t Width);
OW_STATUS OwKUbSanShiftRight(uint64_t Value, uint64_t Shift, uint32_t Width);

OW_STATUS OwKUbSanSignedAdd(int64_t A, int64_t B, int64_t* Out);
OW_STATUS OwKUbSanSignedSub(int64_t A, int64_t B, int64_t* Out);
OW_STATUS OwKUbSanSignedMul(int64_t A, int64_t B, int64_t* Out);

OW_STATUS OwKUbSanDiv(int64_t Dividend, int64_t Divisor, int64_t* OutQuotient);
OW_STATUS OwKUbSanMod(int64_t Dividend, int64_t Divisor, int64_t* OutRemainder);

OW_STATUS OwKUbSanAlign(const void* Ptr, uint64_t Alignment);
OW_STATUS OwKUbSanEnum(int64_t Value, int64_t Min, int64_t Max);
OW_STATUS OwKUbSanNull(const void* Ptr);

#endif /* OW_KUB_SAN_H */
