/* ow_ed25519_test.h - host-build only access to Ed25519 internals
 *
 * The regression tests need to reach below ow_crypto_ed25519_verify(), because a
 * known-answer test at the top level can only report "signature rejected".  When
 * a signature test fails, the useful next question is which layer broke, and the
 * only way to answer it without a debugger is to test the layers directly:
 *
 *   - field add/sub/mul, which is where a bad carry or a bad borrow shows up
 *   - scalar reduction mod L, where the exact-equality case is easy to get wrong
 *   - point decompression, canonicality and the group law
 *   - the derived constants, including sqrt(-1) and the base point
 *
 * Every symbol below is defined only when OW_HOST_HAL is set, so none of this is
 * reachable from a kernel build.  ow_crypto_ed25519_verify() remains the only
 * supported entry point for anything that is not a test.
 *
 * The arithmetic is exposed in its own representation -- 16 little-endian radix
 * 2^16 limbs -- rather than as opaque integers, because the tests compare
 * byte encodings.  ow_ed_test_field_encode()/ow_ed_test_field_decode() convert,
 * and the field tests round-trip through them, so a test failure about an
 * encoding points at the encoding helper rather than at the arithmetic. */
#ifndef OW_ED25519_TEST_H
#define OW_ED25519_TEST_H

#ifdef OW_HOST_HAL

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- field arithmetic, radix 2^16, 16 little-endian limbs ----------------- */

typedef uint16_t ow_ed_test_fe[16];

void ow_ed_test_fe_zero(ow_ed_test_fe r);
void ow_ed_test_fe_one(ow_ed_test_fe r);
void ow_ed_test_fe_copy(ow_ed_test_fe r, const ow_ed_test_fe a);
void ow_ed_test_fe_add(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const ow_ed_test_fe b);
void ow_ed_test_fe_sub(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const ow_ed_test_fe b);
void ow_ed_test_fe_mul(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const ow_ed_test_fe b);
void ow_ed_test_fe_sq(ow_ed_test_fe r, const ow_ed_test_fe a);
bool ow_ed_test_fe_equal(const ow_ed_test_fe a, const ow_ed_test_fe b);
bool ow_ed_test_fe_is_zero(const ow_ed_test_fe a);

/* Load 32 little-endian bytes.  Accepts any 32-byte pattern, including y >= p
 * and other non-canonical values; that is deliberate, because the canonicality
 * rule has to be able to reject such a value and the tests need to build one. */
void ow_ed_test_fe_decode(ow_ed_test_fe r, const uint8_t s[32]);

/* Serialize 32 little-endian bytes.  This does NOT reduce, matching RFC 8032's
 * requirement that a canonical encoding be exactly the reduced value; the
 * canonicality tests depend on that distinction. */
void ow_ed_test_fe_encode(uint8_t s[32], const ow_ed_test_fe a);

/* Reduce fully into [0, p).  Exposed because a partial reduction is exactly the
 * failure mode of fe_reduce, and a caller must be able to ask for the full one. */
void ow_ed_test_fe_reduce(ow_ed_test_fe r, const ow_ed_test_fe a);

bool ow_ed_test_fe_is_negative(const ow_ed_test_fe a);

/* Raise to a 256-bit big-endian exponent by square-and-multiply.  Exposed
 * because fe_pow's exponent byte order is invisible to every other test: a
 * little-endian exponent still yields a field element, just the wrong one, and
 * the only symptom is that inversions do not invert anything.  Inverse-4 is
 * checked directly. */
void ow_ed_test_fe_pow(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const uint8_t exp_be[32]);

/* Inverse of a nonzero field element, i.e. a^(p-2).  False for zero, which has
 * no inverse; the callers here must not paper over that. */
bool ow_ed_test_fe_invert(ow_ed_test_fe r, const ow_ed_test_fe a);

/* ---- scalar arithmetic mod L -------------------------------------------- */

/* Reduce a 64-byte little-endian scalar mod L.  L itself must reduce to 0. */
void ow_ed_test_sc_reduce(uint8_t out[32], const uint8_t in[64]);

/* True when the 32-byte little-endian scalar is already canonical (S < L). */
bool ow_ed_test_sc_is_canonical(const uint8_t s[32]);

/* ---- group ---------------------------------------------------------------- */

/* Decompress a 32-byte point encoding.  False for a non-canonical y, a y with
 * no x, or x == 0 with the sign bit set.  Small-order points DO decode: they
 * are valid curve points, and that is the whole reason the cofactorless
 * verification caveat in ow_ed25519.h exists. */
bool ow_ed_test_point_decode(const uint8_t s[32]);

/* Encode a decompressed point back to its 32-byte form.  False if the point did
 * not decode. */
bool ow_ed_test_point_encode(uint8_t out[32], const uint8_t s[32]);

/* Point arithmetic on compressed encodings, so the tests never handle
 * projective coordinates directly.  They are only equal up to a common factor,
 * which is an easy way to write a test that passes for the wrong reason. */
bool ow_ed_test_point_add(uint8_t out[32], const uint8_t a[32],
                          const uint8_t b[32]);
bool ow_ed_test_point_double(uint8_t out[32], const uint8_t a[32]);
bool ow_ed_test_point_mul(uint8_t out[32], const uint8_t scalar[32],
                          const uint8_t point[32]);
bool ow_ed_test_point_mul_base(uint8_t out[32], const uint8_t scalar[32]);

/* True when the two encodings name the same point, compared as encodings. */
bool ow_ed_test_point_equal(const uint8_t a[32], const uint8_t b[32]);

/* ---- derived constants ---------------------------------------------------- */

/* The identity, i.e. y = 1 with x = 0.  Every group test that multiplies by L
 * is checking against this, so it is exposed rather than spelled out again. */
void ow_ed_test_point_identity(uint8_t out[32]);

/* Group order L as 32 little-endian bytes. */
void ow_ed_test_scalar_order_L(uint8_t out[32]);

/* p - 2 as 32 little-endian bytes.  Encoding a point needs a^(p-2); the base
 * point's T coordinate depends on it, so the tests check the constant rather
 * than trust it. */
void ow_ed_test_field_p_minus_2(uint8_t out[32]);

#endif /* OW_HOST_HAL */

#endif /* OW_ED25519_TEST_H */