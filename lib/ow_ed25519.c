/* ow_ed25519.c - Ed25519 signature verification (RFC 8032)
 *
 * Field arithmetic over GF(2^255 - 19) in radix 2^16 with 16 limbs, group
 * arithmetic in extended twisted-Edwards coordinates.  Schoolbook 16x16
 * multiplication and square-and-multiply exponentiation: verification runs a
 * couple of times per image load, so a fast representation would buy nothing,
 * while arithmetic that can be read against the RFC buys a great deal.
 *
 * Every constant here was generated numerically -- d, 2d, sqrt(-1), the base
 * point, (p-5)/8 and L -- rather than transcribed from another implementation,
 * so a transcription slip cannot survive into a build that reports "verified".
 * tools/cis_sign.py derives the same curve independently and shares no code
 * with this file; the two agreeing on real signatures is part of the test
 * matrix, because mutual agreement between separate derivations is evidence
 * that neither is merely self-consistent.
 *
 * The one genuinely subtle point in this file is in fe_sub(), and it is worth
 * stating up front because getting it wrong yields plausible-looking garbage:
 *
 *   16 limbs of 16 bits span 2^256, and 2^256 is NOT congruent to 0 mod p.  So
 *   the wrapped two's-complement-looking result of a limb-wise subtraction does
 *   not represent (a - b) mod p, and adding p back to it cannot repair it.  On
 *   underflow the only correct move is to compute the magnitude (b - a) and
 *   return p - (b - a).
 *
 * Timing: every input to this file is public data -- a public key, a signature
 * and a manifest -- and the target never holds a signing key, so this code is
 * not written to be constant-time with respect to any secret and does not need
 * to be.  See ow_ed25519.h for the cofactor caveat and why it does not apply
 * to CIS.
 *
 * C99 freestanding: no dynamic allocation, no floating point, no compiler
 * extensions. */

#include "../inc/ow_ed25519.h"
#include "../inc/ow_sha512.h"

typedef struct {
    uint32_t v[16];
} fe;

/* A point in extended twisted-Edwards coordinates: x = X/Z, y = Y/Z, xy = T/Z.
 * Extended form because the addition formula needs T, and computing it on the
 * fly would cost a field inversion per step. */
typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge;

#define FE_ZERO_INIT { { 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, \
                        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U } }

/* d = -121665/121666 mod p */
static const fe fe_d = { {
    0x78A3U, 0x1359U, 0x4DCAU, 0x75EBU,
    0xD8ABU, 0x4141U, 0x0A4DU, 0x0070U,
    0xE898U, 0x7779U, 0x4079U, 0x8CC7U,
    0xFE73U, 0x2B6FU, 0x6CEEU, 0x5203U
} };

/* 2d, used by the extended addition formula. */
static const fe fe_d2 = { {
    0xF159U, 0x26B2U, 0x9B94U, 0xEBD6U,
    0xB156U, 0x8283U, 0x149AU, 0x00E0U,
    0xD130U, 0xEEF3U, 0x80F2U, 0x198EU,
    0xFCE7U, 0x56DFU, 0xD9DCU, 0x2406U
} };

/* sqrt(-1) mod p: the factor that reaches the other square root. */
static const fe fe_sqrtm1 = { {
    0xA0B0U, 0x4A0EU, 0x1B27U, 0xC4EEU,
    0xE478U, 0xAD2FU, 0x1806U, 0x2F43U,
    0xD7A7U, 0x3DFBU, 0x0099U, 0x2B4DU,
    0xDF0BU, 0x4FC1U, 0x2480U, 0x2B83U
} };

/* Base point B = (Bx, By), plus T = Bx*By for its extended representation. */
static const fe fe_by = { {
    0x6658U, 0x6666U, 0x6666U, 0x6666U,
    0x6666U, 0x6666U, 0x6666U, 0x6666U,
    0x6666U, 0x6666U, 0x6666U, 0x6666U,
    0x6666U, 0x6666U, 0x6666U, 0x6666U
} };

static const fe fe_bx = { {
    0xD51AU, 0x8F25U, 0x2D60U, 0xC956U,
    0xA7B2U, 0x9525U, 0xC760U, 0x692CU,
    0xDC5CU, 0xFDD6U, 0xE231U, 0xC0A4U,
    0x53FEU, 0xCD6EU, 0x36D3U, 0x2169U
} };

static const fe fe_bt = { {
    0xDDA3U, 0xA5B7U, 0x8AB3U, 0x6DDEU,
    0x52F5U, 0x7751U, 0x9F80U, 0x20F0U,
    0xE37DU, 0x64ABU, 0x4E8EU, 0x66EAU,
    0x7665U, 0xD78BU, 0x5F0FU, 0x6787U
} };

/* p = 2^255 - 19 */
static const fe fe_p = { {
    0xFFEDU, 0xFFFFU, 0xFFFFU, 0xFFFFU,
    0xFFFFU, 0xFFFFU, 0xFFFFU, 0xFFFFU,
    0xFFFFU, 0xFFFFU, 0xFFFFU, 0xFFFFU,
    0xFFFFU, 0xFFFFU, 0xFFFFU, 0x7FFFU
} };

/* (p - 5) / 8, big-endian, for square root recovery. */
static const uint8_t fe_exp_sqrt_m5[32] = {
    0x0FU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFDU
};

/* The group order L = 2^252 + 27742317777372353535851937790883648493, as
 * radix-2^16 little-endian limbs. */
#define OW_L_LIMBS 16
static const uint32_t fe_L[OW_L_LIMBS] = {
    0xD3EDU, 0x5CF5U, 0x631AU, 0x5812U, 0x9CD6U, 0xA2F7U, 0xF9DEU, 0x14DEU,
    0x0000U, 0x0000U, 0x0000U, 0x0000U, 0x0000U, 0x0000U, 0x0000U, 0x1000U
};

/* ---- field elements ----------------------------------------------------- */

static void fe_0(fe *r) {
    int i;
    for (i = 0; i < 16; i++) r->v[i] = 0U;
}

static void fe_1(fe *r) {
    int i;
    r->v[0] = 1U;
    for (i = 1; i < 16; i++) r->v[i] = 0U;
}

static void fe_copy(fe *r, const fe *a) {
    int i;
    for (i = 0; i < 16; i++) r->v[i] = a->v[i];
}

/* Propagate carries across limbs 0..14 and report the carry out of limb 15.
 * That carry represents a multiple of 2^256, which the caller folds back in as
 * 38 (2^256 == 38 mod p). */
static uint32_t fe_propagate(fe *r) {
    uint32_t carry;
    int i;

    for (i = 0; i < 15; i++) {
        carry = r->v[i] >> 16;
        r->v[i] &= 0xFFFFU;
        r->v[i + 1] += carry;
    }
    carry = r->v[15] >> 16;
    r->v[15] &= 0xFFFFU;
    return carry;
}

/* Bring a 16-limb value into the canonical representative in [0, p).
 *
 * Every routine below routes its result through here, which is what makes the
 * "value below p, each limb under 2^16" precondition true everywhere, and what
 * lets fe_equal compare limbs directly.
 *
 * Two details are load-bearing:
 *
 *  - The top-limb overflow is folded as 38, not discarded.  Dropping it
 *    silently loses a whole multiple of 2^256.
 *  - p is subtracted in a loop, not once.  16 limbs span 2^256 and
 *    2^256 == 2p + 38, so a folded value can land just above 2p; a single
 *    conditional subtract then leaves the result exactly p too large, which is
 *    enough to break verification while still looking like a field element. */
static void fe_reduce(fe *r) {
    fe diff;
    uint32_t borrow;
    uint32_t i;

    for (;;) {
        /* Carry out of limb 15 is a multiple of 2^256, i.e. 38 * carry mod p.
         * Scaling by the carry matters: the top limb can overflow by more than
         * one at a time after a wide fold, and adding a flat 38 leaves a result
         * that is a multiple of p too large -- plausible-looking, and wrong. */
        uint32_t carry = fe_propagate(r);
        if (carry == 0U) {
            break;
        }
        r->v[0] += 38U * carry;
    }

    for (;;) {
        borrow = 0U;
        for (i = 0; i < 16; i++) {
            int64_t d = (int64_t)r->v[i] - (int64_t)fe_p.v[i]
                        - (int64_t)borrow;
            diff.v[i] = (uint32_t)(d & 0xFFFF);
            borrow = (uint32_t)((d < 0) ? 1U : 0U);
        }
        /* Only overwrite the original when the subtraction really happened.
         * Writing unconditionally leaves the wrapped 256-bit difference behind,
         * which is how a plain 0 comes out of this as 2^255 + 19. */
        if (borrow) {
            return; /* value was already below p */
        }
        for (i = 0; i < 16; i++) {
            r->v[i] = diff.v[i];
        }
    }
}

static void fe_add(fe *r, const fe *a, const fe *b) {
    int i;
    for (i = 0; i < 16; i++) r->v[i] = a->v[i] + b->v[i];
    fe_reduce(r);
}

/* r = a - b mod p.
 *
 * On underflow this computes the magnitude (b - a) and returns p - (b - a).
 * Reusing the wrapped limb difference would be wrong: it looks like the
 * modular difference but is not, because 2^256 is not 0 mod p. */
static void fe_sub(fe *r, const fe *a, const fe *b) {
    fe mag;
    uint32_t borrow;
    uint32_t i;

    /* Compare a against b, most significant limb first. */
    for (i = 16; i-- > 0; ) {
        if (a->v[i] != b->v[i]) {
            break;
        }
    }

    if (i < 16 && a->v[i] >= b->v[i]) {
        borrow = 0U;
        for (i = 0; i < 16; i++) {
            int64_t d = (int64_t)a->v[i] - (int64_t)b->v[i] - (int64_t)borrow;
            mag.v[i] = (uint32_t)(d & 0xFFFF);
            borrow = (uint32_t)((d < 0) ? 1U : 0U);
        }
        fe_copy(r, &mag);
    } else {
        /* mag = b - a */
        borrow = 0U;
        for (i = 0; i < 16; i++) {
            int64_t d = (int64_t)b->v[i] - (int64_t)a->v[i] - (int64_t)borrow;
            mag.v[i] = (uint32_t)(d & 0xFFFF);
            borrow = (uint32_t)((d < 0) ? 1U : 0U);
        }
        /* r = p - mag */
        borrow = 0U;
        for (i = 0; i < 16; i++) {
            int64_t d = (int64_t)fe_p.v[i] - (int64_t)mag.v[i]
                        - (int64_t)borrow;
            r->v[i] = (uint32_t)(d & 0xFFFF);
            borrow = (uint32_t)((d < 0) ? 1U : 0U);
        }
    }
    fe_reduce(r);
}

static void fe_mul(fe *r, const fe *a, const fe *b) {
    uint64_t t[32];
    uint32_t carry;
    uint32_t i;
    uint32_t j;

    for (i = 0; i < 32; i++) t[i] = 0U;

    /* Schoolbook product.  Each accumulation is masked back to 16 bits and the
     * carry is carried forward explicitly, so no limb can run away and no carry
     * can be dropped.  (Keeping a single running "acc" and shifting it is the
     * same thing, but writing it out this way is easier to check.) */
    for (i = 0; i < 16; i++) {
        carry = 0U;
        for (j = 0; j < 16; j++) {
            uint64_t cur = t[i + j] + (uint64_t)a->v[i] * (uint64_t)b->v[j]
                           + carry;
            t[i + j] = cur & 0xFFFFU;
            carry = (uint32_t)(cur >> 16);
        }
        t[i + 16] += carry;
    }

    /* Normalise the high half so that every limb folded below is a true 16-bit
     * value; otherwise 38*t[i] would be folding an unnormalised limb. */
    for (i = 16; i < 31; i++) {
        t[i + 1] += t[i] >> 16;
        t[i] &= 0xFFFFU;
    }
    while (t[31] >> 16) {
        t[15] += 38U * (t[31] >> 16);
        t[31] &= 0xFFFFU;
        for (i = 16; i < 31; i++) {
            t[i + 1] += t[i] >> 16;
            t[i] &= 0xFFFFU;
        }
    }

    /* Fold limbs 16..31 down, descending: 2^256 == 38 (mod p). */
    for (i = 31; i > 15; i--) {
        t[i - 16] += 38U * t[i];
    }

    for (i = 0; i < 16; i++) {
        r->v[i] = (uint32_t)t[i];
    }
    fe_reduce(r);
}

static void fe_sq(fe *r, const fe *a) {
    fe_mul(r, a, a);
}

/* Square-and-multiply, most significant bit first, fixed 256 iterations so the
 * exponent's value does not change the execution shape. */
static void fe_pow(fe *r, const fe *a, const uint8_t exp_be[32]) {
    fe acc;
    uint32_t i;

    fe_1(&acc);
    for (i = 0; i < 256U; i++) {
        fe_sq(&acc, &acc);
        if (((exp_be[i >> 3] >> (7U - (i & 7U))) & 1U) != 0U) {
            fe_mul(&acc, &acc, a);
        }
    }
    fe_copy(r, &acc);
}

/* Exact field equality.  Both operands are canonical by the fe_reduce
 * invariant, so a limb-wise comparison is exact. */
static bool fe_equal(const fe *a, const fe *b) {
    uint32_t diff = 0U;
    int i;
    for (i = 0; i < 16; i++) diff |= a->v[i] ^ b->v[i];
    return diff == 0U;
}

static bool fe_is_zero(const fe *a) {
    fe zero = FE_ZERO_INIT;
    return fe_equal(a, &zero);
}

static void fe_frombytes(fe *r, const uint8_t s[32]) {
    int i;
    for (i = 0; i < 16; i++) {
        r->v[i] = (uint32_t)s[2 * i] | ((uint32_t)s[2 * i + 1] << 8);
    }
}

/* fe_tobytes is defined inside the OW_HOST_HAL section below: the kernel only
 * ever verifies, which needs no field-element encoding, and a static function
 * with no caller is an error under the target build's -Werror. */

static bool fe_is_negative(const fe *a) {
    return (a->v[0] & 1U) != 0U;
}

/* True when the 255 value bits in s name an integer strictly below p.
 *
 * This has to be an explicit comparison.  fe_frombytes and fe_tobytes are exact
 * inverses -- neither reduces -- so comparing a field element against its own
 * re-encoding always succeeds and detects nothing.  Two byte strings that differ
 * only by a multiple of p name the same point, so accepting both would let one
 * point have many encodings, and a signature over one of them would not transfer
 * to the other. */
static bool fe_bytes_below_p(const uint8_t s[32]) {
    int i;
    for (i = 15; i >= 0; i--) {
        uint32_t limb = (uint32_t)s[2 * i] | ((uint32_t)s[2 * i + 1] << 8);
        if (limb != fe_p.v[i]) {
            return limb < fe_p.v[i];
        }
    }
    return false; /* equal to p is not below p */
}

/* ---- scalars mod L ------------------------------------------------------ */

/* True when the 32-byte little-endian scalar is greater than or equal to L, i.e.
 * when it is not canonically reduced. */
static bool sc_ge_L(const uint8_t s[32]) {
    uint32_t borrow = 0U;
    uint32_t i;

    for (i = 0; i < OW_L_LIMBS; i++) {
        uint32_t limb = (uint32_t)s[2 * i] | ((uint32_t)s[2 * i + 1] << 8);
        int64_t d = (int64_t)limb - (int64_t)fe_L[i] - (int64_t)borrow;
        borrow = (uint32_t)((d < 0) ? 1U : 0U);
    }
    return borrow == 0U;
}

/* Reduce a 64-byte little-endian value modulo L.
 *
 * Bitwise long division: for each bit from the top, shift it into the remainder
 * and subtract L once when the result is at least L.  This is not the fast
 * reduction, and does not need to be -- it runs twice per verified signature. */
static void sc_reduce_mod_L(uint8_t out[32], const uint8_t in[64]) {
    uint32_t rem[OW_L_LIMBS];
    uint32_t reduced[OW_L_LIMBS];
    uint32_t borrow;
    int32_t bit;
    uint32_t i;

    for (i = 0; i < OW_L_LIMBS; i++) rem[i] = 0U;

    for (bit = 511; bit >= 0; bit--) {
        uint32_t in_bit = (uint32_t)((in[bit >> 3] >> (bit & 7)) & 1u);
        uint32_t carry = in_bit;

        /* rem = rem*2 + in_bit.  rem stays below L < 2^253, so nothing is
         * pushed out of the top limb. */
        for (i = 0; i < OW_L_LIMBS; i++) {
            uint32_t next = rem[i] >> 15;
            rem[i] = ((rem[i] << 1) | carry) & 0xFFFFU;
            carry = next;
        }

        borrow = 0U;
        for (i = 0; i < OW_L_LIMBS; i++) {
            int64_t d = (int64_t)rem[i] - (int64_t)fe_L[i]
                        - (int64_t)borrow;
            reduced[i] = (uint32_t)(d & 0xFFFF);
            borrow = (uint32_t)((d < 0) ? 1U : 0U);
        }
        /* Commit when the subtraction did not borrow, i.e. exactly when
         * rem >= L.  That includes rem == L, which must become zero. */
        if (borrow == 0U) {
            for (i = 0; i < OW_L_LIMBS; i++) rem[i] = reduced[i];
        }
    }

    for (i = 0; i < OW_L_LIMBS; i++) {
        out[2 * i] = (uint8_t)(rem[i] & 0xFFU);
        out[2 * i + 1] = (uint8_t)((rem[i] >> 8) & 0xFFU);
    }
}

/* ---- group arithmetic --------------------------------------------------- */

/* Neutral element. */
static void ge_zero(ge *r) {
    fe_0(&r->X);
    fe_1(&r->Y);
    fe_1(&r->Z);
    fe_0(&r->T);
}

static void ge_base(ge *r) {
    fe_copy(&r->X, &fe_bx);
    fe_copy(&r->Y, &fe_by);
    fe_1(&r->Z);
    fe_copy(&r->T, &fe_bt);
}

/* Extended-coordinate addition for a = -1 (Hisil et al., "Twisted Edwards
 * Curves Revisited"), unified so it also doubles when p == q. */
static void ge_add(ge *r, const ge *p, const ge *q) {
    fe a, b, c, d, e, f, g, h, t;

    fe_sub(&t, &p->Y, &p->X);
    fe_sub(&a, &q->Y, &q->X);
    fe_mul(&a, &t, &a);

    fe_add(&t, &p->Y, &p->X);
    fe_add(&b, &q->Y, &q->X);
    fe_mul(&b, &t, &b);

    fe_mul(&c, &p->T, &q->T);
    fe_mul(&c, &c, &fe_d2);

    fe_mul(&d, &p->Z, &q->Z);
    fe_add(&d, &d, &d);

    fe_sub(&e, &b, &a);
    fe_sub(&f, &d, &c);
    fe_add(&g, &d, &c);
    fe_add(&h, &b, &a);

    fe_mul(&r->X, &e, &f);
    fe_mul(&r->Y, &g, &h);
    fe_mul(&r->T, &e, &h);
    fe_mul(&r->Z, &f, &g);
}

/* [scalar]p for a 32-byte little-endian scalar. */
static void ge_scalarmult(ge *r, const uint8_t scalar[32], const ge *p) {
    ge acc;
    ge tmp;
    int32_t bit;

    ge_zero(&acc);
    for (bit = 255; bit >= 0; bit--) {
        ge_add(&tmp, &acc, &acc);
        acc = tmp;
        if (((scalar[bit >> 3] >> (bit & 7)) & 1u) != 0u) {
            ge_add(&tmp, &acc, p);
            acc = tmp;
        }
    }
    *r = acc;
}

/* Projective equality: X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1. */
static bool ge_equal(const ge *p, const ge *q) {
    fe x1, x2, y1, y2;
    bool eq;

    fe_mul(&x1, &p->X, &q->Z);
    fe_mul(&x2, &q->X, &p->Z);
    eq = fe_equal(&x1, &x2);
    fe_mul(&y1, &p->Y, &q->Z);
    fe_mul(&y2, &q->Y, &p->Z);
    eq = eq && fe_equal(&y1, &y2);
    return eq;
}

/* Decompress a 32-byte point encoding.  Returns false for a non-canonical y
 * (y >= p), for a y with no x on the curve, and for x == 0 with the sign bit
 * set, which RFC 8032 forbids as an encoding.
 *
 * Canonicality is an explicit "y < p" test on the 255 value bits, done before any
 * field arithmetic.  It has to come first: once y has been loaded, y and y + p
 * are the same field element, so nothing downstream can tell the two encodings
 * apart.  Accepting both would give one point two encodings, and a signature over
 * one would not verify against the other. */
static bool ge_frombytes(ge *p, const uint8_t s[32]) {
    fe y, y2, u, v, v3, v7, x, check;
    uint8_t value_bits[32];
    uint32_t sign;
    int i;

    sign = (uint32_t)(s[31] >> 7);
    for (i = 0; i < 32; i++) value_bits[i] = s[i];
    value_bits[31] = (uint8_t)(value_bits[31] & 0x7FU);

    if (!fe_bytes_below_p(value_bits)) {
        return false;
    }

    fe_frombytes(&y, value_bits);

    /* x^2 = (y^2 - 1) / (d*y^2 + 1), taken as a square root. */
    fe_sq(&y2, &y);
    fe_1(&u);
    fe_sub(&u, &y2, &u);            /* u = y^2 - 1 */
    fe_mul(&v, &y2, &fe_d);
    fe_1(&check);
    fe_add(&v, &v, &check);         /* v = d*y^2 + 1 */
    if (fe_is_zero(&v)) {
        return false;               /* no x satisfies the equation */
    }

    /* RFC 8032 section 5.1.3 recovery:
     *   x = (u * v^3) * (u * v^7)^((p-5)/8) */
    fe_sq(&v3, &v);
    fe_mul(&v3, &v3, &v);           /* v^3 */
    fe_sq(&v7, &v3);
    fe_mul(&v7, &v7, &v);           /* v^7 */
    fe_mul(&x, &u, &v7);
    fe_pow(&x, &x, fe_exp_sqrt_m5);
    fe_mul(&x, &x, &u);
    fe_mul(&x, &x, &v3);

    /* Accept the candidate when v*x^2 == u.  Otherwise the expression landed
     * on the other root; multiplying by sqrt(-1) reaches it.  Neither working
     * means y is not on the curve. */
    fe_sq(&check, &x);
    fe_mul(&check, &check, &v);
    if (!fe_equal(&check, &u)) {
        fe_mul(&x, &x, &fe_sqrtm1);
        fe_sq(&check, &x);
        fe_mul(&check, &check, &v);
        if (!fe_equal(&check, &u)) {
            return false;
        }
    }

    if (fe_is_zero(&x) && sign != 0U) {
        return false;               /* x == 0 with the sign bit set */
    }
    if (fe_is_negative(&x) != (sign != 0U)) {
        fe neg;
        fe_0(&neg);
        fe_sub(&neg, &neg, &x);
        fe_copy(&x, &neg);
    }

    fe_copy(&p->X, &x);
    fe_copy(&p->Y, &y);
    fe_1(&p->Z);
    fe_mul(&p->T, &x, &y);
    return true;
}

/* ---- verification ------------------------------------------------------- */

bool ow_crypto_ed25519_verify(
    const uint8_t public_key[OW_ED25519_PUBLIC_KEY_SIZE],
    const uint8_t signature[OW_ED25519_SIGNATURE_SIZE],
    const uint8_t *message,
    size_t message_len) {

    ge A, R, B, sB, kA, sum;
    uint8_t hash[OW_SHA512_DIGEST_SIZE];
    uint8_t scalar[32];
    ow_sha512_ctx_t ctx;
    uint8_t nonzero = 0U;
    int i;

    if (!public_key || !signature) {
        return false;
    }
    if (!message && message_len != 0u) {
        return false;
    }

    /* An all-zero signature is not valid under any key.  Rejecting it outright
     * means "no signature at all" can never be mistaken for a pass. */
    for (i = 0; i < OW_ED25519_SIGNATURE_SIZE; i++) nonzero |= signature[i];
    if (nonzero == 0U) {
        return false;
    }

    if (!ge_frombytes(&A, public_key)) {
        return false;
    }
    if (!ge_frombytes(&R, signature)) {
        return false;
    }

    /* S must be canonically reduced.  A non-reduced S is the standard lever for
     * forging a second valid signature over the same message, so this is a
     * correctness requirement rather than a strictness preference. */
    if (sc_ge_L(signature + 32)) {
        return false;
    }

    /* k = SHA512(R_enc || A_enc || M) mod L, over the ENCODED forms exactly as
     * they arrived.  Re-encoding them here would hash a different message. */
    ow_sha512_init(&ctx);
    ow_sha512_update(&ctx, signature, 32);
    ow_sha512_update(&ctx, public_key, 32);
    if (message_len != 0u) {
        ow_sha512_update(&ctx, message, message_len);
    }
    ow_sha512_final(&ctx, hash);
    sc_reduce_mod_L(scalar, hash);

    ge_base(&B);
    ge_scalarmult(&sB, signature + 32, &B);
    ge_scalarmult(&kA, scalar, &A);
    ge_add(&sum, &R, &kA);

    /* [S]B == R + [k]A */
    return ge_equal(&sB, &sum);
}

/* ---- host-test accessors -------------------------------------------------
 *
 * Compiled only for the host harness, which is the sole consumer.  The kernel
 * build has none of this: nothing below is reachable, and the supported entry
 * point remains ow_crypto_ed25519_verify().
 *
 * These exist because a signature-level known-answer test can only say
 * "rejected".  Reaching the field, scalar and group layers individually is what
 * turns a regression into a diagnosis -- and several of the bugs found while
 * writing this file (a flat 38 instead of 38 * carry, a subtraction committed
 * on borrow, a dropped product carry, a reduction that refused to commit when
 * the value was exactly L, and sqrt(-1) with limb 0 as 0x0A0B) were all
 * invisible at the signature layer and obvious at the layer below.
 *
 * Everything crosses the boundary as bytes, never as internal structs, so the
 * tests compare the same canonical encodings that go on the wire.  Projective
 * points are only equal up to a common factor, and comparing them directly
 * would let a test pass for the wrong reason. */

#ifdef OW_HOST_HAL

#include "../inc/ow_ed25519_test.h"

/* Exact inverse of fe_frombytes; neither reduces.  Host-only, because the kernel
 * path never encodes a field element -- it verifies signatures, and decoding a
 * point does not require producing its canonical form. */
static void fe_tobytes(uint8_t s[32], const fe *a) {
    int i;
    for (i = 0; i < 16; i++) {
        s[2 * i] = (uint8_t)(a->v[i] & 0xFFU);
        s[2 * i + 1] = (uint8_t)((a->v[i] >> 8) & 0xFFU);
    }
}

/* p - 2, little-endian bytes, for the inversion that point encoding needs. */
/* Exponents are big-endian, because fe_pow walks them most significant bit
 * first.  A little-endian exponent here would still square-and-multiply a
 * plausible-looking value and produce a plausible-looking field element; only an
 * inversion test exposes it. */
static const uint8_t fe_exp_p_minus_2[32] = {
    0x7FU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU,
    0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xFFU, 0xEBU
};

/* Compress a point back to 32 bytes.  Not part of verification -- verification
 * compares projectively and never needs to re-encode anything -- so this lives
 * in the test block and exists because the tests must be able to express an
 * expected point as the exact bytes that would appear in a signature. */
static bool ge_tobytes(uint8_t s[32], const ge *p) {
    fe recip, x, y;

    /* recip = Z^(p-2) = 1/Z.  Raising Z*Z instead would give (Z^2)^(p-2) =
     * Z^(2p-4) = Z^-2, which is wrong in a way that looks fine whenever Z is
     * fixed: the result is still a scaled point, just scaled wrongly. */
    fe_pow(&recip, &p->Z, fe_exp_p_minus_2);
    fe_mul(&x, &p->X, &recip);
    fe_mul(&y, &p->Y, &recip);

    fe_tobytes(s, &y);
    s[31] |= (uint8_t)(fe_is_negative(&x) ? 0x80U : 0x00U);
    return true;
}

void ow_ed_test_fe_zero(ow_ed_test_fe r) {
    int i;
    for (i = 0; i < 16; i++) r[i] = 0U;
}

void ow_ed_test_fe_one(ow_ed_test_fe r) {
    int i;
    r[0] = 1U;
    for (i = 1; i < 16; i++) r[i] = 0U;
}

void ow_ed_test_fe_copy(ow_ed_test_fe r, const ow_ed_test_fe a) {
    int i;
    for (i = 0; i < 16; i++) r[i] = a[i];
}

void ow_ed_test_fe_add(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const ow_ed_test_fe b) {
    fe out, x, y;
    int i;
    for (i = 0; i < 16; i++) { x.v[i] = a[i]; y.v[i] = b[i]; }
    fe_add(&out, &x, &y);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)out.v[i];
}

void ow_ed_test_fe_sub(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const ow_ed_test_fe b) {
    fe out, x, y;
    int i;
    for (i = 0; i < 16; i++) { x.v[i] = a[i]; y.v[i] = b[i]; }
    fe_sub(&out, &x, &y);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)out.v[i];
}

void ow_ed_test_fe_mul(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const ow_ed_test_fe b) {
    fe out, x, y;
    int i;
    for (i = 0; i < 16; i++) { x.v[i] = a[i]; y.v[i] = b[i]; }
    fe_mul(&out, &x, &y);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)out.v[i];
}

void ow_ed_test_fe_sq(ow_ed_test_fe r, const ow_ed_test_fe a) {
    fe out, x;
    int i;
    for (i = 0; i < 16; i++) x.v[i] = a[i];
    fe_sq(&out, &x);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)out.v[i];
}

bool ow_ed_test_fe_equal(const ow_ed_test_fe a, const ow_ed_test_fe b) {
    fe x, y;
    int i;
    for (i = 0; i < 16; i++) { x.v[i] = a[i]; y.v[i] = b[i]; }
    return fe_equal(&x, &y);
}

bool ow_ed_test_fe_is_zero(const ow_ed_test_fe a) {
    fe x;
    int i;
    for (i = 0; i < 16; i++) x.v[i] = a[i];
    return fe_is_zero(&x);
}

void ow_ed_test_fe_decode(ow_ed_test_fe r, const uint8_t s[32]) {
    fe x;
    int i;
    fe_frombytes(&x, s);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)x.v[i];
}

void ow_ed_test_fe_encode(uint8_t s[32], const ow_ed_test_fe a) {
    fe x;
    int i;
    for (i = 0; i < 16; i++) x.v[i] = a[i];
    fe_tobytes(s, &x);
}

void ow_ed_test_fe_reduce(ow_ed_test_fe r, const ow_ed_test_fe a) {
    fe x;
    int i;
    for (i = 0; i < 16; i++) x.v[i] = a[i];
    fe_reduce(&x);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)x.v[i];
}

bool ow_ed_test_fe_is_negative(const ow_ed_test_fe a) {
    fe x;
    int i;
    for (i = 0; i < 16; i++) x.v[i] = a[i];
    return fe_is_negative(&x);
}

void ow_ed_test_fe_pow(ow_ed_test_fe r, const ow_ed_test_fe a,
                       const uint8_t exp_be[32]) {
    fe base, out;
    int i;
    for (i = 0; i < 16; i++) base.v[i] = a[i];
    fe_pow(&out, &base, exp_be);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)out.v[i];
}

bool ow_ed_test_fe_invert(ow_ed_test_fe r, const ow_ed_test_fe a) {
    fe base, out;
    int i;
    for (i = 0; i < 16; i++) base.v[i] = a[i];
    if (fe_is_zero(&base)) {
        return false;
    }
    fe_pow(&out, &base, fe_exp_p_minus_2);
    for (i = 0; i < 16; i++) r[i] = (uint16_t)out.v[i];
    return true;
}

void ow_ed_test_sc_reduce(uint8_t out[32], const uint8_t in[64]) {
    sc_reduce_mod_L(out, in);
}

bool ow_ed_test_sc_is_canonical(const uint8_t s[32]) {
    return !sc_ge_L(s);
}

bool ow_ed_test_point_decode(const uint8_t s[32]) {
    ge p;
    return ge_frombytes(&p, s);
}

bool ow_ed_test_point_encode(uint8_t out[32], const uint8_t s[32]) {
    ge p;
    if (!ge_frombytes(&p, s)) {
        return false;
    }
    return ge_tobytes(out, &p);
}

bool ow_ed_test_point_add(uint8_t out[32], const uint8_t a[32],
                          const uint8_t b[32]) {
    ge p, q, r;
    if (!ge_frombytes(&p, a) || !ge_frombytes(&q, b)) {
        return false;
    }
    ge_add(&r, &p, &q);
    return ge_tobytes(out, &r);
}

bool ow_ed_test_point_double(uint8_t out[32], const uint8_t a[32]) {
    ge p, r;
    if (!ge_frombytes(&p, a)) {
        return false;
    }
    ge_add(&r, &p, &p);
    return ge_tobytes(out, &r);
}

bool ow_ed_test_point_mul(uint8_t out[32], const uint8_t scalar[32],
                          const uint8_t point[32]) {
    ge p, r;
    if (!ge_frombytes(&p, point)) {
        return false;
    }
    ge_scalarmult(&r, scalar, &p);
    return ge_tobytes(out, &r);
}

bool ow_ed_test_point_mul_base(uint8_t out[32], const uint8_t scalar[32]) {
    ge b, r;
    ge_base(&b);
    ge_scalarmult(&r, scalar, &b);
    return ge_tobytes(out, &r);
}

bool ow_ed_test_point_equal(const uint8_t a[32], const uint8_t b[32]) {
    ge p, q;
    if (!ge_frombytes(&p, a) || !ge_frombytes(&q, b)) {
        return false;
    }
    return ge_equal(&p, &q);
}

void ow_ed_test_point_identity(uint8_t out[32]) {
    ge e;
    ge_zero(&e);
    (void)ge_tobytes(out, &e);
}

void ow_ed_test_scalar_order_L(uint8_t out[32]) {
    int i;
    for (i = 0; i < 16; i++) {
        out[2 * i] = (uint8_t)(fe_L[i] & 0xFFU);
        out[2 * i + 1] = (uint8_t)((fe_L[i] >> 8) & 0xFFU);
    }
}

void ow_ed_test_field_p_minus_2(uint8_t out[32]) {
    int i;
    for (i = 0; i < 16; i++) {
        out[2 * i] = (uint8_t)(fe_p.v[i] & 0xFFU);
        out[2 * i + 1] = (uint8_t)((fe_p.v[i] >> 8) & 0xFFU);
    }
    /* p - 2 == p - 1 - 1, and p - 1 is 0xFFED in limb 0 with every other limb
     * at its maximum, so this is a subtraction in the field rather than a
     * transcribed constant. */
    out[0] = (uint8_t)(out[0] - 2U);
}

#endif /* OW_HOST_HAL */