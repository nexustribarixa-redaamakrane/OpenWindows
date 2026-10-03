#!/usr/bin/env python3
"""Generate the checked-in Ed25519 regression vector set.

Emits tools/hosttest/crypto_vectors.h.  Regenerate with:

    python tools/gen_crypto_vectors.py > tools/hosttest/crypto_vectors.h

Why a generator writes a checked-in header rather than generating at build
time: crypto test vectors should be reviewable in a diff, because the whole
point of a known-answer test is that a human can confirm the expected values are
the real ones.  Values here come from tools/cis_sign.py, an independent
derivation of the curve that shares no code with lib/ow_ed25519.c, so this
file is cross-implementation agreement rather than one implementation agreeing
with itself.

The set is deliberately split into layers.  The top-level Ed25519 vectors say
"a signature verifies"; they cannot say *which* layer broke when one stops.  So
the field, scalar and point layers sit underneath, and each one targets a
specific mistake that was actually made while writing lib/ow_ed25519.c:

  - fe_reduce folding a flat 38 instead of 38 * carry
  - fe_reduce committing its subtraction result even on borrow
  - fe_mul dropping a carry
  - sc_reduce_mod_L refusing to commit when the value equals L exactly
  - fe_sqrtm1 limb 0 transcribed as 0x0A0B instead of 0xA0B0

Keeping the low layers means a future arithmetic edit fails a test that names
the broken operation, instead of surfacing as "RFC vector 3 fails".
"""

import hashlib
import sys

sys.path.insert(0, "tools")

import cis_sign as S  # noqa: E402

P = S.P
L = S.L

# ---------------------------------------------------------------------------
# Field operands
# ---------------------------------------------------------------------------
# Chosen for the failure modes above rather than for tidiness.  (P-1) and its
# neighbours are where a wide multiplication overflows limb 15 by more than one,
# which is the only situation that distinguishes 38 * carry from a flat 38.

FIELD_SEED_VALUES = [
    0,
    1,
    2,
    3,
    38,                      # the reduction constant itself
    P - 20,                  # 2^255 - 1
    P - 1,
    P - 2,
    P - 3,
    P - 19,
    P - 38,
    (P - 1) // 2,
    (P - 5) // 4,
    2 ** 128,
    2 ** 192,
    2 ** 240,
    2 ** 252,
    2 ** 254,
    P // 3,
    P // 7,
]

FIELD_RANDOM_VALUES = 12


def field_random_values(n):
    """Deterministic pseudo-random field elements.

    Keyed off SHA-256 of a fixed label so the set is reproducible across
    machines and Python versions -- a test corpus that changes shape when
    someone reorders a dict is not a regression test.
    """
    out = []
    for i in range(n):
        h = hashlib.sha256(("cis-field-vector-%d" % i).encode()).digest()
        v = int.from_bytes(h, "little") % P
        # Include a few values that sit just below p, where reduction has to
        # subtract more than once.
        if i % 4 == 0:
            v = P - 1 - (i % 37)
        out.append(v)
    return out


# Explicit pairs, each with the reason it exists.  Order is preserved.
FIELD_PAIRS = [
    (0, 0, "zero times zero: the subtraction-on-borrow path must leave 0 alone"),
    (0, 1, "zero times one"),
    (1, 0, "one times zero, the other operand order"),
    (0, P - 1, "zero times the largest element"),
    (P - 1, 0, "the largest element times zero"),
    (1, 1, "one times one"),
    (P - 1, P - 1, "the squaring that overflows limb 15 by more than one"),
    (P - 1, P - 2, "product lands just above 2p, so reduction must run twice"),
    (P - 1, P - 3, "product just above 2p again, one unit further out"),
    (P - 2, P - 2, "near-maximal squaring"),
    (P - 20, P - 20, "the largest y a compressed point may carry"),
    (38, 38, "reduction constant squared, feeds the 38 folding path"),
    (38, P - 1, "38 times the largest element"),
    (2 ** 254, 2 ** 254, "top limb at its maximum, square"),
    (2 ** 252, 2 ** 252, "2^252 squared spans the whole 32-limb product"),
    (P - 1, 1, "multiplication must reduce to exactly 1"),
    (P - 19, P - 19, "just below the largest element"),
    (P // 3, P // 3, "a value with no special structure"),
    (1, P - 1, "one times the largest element: reduction to exactly 1"),
    (3, P - 38, "a-38 multiplied out, exercises repeated top folding"),
]


# ---------------------------------------------------------------------------
# Scalar (mod L) inputs
# ---------------------------------------------------------------------------
SCALAR_CASES = [
    (0, "zero reduces to zero"),
    (1, "one reduces to one"),
    (L - 1, "the largest canonical scalar passes through unchanged"),
    (L, "L itself must reduce to exactly zero, not to L"),
    (L + 1, "one past L reduces to one"),
    (2 * L, "an exact multiple of L reduces to zero"),
    (2 * L - 1, "one below an exact multiple"),
    (L // 2, "half the group order"),
    (2 ** 256 - 1, "the maximum 32-byte scalar is well below L and passes"),
    (2 ** 512 - 1, "the maximum 64-byte input reduces below L"),
    (2 ** 512 - 1 - L, "one below a multiple of L at full width"),
    (S.D, "an arbitrary 255-bit value"),
]

# Canonicality boundaries for the S < L check the verifier performs.
SCALAR_CANONICALITY = [
    (L - 1, True, "S = L-1 is canonical"),
    (L, False, "S = L is rejected as non-canonical"),
    (L + 1, False, "S = L+1 is rejected"),
    (2 ** 256 - 1, False, "S = 2^256-1 is rejected, far above L"),
]


# ---------------------------------------------------------------------------
# Point encodings
# ---------------------------------------------------------------------------
# The complete 8-torsion subgroup of Ed25519, each verified here to have the
# order claimed.  These are the points behind the cofactorless-verification
# caveat: they decode successfully because they are valid curve points, so
# nothing in point decompression can be relied on to filter them.

TORSION_POINTS = [
    ("0100000000000000000000000000000000000000000000000000000000000000", 1,
     "the identity, y = 1"),
    ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", 2,
     "y = p-1, the unique point of order 2"),
    ("0000000000000000000000000000000000000000000000000000000000000000", 4,
     "y = 0, x even, order 4"),
    ("0000000000000000000000000000000000000000000000000000000000000080", 4,
     "y = 0, x odd, the other order-4 point"),
    ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", 8,
     "order 8"),
    ("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", 8,
     "order 8"),
    ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", 8,
     "order 8"),
    ("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", 8,
     "order 8"),
]

# Encodings that must be refused during decompression.  Each is a real curve
# coordinate or a real byte string, so the reason for refusal is a rule rather
# than corruption.
MALFORMED_POINTS = [
    ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
     "y = 2^255-1 is above p, so the encoding is not canonical"),
    ("ed" + "ff" * 30 + "7f",
     "y = p exactly is not below p, so it is not canonical"),
    ("0100000000000000000000000000000000000000000000000000000000000080",
     "y = 1 with the sign bit set: x = 0 forbids a set sign bit"),
    ("0200000000000000000000000000000000000000000000000000000000000000",
     "y = 2 is not on the curve, so x cannot be recovered"),
    ("0200000000000000000000000000000000000000000000000000000000000080",
     "y = 2 with the sign bit set: y = 2 is not on the curve at all"),
    ("0700000000000000000000000000000000000000000000000000000000000000",
     "y = 7 is not on the curve, so no x can be recovered"),
    ("0b00000000000000000000000000000000000000000000000000000000000080",
     "y = 11 with the sign bit set is not on the curve"),
    ("2600000000000000000000000000000000000000000000000000000000000000",
     "y = 38, the reduction constant, is not on the curve"),
]

# A real public key and a few point-arithmetic identities around it, checked
# against this implementation's own group law.
POINT_IDENTITIES = [
    # (left enc, right enc, operation, expected result hex or None)
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "add",
     "1a3ca3f85fa9357d7605a957d45c693418b7a95e191e0c75e70e9882a98f3662",
     "B added to itself is 2B, not the identity"),
    ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "add",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "adding the identity is the identity"),
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000080",
     "add",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "the two order-4 points sum to the identity"),
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "add",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
     "an order-4 point doubled is the order-2 point"),
    ("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
     "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
     "add",
     "0100000000000000000000000000000000000000000000000000000000000000",
     "the order-2 point doubled is the identity, exercising T = XY = 0"),
]


def main():
    field_values = FIELD_SEED_VALUES + field_random_values(FIELD_RANDOM_VALUES)

    pairs = list(FIELD_PAIRS)
    for a in field_values:
        for b in field_values:
            pairs.append((a, b, "generated operand pair"))
    seen = set()
    deduped = []
    for a, b, why in pairs:
        key = (a, b)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((a, b, why))

    out = sys.stdout
    out.write("/* Generated by tools/gen_crypto_vectors.py -- do not edit.\n")
    out.write(" *\n")
    out.write(" * Cross-implementation known-answer vectors for lib/ow_ed25519.c,\n")
    out.write(" * produced by tools/cis_sign.py.  Layered: Ed25519 signatures on\n")
    out.write(" * top, then field, scalar and point layers underneath so that a\n")
    out.write(" * regression names the operation that broke.\n")
    out.write(" *\n")
    out.write(" * Regenerate: python tools/gen_crypto_vectors.py \\\n")
    out.write(" *                     > tools/hosttest/crypto_vectors.h\n")
    out.write(" */\n")
    out.write("#ifndef CRYPTO_VECTORS_H\n#define CRYPTO_VECTORS_H\n\n")
    out.write("#include <stdint.h>\n\n")

    # ---- SHA-512 known answers ----
    # Underneath every signature, so a defect here presents as "the curve code
    # is broken".  The lengths straddle the 128-byte block boundary, which is
    # where a length or buffer-carry defect would live.
    sha = []
    for label, data in SHA512_VECTORS:
        # The buffer has to be large enough for every vector.  Asserted rather
        # than assumed: an over-long message would otherwise emit a C initializer
        # that overflows its own array, which the compiler reports as a wall of
        # "excess element" notes with the real cause somewhere far above.
        assert len(data) <= SHA512_MAX_MSG, (
            "%s is %d bytes, over the %d-byte vector buffer"
            % (label, len(data), SHA512_MAX_MSG))
        sha.append((label, data, hashlib.sha512(data).digest()))

    out.write("/* SHA-512 known answers (FIPS 180-4 and block-boundary lengths).\n")
    out.write(" * The digest width is restated here rather than taken from\n")
    out.write(" * ow_sha512.h, so this header stands alone and a change to the\n")
    out.write(" * implementation's declared width cannot silently reshape the\n")
    out.write(" * expected values. */\n")
    out.write("#define OW_SHA512_VECTOR_MAX_MSG %du\n" % SHA512_MAX_MSG)
    out.write("#define OW_SHA512_VECTOR_DIGEST 64u\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t msg[OW_SHA512_VECTOR_MAX_MSG];\n")
    out.write("  uint8_t want[OW_SHA512_VECTOR_DIGEST];\n")
    out.write("  uint32_t msg_len;\n")
    out.write("} ow_sha512_vector;\n\n")
    out.write("static const ow_sha512_vector ow_sha512_vectors[] = {\n")
    for label, data, want in sha:
        out.write("  /* %s */\n" % label)
        out.write("  {\n")
        out.write("    { %s },\n" % byte_list(data))
        out.write("    { %s },\n" % byte_list(want))
        out.write("    %du\n" % len(data))
        out.write("  },\n")
    out.write("};\n")
    out.write("#define OW_SHA512_VECTOR_COUNT %du\n\n" % len(sha))

    # ---- field constants ----
    # Checked by identity rather than by quoting a second copy: d*d_denom ==
    # -d_num pins d to the curve parameter, sqrtm1^2 == p-1 pins the square
    # root, and the base point's curve equation plus T == X*Y pins bx, by, bt.
    out.write("/* Curve constants, little-endian field encodings. */\n")
    out.write("typedef struct {\n")
    out.write("  const char *name;\n")
    out.write("  uint8_t value[32];\n")
    out.write("} ow_field_constant;\n\n")
    out.write("static const ow_field_constant ow_field_constants[] = {\n")
    for name, value in FIELD_CONSTANTS:
        out.write('  { "%s",\n    { %s } },\n'
                  % (name, byte_list(value.to_bytes(32, "little"))))
    out.write("};\n")
    out.write("#define OW_FIELD_CONSTANT_COUNT %du\n\n" % len(FIELD_CONSTANTS))

    # ---- group constants ----
    out.write("/* Group constants, compressed point encodings. */\n")
    out.write("typedef struct {\n")
    out.write("  const char *name;\n")
    out.write("  uint8_t enc[32];\n")
    out.write("} ow_point_constant;\n\n")
    out.write("static const ow_point_constant ow_point_constants[] = {\n")
    for name, enc in POINT_CONSTANTS:
        assert S._decode_point(enc) is not None, name
        out.write('  { "%s",\n    { %s } },\n'
                  % (name, byte_list(enc)))
    out.write("};\n")
    out.write("#define OW_POINT_CONSTANT_COUNT %du\n\n" % len(POINT_CONSTANTS))

    # ---- field vectors ----
    out.write("/* GF(2^255-19), radix 2^16, little-endian limbs. */\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t a[32];\n  uint8_t b[32];\n  uint8_t add[32];\n")
    out.write("  uint8_t sub[32];\n  uint8_t mul[32];\n")
    out.write("} ow_field_vector;\n\n")

    out.write("static const ow_field_vector ow_field_vectors[] = {\n")
    for a, b, why in deduped:
        out.write("  /* %s */\n" % why)
        out.write("  {\n")
        out.write("    { %s },\n" % byte_list(a.to_bytes(32, "little")))
        out.write("    { %s },\n" % byte_list(b.to_bytes(32, "little")))
        out.write("    { %s },\n" % byte_list(((a + b) % P).to_bytes(32, "little")))
        out.write("    { %s },\n" % byte_list(((a - b) % P).to_bytes(32, "little")))
        out.write("    { %s }\n" % byte_list(((a * b) % P).to_bytes(32, "little")))
        out.write("  },\n")
    out.write("};\n")
    out.write("#define OW_FIELD_VECTOR_COUNT %du\n\n"
              % len(deduped))

    # ---- scalar vectors ----
    out.write("/* Scalars as 64-byte little-endian inputs to reduction mod L. */\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t in[64];\n  uint8_t want[32];\n")
    out.write("} ow_scalar_vector;\n\n")
    out.write("static const ow_scalar_vector ow_scalar_vectors[] = {\n")
    for value, why in SCALAR_CASES:
        out.write("  /* %s */\n" % why)
        out.write("  {\n")
        out.write("    { %s },\n"
                  % byte_list((value % (1 << 512)).to_bytes(64, "little")))
        out.write("    { %s }\n" % byte_list((value % L).to_bytes(32, "little")))
        out.write("  },\n")
    out.write("};\n")
    out.write("#define OW_SCALAR_VECTOR_COUNT %du\n\n" % len(SCALAR_CASES))

    out.write("/* S < L canonicality boundaries. */\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t s[32];\n  int canonical;\n")
    out.write("} ow_scalar_canon_vector;\n\n")
    out.write("static const ow_scalar_canon_vector ow_scalar_canon_vectors[] = {\n")
    for value, canon, why in SCALAR_CANONICALITY:
        out.write("  /* %s */\n" % why)
        out.write("  {\n")
        out.write("    { %s },\n" % byte_list(value.to_bytes(32, "little")))
        out.write("    %s\n" % ("1" if canon else "0"))
        out.write("  },\n")
    out.write("};\n")
    out.write("#define OW_SCALAR_CANON_COUNT %du\n\n" % len(SCALAR_CANONICALITY))

    # ---- torsion / malformed points ----
    out.write("/* Valid small-order points: these MUST decode. */\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t enc[32];\n  uint32_t order;\n")
    out.write("} ow_torsion_vector;\n\n")
    out.write("static const ow_torsion_vector ow_torsion_vectors[] = {\n")
    for hexs, order, why in TORSION_POINTS:
        got = point_order(bytes.fromhex(hexs))
        assert got == order, (
            "%s claims order %d, model measured %r" % (hexs, order, got))
        out.write("  /* %s */\n" % why)
        out.write("  {\n    { %s },\n    %du\n  },\n"
                  % (byte_list(bytes.fromhex(hexs)), order))
    out.write("};\n")
    out.write("#define OW_TORSION_VECTOR_COUNT %du\n\n" % len(TORSION_POINTS))

    out.write("/* Encodings that MUST be refused during decompression. */\n")
    out.write("static const uint8_t ow_malformed_points[][32] = {\n")
    for hexs, why in MALFORMED_POINTS:
        raw = bytes.fromhex(hexs)
        assert len(raw) == 32
        assert S._decode_point(raw) is None, (
            "%s is expected to be refused, but the model decoded it" % hexs)
        out.write("  /* %s */\n  { %s },\n"
                  % (why, byte_list(raw)))
    out.write("};\n")
    out.write("#define OW_MALFORMED_POINT_COUNT %du\n\n" % len(MALFORMED_POINTS))

    # ---- point identities ----
    out.write("/* Group-law identities. */\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t a[32];\n  uint8_t b[32];\n  uint8_t want[32];\n")
    out.write("} ow_point_identity;\n\n")
    out.write("static const ow_point_identity ow_point_identities[] = {\n")
    for ahex, bhex, op, wanthex, why in POINT_IDENTITIES:
        assert check_point_identity(ahex, bhex, op, wanthex), why
        out.write("  /* %s */\n" % why)
        out.write("  {\n")
        out.write("    { %s },\n" % byte_list(bytes.fromhex(ahex)))
        out.write("    { %s },\n" % byte_list(bytes.fromhex(bhex)))
        out.write("    { %s }\n" % byte_list(bytes.fromhex(wanthex)))
        out.write("  },\n")
    out.write("};\n")
    out.write("#define OW_POINT_IDENTITY_COUNT %du\n\n"
              % len(POINT_IDENTITIES))

    # ---- Ed25519 signature vectors ----
    out.write("/* Ed25519 signature vectors. */\n")
    out.write("#define OW_ED25519_MAX_MSG 256u\n")
    out.write("typedef struct {\n")
    out.write("  uint8_t pub[32];\n")
    out.write("  uint8_t msg[OW_ED25519_MAX_MSG];\n")
    out.write("  uint8_t sig[64];\n")
    out.write("  uint32_t msg_len;\n  int expect;\n")
    out.write("} ow_ed25519_vector;\n\n")
    out.write("static const ow_ed25519_vector ow_ed25519_vectors[] = {\n")

    base_seed = S.RFC8032_VECTORS[1][0]
    base_pub = S.public_key_from_seed(bytes.fromhex(base_seed))
    base_msg = bytes.fromhex(S.RFC8032_VECTORS[1][1])
    base_sig = bytes.fromhex(S.RFC8032_VECTORS[1][2])
    other_pub = S.public_key_from_seed(bytes.fromhex(S.RFC8032_VECTORS[2][0]))
    identity_enc = ID_ENC
    order2_enc = bytes.fromhex(
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")

    # (why, pub, msg, sig, expect)
    ed_cases = []
    for i, (seed_hex, msg_hex, sig_hex) in enumerate(S.RFC8032_VECTORS, 1):
        seed = bytes.fromhex(seed_hex)
        ed_cases.append(("RFC 8032 vector %d" % i,
                         S.public_key_from_seed(seed),
                         bytes.fromhex(msg_hex), bytes.fromhex(sig_hex), True))
    for length in (0, 1, 2, 3, 31, 32, 33, 64, 127, 128, 255):
        seed = hashlib.sha256(("cis-k-%d" % length).encode()).digest()
        msg = (hashlib.sha256(("cis-m-%d" % length).encode()).digest()
               * ((length + 31) // 32))[:length]
        ed_cases.append(("round trip, %d byte message" % length,
                         S.public_key_from_seed(seed), msg, S.sign(seed, msg),
                         True))

    ed_cases += [
        ("message altered by one bit", base_pub,
         bytes([base_msg[0] ^ 1]), base_sig, False),
        ("empty message against a signed one", base_pub, b"", base_sig, False),
        ("wrong public key", other_pub, base_msg, base_sig, False),
        ("R altered", base_pub, base_msg,
         bytes([base_sig[0] ^ 1]) + base_sig[1:], False),
        ("S altered", base_pub, base_msg,
         base_sig[:32] + bytes([base_sig[32] ^ 1]) + base_sig[33:], False),
        ("all-zero signature", base_pub, base_msg, bytes(64), False),
        ("S replaced with exactly L", base_pub, base_msg,
         base_sig[:32] + L.to_bytes(32, "little"), False),
        ("S = L+1", base_pub, base_msg,
         base_sig[:32] + (L + 1).to_bytes(32, "little"), False),
        ("S at the maximum 32-byte value", base_pub, base_msg,
         base_sig[:32] + b"\xff" * 32, False),
        ("non-canonical R: y above p", base_pub, base_msg,
         b"\xff" * 32 + base_sig[32:], False),
        ("non-canonical R: y = p", base_pub, base_msg,
         P.to_bytes(32, "little") + base_sig[32:], False),
        ("R that is not on the curve", base_pub, base_msg,
         (2).to_bytes(32, "little") + base_sig[32:], False),
        ("R that is a valid torsion point, not on the curve with this A",
         base_pub, base_msg, identity_enc + base_sig[32:], False),
        ("R with the order-2 y", base_pub, base_msg,
         order2_enc + base_sig[32:], False),
        ("public key that is the identity", identity_enc,
         base_msg, base_sig, False),
        ("public key with the order-2 y", order2_enc, base_msg, base_sig, False),
        ("public key above p", b"\xff" * 32, base_msg, base_sig, False),
    ]

    # Cross-check every case against the independent model before emitting, so
    # a mistake in this generator cannot bake a wrong expectation into the
    # C test.  A negative that the model accepts is a real finding, not a
    # vector to discard.
    for why, pub, msg, sig, expect in ed_cases:
        got = S.verify(pub, msg, sig)
        assert got == expect, (
            "model disagrees with generator on %r: model says %r, vector says %r"
            % (why, got, expect))

    for why, pub, msg, sig, expect in ed_cases:
        emit_ed(out, why, pub, msg, sig, expect)

    out.write("};\n")
    out.write("#define OW_ED25519_VECTOR_COUNT %du\n\n" % len(ed_cases))
    out.write("#endif /* CRYPTO_VECTORS_H */\n")


# ---------------------------------------------------------------------------
# SHA-512 inputs
# ---------------------------------------------------------------------------
SHA512_VECTORS = [
    ("the empty message", b""),
    ("\"abc\"", b"abc"),
    ("the two-block FIPS 180-4 example",
     b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
     b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
    ("one byte", b"a"),
    ("exactly one block", b"a" * 128),
    ("one block plus one byte", b"a" * 129),
    ("a message that is all 0xff", b"\xff" * 200),
]

# Size of the fixed message buffer in the emitted ow_sha512_vector.  256 covers
# every vector above and keeps the generated header readable.
SHA512_MAX_MSG = 256


# ---------------------------------------------------------------------------
# The identity in compressed form: x = 0, y = 1.  Defined here rather than
# copied from the C side, because a constant that exists in only one of the two
# implementations is not a cross-check.
ID_ENC = b"\x01" + b"\x00" * 31

# Constants, derived here and checked by identity in the C test
# ---------------------------------------------------------------------------
# d = -121665/121666, and the C test confirms the pair satisfies
# d * 121666 == -121665 rather than trusting either number in isolation.
FIELD_CONSTANTS = [
    ("d", S.D),
    ("d2", (2 * S.D) % P),
    ("sqrtm1", S.SQRT_M1),
    ("bx", S.B[0]),
    ("by", S.B[1]),
    ("bt", S.B[3]),
    ("p", P),
    ("p_minus_2", P - 2),
    ("p_minus_5", P - 5),
    ("exp_sqrt_m5", (P - 5) // 8),
    ("L", L),
    ("d_neg_num", 121665),
    ("d_denom", 121666),
    ("two_pow_248", 1 << 248),
    # Small powers and their inverses.  The inverses exist because fe_pow's
    # exponent byte order is the kind of defect that every other test tolerates:
    # square-and-multiply returns a well-formed field element either way.
    ("two", 2),
    ("four", 4),
    ("inv2", pow(2, P - 2, P)),
    ("inv4", pow(4, P - 2, P)),
]

# A point constant must decode, or the base point is wrong.  The identity and
# the base point are the two the group tests need by name.
POINT_CONSTANTS = [
    ("identity", ID_ENC),
    ("base", S._encode_point(S.B)),
]


def point_order(enc):
    """Exact order of a decoded point, via repeated doubling.

    Returns None if the encoding does not decode.  Compares *encodings*, not
    projective coordinates: projective tuples are equal only up to a common
    factor, so comparing tuples reports a correct point as unmatched.
    """
    point = S._decode_point(bytes(enc))
    if point is None:
        return None
    for order in (1, 2, 4, 8, 16):
        if S._encode_point(S._scalarmult(point, order)) == ID_ENC:
            return order
    return None


def check_point_identity(ahex, bhex, op, wanthex):
    """Confirm the expected point identity against this model."""
    a = S._decode_point(bytes.fromhex(ahex))
    b = S._decode_point(bytes.fromhex(bhex))
    if a is None or b is None:
        return False
    if op == "add":
        got = S._encode_point(S._add(a, b))
    elif op == "mul":
        got = S._encode_point(S._scalarmult(a, int.from_bytes(
            bytes.fromhex(bhex), "little")))
    else:
        raise ValueError("unknown op %r" % op)
    return got == bytes.fromhex(wanthex)


def emit_ed(out, why, pub, msg, sig, expect):
    assert len(msg) <= 256, len(msg)
    out.write("  /* %s */\n" % why)
    out.write("  {\n")
    out.write("    { %s },\n" % byte_list(pub))
    if msg:
        out.write("    { %s },\n" % byte_list(msg))
    else:
        out.write("    { 0U },\n")
    out.write("    { %s },\n" % byte_list(sig))
    out.write("    %du,\n    %s\n" % (len(msg), "1" if expect else "0"))
    out.write("  },\n")


def byte_list(data, per_line=12):
    chunks = []
    for i in range(0, len(data), per_line):
        chunks.append(", ".join("0x%02xU" % b for b in data[i:i + per_line]))
    return ", ".join(chunks)


if __name__ == "__main__":
    main()