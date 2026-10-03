#!/usr/bin/env python3
"""Ed25519 signing for OpenWindows Copyleft Integrity Safeguard (CIS).

This tool is the *writer* half of CIS and is deliberately kept out of the
kernel build.  The target only ever verifies; a signing capability inside
openwinkrnl.owx would mean the private key ships in the same artifact the
signature is supposed to vouch for.

It also exists as an independent second derivation of the curve: ow_ed25519.c
and this file share no code and no constants, so a signature produced here and
accepted there is evidence that both are correct, rather than evidence that
both are wrong in the same way.

Pure Python on purpose.  No third-party dependency means no wheel to pin, no
build step, and a tool a reviewer can read end to end.  Python is not fast,
which is fine: this signs a handful of images per release, in an offline
environment, next to the release key.

Usage:
  cis_sign.py selftest                 RFC 8032 known-answer tests
  cis_sign.py keygen --out-key K --out-pub P   development keypair
  cis_sign.py sign --key K --input FILE --output FILE.owx
  cis_sign.py verify --pub P --input FILE [--signature SIG]
"""

import argparse
import hashlib
import sys

# ---------------------------------------------------------------------------
# Curve parameters, derived rather than copied.
#
# Everything below is computed from p and the two curve-defining constants, so
# a typo cannot be introduced by transcribing a long literal from a spec.  The
# results are cross-checked against RFC 8032 by selftest().
# ---------------------------------------------------------------------------

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = (-121665 * _inv(121666)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    """Recover the x matching an encoded y and sign bit, or None."""
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return x


# Base point: the point with y = 4/5, per RFC 8032 section 5.1.
_BY = 4 * _inv(5) % P
_BX = _recover_x(_BY, 0)
B = (_BX, _BY, 1, _BX * _BY % P)
IDENTITY = (0, 1, 1, 0)


def _add(p, q):
    """Extended twisted-Edwards addition."""
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(point, scalar):
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode_point(point):
    x, y, z, _t = point
    zi = _inv(z)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode_point(data):
    """Decompress a point encoding, rejecting non-canonical y.  Returns None on
    failure so callers cannot accidentally use an unvalidated key."""
    if len(data) != 32:
        return None
    value = int.from_bytes(data, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= P:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def _sha512_int(*chunks):
    h = hashlib.sha512()
    for chunk in chunks:
        h.update(chunk)
    return int.from_bytes(h.digest(), "little")


def _clamp(h32):
    a = bytearray(h32)
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return int.from_bytes(bytes(a), "little")


def public_key_from_seed(seed):
    """Derive the 32-byte public key from a 32-byte seed (the "private key")."""
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    return _encode_point(_scalarmult(B, _clamp(h[:32])))


def sign(seed, message):
    """RFC 8032 Ed25519 signature.  Returns 64 bytes."""
    if len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    h = hashlib.sha512(seed).digest()
    a = _clamp(h[:32])
    prefix = h[32:]
    pub = _encode_point(_scalarmult(B, a))
    r = _sha512_int(prefix, message) % L
    rp = _encode_point(_scalarmult(B, r))
    k = _sha512_int(rp, pub, message) % L
    s = (r + k * a) % L
    return rp + s.to_bytes(32, "little")


def verify(pub, message, signature):
    """Verification, for the signer's own self-test.  The kernel verifier in
    ow_ed25519.c is the implementation that actually gates image loading."""
    if len(signature) != 64 or len(pub) != 32:
        return False
    a = _decode_point(pub)
    if a is None:
        return False
    rp = _decode_point(signature[:32])
    if rp is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = _sha512_int(signature[:32], pub, message) % L
    return _encode_point(_scalarmult(B, s)) == _encode_point(
        _add(rp, _scalarmult(a, k))
    )


# ---------------------------------------------------------------------------
# RFC 8032 known-answer tests
#
# If these do not pass, the derived constants above are wrong and nothing this
# tool signs can be trusted, so selftest() runs before any other command.
# ---------------------------------------------------------------------------

RFC8032_VECTORS = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
    (
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3a"
        "c18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    ),
    (
        # SHA(abc): a single-block hash fed through the nonce path.
        "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58"
        "909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    ),
]

# Message lengths for generated round-trip tests.  0 and 1 straddle the empty
# and minimal cases, 31/32/33 straddle the SHA-512 block boundary, and 1023
# forces a multi-block hash with a reduced scalar.
ROUNDTRIP_LENGTHS = [0, 1, 31, 32, 33, 127, 128, 255, 1023]


def selftest(verbose=True):
    failures = 0
    for i, (seed_hex, msg_hex, sig_hex) in enumerate(RFC8032_VECTORS, 1):
        seed = bytes.fromhex(seed_hex)
        msg = bytes.fromhex(msg_hex)
        want = bytes.fromhex(sig_hex)
        got = sign(seed, msg)
        ok = got == want and verify(public_key_from_seed(seed), msg, got)
        failures += 0 if ok else 1
        if verbose:
            print(f"  RFC 8032 vector {i}: {'ok' if ok else 'FAILED'}")

    # Round-trips across message sizes, including lengths that force multi-block
    # SHA-512 and a scalar needing reduction.
    for length in ROUNDTRIP_LENGTHS:
        seed = hashlib.sha256(b"cis-selftest-seed-%d" % length).digest()
        msg = hashlib.sha256(b"cis-selftest-msg-%d" % length).digest() * (
            (length + 31) // 32)
        msg = msg[:length]
        sig = sign(seed, msg)
        ok = verify(public_key_from_seed(seed), msg, sig)
        failures += 0 if ok else 1
        if verbose:
            print(f"  round trip {length:5d} bytes: {'ok' if ok else 'FAILED'}")

    # A signature must not verify against a different message, a different key,
    # or an altered signature.
    seed = bytes.fromhex(RFC8032_VECTORS[1][0])
    pub = public_key_from_seed(seed)
    sig = sign(seed, b"\x72")
    other = public_key_from_seed(bytes.fromhex(RFC8032_VECTORS[2][0]))
    cases = [
        ("altered message", pub, b"\x73", sig, False),
        ("wrong key", other, b"\x72", sig, False),
        ("altered R", pub, b"\x72", bytes([sig[0] ^ 1]) + sig[1:], False),
        ("altered S", pub, b"\x72", sig[:32] + bytes([sig[32] ^ 1]) + sig[33:],
         False),
        ("zero signature", pub, b"\x72", bytes(64), False),
    ]
    for name, pk, msg, sg, want in cases:
        got = verify(pk, msg, sg)
        failures += 0 if got == want else 1
        if verbose:
            print(f"  {name}: {'ok' if got == want else 'FAILED'}")

    return failures


def main(argv=None):
    parser = argparse.ArgumentParser(description="OpenWindows CIS Ed25519 signer")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("selftest", help="run RFC 8032 known-answer tests")

    kg = sub.add_parser("keygen", help="derive a public key from a seed")
    kg.add_argument("--out-key", required=True)
    kg.add_argument("--out-pub", required=True)

    sg = sub.add_parser("sign", help="sign a CIS manifest for an OWX image")
    sg.add_argument("--key", required=True)
    sg.add_argument("--input", required=True)
    sg.add_argument("--output", required=True)

    vf = sub.add_parser("verify", help="verify a signature (offline tooling only)")
    vf.add_argument("--pub", required=True)
    vf.add_argument("--input", required=True)
    vf.add_argument("--signature", required=True)

    args = parser.parse_args(argv)

    if args.command == "selftest":
        failures = selftest()
        if failures:
            print(f"selftest FAILED ({failures})", file=sys.stderr)
            return 1
        print("selftest passed")
        return 0

    if args.command == "keygen":
        with open(args.out_key, "rb") as fh:
            seed = fh.read()
        pub = public_key_from_seed(seed)
        with open(args.out_pub, "wb") as fh:
            fh.write(pub)
        print(f"wrote public key {args.out_pub}")
        return 0

    with open(args.input, "rb") as fh:
        data = fh.read()

    if args.command == "sign":
        with open(args.key, "rb") as fh:
            seed = fh.read()
        signature = sign(seed, data)
        with open(args.output, "wb") as fh:
            fh.write(signature)
        print(f"wrote signature {args.output}")
        return 0

    with open(args.pub, "rb") as fh:
        pub = fh.read()
    with open(args.signature, "rb") as fh:
        signature = fh.read()
    if verify(pub, data, signature):
        print("valid")
        return 0
    print("INVALID", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
