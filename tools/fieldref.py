#!/usr/bin/env python3
"""Correct-by-construction reference for the C field arithmetic.

Written to be *obvious*, not fast: each stage is a bounded operation whose
value preservation can be checked by eye.  This models lib/ow_ed25519.c; if the
model is right and the C disagrees, the fault is in the C translation.

The subtlety worth recording, because getting it wrong produces values that
look plausible (1 becomes 0x01ff..ff00..ff):

  16 limbs of 16 bits span 2^256, and 2^256 is NOT congruent to 0 mod p.  So the
  two's-complement-looking wrapped result of a 16-limb subtraction does NOT
  represent (a - b) mod p, and adding p back to it does not repair it.  On
  underflow the only correct move is to form p - (b - a) from the magnitude.
"""
import hashlib

P = 2 ** 255 - 19


def to_limbs(v):
    return [(v >> (16 * i)) & 0xFFFF for i in range(16)]


def from_limbs(limbs):
    return sum(x << (16 * i) for i, x in enumerate(limbs))


def _norm16(t):
    """Normalise 16 limbs in place and return the carry out (a multiple of 38)."""
    for i in range(15):
        t[i + 1] += t[i] >> 16
        t[i] &= 0xFFFF
    carry = t[15] >> 16
    t[15] &= 0xFFFF
    return carry


def _finish(t):
    """Fold any overflow out of the top limb, then reduce below p."""
    while True:
        carry = _norm16(t)
        if carry == 0:
            break
        t[0] += 38 * carry

    # 16 limbs span 2^256 and 2^256 == 2p + 38, so the folded value can land
    # just above 2p.  Subtract p until it is genuinely below p; the loop runs at
    # most three times, and "subtract only once" is what leaves results a hair
    # too large (off by exactly p) in the (p-1)*(p-2) case.
    v = from_limbs(t)
    while v >= P:
        v -= P
    return to_limbs(v)


def cmul(a, b):
    t = [0] * 32
    for i in range(16):
        carry = 0
        for j in range(16):
            cur = t[i + j] + a[i] * b[j] + carry
            t[i + j] = cur & 0xFFFF
            carry = cur >> 16
        t[i + 16] += carry

    # Normalise the high half too, so every folded limb is a true 16-bit value
    # and 38*t[i] is exact.
    for i in range(16, 31):
        t[i + 1] += t[i] >> 16
        t[i] &= 0xFFFF
    while t[31] >> 16:
        t[15] += 38 * (t[31] >> 16)
        t[31] &= 0xFFFF
        for i in range(16, 31):
            t[i + 1] += t[i] >> 16
            t[i] &= 0xFFFF

    # Fold the high half down, descending.
    for i in range(31, 15, -1):
        t[i - 16] += 38 * t[i]

    return _finish(t[:16])


def cadd(a, b):
    t = [a[i] + b[i] for i in range(16)]
    return _finish(t)


def csub(a, b):
    """a - b mod p.

    Detect underflow by magnitude comparison, then form p - (b - a).  Never
    reuse the wrapped difference: 2^256 is not 0 mod p, so the wrap carries
    information that p-cancellation cannot undo.
    """
    for i in range(15, -1, -1):
        if a[i] != b[i]:
            underflow = a[i] < b[i]
            break
    else:
        underflow = False

    if not underflow:
        t = [0] * 16
        borrow = 0
        for i in range(16):
            d = a[i] - b[i] - borrow
            t[i] = d & 0xFFFF
            borrow = 1 if d < 0 else 0
        return _finish(t)

    # Magnitude of (b - a), then p minus that.
    mag = [0] * 16
    borrow = 0
    for i in range(16):
        d = b[i] - a[i] - borrow
        mag[i] = d & 0xFFFF
        borrow = 1 if d < 0 else 0

    t = list(to_limbs(P))
    for i in range(15):
        t[i + 1] += t[i] >> 16
        t[i] &= 0xFFFF
    borrow = 0
    for i in range(16):
        d = t[i] - mag[i] - borrow
        t[i] = d & 0xFFFF
        borrow = 1 if d < 0 else 0
    return _finish(t)


def main():
    vals = [0, 1, 2, 3, P - 1, P - 2, P - 20, 2 ** 240, 2 ** 254, (P - 1) // 2]
    for i in range(30):
        vals.append(int.from_bytes(hashlib.sha256(b"fc%d" % i).digest(), "little") % P)

    bad = 0
    total = 0
    for a in vals:
        for b in vals:
            total += 3
            for name, got_fn, want in (
                ("mul", cmul, (a * b) % P),
                ("add", cadd, (a + b) % P),
                ("sub", csub, (a - b) % P),
            ):
                got = from_limbs(got_fn(to_limbs(a), to_limbs(b)))
                if got != want:
                    bad += 1
                    if bad <= 5:
                        print("%s FAIL a=%x b=%x got=%x want=%x"
                              % (name, a, b, got, want))
    print("%d cases, %d failures" % (total, bad))


if __name__ == "__main__":
    main()