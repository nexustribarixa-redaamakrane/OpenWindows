/* ow_ed25519.h - Ed25519 signature VERIFICATION (RFC 8032)
 *
 * Verify-only, deliberately.  The kernel holds public keys and no signing
 * capability whatsoever; there is no sign function here and no way to add one
 * without changing this header's contract.  Signing is release tooling's job
 * and lives outside the target (tools/cis_sign.py).
 *
 * Verification is the cheap direction to implement correctly: it operates
 * entirely on public data (a public key, a signature, and a message), so
 * there is no secret-dependent branch and therefore no secret-dependent timing
 * leak to get wrong.  That property is the reason this is safe to implement
 * in-tree at all, and it is also why the private half of a release key must
 * never be present here -- with verify-only, holding the private key would buy
 * an attacker nothing this function would help them use.
 *
 * What is enforced, beyond the RFC equation:
 *
 *   - the public key must be a canonical point encoding (y < p, x recoverable)
 *   - the scalar S must be canonically reduced (S < L)
 *   - R must be a canonical point encoding
 *   - a signature of all-zero bytes is rejected
 *
 * Known limitation, stated rather than hidden: the RFC 8032 equation is
 * checked without multiplying through the group cofactor, as most
 * implementations do.  That admits a narrow class of malleable-signature
 * encodings under an adversarial public key.  The kernel never accepts a
 * caller-supplied public key -- every key comes from the pinned trust store --
 * so the attacker cannot choose the key and cannot exploit this.  If CIS ever
 * grows a path that verifies against a caller-supplied key, this must move to
 * the cofactored equation first.
 *
 * C99 freestanding, no dynamic allocation, no floating point. */
#ifndef OW_ED25519_H
#define OW_ED25519_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OW_ED25519_PUBLIC_KEY_SIZE 32
#define OW_ED25519_SIGNATURE_SIZE  64

/* Verify an Ed25519 signature.
 *
 *   public_key  32 bytes, RFC 8032 compressed point
 *   signature   64 bytes, little-endian R (32) || S (32)
 *   message     the exact bytes that were signed
 *
 * Returns true only for a well-formed signature that verifies.  Every failure
 * mode -- malformed key, malformed signature, non-reduced scalar, altered
 * message, wrong key -- returns false; this function has one bit of output
 * because the caller learns WHICH failure from the surrounding verification
 * pipeline, which distinguishes them by what it checked and in what order. */
bool ow_crypto_ed25519_verify(
    const uint8_t public_key[OW_ED25519_PUBLIC_KEY_SIZE],
    const uint8_t signature[OW_ED25519_SIGNATURE_SIZE],
    const uint8_t *message,
    size_t message_len);

#endif /* OW_ED25519_H */
