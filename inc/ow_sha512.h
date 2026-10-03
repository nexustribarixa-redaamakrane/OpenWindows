/* ow_sha512.h - Freestanding SHA-512 (FIPS 180-4)
 *
 * Added for Ed25519 (RFC 8032), which specifies SHA-512 as its only hash and
 * cannot be implemented without it.  SHA-256 remains the hash used for image
 * digests and every pre-existing caller; this is a second primitive for a
 * second protocol, not a replacement.
 *
 * Self-contained: no external dependencies, safe for early boot and kernel. */
#ifndef OW_SHA512_H
#define OW_SHA512_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OW_SHA512_DIGEST_SIZE 64
#define OW_SHA512_BLOCK_SIZE 128

typedef struct {
  uint64_t state[8];
  uint64_t count_lo; /* Message length in bytes, low 64 bits.  The full 128-bit
                      * length field is irrelevant for any message that fits in
                      * the address space of this kernel, and the wrap that
                      * would need it cannot be reached. */
  uint8_t buffer[OW_SHA512_BLOCK_SIZE];
} ow_sha512_ctx_t;

void ow_sha512_init(ow_sha512_ctx_t *ctx);
void ow_sha512_update(ow_sha512_ctx_t *ctx, const void *data, size_t len);
void ow_sha512_final(ow_sha512_ctx_t *ctx,
                     uint8_t digest[OW_SHA512_DIGEST_SIZE]);
void ow_sha512(const void *data, size_t len,
               uint8_t digest[OW_SHA512_DIGEST_SIZE]);

#endif /* OW_SHA512_H */
