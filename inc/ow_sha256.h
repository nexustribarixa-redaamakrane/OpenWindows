/* ow_sha256.h - Freestanding SHA-256 implementation for OpenWindows */
#ifndef OW_SHA256_H
#define OW_SHA256_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define OW_SHA256_DIGEST_SIZE 32
#define OW_SHA256_HEX_SIZE 65 /* 64 hex characters + null terminator */

typedef struct {
  uint32_t state[8];
  uint64_t count;     /* Number of bytes processed */
  uint8_t buffer[64]; /* 512-bit input block buffer */
} ow_sha256_ctx_t;

void ow_sha256_init(ow_sha256_ctx_t *ctx);
void ow_sha256_update(ow_sha256_ctx_t *ctx, const void *data, size_t len);
void ow_sha256_final(ow_sha256_ctx_t *ctx,
                     uint8_t digest[OW_SHA256_DIGEST_SIZE]);

/* One-shot SHA-256 calculation */
void ow_sha256(const void *data, size_t len,
               uint8_t digest[OW_SHA256_DIGEST_SIZE]);

/* Convert 32-byte binary digest to 64-char lowercase hex string
 * (null-terminated) */
void ow_sha256_to_hex(const uint8_t digest[OW_SHA256_DIGEST_SIZE],
                      char hex_out[OW_SHA256_HEX_SIZE]);

/* Compare two 64-character hex strings case-insensitively. Returns true if
 * identical. */
bool ow_sha256_hex_equal(const char *hex_a, const char *hex_b);

#endif /* OW_SHA256_H */
