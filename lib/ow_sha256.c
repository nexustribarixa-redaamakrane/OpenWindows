/* ow_sha256.c - Freestanding SHA-256 implementation (FIPS 180-4)
 * Self-contained: zero external dependencies, safe for early boot and kernel. */
#include "../inc/ow_sha256.h"

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIGMA1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIGMA_LOWER0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIGMA_LOWER1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K[64] = {
    0x428A2F98U, 0x71374491U, 0xB5C0FBCFU, 0xE9B5DBA5U,
    0x3956C25BU, 0x59F111F1U, 0x923F82A4U, 0xAB1C5ED5U,
    0xD807AA98U, 0x12835B01U, 0x243185BEU, 0x550C7DC3U,
    0x72BE5D74U, 0x80DEB1FEU, 0x9BDC06A7U, 0xC19BF174U,
    0xE49B69C1U, 0xEFBE4786U, 0x0FC19DC6U, 0x240CA1CCU,
    0x2DE92C6FU, 0x4A7484AAU, 0x5CB0A9DCU, 0x76F988DAU,
    0x983E5152U, 0xA831C66DU, 0xB00327C8U, 0xBF597FC7U,
    0xC6E00BF3U, 0xD5A79147U, 0x06CA6351U, 0x14292967U,
    0x27B70A85U, 0x2E1B2138U, 0x4D2C6DFCU, 0x53380D13U,
    0x650A7354U, 0x766A0ABBU, 0x81C2C92EU, 0x92722C85U,
    0xA2BFE8A1U, 0xA81A664BU, 0xC24B8B70U, 0xC76C51A3U,
    0xD192E819U, 0xD6990624U, 0xF40E3585U, 0x106AA070U,
    0x19A4C116U, 0x1E376C08U, 0x2748774CU, 0x34B0BCB5U,
    0x391C0CB3U, 0x4ED8AA4AU, 0x5B9CCA4FU, 0x682E6FF3U,
    0x748F82EEU, 0x78A5636FU, 0x84C87814U, 0x8CC70208U,
    0x90BEFFFAU, 0xA4506CEBU, 0xBEF9A3F7U, 0xC67178F2U
};

static void sha256_transform(ow_sha256_ctx_t* ctx, const uint8_t block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t;

    for (t = 0; t < 16; t++) {
        w[t] = ((uint32_t)block[t * 4] << 24) |
               ((uint32_t)block[t * 4 + 1] << 16) |
               ((uint32_t)block[t * 4 + 2] << 8) |
               ((uint32_t)block[t * 4 + 3]);
    }

    for (t = 16; t < 64; t++) {
        w[t] = SIGMA_LOWER1(w[t - 2]) + w[t - 7] +
               SIGMA_LOWER0(w[t - 15]) + w[t - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (t = 0; t < 64; t++) {
        uint32_t t1 = h + SIGMA1(e) + CH(e, f, g) + K[t] + w[t];
        uint32_t t2 = SIGMA0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void ow_sha256_init(ow_sha256_ctx_t* ctx) {
    if (!ctx) return;
    ctx->state[0] = 0x6A09E667U;
    ctx->state[1] = 0xBB67AE85U;
    ctx->state[2] = 0x3C6EF372U;
    ctx->state[3] = 0xA54FF53AU;
    ctx->state[4] = 0x510E527FU;
    ctx->state[5] = 0x9B05688CU;
    ctx->state[6] = 0x1F83D9ABU;
    ctx->state[7] = 0x5BE0CD19U;
    ctx->count = 0;
}

void ow_sha256_update(ow_sha256_ctx_t* ctx, const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    size_t buffer_bytes;

    if (!ctx || !data || len == 0) return;

    buffer_bytes = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    if (buffer_bytes > 0) {
        size_t needed = 64 - buffer_bytes;
        if (len < needed) {
            size_t i;
            for (i = 0; i < len; i++) {
                ctx->buffer[buffer_bytes + i] = p[i];
            }
            return;
        }
        for (size_t i = 0; i < needed; i++) {
            ctx->buffer[buffer_bytes + i] = p[i];
        }
        sha256_transform(ctx, ctx->buffer);
        p += needed;
        len -= needed;
    }

    while (len >= 64) {
        sha256_transform(ctx, p);
        p += 64;
        len -= 64;
    }

    if (len > 0) {
        for (size_t i = 0; i < len; i++) {
            ctx->buffer[i] = p[i];
        }
    }
}

void ow_sha256_final(ow_sha256_ctx_t* ctx, uint8_t digest[OW_SHA256_DIGEST_SIZE]) {
    uint8_t pad[64];
    uint64_t total_bits;
    size_t buffer_bytes;
    size_t pad_len;

    if (!ctx || !digest) return;

    total_bits = ctx->count * 8ULL;
    buffer_bytes = (size_t)(ctx->count & 0x3F);

    pad[0] = 0x80;
    for (size_t i = 1; i < 64; i++) pad[i] = 0;

    if (buffer_bytes < 56) {
        pad_len = 56 - buffer_bytes;
    } else {
        pad_len = (64 + 56) - buffer_bytes;
    }
    ow_sha256_update(ctx, pad, pad_len);

    /* Append 64-bit big-endian bit count */
    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)((total_bits >> (i * 8)) & 0xFF);
        ow_sha256_update(ctx, &b, 1);
    }

    /* Output big-endian state */
    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        digest[i * 4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i * 4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i * 4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
}

void ow_sha256(const void* data, size_t len, uint8_t digest[OW_SHA256_DIGEST_SIZE]) {
    ow_sha256_ctx_t ctx;
    ow_sha256_init(&ctx);
    ow_sha256_update(&ctx, data, len);
    ow_sha256_final(&ctx, digest);
}

void ow_sha256_to_hex(const uint8_t digest[OW_SHA256_DIGEST_SIZE], char hex_out[OW_SHA256_HEX_SIZE]) {
    static const char hex_digits[] = "0123456789abcdef";
    if (!digest || !hex_out) return;
    for (int i = 0; i < OW_SHA256_DIGEST_SIZE; i++) {
        hex_out[i * 2]     = hex_digits[(digest[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_digits[digest[i] & 0x0F];
    }
    hex_out[64] = '\0';
}

static char to_lower_char(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + ('a' - 'A'));
    return c;
}

bool ow_sha256_hex_equal(const char* hex_a, const char* hex_b) {
    if (!hex_a || !hex_b) return false;
    for (int i = 0; i < 64; i++) {
        if (to_lower_char(hex_a[i]) != to_lower_char(hex_b[i])) return false;
    }
    return true;
}
