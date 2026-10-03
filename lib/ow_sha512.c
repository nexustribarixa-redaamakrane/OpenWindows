/* ow_sha512.c - Freestanding SHA-512 (FIPS 180-4)
 *
 * Straight transcription of FIPS 180-4 section 6.4 with no substitutions.
 * Added only because Ed25519 (RFC 8032) specifies SHA-512; SHA-256 is still the
 * hash CIS uses for image digests.
 *
 * The length counter carries 64 bits rather than the 128 the standard defines.
 * That is not a simplification of the message limit: 2^64 bytes is far beyond
 * anything addressable on this target, so the discarded high half can never be
 * non-zero for an input this code can be given. */

#include "../inc/ow_sha512.h"

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define BSIG1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SSIG0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SSIG1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static const uint64_t K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL,
    0xE9B5DBA58189DBBCULL, 0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL,
    0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL, 0xD807AA98A3030242ULL,
    0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL,
    0xC19BF174CF692694ULL, 0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL,
    0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL, 0x2DE92C6F592B0275ULL,
    0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL,
    0xBF597FC7BEEF0EE4ULL, 0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL,
    0x06CA6351E003826FULL, 0x142929670A0E6E70ULL, 0x27B70A8546D22FFCULL,
    0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL,
    0x92722C851482353BULL, 0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL,
    0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL, 0xD192E819D6EF5218ULL,
    0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL,
    0x34B0BCB5E19B48A8ULL, 0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL,
    0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL, 0x748F82EE5DEFB2FCULL,
    0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL,
    0xC67178F2E372532BULL, 0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL,
    0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL, 0x06F067AA72176FBAULL,
    0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL,
    0x431D67C49C100D4CULL, 0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL,
    0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

static void sha512_transform(ow_sha512_ctx_t *ctx, const uint8_t block[128]) {
    uint64_t w[80];
    uint64_t a, b, c, d, e, f, g, h;
    uint64_t t1, t2;
    int t;

    for (t = 0; t < 16; t++) {
        w[t] = ((uint64_t)block[t * 8] << 56) |
               ((uint64_t)block[t * 8 + 1] << 48) |
               ((uint64_t)block[t * 8 + 2] << 40) |
               ((uint64_t)block[t * 8 + 3] << 32) |
               ((uint64_t)block[t * 8 + 4] << 24) |
               ((uint64_t)block[t * 8 + 5] << 16) |
               ((uint64_t)block[t * 8 + 6] << 8) |
               ((uint64_t)block[t * 8 + 7]);
    }
    for (t = 16; t < 80; t++) {
        w[t] = SSIG1(w[t - 2]) + w[t - 7] + SSIG0(w[t - 15]) + w[t - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (t = 0; t < 80; t++) {
        t1 = h + BSIG1(e) + CH(e, f, g) + K[t] + w[t];
        t2 = BSIG0(a) + MAJ(a, b, c);
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

void ow_sha512_init(ow_sha512_ctx_t *ctx) {
    ctx->state[0] = 0x6A09E667F3BCC908ULL;
    ctx->state[1] = 0xBB67AE8584CAA73BULL;
    ctx->state[2] = 0x3C6EF372FE94F82BULL;
    ctx->state[3] = 0xA54FF53A5F1D36F1ULL;
    ctx->state[4] = 0x510E527FADE682D1ULL;
    ctx->state[5] = 0x9B05688C2B3E6C1FULL;
    ctx->state[6] = 0x1F83D9ABFB41BD6BULL;
    ctx->state[7] = 0x5BE0CD19137E2179ULL;
    ctx->count_lo = 0;
}

void ow_sha512_update(ow_sha512_ctx_t *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t have = (size_t)(ctx->count_lo % 128u);
    size_t i;

    if (len == 0u) {
        return;
    }

    /* Top up a partially filled block first.  count_lo is advanced as bytes are
     * consumed rather than once at the top, so `have` stays the true offset
     * into the block for the next call. */
    if (have != 0u) {
        size_t need = 128u - have;
        size_t take = (len < need) ? len : need;

        for (i = 0; i < take; i++) {
            ctx->buffer[have + i] = p[i];
        }
        ctx->count_lo += (uint64_t)take;
        p += take;
        len -= take;

        if (have + take < 128u) {
            return; /* still a partial block; nothing to compress yet */
        }
        sha512_transform(ctx, ctx->buffer);
    }

    while (len >= 128u) {
        sha512_transform(ctx, p);
        p += 128u;
        len -= 128u;
        ctx->count_lo += 128u;
    }

    for (i = 0; i < len; i++) {
        ctx->buffer[i] = p[i];
    }
    ctx->count_lo += (uint64_t)len;
}

void ow_sha512_final(ow_sha512_ctx_t *ctx, uint8_t digest[OW_SHA512_DIGEST_SIZE]) {
    uint64_t bitlen = ctx->count_lo << 3;
    size_t have = (size_t)(ctx->count_lo % 128u);
    size_t i;
    uint8_t tail[256];
    size_t taillen;

    tail[0] = 0x80;
    /* One block of zeros when the message ends within 111 bytes of the block
     * boundary, otherwise pad out to the next block. */
    taillen = (have < 112u) ? (128u - have) : (256u - have);
    for (i = 1; i < taillen; i++) {
        tail[i] = 0;
    }
    for (i = 0; i < 8; i++) {
        tail[taillen - 1u - i] = (uint8_t)(bitlen >> (8u * i));
    }

    /* Feed the padding through the same buffering path.  count_lo is saved and
     * restored because padding bytes are not message bytes. */
    {
        uint64_t saved = ctx->count_lo;
        ow_sha512_update(ctx, tail, taillen);
        ctx->count_lo = saved;
    }

    for (i = 0; i < 8; i++) {
        int b;
        for (b = 0; b < 8; b++) {
            digest[i * 8u + (size_t)b] =
                (uint8_t)(ctx->state[i] >> (56u - 8u * (unsigned)b));
        }
    }
}

void ow_sha512(const void *data, size_t len, uint8_t digest[OW_SHA512_DIGEST_SIZE]) {
    ow_sha512_ctx_t ctx;

    ow_sha512_init(&ctx);
    ow_sha512_update(&ctx, data, len);
    ow_sha512_final(&ctx, digest);
}
