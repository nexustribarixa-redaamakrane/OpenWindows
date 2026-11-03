/*
 * sufrender_host.c - hosted end-to-end check for the OpenWindows terminal SUF.
 *
 * This is deliberately not a "does the file exist" smoke test.  It loads the
 * binary asset through the production sufrender library, validates the SUF
 * header, walks the cmap, rasterises real text into a 32bpp framebuffer, and
 * then re-reads every pixel against the cached SUF glyph bitmap.  It also
 * writes a PPM so the output can be inspected visually.
 *
 * Exit status is zero only when every check passes.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../OpenWindows-Essentials/DLL/sufrender/sufrender.h"

#ifndef OW_SUFRENDER_ASSET
#define OW_SUFRENDER_ASSET "assets/openwindows-terminal.suf"
#endif

#ifndef OW_SUFRENDER_PPM
#define OW_SUFRENDER_PPM "sufrender.ppm"
#endif

#define PROOF_WIDTH   (8u * 80u)
#define PROOF_HEIGHT  16u
#define PROOF_FG      0xFFE8E8E8u
#define PROOF_BG      0xFF101010u

static int g_failures;

static void check(bool condition, const char *what)
{
    if (condition) {
        printf("[PASS] %s\n", what);
    } else {
        printf("[FAIL] %s\n", what);
        ++g_failures;
    }
}

static unsigned glyph_bits(const uint8_t *bitmap)
{
    unsigned bits = 0u;
    unsigned row;
    for (row = 0u; row < SUF_GLYPH_HEIGHT; ++row) {
        uint8_t value = bitmap[row];
        while (value != 0u) {
            bits += (unsigned)(value & 1u);
            value >>= 1;
        }
    }
    return bits;
}

static bool pixels_match(const uint32_t *fb, uint32_t pitch, uint32_t x,
                         uint32_t y, const uint8_t *bitmap, uint32_t fg,
                         uint32_t bg)
{
    uint32_t row;
    for (row = 0u; row < SUF_GLYPH_HEIGHT; ++row) {
        uint32_t col;
        for (col = 0u; col < SUF_GLYPH_WIDTH; ++col) {
            uint32_t expected = (bitmap[row] & (0x80u >> col)) != 0u ? fg : bg;
            if (fb[(y + row) * pitch + x + col] != expected) {
                return false;
            }
        }
    }
    return true;
}

static uint8_t *read_file(const char *path, size_t *out_size)
{
    FILE *file = fopen(path, "rb");
    long length;
    uint8_t *data;

    if (file == NULL) {
        return NULL;
    }
    if (fseek(file, 0L, SEEK_END) != 0) {
        fclose(file);
        return NULL;
    }
    length = ftell(file);
    if (length < 0 || fseek(file, 0L, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    data = (uint8_t *)malloc((size_t)length);
    if (data == NULL) {
        fclose(file);
        return NULL;
    }
    if (length > 0 && fread(data, 1u, (size_t)length, file) !=
                          (size_t)length) {
        free(data);
        fclose(file);
        return NULL;
    }
    fclose(file);
    *out_size = (size_t)length;
    return data;
}

static bool write_ppm(const char *path, const uint32_t *fb, uint32_t width,
                      uint32_t height, uint32_t pitch)
{
    FILE *file = fopen(path, "wb");
    uint32_t x;
    uint32_t y;

    if (file == NULL) {
        return false;
    }
    if (fprintf(file, "P6\n%u %u\n255\n", width, height) < 0) {
        fclose(file);
        return false;
    }
    for (y = 0u; y < height; ++y) {
        for (x = 0u; x < width; ++x) {
            uint32_t pixel = fb[y * pitch + x];
            unsigned char rgb[3];
            rgb[0] = (unsigned char)((pixel >> 16) & 0xFFu);
            rgb[1] = (unsigned char)((pixel >> 8) & 0xFFu);
            rgb[2] = (unsigned char)(pixel & 0xFFu);
            if (fwrite(rgb, 1u, sizeof(rgb), file) != sizeof(rgb)) {
                fclose(file);
                return false;
            }
        }
    }
    if (fclose(file) != 0) {
        return false;
    }
    return true;
}

int main(int argc, char **argv)
{
    const char *asset_path = argc > 1 ? argv[1] : OW_SUFRENDER_ASSET;
    const char *ppm_path = argc > 2 ? argv[2] : OW_SUFRENDER_PPM;
    static const uint8_t proof[] = "OpenWindows SUF 8x16  AZ09? ~az";
    static const size_t proof_length = sizeof(proof) - 1u;
    static uint32_t framebuffer[PROOF_WIDTH * PROOF_HEIGHT];
    static const uint32_t probe_cps[] = {
        0x20u, 0x41u, 0x5Au, 0x30u, 0x39u, 0x21u, 0x2Eu, 0x7Eu
    };
    static const char *const probe_names[] = {
        "space", "A", "Z", "0", "9", "!", ".", "~"
    };
    static const uint32_t probe_gids[] = {
        1u, 34u, 59u, 17u, 26u, 2u, 15u, 95u
    };
    static const unsigned probe_bits[] = {
        0u, 39u, 36u, 48u, 35u, 24u, 4u, 10u
    };
    suf_header_t header;
    suf_font_face_t font;
    uint8_t *asset;
    size_t asset_size = 0u;
    uint32_t cmap_count;
    uint32_t cp;
    uint32_t rendered = 0u;
    uint32_t matched = 0u;
    bool printable_complete = true;
    bool probes_ok = true;
    unsigned i;

    asset = read_file(asset_path, &asset_size);
    printf("asset: %s (%lu bytes)\n", asset_path,
           (unsigned long)asset_size);
    check(asset != NULL && asset_size == 4016u, "asset read (4016 bytes)");
    if (asset == NULL) {
        printf("RESULT: FAIL (%d failures)\n", g_failures);
        return 1;
    }

    check(suf_validate_header(asset, asset_size, &header) == SUF_OK,
          "SUF header validates");
    printf("header: magic=0x%08lX version=%u flags=0x%04X glyphs=%lu\n",
           (unsigned long)header.magic, (unsigned)header.version,
           (unsigned)header.flags, (unsigned long)header.glyph_count);
    check(header.magic == SUF_MAGIC, "magic is SUF1");
    check(header.version == SUF_VERSION_CURRENT, "version is current");
    check((header.flags & SUF_FLAG_BOOT_BITMAP) != 0u,
          "boot bitmap flag is set");
    check(header.glyph_count == 96u, "glyph count is 96");
    check(header.boot_bitmap_width == 8u, "boot bitmap width is 8");
    check(header.boot_bitmap_height == 16u, "boot bitmap height is 16");
    check(header.boot_bitmap_bpp == 1u, "boot bitmap is 1bpp");

    check(header.cmap_size % sizeof(suf_cmap_entry_t) == 0u,
          "cmap is entry-aligned");
    cmap_count = header.cmap_size / (uint32_t)sizeof(suf_cmap_entry_t);
    printf("cmap: %lu entries\n", (unsigned long)cmap_count);
    check(cmap_count == 96u, "cmap has 96 entries");
    for (cp = 0x20u; cp <= 0x7Eu; ++cp) {
        uint32_t glyph_id = 0xFFFFFFFFu;
        const uint8_t *bitmap = NULL;
        size_t bitmap_size = 0u;
        if (suf_lookup_glyph_id(asset, asset_size, cp, &glyph_id) != SUF_OK ||
            suf_get_boot_bitmap(asset, asset_size, glyph_id, &bitmap,
                                &bitmap_size) != SUF_OK ||
            bitmap_size != 16u || bitmap == NULL) {
            printable_complete = false;
        }
    }
    check(printable_complete, "complete printable ASCII cmap 0x20..0x7E");

    {
        uint32_t fallback_gid = 0xFFFFFFFFu;
        const uint8_t *fallback = NULL;
        size_t fallback_size = 0u;
        check(suf_lookup_glyph_id(asset, asset_size, 0u, &fallback_gid) ==
                      SUF_OK &&
                  fallback_gid == 0u,
              "fallback codepoint 0x0 maps to glyph 0");
        check(suf_get_boot_bitmap(asset, asset_size, 0u, &fallback,
                                  &fallback_size) == SUF_OK &&
                  fallback_size == 16u && fallback != NULL &&
                  glyph_bits(fallback) == 54u,
              "fallback glyph 0 has a non-empty 8x16 bitmap");
    }

    check(sufrender_load_suf(&font, asset, asset_size),
          "sufrender_load_suf accepts the asset");
    printf("sufrender cache: %lu glyphs\n", (unsigned long)font.glyph_count);

    for (i = 0u; i < sizeof(probe_cps) / sizeof(probe_cps[0]); ++i) {
        const uint8_t *bitmap = sufrender_get_glyph(&font, probe_cps[i]);
        uint32_t glyph_id = 0xFFFFFFFFu;
        if (suf_lookup_glyph_id(asset, asset_size, probe_cps[i], &glyph_id) !=
                SUF_OK ||
            bitmap == NULL || glyph_id != probe_gids[i] ||
            glyph_bits(bitmap) != probe_bits[i]) {
            probes_ok = false;
            printf("[FAIL] probe %s: gid=%lu bits=%u\n", probe_names[i],
                   (unsigned long)glyph_id,
                   bitmap == NULL ? 0u : glyph_bits(bitmap));
        } else {
            printf("[PASS] probe %-5s cp=0x%02lX gid=%lu bits=%u\n",
                   probe_names[i], (unsigned long)probe_cps[i],
                   (unsigned long)glyph_id, glyph_bits(bitmap));
        }
    }
    check(probes_ok, "representative glyph lookups and bitmaps");

    for (i = 0u; i < PROOF_WIDTH * PROOF_HEIGHT; ++i) {
        framebuffer[i] = 0xDEADBEEFu;
    }
    for (i = 0u; i < proof_length; ++i) {
        const uint8_t *bitmap = sufrender_get_glyph(&font,
                                                    (uint32_t)proof[i]);
        if (bitmap == NULL) {
            printf("[FAIL] render: no glyph for '%c'\n", proof[i]);
            ++g_failures;
            continue;
        }
        sufrender_blit_char(framebuffer, PROOF_WIDTH * sizeof(uint32_t),
                            (int32_t)(i * 8u), 0,
                            bitmap, PROOF_FG, PROOF_BG);
        ++rendered;
    }
    printf("render: \"%s\" -> %lu glyphs\n", proof,
           (unsigned long)rendered);
    check(rendered == proof_length, "every proof character resolved a glyph");

    for (i = 0u; i < proof_length; ++i) {
        const uint8_t *bitmap = sufrender_get_glyph(&font,
                                                    (uint32_t)proof[i]);
        if (bitmap != NULL &&
            pixels_match(framebuffer, PROOF_WIDTH, i * 8u, 0u, bitmap,
                         PROOF_FG, PROOF_BG)) {
            ++matched;
        } else {
            printf("[FAIL] pixel mismatch at cell %u ('%c')\n", i, proof[i]);
        }
    }
    printf("pixels: %lu/%lu cells match the SUF glyph bitmaps\n",
           (unsigned long)matched, (unsigned long)proof_length);
    check(matched == proof_length, "framebuffer pixels match SUF bitmaps");

    check(write_ppm(ppm_path, framebuffer, (uint32_t)proof_length * 8u,
                    PROOF_HEIGHT, PROOF_WIDTH),
          "PPM written");
    printf("ppm: %s\n", ppm_path);

    free(asset);
    printf("RESULT: %s (%d failures)\n", g_failures == 0 ? "PASS" : "FAIL",
           g_failures);
    return g_failures == 0 ? 0 : 1;
}
