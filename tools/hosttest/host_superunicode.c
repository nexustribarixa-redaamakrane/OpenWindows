#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../superunicode/suf/include/suf/suf_parser.h"
#include "ow_terminal_font.h"

#include "../../superunicode/include/suas/suas_sktc.h"
#include "../../superunicode/include/suas/suas_sucha.h"
#include "../../superunicode/include/suas/suas_stx.h"
#include "../../superunicode/include/sutr/sutr_sfs.h"
#include "../../superunicode/include/sutr/sutr_sie.h"
#include "../../superunicode/include/sutr/sutr_sim.h"
#include "../../superunicode/include/sutr/sutr_skc.h"
#include "../../superunicode/sutf/include/sutf.h"
#include "../../superunicode/sust/include/sust.h"
#include "../../inc/ow_superunicode.h"

static int check(bool condition, int *passed)
{
    if (condition) {
        ++*passed;
        return 0;
    }
    return 1;
}

static unsigned glyph_bit_count(const uint8_t *bitmap)
{
    unsigned bits = 0u;
    unsigned i;
    for (i = 0u; i < 16u; ++i) {
        uint8_t row = bitmap[i];
        while (row != 0u) {
            bits += (unsigned)(row & 1u);
            row >>= 1;
        }
    }
    return bits;
}

static bool framebuffer_matches_glyph(const uint32_t *framebuffer,
                                      uint32_t pitch, uint32_t x, uint32_t y,
                                      const uint8_t *bitmap, uint32_t fg,
                                      uint32_t bg)
{
    uint32_t row;
    for (row = 0u; row < 16u; ++row) {
        uint32_t col;
        for (col = 0u; col < 8u; ++col) {
            uint32_t expected = (bitmap[row] & (0x80u >> col)) != 0u ? fg : bg;
            if (framebuffer[(y + row) * pitch + x + col] != expected) {
                return false;
            }
        }
    }
    return true;
}

int test_superunicode_run(int *out_passed)
{
    int passed = 0;
    int failures = 0;
    suas_sktc_report_t report;
    sutr_sie_queue_t events;
    sutr_sim_channel_t channel;
    sutr_skc_buffer_t console;
    uint32_t event = 0;
    char payload[8] = {0};
    size_t payload_length = 0;
    uint8_t transport[8];
    sucs_char_t decoded = SUCS_INVALID_CODEPOINT;
    sucs_ex_char_t extended_decoded = 0;
    suas_stx_state_t text_state;
    static const uint8_t terminal_text[] = "OpenWindows SUTF console\r\n";
    static const uint8_t clear_screen[] = "\x1b[2J\x1b[H";

    if (out_passed == NULL) {
        return 1;
    }

    /* SUCD data is an optional runtime image in this hosted harness; verify
     * the authority surface without requiring that image to be mounted. */
    failures += check(suas_sucha_version_string() != NULL, &passed);
    failures += check(sutr_sfs_valid_name("kernel", 6), &passed);
    failures += check(!sutr_sfs_valid_name("bad/name", 8), &passed);
    failures += check(suas_stx_version_string() != NULL, &passed);
    suas_stx_init(&text_state);
    failures += check(suas_stx_feed(&text_state, (sucs_ex_char_t)'A'),
                      &passed);

    sutr_sie_init(&events);
    failures += check(sutr_sie_push(&events, 0x41u), &passed);
    failures += check(sutr_sie_pop(&events, &event) && event == 0x41u, &passed);

    sutr_sim_init(&channel);
    failures += check(sutr_sim_send(&channel, "boot", 4), &passed);
    failures += check(sutr_sim_receive(&channel, payload, sizeof(payload),
                                       &payload_length) &&
                     payload_length == 4 && payload[0] == 'b', &passed);

    sutr_skc_init(&console);
    failures += check(sutr_skc_write(&console, "SuperUnicode", 12) &&
                     console.length == 12, &passed);
    failures += check(OwSuperUnicodeConsoleWrite("kernel SUTF\r\n", 12),
                      &passed);
    failures += check(OwSuperUnicodeFontReady(), &passed);
    failures += check(OwSuperUnicodeFontGlyph((uint32_t)'A') != NULL, &passed);
    failures += check(OwSuperUnicodeValidateSutf(
                          (const uint8_t *)"valid", 5u),
                      &passed);
    failures += check(sutf8_encode_char((sucs_char_t)'A', transport,
                                        sizeof(transport)) == 1u,
                      &passed);
    failures += check(sutf8_decode_char(transport, 1u, &decoded) == 1u &&
                     decoded == (sucs_char_t)'A', &passed);
    failures += check(sust64_encode((sucs_ex_char_t)0x1234u, transport,
                                    sizeof(transport)) == SUST64_BYTES,
                      &passed);
    failures += check(sust64_decode(transport, sizeof(transport),
                                    &extended_decoded) == SUST64_BYTES &&
                     extended_decoded == (sucs_ex_char_t)0x1234u, &passed);
    {
        static const uint8_t malformed[] = {0xFFu};
        failures += check(!OwSuperUnicodeValidateSutf(malformed,
                                                       sizeof(malformed)),
                          &passed);
    }
    failures += check(OwSuperUnicodeRenderSutf(
                          terminal_text, sizeof(terminal_text) - 1u),
                      &passed);
    failures += check(OwSuperUnicodeTextPlane()->writes > 0u, &passed);

    /* --- Embedded SUF font: header, cmap, lookups, and fallback --------- */
    {
        suf_header_t font_header;
        uint32_t cmap_count = 0u;
        bool printable_complete = true;
        bool representative_ok = true;
        const char *family = NULL;
        size_t family_len = 0u;
        const uint8_t *fallback;
        uint32_t fallback_gid = 0xFFFFFFFFu;
        uint32_t cp;
        unsigned i;
        static const uint32_t representative_cps[] = {
            0x20u, 0x21u, 0x2Eu, 0x30u, 0x39u, 0x41u, 0x5Au, 0x7Eu
        };
        static const uint32_t representative_gids[] = {
            1u, 2u, 15u, 17u, 26u, 34u, 59u, 95u
        };
        static const unsigned representative_bits[] = {
            0u, 24u, 4u, 48u, 35u, 39u, 36u, 10u
        };

        failures += check(sizeof(ow_terminal_font_data) ==
                              ow_terminal_font_size,
                          &passed);
        failures += check(ow_terminal_font_size == 4016u, &passed);
        failures += check(suf_validate_header(ow_terminal_font_data,
                                              ow_terminal_font_size,
                                              &font_header) == SUF_OK,
                          &passed);
        failures += check(font_header.magic == SUF_MAGIC, &passed);
        failures += check(font_header.version == SUF_VERSION_CURRENT, &passed);
        failures += check((font_header.flags & SUF_FLAG_BOOT_BITMAP) != 0u,
                          &passed);
        failures += check(font_header.glyph_count == 96u, &passed);
        failures += check(font_header.checksum == 0x7B472F5Cu, &passed);
        failures += check(font_header.boot_bitmap_width == 8u, &passed);
        failures += check(font_header.boot_bitmap_height == 16u, &passed);
        failures += check(font_header.boot_bitmap_bpp == 1u, &passed);
        failures += check(font_header.boot_bitmap_size ==
                              96u * 16u,
                          &passed);

        failures += check(font_header.cmap_size %
                              sizeof(suf_cmap_entry_t) == 0u,
                          &passed);
        cmap_count = font_header.cmap_size /
                     (uint32_t)sizeof(suf_cmap_entry_t);
        failures += check(cmap_count == 96u, &passed);

        for (cp = 0x20u; cp <= 0x7Eu; ++cp) {
            uint32_t glyph_id = 0xFFFFFFFFu;
            const uint8_t *bitmap = NULL;
            size_t bitmap_size = 0u;
            if (suf_lookup_glyph_id(ow_terminal_font_data,
                                    ow_terminal_font_size, cp,
                                    &glyph_id) != SUF_OK ||
                suf_get_boot_bitmap(ow_terminal_font_data,
                                    ow_terminal_font_size, glyph_id,
                                    &bitmap, &bitmap_size) != SUF_OK ||
                bitmap_size != 16u || bitmap == NULL ||
                OwSuperUnicodeFontGlyph(cp) == NULL ||
                memcmp(OwSuperUnicodeFontGlyph(cp), bitmap, 16u) != 0) {
                printable_complete = false;
            }
        }
        failures += check(printable_complete, &passed);

        for (i = 0u; i < sizeof(representative_cps) /
                            sizeof(representative_cps[0]); ++i) {
            uint32_t glyph_id = 0xFFFFFFFFu;
            const uint8_t *bitmap = OwSuperUnicodeFontGlyph(
                representative_cps[i]);
            if (suf_lookup_glyph_id(ow_terminal_font_data,
                                    ow_terminal_font_size,
                                    representative_cps[i],
                                    &glyph_id) != SUF_OK ||
                glyph_id != representative_gids[i] || bitmap == NULL ||
                glyph_bit_count(bitmap) != representative_bits[i]) {
                representative_ok = false;
            }
        }
        failures += check(representative_ok, &passed);

        failures += check(suf_lookup_glyph_id(ow_terminal_font_data,
                                              ow_terminal_font_size, 0u,
                                              &fallback_gid) == SUF_OK &&
                              fallback_gid == 0u,
                          &passed);
        fallback = OwSuperUnicodeFontGlyph(0u);
        failures += check(fallback != NULL &&
                              glyph_bit_count(fallback) == 54u &&
                              fallback[0] == 0xFFu && fallback[15] == 0x00u,
                          &passed);
        failures += check(OwSuperUnicodeFontGlyph(0x10FFFFu) == NULL, &passed);

        failures += check(suf_get_name(ow_terminal_font_data,
                                       ow_terminal_font_size, 1u,
                                       &family, &family_len) == SUF_OK &&
                              family != NULL && family_len == 24u &&
                              strncmp(family, "OpenWindows Terminal SUF",
                                      family_len) == 0,
                          &passed);
        printf("[SUF] embedded=%lu bytes magic=0x%08lX glyphs=%lu "
               "bitmap=%ux%u/%ubpp cmap=%lu checksum=0x%08lX family=%.*s\n",
               (unsigned long)ow_terminal_font_size,
               (unsigned long)font_header.magic,
               (unsigned long)font_header.glyph_count,
               (unsigned)font_header.boot_bitmap_width,
               (unsigned)font_header.boot_bitmap_height,
               (unsigned)font_header.boot_bitmap_bpp,
               (unsigned long)cmap_count,
               (unsigned long)font_header.checksum,
               (int)(family != NULL ? family_len : 0u),
               family != NULL ? family : "(missing)");
        printf("[SUF] fallback: cp=0x0 gid=%lu bitmap_bytes=16 bits=%u\n",
               (unsigned long)fallback_gid,
               fallback != NULL ? glyph_bit_count(fallback) : 0u);
    }

    /* --- CLI bytes travel through SCTE into the SCTS cell plane --------- */
    {
        static const uint8_t cli_text[] = "CLI> ";
        const scts_plane_t *plane;

        failures += check(OwSuperUnicodeRenderSutf(clear_screen,
                                                   sizeof(clear_screen) - 1u),
                          &passed);
        failures += check(OwSuperUnicodeConsoleWrite((const char *)cli_text,
                                                     sizeof(cli_text) - 1u),
                          &passed);
        plane = OwSuperUnicodeTextPlane();
        failures += check(plane->rows == 25u && plane->cols == 80u, &passed);
        failures += check(plane->cursor_row == 0u &&
                              plane->cursor_col == sizeof(cli_text) - 1u,
                          &passed);
        failures += check(plane->cells[0].cp == (uint32_t)'C' &&
                              plane->cells[1].cp == (uint32_t)'L' &&
                              plane->cells[2].cp == (uint32_t)'I' &&
                              plane->cells[3].cp == (uint32_t)'>' &&
                              plane->cells[4].cp == (uint32_t)' ',
                          &passed);
        printf("[SUF] CLI->SCTE->SCTS: row=%u col=%u cells=\"CLI> \"\n",
               (unsigned)plane->cursor_row, (unsigned)plane->cursor_col);
    }

    /* --- The renderer draws the actual SUF bitmap into the framebuffer --- */
    {
        static const uint8_t proof_text[] = "AZ09? ~az";
        static uint32_t framebuffer[640u * 16u];
        const size_t proof_len = sizeof(proof_text) - 1u;
        const uint32_t fg = 0xFF00FF00u;
        const uint32_t bg = 0xFF000000u;
        const scts_plane_t *plane;
        const uint8_t *fallback;
        uint8_t unknown[8];
        size_t unknown_len;
        bool cells_ok = true;
        bool pixels_ok = true;
        unsigned pixel_cells = 0u;
        unsigned i;

        failures += check(OwSuperUnicodeRenderSutf(clear_screen,
                                                   sizeof(clear_screen) - 1u),
                          &passed);
        failures += check(OwSuperUnicodeRenderSutf(
                              proof_text, proof_len), &passed);
        unknown_len = sutf8_encode_char((sucs_char_t)0x10FFFFu, unknown,
                                        sizeof(unknown));
        failures += check(unknown_len == 4u, &passed);
        failures += check(OwSuperUnicodeRenderSutf(unknown, unknown_len),
                          &passed);

        plane = OwSuperUnicodeTextPlane();
        failures += check(plane->cursor_row == 0u &&
                              plane->cursor_col == proof_len + 1u,
                          &passed);
        for (i = 0u; i < proof_len; ++i) {
            if (plane->cells[i].cp != (uint32_t)proof_text[i]) {
                cells_ok = false;
            }
        }
        if (plane->cells[proof_len].cp != 0x10FFFFu) {
            cells_ok = false;
        }
        failures += check(cells_ok, &passed);

        for (i = 0u; i < sizeof(framebuffer) /
                            sizeof(framebuffer[0]); ++i) {
            framebuffer[i] = 0xDEADBEEFu;
        }
        failures += check(OwSuperUnicodeRenderPlane(framebuffer, 640u, 16u,
                                                    640u, fg, bg),
                          &passed);

        for (i = 0u; i < proof_len; ++i) {
            const uint8_t *glyph = OwSuperUnicodeFontGlyph(
                (uint32_t)proof_text[i]);
            if (glyph == NULL ||
                !framebuffer_matches_glyph(framebuffer, 640u, i * 8u, 0u,
                                           glyph, fg, bg)) {
                pixels_ok = false;
            } else {
                ++pixel_cells;
            }
        }
        fallback = OwSuperUnicodeFontGlyph(0u);
        if (fallback == NULL ||
            !framebuffer_matches_glyph(framebuffer, 640u,
                                       (uint32_t)proof_len * 8u, 0u,
                                       fallback, fg, bg)) {
            pixels_ok = false;
        } else {
            ++pixel_cells;
        }
        failures += check(pixels_ok, &passed);
        printf("[SUF] renderer: %u/%u cells pixel-exact "
               "(\"%s\" + fallback cp=0x10FFFF -> gid 0)\n",
               pixel_cells, (unsigned)proof_len + 1u, (const char *)proof_text);
    }

    suas_sktc_reset(&report);
    failures += check(suas_sktc_record(&report, failures == 0), &passed);
    failures += check(suas_sktc_complete(&report), &passed);

    *out_passed = passed;
    return failures;
}
