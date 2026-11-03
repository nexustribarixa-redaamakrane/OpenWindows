#include "../inc/ow_superunicode.h"
#include "../../superunicode/sutf/include/sutf8.h"
#include "../../superunicode/suf/include/suf/suf_parser.h"
#include "build/generated/ow_terminal_font.h"

static sutr_sie_queue_t g_input;
static sutr_sim_channel_t g_messages;
static sutr_skc_buffer_t g_console;
static scts_cell_t g_cells[25u * 80u];
static scts_plane_t g_plane;
static scte_term_t g_terminal;
static bool g_initialized;
static bool g_font_ready;

void OwSuperUnicodeInitialize(void) {
    if (g_initialized) {
        return;
    }
    sutr_sie_init(&g_input);
    sutr_sim_init(&g_messages);
    sutr_skc_init(&g_console);
    {
        suf_header_t header;
        g_font_ready = suf_validate_header(ow_terminal_font_data,
                                            ow_terminal_font_size,
                                            &header) == SUF_OK &&
                       (header.flags & SUF_FLAG_BOOT_BITMAP) != 0u &&
                       header.boot_bitmap_width == 8u &&
                       header.boot_bitmap_height == 16u &&
                       header.boot_bitmap_bpp == 1u;
    }
    {
        scts_plane_options_t options;
        scts_plane_options_default(&options);
        (void)scts_plane_init(&g_plane, g_cells, 25u, 80u, &options);
        (void)suts_scte_init(&g_terminal, &g_plane, (scte_scp_fn)0,
                             (scte_bell_fn)0, (uintptr_t)0);
    }

    g_initialized = true;
}

bool OwSuperUnicodeFontReady(void) {
    OwSuperUnicodeInitialize();
    return g_font_ready;
}

const uint8_t *OwSuperUnicodeFontGlyph(uint32_t codepoint) {
    uint32_t glyph_id;
    const uint8_t *bitmap;
    size_t bitmap_size;
    if (!OwSuperUnicodeFontReady() ||
        suf_lookup_glyph_id(ow_terminal_font_data, ow_terminal_font_size,
                            codepoint, &glyph_id) != SUF_OK ||
        suf_get_boot_bitmap(ow_terminal_font_data, ow_terminal_font_size,
                            glyph_id, &bitmap, &bitmap_size) != SUF_OK ||
        bitmap_size != 16u) {
        return (const uint8_t *)0;
    }
    return bitmap;
}

bool OwSuperUnicodeInputPush(uint32_t event) {
    OwSuperUnicodeInitialize();
    return sutr_sie_push(&g_input, event);
}

bool OwSuperUnicodeInputPop(uint32_t *event) {
    OwSuperUnicodeInitialize();
    return sutr_sie_pop(&g_input, event);
}

bool OwSuperUnicodeMessageSend(const void *data, size_t length) {
    OwSuperUnicodeInitialize();
    return sutr_sim_send(&g_messages, data, length);
}

bool OwSuperUnicodeMessageReceive(void *data, size_t capacity, size_t *length) {
    OwSuperUnicodeInitialize();
    return sutr_sim_receive(&g_messages, data, capacity, length);
}

bool OwSuperUnicodeConsoleWrite(const char *text, size_t length) {
    bool rendered;
    OwSuperUnicodeInitialize();
    if (!text) {
        return false;
    }
    /* g_console is a bounded capture of recent console bytes, not the console
     * itself.  The kernel formatter feeds every character through here, so once
     * the 512-byte capture is full a failure return must not disable all later
     * console output.  Keep rendering unconditionally and let the raw SKC
     * contract report overflow to callers that write to it directly. */
    (void)sutr_skc_write(&g_console, text, length);
    rendered = suts_scte_feed(&g_terminal, (const uint8_t *)text, length) == SCTE_OK;
    return rendered;
}

bool OwSuperUnicodeValidateSutf(const uint8_t *bytes, size_t length) {
    size_t offset = 0u;
    OwSuperUnicodeInitialize();
    if (!bytes && length != 0u) {
        return false;
    }
    while (offset < length) {
        sucs_char_t codepoint;
        size_t consumed = sutf8_decode_char(bytes + offset, length - offset,
                                            &codepoint);
        if (consumed == 0u || !sucs_is_valid(codepoint)) {
            return false;
        }
        offset += consumed;
    }
    return true;
}

const sutr_skc_buffer_t *OwSuperUnicodeConsoleBuffer(void) {
    OwSuperUnicodeInitialize();
    return &g_console;
}

bool OwSuperUnicodeRenderSutf(const uint8_t *bytes, size_t length) {
    OwSuperUnicodeInitialize();
    return suts_scte_feed(&g_terminal, bytes, length) == SCTE_OK;
}

const scts_plane_t *OwSuperUnicodeTextPlane(void) {
    OwSuperUnicodeInitialize();
    return &g_plane;
}

bool OwSuperUnicodeRenderPlane(uint32_t *framebuffer, uint32_t width,
                               uint32_t height, uint32_t pitch,
                               uint32_t fg_color, uint32_t bg_color) {
    uint32_t row;
    uint32_t col;
    uint32_t drawn = 0u;

    OwSuperUnicodeInitialize();
    if (!g_font_ready || !framebuffer || width == 0u || height == 0u) {
        return false;
    }
    if (pitch == 0u) {
        pitch = width;
    }
    if (pitch < width) {
        return false;
    }

    /* The SUF boot bitmap is 8x16 at 1bpp; the cell grid is a direct mapping,
     * so a terminal row/column is a pixel rectangle, not a guess. */
    for (row = 0u; row < g_plane.rows && row * 16u < height; ++row) {
        for (col = 0u; col < g_plane.cols && col * 8u < width; ++col) {
            const scts_cell_t *cell =
                &g_plane.cells[(size_t)row * (size_t)g_plane.cols + (size_t)col];
            uint32_t codepoint = cell->cp;
            uint32_t glyph_id = 0u;

            /* The tail cell of a wide cluster has no glyph of its own. */
            if (codepoint == SCTS_MARK_CONT) {
                continue;
            }
            if (codepoint == SCTS_MARK_BLANK) {
                codepoint = (uint32_t)' ';
            }
            if (suf_lookup_glyph_id(ow_terminal_font_data,
                                    ow_terminal_font_size, codepoint,
                                    &glyph_id) != SUF_OK) {
                /* Same fallback rule as a shaping engine: an unencoded
                 * codepoint is drawn as the font's notdef glyph. */
                glyph_id = 0u;
            }
            if (suf_render_boot_glyph_to_fb(ow_terminal_font_data,
                                            ow_terminal_font_size, glyph_id,
                                            framebuffer, width, height, pitch,
                                            col * 8u, row * 16u, fg_color,
                                            bg_color) != SUF_OK) {
                continue;
            }
            ++drawn;
        }
    }

    return drawn != 0u;
}
