#ifndef OW_SUPERUNICODE_H
#define OW_SUPERUNICODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../superunicode/include/sutr/sutr_sie.h"
#include "../../superunicode/include/sutr/sutr_sim.h"
#include "../../superunicode/include/sutr/sutr_skc.h"
#include "../../superunicode/include/suts/suts_scts.h"
#include "../../superunicode/include/suts/suts_scte.h"

void OwSuperUnicodeInitialize(void);
bool OwSuperUnicodeInputPush(uint32_t event);
bool OwSuperUnicodeInputPop(uint32_t *event);
bool OwSuperUnicodeMessageSend(const void *data, size_t length);
bool OwSuperUnicodeMessageReceive(void *data, size_t capacity, size_t *length);
bool OwSuperUnicodeConsoleWrite(const char *text, size_t length);
bool OwSuperUnicodeValidateSutf(const uint8_t *bytes, size_t length);
bool OwSuperUnicodeFontReady(void);
const uint8_t *OwSuperUnicodeFontGlyph(uint32_t codepoint);
const sutr_skc_buffer_t *OwSuperUnicodeConsoleBuffer(void);
bool OwSuperUnicodeRenderSutf(const uint8_t *bytes, size_t length);
const scts_plane_t *OwSuperUnicodeTextPlane(void);

/* Rasterize the live SCTS text plane through the embedded SUF boot bitmap.
 *
 * framebuffer is a 32bpp XRGB pixel buffer with `pitch` pixels per row.  Cells
 * whose codepoint has no cmap entry render with the font's notdef/fallback
 * glyph (glyph 0).  Returns true when at least one 8x16 cell was drawn. */
bool OwSuperUnicodeRenderPlane(uint32_t *framebuffer, uint32_t width,
                               uint32_t height, uint32_t pitch,
                               uint32_t fg_color, uint32_t bg_color);

#endif
