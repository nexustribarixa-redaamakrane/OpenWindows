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
const sutr_skc_buffer_t *OwSuperUnicodeConsoleBuffer(void);
bool OwSuperUnicodeRenderSutf(const uint8_t *bytes, size_t length);
const scts_plane_t *OwSuperUnicodeTextPlane(void);

#endif
