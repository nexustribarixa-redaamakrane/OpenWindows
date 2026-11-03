#include "../inc/ow_superunicode.h"
#include "../../superunicode/sutf/include/sutf8.h"

static sutr_sie_queue_t g_input;
static sutr_sim_channel_t g_messages;
static sutr_skc_buffer_t g_console;
static scts_cell_t g_cells[25u * 80u];
static scts_plane_t g_plane;
static scte_term_t g_terminal;
static bool g_initialized;

void OwSuperUnicodeInitialize(void) {
    if (g_initialized) {
        return;
    }
    sutr_sie_init(&g_input);
    sutr_sim_init(&g_messages);
    sutr_skc_init(&g_console);
    {
        scts_plane_options_t options;
        scts_plane_options_default(&options);
        (void)scts_plane_init(&g_plane, g_cells, 25u, 80u, &options);
        (void)suts_scte_init(&g_terminal, &g_plane, (scte_scp_fn)0,
                             (scte_bell_fn)0, (uintptr_t)0);
    }
    g_initialized = true;
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
    if (!text && length != 0u) {
        return false;
    }
    if (!sutr_skc_write(&g_console, text, length)) {
        return false;
    }
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
