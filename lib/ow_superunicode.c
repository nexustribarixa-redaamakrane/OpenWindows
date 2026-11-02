#include "../inc/ow_superunicode.h"

static sutr_sie_queue_t g_input;
static sutr_sim_channel_t g_messages;
static sutr_skc_buffer_t g_console;
static bool g_initialized;

void OwSuperUnicodeInitialize(void) {
    if (g_initialized) {
        return;
    }
    sutr_sie_init(&g_input);
    sutr_sim_init(&g_messages);
    sutr_skc_init(&g_console);
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
    OwSuperUnicodeInitialize();
    return sutr_skc_write(&g_console, text, length);
}

const sutr_skc_buffer_t *OwSuperUnicodeConsoleBuffer(void) {
    OwSuperUnicodeInitialize();
    return &g_console;
}
