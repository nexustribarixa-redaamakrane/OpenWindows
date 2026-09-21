/* kbd.c - PS/2 keyboard driver with automatic detection (HAL component)
 *
 * Polls the classic PC 8042 / i8042 controller (ports 0x60/0x64) and
 * translates scancode set 1 into ASCII for the debug shell. No IRQs
 * required: the shell polls OwHalKbdCanRead in its input loop.
 *
 * Automatic detection: the controller is probed with 0xAA self-test, the
 * keyboard interface with 0xAB, then the keyboard is reset (0xFF) and
 * scanning is enabled (0xF4). Scancode set 1 is used: on PC compatibles the
 * i8042 is in translation mode and delivers set 1 to software automatically,
 * so no 0xF0 scancode-set request is made (it would be double-translated).
 * Any time-out or unexpected response marks the device as absent so the
 * shell silently falls back to UART input. */
#include "../inc/ow_hal.h"
#include "../inc/ow_io.h"
#include <stdint.h>
#include <stddef.h>

#define KBD_STATUS_PORT  0x64U
#define KBD_DATA_PORT    0x60U

#define KBD_STAT_OUT_FULL    0x01U   /* output buffer (0x60) full */
#define KBD_STAT_IN_EMPTY    0x02U   /* input buffer (0x60/0x64) empty */
#define KBD_ACK              0xFAU

#define KBD_CMD_SELF_TEST    0xAAU   /* controller self-test -> 0x55 */
#define KBD_CMD_TEST_KB      0xABU   /* test keyboard interface -> 0x00 */
#define KBD_CMD_RESET         0xFFU   /* keyboard reset -> ACK + 0xAA */
#define KBD_CMD_ENABLE        0xF4U   /* start scanning -> ACK */

#define KBD_STATUS_TIMEOUT  0x8000U

/* Scancode set 1 translation tables (0 = swallow, modifier, or unknown). */
static const char g_kbd_plain[128] = {
    [0x01] = 0, [0x02] = '1', [0x03] = '2', [0x04] = '3', [0x05] = '4',
    [0x06] = '5', [0x07] = '6', [0x08] = '7', [0x09] = '8', [0x0A] = '9',
    [0x0B] = '0', [0x0C] = '-', [0x0D] = '=', [0x0E] = '\b', [0x0F] = '\t',
    [0x10] = 'q', [0x11] = 'w', [0x12] = 'e', [0x13] = 'r', [0x14] = 't',
    [0x15] = 'y', [0x16] = 'u', [0x17] = 'i', [0x18] = 'o', [0x19] = 'p',
    [0x1A] = '[', [0x1B] = ']', [0x1C] = '\r', [0x1E] = 'a', [0x1F] = 's', [0x20] = 'd',
    [0x21] = 'f', [0x22] = 'g', [0x23] = 'h', [0x24] = 'j', [0x25] = 'k',
    [0x26] = 'l', [0x27] = ';', [0x28] = '\'', [0x29] = '`', [0x2B] = '\\',
    [0x2C] = 'z', [0x2D] = 'x', [0x2E] = 'c', [0x2F] = 'v', [0x30] = 'b',
    [0x31] = 'n', [0x32] = 'm', [0x33] = ',', [0x34] = '.', [0x35] = '/',
    [0x37] = '*', [0x39] = ' '
};

static const char g_kbd_shift[128] = {
    [0x02] = '!', [0x03] = '@', [0x04] = '#', [0x05] = '$', [0x06] = '%',
    [0x07] = '^', [0x08] = '&', [0x09] = '*', [0x0A] = '(', [0x0B] = ')',
    [0x0C] = '_', [0x0D] = '+', [0x1A] = '{', [0x1B] = '}', [0x1C] = '\r', [0x27] = ':',
    [0x28] = '"', [0x29] = '~', [0x2B] = '|', [0x33] = '<', [0x34] = '>',
    [0x35] = '?', [0x37] = '*', [0x39] = ' ',
    [0x10] = 'Q', [0x11] = 'W', [0x12] = 'E', [0x13] = 'R', [0x14] = 'T',
    [0x15] = 'Y', [0x16] = 'U', [0x17] = 'I', [0x18] = 'O', [0x19] = 'P',
    [0x1E] = 'A', [0x1F] = 'S', [0x20] = 'D', [0x21] = 'F', [0x22] = 'G',
    [0x23] = 'H', [0x24] = 'J', [0x25] = 'K', [0x26] = 'L',
    [0x2C] = 'Z', [0x2D] = 'X', [0x2E] = 'C', [0x2F] = 'V', [0x30] = 'B',
    [0x31] = 'N', [0x32] = 'M'
};

static uint8_t g_kbd_present = 0;
static uint8_t g_kbd_init    = 0;
static uint8_t g_shift_state = 0;
static uint8_t g_kbd_caps    = 0;
static uint8_t g_kbd_ext     = 0;
static uint8_t g_kbd_have    = 0;
static char    g_kbd_char    = 0;

static uint8_t kbd_status_wait_output(void) {
    uint32_t t;
    for (t = 0; t < KBD_STATUS_TIMEOUT; t++) {
        if (!(ow_inb(KBD_STATUS_PORT) & KBD_STAT_IN_EMPTY)) return 1;
    }
    return 0;
}

static uint8_t kbd_status_wait_input(void) {
    uint32_t t;
    for (t = 0; t < KBD_STATUS_TIMEOUT; t++) {
        if (ow_inb(KBD_STATUS_PORT) & KBD_STAT_OUT_FULL) return 1;
    }
    return 0;
}

static uint8_t kbd_write_cmd(uint8_t Command) {
    if (!kbd_status_wait_output()) return 0;
    ow_outb(KBD_STATUS_PORT, Command);
    return 1;
}

static uint8_t kbd_write_data(uint8_t Data) {
    if (!kbd_status_wait_output()) return 0;
    ow_outb(KBD_DATA_PORT, Data);
    return 1;
}

static uint8_t kbd_read_byte(void) {
    if (!kbd_status_wait_input()) return 0;
    return ow_inb(KBD_DATA_PORT);
}

/* Translate one make/release scancode into an ASCII char (0 = swallow). */
static char kbd_translate(uint8_t Scancode) {
    uint8_t make = Scancode & 0x7FU;

    if (Scancode & 0x80U) {
        /* Release: track the shift keys only. */
        if (make == 0x2A || make == 0x36) g_shift_state = 0;
        return 0;
    }

    switch (make) {
    case 0x2A: case 0x36:                      /* left/right shift */
        g_shift_state = 1;
        return 0;
    case 0x3A:                                 /* caps lock */
        g_kbd_caps = g_kbd_caps ? 0U : 1U;
        return 0;
    case 0x1D: case 0x38:                      /* ctrl / alt */
    case 0x45: case 0x46:                      /* num / scroll lock */
        return 0;
    default:
        break;
    }

    if (g_shift_state) {
        return g_kbd_shift[make];
    }
    if (g_kbd_caps && make >= 0x10 && make <= 0x32 && g_kbd_plain[make] >= 'a' &&
        g_kbd_plain[make] <= 'z') {
        return (char)(g_kbd_plain[make] - 32);
    }
    return g_kbd_plain[make];
}

/* Drain the output buffer so stale bytes don't surface as input. */
static void kbd_drain(void) {
    uint32_t n;
    for (n = 0; n < 64U; n++) {
        if (!(ow_inb(KBD_STATUS_PORT) & KBD_STAT_OUT_FULL)) break;
        (void)ow_inb(KBD_DATA_PORT);
    }
}

bool OwHalKbdInitialize(void) {
    uint8_t present;
    if (g_kbd_init) return g_kbd_present != 0;
    g_kbd_init = 1;
    present = 1;

    /* Probe (best effort, non-fatal): controller self-test 0xAA -> 0x55. */
    if (!kbd_write_cmd(KBD_CMD_SELF_TEST)) present = 0;
    else if (kbd_read_byte() != 0x55U) present = 0;

    /* Keyboard interface test 0xAB -> 0x00. */
    if (present) {
        if (!kbd_write_cmd(KBD_CMD_TEST_KB)) present = 0;
        else if (kbd_read_byte() != 0x00U) present = 0;
    }

    /* Reset 0xFF -> ACK then self-test result 0xAA. */
    if (present) {
        if (!kbd_write_data(KBD_CMD_RESET)) present = 0;
        else if (kbd_read_byte() != KBD_ACK) present = 0;
        else if (kbd_read_byte() != 0xAAU) present = 0;
    }

    /* ALWAYS attempt to enable scanning: 0xF4 -> ACK. This is what makes the
     * keyboard start streaming scan codes; some emulators (VirtualBox) stay
     * silent until the guest sends it, so never skip it even if the probe
     * above failed. */
    if (!kbd_write_data(KBD_CMD_ENABLE)) present = 0;
    else if (kbd_read_byte() != KBD_ACK) present = 0;

    kbd_drain();

    if (present) {
        g_kbd_present = 1;
        OwHalUartWriteString("[KBD] PS/2 keyboard detected (port 0x60, scancode set 1)\r\n");
        return true;
    }
    g_kbd_present = 0;
    OwHalUartWriteString("[KBD] no PS/2 keyboard response - raw scan polling active\r\n");
    return false;
}

bool OwHalKbdCanRead(void) {
    if (!g_kbd_init) return false;
    if (!g_kbd_have) {
        while (ow_inb(KBD_STATUS_PORT) & KBD_STAT_OUT_FULL) {
            uint8_t sc = ow_inb(KBD_DATA_PORT);
            char c;
            if (g_kbd_ext) { g_kbd_ext = 0; continue; }
            if (sc == 0xE0U || sc == 0xE1U) { g_kbd_ext = 1; continue; }
            c = kbd_translate(sc);
            if (c != 0) { g_kbd_have = 1; g_kbd_char = c; break; }
        }
    }
    return g_kbd_have != 0;
}

char OwHalKbdReadChar(void) {
    if (!OwHalKbdCanRead()) return '\0';
    g_kbd_have = 0;
    return g_kbd_char;
}
