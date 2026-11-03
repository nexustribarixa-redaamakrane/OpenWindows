#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

    suas_sktc_reset(&report);
    failures += check(suas_sktc_record(&report, failures == 0), &passed);
    failures += check(suas_sktc_complete(&report), &passed);

    *out_passed = passed;
    return failures;
}
