/* bancode_krnl.c - Diagnostic Engine (BANcode Integration) */
#include "../inc/ow_diag.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_io.h"

/* Include the BANcode library headers */
#include "bancode/bancode_all.h"

static void ow_banhammer_screen(const char* Name, uint32_t Code) {
    ow_crash_recovery_status_t telemetry_status =
        OwHalGetKdump() ? OW_CRASH_RECOVERY_FAILED
                        : OW_CRASH_RECOVERY_NOT_ATTEMPTED;

    OwHalCrashScreenState(Name, Code, OW_CRASH_RECOVERY_NOT_ATTEMPTED,
                          telemetry_status, false);
}

/* Kernel crash handler invoked by BANcode trap dispatch */
static void ow_banhammer_handler(bancode_t trap_cp, bancode_t bancode_cp, void* context) {
    const char* code_name = bancode_name(bancode_cp);
    const char* explanation = (const char*)context;

    (void)trap_cp;

    ow_banhammer_screen(code_name, (uint32_t)bancode_cp);
    OwHalVgaSetEnabled(false);

    OwHalUartWriteString("\r\n");
    OwHalUartWriteString("========================================================================\r\n");
    OwHalUartWriteString("[FATAL] SYSTEM HALTED\r\n");
    OwHalUartWriteString("========================================================================\r\n");
    ow_kprintf("CRITICAL ERROR CODE: U+%08X (%s)\r\n", (unsigned)bancode_cp, code_name);
    ow_kprintf("COMPONENT: Kernel Executive Core\r\n");
    ow_kprintf("REASON: %s\r\n", explanation ? explanation : "Unspecified");
    ow_kprintf("STATE DUMP: Registers frozen. SMP cores halted via IPI.\r\n");
    OwHalUartWriteString("========================================================================\r\n");
    OwHalSmpHaltIPI();
}

OW_STATUS OwDiagInitialize(void) {
    uint32_t i;
    bancode_set_mode(BANCODE_MODE_SYSTEM);
    bancode_trap_clear_all();

    /* Register our crash handler for all trap slots */
    for (i = 0; i < BANCODE_TRAP_SLOT_COUNT; i++) {
        bancode_trap_register_handler(i, ow_banhammer_handler, (void*)"Kernel BANcode Trap");
    }

    return OW_SUCCESS;
}

void OwDiagLogStarted(const char* Name) {
    ow_kprintf("[STARTED] %s\r\n", Name);
}

void OwDiagLogFinished(const char* Name, OW_STATUS Code) {
    ow_kprintf("[FINISHED] %s", Name);
    if (Code) {
        ow_kprintf(" (code 0x%X)", (unsigned)Code);
    }
    ow_kprintf("\r\n");
}

void OwDiagLogFailed(const char* Name, OW_STATUS Code) {
    ow_kprintf("[FAIL] %s", Name);
    if (Code) {
        ow_kprintf(" (code 0x%X)", (unsigned)Code);
    }
    ow_kprintf("\r\n");
}

void OwDiagLogWarning(OW_STATUS Code, const char* Detail) {
    ow_kprintf("[WARNING] W+%08X: %s\r\n", (unsigned)Code, Detail ? Detail : "");
}

void OwDiagLogSoft(OW_STATUS Code, const char* Detail) {
    ow_kprintf("[SOFT] S+%08X: %s\r\n", (unsigned)Code, Detail ? Detail : "");
}

void OwDiagBanHammer(OW_STATUS Code, const char* Component, const char* Explanation) {
    const char* name = bancode_name((bancode_t)Code);
    if (!name || !*name) name = (Explanation && *Explanation) ? Explanation : (Component ? Component : "System Fault");

    ow_banhammer_screen(name, (uint32_t)Code);
    OwHalVgaSetEnabled(false);

    /* Try BANcode trap dispatch first */
    if (bancode_is_bancode((bancode_t)Code)) {
        bancode_trap_dispatch((bancode_t)Code);
    }

    /* If trap dispatch didn't halt us, do it manually */
    OwHalUartWriteString("\r\n");
    OwHalUartWriteString("========================================================================\r\n");
    OwHalUartWriteString("[FATAL] SYSTEM HALTED\r\n");
    OwHalUartWriteString("========================================================================\r\n");
    ow_kprintf("CRITICAL ERROR CODE: U+%08X (%s)\r\n", (unsigned)Code, bancode_name((bancode_t)Code));
    ow_kprintf("COMPONENT FAULT: %s\r\n", Component ? Component : "Unknown");
    ow_kprintf("REASON: %s\r\n", Explanation ? Explanation : "Unspecified");
    if (OwHalGetKdump()) {
        OwHalUartWriteString("STATE DUMP: Collection failed; no dump writer is active.\r\n");
    } else {
        OwHalUartWriteString("STATE DUMP: Collection was not requested.\r\n");
    }
    OwHalUartWriteString("ACTION: CPU cores frozen via IPI. Lock established.\r\n");
    OwHalUartWriteString("========================================================================\r\n");

    OwHalSmpHaltIPI();
    ow_hlt_loop();
}

const char* OwDiagCodeName(OW_STATUS Code) {
    return bancode_name((bancode_t)Code);
}
