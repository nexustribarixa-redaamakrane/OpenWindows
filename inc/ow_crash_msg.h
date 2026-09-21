/* ow_crash_msg.h - BANhammer quotes & crash screen message catalog
 * Sourced from OpenWindows-Essentials/Assets/BANHammerTexts.txt */
#ifndef OW_CRASH_MSG_H
#define OW_CRASH_MSG_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    OW_CRASH_RECOVERY_NOT_ATTEMPTED = 0,
    OW_CRASH_RECOVERY_ATTEMPTED,
    OW_CRASH_RECOVERY_SUCCEEDED,
    OW_CRASH_RECOVERY_FAILED
} ow_crash_recovery_status_t;

static const char *const g_ow_banhammer_messages[] = {
    /* [SARCASTIC] */
    "Well, that was graceful.",
    "Congratulations, you hit the B+ trap jackpot!",
    "Have you tried turning the kernel off and never turning it on again?",
    "Kernel went out for milk. It is not coming back.",
    "A wild BANcode appeared! It was super effective.",
    "Oops, all traps.",
    "The kernel has encountered a fatal moment of philosophical self-doubt.",
    "System crashed successfully. No humans were harmed in this disaster.",
    "Divide by cucumber error. Please reinstall universe and reboot.",
    "You have unlocked the secret BANhammer emergency halt achievement.",
    "Freestanding C99 does not stand anymore. It fell over.",
    "We apologize for the fault in the kernel. Those responsible have been sacked.",
    "Look on the bright side: at least it was deterministic.",
    "404 Kernel Not Found.",
    "Everything is fine. Just breathe and check the UART console.",

    /* [INFORMATIONAL] */
    "Hardware Translation Layer reported unrecoverable bus stall.",
    "Sentinel recovery was invoked, but damage exceeded threshold.",
    "Page fault in ring-0 without matching PML4 descriptor.",
    "Kernel integrity trap triggered by invalid state vector.",
    "Zero-allocation static buffer bounds overrun intercepted by guard page.",
    "Volume Indexing Protocol (VIP) root partition checksum mismatch.",
    "Modular Bootloader handoff descriptor corrupted in early stage.",
    "Non-maskable interrupt fired during critical spinlock acquisition.",
    "SuperUnicode Control Point (SCP) trap range violation in userland stream.",
    "PnP bus negotiation timed out during critical device enumeration.",

    /* [SENTINEL_RECOVERY] */
    "Damage Control sentinel initialized post-panic recovery pass.",
    "Attempting shadow file table rollback on root VIP partition.",
    "Isolating faulted peripheral bus and clearing interrupt mask.",
    "Rebuilding FVIP fast indexing sector table.",
    "Sentinel recovery pass was requested, but the kernel remains halted.",
    "Diagnostic state was preserved as far as the crash path allowed."
};

#define OW_BANHAMMER_MSG_COUNT                                                 \
  ((uint32_t)(sizeof(g_ow_banhammer_messages) /                                \
              sizeof(g_ow_banhammer_messages[0])))

/* Dynamic restart/recovery message based on autoreboot & kdump settings */
static inline const char *OwCrashGetRestartMessage(bool autoreboot, bool kdump) {
    if (autoreboot && kdump) {
        return "We're collecting debug information, then your device will restart.";
    } else if (!autoreboot && kdump) {
        return "We're collecting debug information, but once we're done, you need to restart your device.";
    } else if (autoreboot && !kdump) {
        return "Your device will restart.";
    } else {
        return "You need to restart your device.";
    }
}

static inline const char *OwCrashGetTelemetryMessage(
    ow_crash_recovery_status_t status) {
    if (status == OW_CRASH_RECOVERY_SUCCEEDED) {
        return "Kernel telemetry saved to diagnostic storage.";
    }
    if (status == OW_CRASH_RECOVERY_FAILED) {
        return "Kernel telemetry could not be saved to diagnostic storage.";
    }
    if (status == OW_CRASH_RECOVERY_ATTEMPTED) {
        return "Kernel telemetry collection is in progress.";
    }
    return "Kernel telemetry collection was not attempted.";
}

static inline const char *OwCrashGetRecoveryMessage(
    ow_crash_recovery_status_t status, bool reset_requested) {
    if (status == OW_CRASH_RECOVERY_SUCCEEDED && reset_requested) {
        return "Sentinel recovery completed successfully; reset requested.";
    }
    if (status == OW_CRASH_RECOVERY_SUCCEEDED) {
        return "Sentinel recovery completed successfully; manual restart required.";
    }
    if (status == OW_CRASH_RECOVERY_FAILED) {
        return "Sentinel recovery failed; system remains halted.";
    }
    if (status == OW_CRASH_RECOVERY_ATTEMPTED) {
        return "Sentinel recovery is in progress; system remains halted.";
    }
    return "Sentinel recovery was not attempted; system remains halted.";
}

static inline const char *OwCrashPickMessage(uint64_t entropy, bool autoreboot, bool kdump) {
    /* ~50% of the time, use the restart / debug collection message.
     * The other ~50% of the time, randomly pick one of the BANhammer catalog quotes. */
    if ((entropy & 1ULL) == 0ULL) {
        return OwCrashGetRestartMessage(autoreboot, kdump);
    }
    return g_ow_banhammer_messages[(entropy >> 1) % OW_BANHAMMER_MSG_COUNT];
}

static inline const char *OwCrashPickDiagnosticMessage(
    uint64_t entropy, bool autoreboot, bool kdump,
    ow_crash_recovery_status_t recovery_status,
    ow_crash_recovery_status_t telemetry_status, bool reset_requested) {
    if (recovery_status != OW_CRASH_RECOVERY_NOT_ATTEMPTED &&
        (entropy % 3ULL) == 0ULL) {
        return OwCrashGetRecoveryMessage(recovery_status, reset_requested);
    }
    if (kdump && (entropy % 3ULL) == 1ULL) {
        return OwCrashGetTelemetryMessage(telemetry_status);
    }
    return OwCrashPickMessage(entropy, autoreboot, kdump);
}

#endif /* OW_CRASH_MSG_H */
