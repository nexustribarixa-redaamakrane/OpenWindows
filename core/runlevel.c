/* runlevel.c - OpenWindows Runlevel Subsystem
 * Freestanding C99. Computes and drives the -6..6 runlevel profiles that
 * shape which boot phases / subsystems are armed and their custom config.
 * Each live switch logs a COMcode milestone and re-tears-down subsystems
 * that the destination profile does not arm. */
#include "../inc/ow_runlevel.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_net.h"
#include "../inc/ow_io.h"
#include "../inc/ow_rc.h"
#include "../inc/ow_acpi.h"

/* Positive runtime ladder (each step arms strictly more than the previous). */
#define RLVL_L1_FEATURES \
    (OW_RUNLEVEL_CORE_FEATURES | OW_RUNLVL_F_ALPC | OW_RUNLVL_F_SUCS | \
     OW_RUNLVL_F_SENTINEL | OW_RUNLVL_F_SYSCALL | OW_RUNLVL_F_SHELL)
#define RLVL_L2_FEATURES \
    (RLVL_L1_FEATURES | OW_RUNLVL_F_VFS | OW_RUNLVL_F_USFS | \
     OW_RUNLVL_F_STORAGE | OW_RUNLVL_F_OWINIT | OW_RUNLVL_F_INTEGRITY)
#define RLVL_L3_FEATURES (RLVL_L2_FEATURES | OW_RUNLVL_F_NETWORK)
#define RLVL_L4_FEATURES (RLVL_L3_FEATURES | OW_RUNLVL_F_VIP)
#define RLVL_L5_FEATURES (RLVL_L4_FEATURES | OW_RUNLVL_F_AI)

static const OW_RUNLEVEL_DEF k_Runlevels[OW_RUNLEVEL_COUNT] = {
    { -6, "DIAG-MIN",     "emergency bring-up - HAL + diagnostics only",
      OW_RUNLVL_F_HAL | OW_RUNLVL_F_DIAG, 0U,
      5U, 10000U, 128U, 32U },
    { -5, "DIAG-SYS",     "diagnostic core with memory + object services",
      OW_RUNLEVEL_CORE_FEATURES, 0U,
      4U, 15000U, 512U, 128U },
    { -4, "SAFE-CONSOLE", "recovery console with ALPC + sentinel defense",
      OW_RUNLEVEL_CORE_FEATURES | OW_RUNLVL_F_ALPC | OW_RUNLVL_F_SENTINEL, 0U,
      3U, 30000U, 1024U, 256U },
    { -3, "RECOVERY-FS",  "primary volume recovery (OWFS mount service)",
      OW_RUNLEVEL_CORE_FEATURES | OW_RUNLVL_F_ALPC | OW_RUNLVL_F_SENTINEL |
      OW_RUNLVL_F_VFS | OW_RUNLVL_F_STORAGE, 0U,
      3U, 45000U, 2048U, 512U },
    { -2, "SINGLE-USER",  "local maintenance (secure volume, no network)",
      OW_RUNLEVEL_CORE_FEATURES | OW_RUNLVL_F_ALPC | OW_RUNLVL_F_SENTINEL |
      OW_RUNLVL_F_VFS | OW_RUNLVL_F_USFS | OW_RUNLVL_F_STORAGE |
      OW_RUNLVL_F_SUCS, 0U,
      2U, 60000U, 4096U, 1024U },
    { -1, "MAINTENANCE",  "full local maintenance (owinit/integrity/shell)",
      OW_RUNLEVEL_CORE_FEATURES | OW_RUNLVL_F_ALPC | OW_RUNLVL_F_SENTINEL |
      OW_RUNLVL_F_VFS | OW_RUNLVL_F_USFS | OW_RUNLVL_F_STORAGE |
      OW_RUNLVL_F_SUCS | OW_RUNLVL_F_OWINIT | OW_RUNLVL_F_INTEGRITY |
      OW_RUNLVL_F_SYSCALL | OW_RUNLVL_F_SHELL, 0U,
      2U, 120000U, 8192U, 2048U },
    { OW_RUNLEVEL_HALT, "HALT", "system halt - all subsystems torn down",
      0U, OW_RUNLVL_FLAG_HALT,
      0U, 0U, 0U, 0U },
    { 1, "BOOT-CONSOLE", "single-user boot console",
      RLVL_L1_FEATURES, 0U,
      1U, 150000U, 16384U, 4096U },
    { 2, "MULTIUSER",    "multi-user console (VFS/USFS backed, no network)",
      RLVL_L2_FEATURES, 0U,
      1U, 300000U, 32768U, 8192U },
    { 3, "NETWORK",      "multi-user with univip 44-bit router online",
      RLVL_L3_FEATURES, 0U,
      1U, 600000U, 65536U, 16384U },
    { 4, "SERVICES",     "full services (UniVIP volume / FVIP index armed)",
      RLVL_L4_FEATURES, 0U,
      1U, 0U, 131072U, 32768U },
    { 5, "FULL",         "full system - AI module ecosystem armed",
      RLVL_L5_FEATURES, 0U,
      1U, 0U, 262144U, 65536U },
    { 6, "REBOOT",       "full system recycle / reboot target",
      RLVL_L5_FEATURES, OW_RUNLVL_FLAG_REBOOT,
      1U, 0U, 262144U, 65536U }
};

typedef struct _OW_FEATURE_NAME {
    uint32_t    Bit;
    const char* Name;
} OW_FEATURE_NAME;

static const OW_FEATURE_NAME k_FeatureNames[] = {
    { OW_RUNLVL_F_HAL,       "HAL" },
    { OW_RUNLVL_F_MEMORY,    "MEMORY" },
    { OW_RUNLVL_F_OBJECT,    "OBJECT" },
    { OW_RUNLVL_F_DIAG,      "DIAG" },
    { OW_RUNLVL_F_ALPC,      "ALPC" },
    { OW_RUNLVL_F_SUCS,      "SUCS" },
    { OW_RUNLVL_F_VFS,       "VFS" },
    { OW_RUNLVL_F_USFS,      "USFS" },
    { OW_RUNLVL_F_STORAGE,   "STORAGE" },
    { OW_RUNLVL_F_OWINIT,    "OWINIT" },
    { OW_RUNLVL_F_INTEGRITY, "INTEGRITY" },
    { OW_RUNLVL_F_NETWORK,   "NETWORK" },
    { OW_RUNLVL_F_VIP,       "VIP" },
    { OW_RUNLVL_F_SENTINEL,  "SENTINEL" },
    { OW_RUNLVL_F_SYSCALL,   "SYSCALL" },
    { OW_RUNLVL_F_SHELL,     "SHELL" },
    { OW_RUNLVL_F_AI,        "AI" },
    { OW_RUNLVL_F_CIS,       "CIS" },
};
#define OW_FEATURE_NAME_COUNT \
    ((uint32_t)(sizeof(k_FeatureNames) / sizeof(k_FeatureNames[0])))

static const OW_RUNLEVEL_DEF* g_Current;
static int       g_Target = OW_RUNLEVEL_BOOT_DEFAULT;
static uint32_t  g_Transitions = 0;

static uint32_t feat_count(uint32_t bits) {
    uint32_t n = 0;
    while (bits) { n += bits & 1U; bits >>= 1; }
    return n;
}

const OW_RUNLEVEL_DEF* OwRunlevelLookup(int level) {
    if (level < OW_RUNLEVEL_MIN || level > OW_RUNLEVEL_MAX) return (void*)0;
    return &k_Runlevels[level + 6];
}

OW_STATUS OwRunlevelInitialize(int target) {
    const OW_RUNLEVEL_DEF* def = OwRunlevelLookup(target);
    if (!def) return OW_ERR_INVALID_PARAM;
    g_Current = def;
    g_Target = target;
    g_Transitions = 0;
    return OW_SUCCESS;
}

int OwRunlevelGetCurrent(void) {
    return g_Current ? g_Current->Level : OW_RUNLEVEL_BOOT_DEFAULT;
}

int OwRunlevelGetTarget(void) { return g_Target; }

const OW_RUNLEVEL_DEF* OwRunlevelCurrent(void) { return g_Current; }

uint32_t OwRunlevelActiveFeatures(void) {
    return g_Current ? g_Current->Features : 0U;
}

uint32_t OwRunlevelActiveFeatureCount(void) {
    return feat_count(OwRunlevelActiveFeatures());
}

bool OwRunlevelRequires(uint32_t feature) {
    return g_Current && (g_Current->Features & feature) != 0U;
}

const char* OwRunlevelName(int level) {
    const OW_RUNLEVEL_DEF* def = OwRunlevelLookup(level);
    return def ? def->Name : "UNKNOWN";
}

const char* OwRunlevelDescription(int level) {
    const OW_RUNLEVEL_DEF* def = OwRunlevelLookup(level);
    return def ? def->Description : "no such runlevel";
}

uint32_t OwRunlevelTransitions(void) { return g_Transitions; }

static void runlevel_stop(void) {
    OwHalSmpHaltIPI();
    ow_hlt_loop();
}

OW_STATUS OwRunlevelTeardown(int from, int to) {
    const OW_RUNLEVEL_DEF* f = OwRunlevelLookup(from);
    const OW_RUNLEVEL_DEF* t = OwRunlevelLookup(to);
    if (!f || !t) return OW_ERR_INVALID_PARAM;
    if ((f->Features & OW_RUNLVL_F_NETWORK) && !(t->Features & OW_RUNLVL_F_NETWORK)) {
        ow_kprintf("[RUNLVL] tearing down network router\r\n");
        OwNetShutdown();
    }
    return OW_SUCCESS;
}

OW_STATUS OwRunlevelSet(int level) {
    const OW_RUNLEVEL_DEF* next = OwRunlevelLookup(level);
    OW_STATUS st;
    if (!next) return OW_ERR_INVALID_PARAM;
    if (g_Current == next) {
        ow_kprintf("[RUNLVL] already at level %d (%s)\r\n", level, next->Name);
        return OW_SUCCESS;
    }
    if (next->Flags & OW_RUNLVL_FLAG_REBOOT) {
        ow_kprintf("[SHUTDOWN] Runlevel %d (%s) - restart\r\n",
                   level, next->Name);
        /* Run the rc.d shutdown sequence, then software-reset via ACPI /
         * legacy reset control. runlevel_stop() is only reached when the
         * harness never acknowledges the reset request. */
        OwRcRestart();
        OwAcpiReset();
        runlevel_stop();
        return OW_SUCCESS;
    }
    if (next->Flags & OW_RUNLVL_FLAG_HALT) {
        ow_kprintf("[SHUTDOWN] Runlevel %d (%s) - power off\r\n",
                   level, next->Name);
        /* Run the rc.d shutdown sequence, then software power-off (ACPI S5). */
        OwRcShutdown();
        OwAcpiPowerOff();
        runlevel_stop();
        return OW_SUCCESS;
    }

    st = OwRunlevelTeardown(g_Current->Level, level);
    if (ow_status_error(st)) return st;

    g_Transitions++;
    g_Target = level;
    g_Current = next;
    ow_kprintf("[RUNLVL] transition complete -> level %d (%s), %u feature(s) armed\r\n",
               next->Level, next->Name, feat_count(next->Features));
    OwDiagLogFinished("Runlevel Transition", OW_C_RUNLEVEL_TRANSITION);
    return OW_SUCCESS;
}

void OwRunlevelPrintTable(void) {
    uint32_t i;
    const char* cls;
    ow_kprintf("[RUNLVL] runlevel table -6..6 (%u profiles):\r\n",
               (unsigned int)OW_RUNLEVEL_COUNT);
    for (i = 0; i < OW_RUNLEVEL_COUNT; i++) {
        const OW_RUNLEVEL_DEF* d = &k_Runlevels[i];
        if (d->Flags & OW_RUNLVL_FLAG_HALT)      cls = "TERMINAL";
        else if (d->Flags & OW_RUNLVL_FLAG_REBOOT) cls = "RECYCLE";
        else if (d->Level < 0)                   cls = "RECOVERY";
        else                                     cls = "RUNTIME";
        ow_kprintf("[RUNLVL] profile: level %d, name %s, class %s, features %u: %s\r\n",
                   d->Level, d->Name, cls,
                   (unsigned int)feat_count(d->Features), d->Description);
    }
}

void OwRunlevelPrintFeatures(void) {
    uint32_t armed = OwRunlevelActiveFeatures();
    uint32_t i;
    ow_kprintf("[RUNLVL] active features (0x%X):\r\n", (unsigned int)armed);
    for (i = 0; i < OW_FEATURE_NAME_COUNT; i++) {
        if (armed & k_FeatureNames[i].Bit) {
            ow_kprintf("[RUNLVL]   + %s\r\n", k_FeatureNames[i].Name);
        }
    }
    if (!armed) ow_kprintf("[RUNLVL]   (none)\r\n");
}