/* owksan.h - OpenWindows Kernel Sanitization Framework (OWKSan)
 *
 * Phase 1 of the OWKSan Suite: the framework core.  The individual check
 * modules (OWKAsan, OWKUbSan, OWKMSan, OWKTSan, OWKLSan, OWStackSan, OWKHeapSan,
 * OWKPageSan, OWKBoundsSan, OWKIntSan, OWKInitSan, OWKLockSan) are registered
 * here as modules with an initialize/shutdown lifecycle and a per-module
 * enable/disable switch.  The core owns the bounded module table, the runtime
 * configuration, diagnostic reporting, panic integration and counters.
 *
 * This phase delivers the framework only.  The check implementations land in
 * later phases; the core is written so those modules can register into the same
 * table without further architectural changes.
 *
 * Conventions followed here (rather than inventing a parallel abstraction):
 *   - statuses come from ow_types.h (OW_SUCCESS / OW_ERR_*);
 *   - formatted output goes through ow_kprintf (kernel UART console);
 *   - all storage is static and bounded, no dynamic allocation;
 *   - the API is single-threaded kernel code and takes no locks.
 */
#ifndef OW_KSAN_H
#define OW_KSAN_H

#include "ow_types.h"

/* Bounded module table and text sizes. */
#define OW_KSAN_MODULE_MAX       16U
#define OW_KSAN_MODULE_NAME_MAX  32U
#define OW_KSAN_REPORT_TEXT_MAX  192U

/* Diagnostic severities.  Ordered so a comparison is a numeric ordering:
 * OK < WARNING < ERROR < FATAL. */
typedef enum _OW_KSAN_SEVERITY {
    OW_KSAN_SEVERITY_OK = 0,
    OW_KSAN_SEVERITY_WARNING = 1,
    OW_KSAN_SEVERITY_ERROR = 2,
    OW_KSAN_SEVERITY_FATAL = 3
} OW_KSAN_SEVERITY;

/* One sanitizer module inside the suite.  A module owns its check, its
 * lifecycle and its enable/disable state; the core never inspects what the
 * check does.  Modules are kept sorted by InitOrder so the core can initialise
 * and shut them down in a deterministic order; DependsOn names a module that
 * must be initialised first. */
typedef struct _OW_KSAN_MODULE {
    char Name[OW_KSAN_MODULE_NAME_MAX];
    uint32_t InitOrder;
    bool Enabled;
    const char* DependsOn;
    int (*Initialize)(void);
    void (*Shutdown)(void);
    bool Inited;
    OW_STATUS InitStatus;
} OW_KSAN_MODULE;

/* Canonical module names for the first twelve OWKSan Suite components.  The
 * core does not register these itself (Phase 1 ships the framework only); each
 * later phase registers its own implementation under these names. */
#define OW_KSAN_MODULE_NAME_OWKASAN      "OWKAsan"
#define OW_KSAN_MODULE_NAME_OWKUBSAN      "OWKUbSan"
#define OW_KSAN_MODULE_NAME_OWKMSAN       "OWKMSan"
#define OW_KSAN_MODULE_NAME_OWKTSAN       "OWKTSan"
#define OW_KSAN_MODULE_NAME_OWKLSAN       "OWKLSan"
#define OW_KSAN_MODULE_NAME_OWSTACKSAN    "OWStackSan"
#define OW_KSAN_MODULE_NAME_OWKHEAPSAN    "OWKHeapSan"
#define OW_KSAN_MODULE_NAME_OWKPageSan    "OWKPageSan"
#define OW_KSAN_MODULE_NAME_OWKBOUNDSAN   "OWKBoundsSan"
#define OW_KSAN_MODULE_NAME_OWKINTSAN     "OWKIntSan"
#define OW_KSAN_MODULE_NAME_OWKINITSAN    "OWKInitSan"
#define OW_KSAN_MODULE_NAME_OWKLOCKSAN    "OWKLockSan"

/* Panic hook: called when a diagnostic reaches FATAL severity.  The default
 * implementation logs through the kernel console; a host build or a boot-time
 * caller may install a stricter hook (for example the BANhammer crash screen). */
typedef void (*OW_KSAN_PANIC_HOOK)(const char* Module, const char* Detail,
                                  OW_STATUS Status);

/* ---- Suite lifecycle -------------------------------------------------------- */
OW_STATUS OwKSanInitialize(void);
void OwKSanShutdown(void);
bool OwKSanReady(void);

/* ---- Module registry -------------------------------------------------------- */
OW_STATUS OwKSanRegisterModule(const OW_KSAN_MODULE* Module);
void OwKSanUnregisterModule(const char* Name);
OW_STATUS OwKSanGetModule(const char* Name, OW_KSAN_MODULE* OutModule);
uint32_t OwKSanModuleCount(void);
uint32_t OwKSanEnabledModuleCount(void);

/* ---- Runtime configuration -------------------------------------------------- */
OW_STATUS OwKSanEnableModule(const char* Name);
OW_STATUS OwKSanDisableModule(const char* Name);
OW_STATUS OwKSanConfigureModule(const char* Name, bool Enabled);
void OwKSanSetMasterEnabled(bool On);
bool OwKSanMasterEnabled(void);
bool OwKSanIsEnabled(const char* Name);
OW_STATUS OwKSanInitializeEnabledModules(void);

/* ---- Diagnostic reporting ---------------------------------------------------- */
OW_KSAN_SEVERITY OwKSanReport(OW_KSAN_SEVERITY Severity, const char* Module,
                              const char* Format, ...);
uint32_t OwKSanReportCount(void);
uint32_t OwKSanFatalCount(void);
void OwKSanResetCounters(void);

/* ---- Panic integration -------------------------------------------------------- */
void OwKSanSetPanicHook(OW_KSAN_PANIC_HOOK Hook);
void OwKSanPanic(const char* Module, const char* Detail, OW_STATUS Status);

/* ---- Introspection -------------------------------------------------------- */
const char* OwKSanSeverityName(OW_KSAN_SEVERITY Severity);
const char* OwKSanModuleName(uint32_t Index);

/* ---- Error classification ---------------------------------------------------- */
OW_STATUS OwKSanSeverityToStatus(OW_KSAN_SEVERITY Severity);

#endif /* OW_KSAN_H */
