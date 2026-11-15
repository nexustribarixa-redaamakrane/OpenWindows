/* owksan_core.c - OWKSan Suite framework core (Phase 1) */
#include "../inc/owksan.h"
#include "../inc/ow_string.h"
#include "../inc/ow_kprintf.h"

/* Bounded module table.  Modules are kept sorted by ascending InitOrder so a
 * forward scan during initialisation and a reverse scan during shutdown give a
 * deterministic dependency-friendly order without any dynamic sorting. */
static OW_KSAN_MODULE g_Modules[OW_KSAN_MODULE_MAX];
static uint32_t g_ModuleCount;
static uint32_t g_ReportCount;
static uint32_t g_FatalCount;
static bool g_Initialized;
static bool g_MasterEnabled;
static OW_KSAN_PANIC_HOOK g_PanicHook = (OW_KSAN_PANIC_HOOK)0;

static OW_KSAN_MODULE* ksan_find(const char* Name) {
    uint32_t i;

    if (Name == (const char*)0) {
        return (OW_KSAN_MODULE*)0;
    }
    for (i = 0U; i < g_ModuleCount; ++i) {
        if (ow_strcmp(g_Modules[i].Name, Name) == 0) {
            return &g_Modules[i];
        }
    }
    return (OW_KSAN_MODULE*)0;
}

OW_STATUS OwKSanRegisterModule(const OW_KSAN_MODULE* Module) {
    uint32_t slot;
    uint32_t i;

    if (Module == (const OW_KSAN_MODULE*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (Module->Name[0] == '\0') {
        return OW_ERR_INVALID_PARAM;
    }
    if (ksan_find(Module->Name) != (OW_KSAN_MODULE*)0) {
        return OW_ERR_ALREADY_EXISTS;
    }
    if (g_ModuleCount >= OW_KSAN_MODULE_MAX) {
        return OW_ERR_INSUFFICIENT;
    }

    /* Insertion sort by InitOrder, keeping the table sorted ascending. */
    slot = g_ModuleCount;
    for (i = 0U; i < g_ModuleCount; ++i) {
        if (Module->InitOrder < g_Modules[i].InitOrder) {
            slot = i;
            break;
        }
    }
    if (slot < g_ModuleCount) {
        uint32_t i2;

        for (i2 = g_ModuleCount; i2 > slot; --i2) {
            g_Modules[i2 - 1U] = g_Modules[i2 - 2U];
        }
    }
    g_Modules[slot] = *Module;
    ow_strncpy(g_Modules[slot].Name, Module->Name, OW_KSAN_MODULE_NAME_MAX);
    g_Modules[slot].Name[OW_KSAN_MODULE_NAME_MAX - 1U] = '\0';
    g_Modules[slot].Inited = false;
    g_Modules[slot].InitStatus = OW_SUCCESS;
    if (slot == g_ModuleCount) {
        g_ModuleCount++;
    }
    return OW_SUCCESS;
}

void OwKSanUnregisterModule(const char* Name) {
    uint32_t idx;
    uint32_t i;
    OW_KSAN_MODULE* m = ksan_find(Name);

    if (m == (OW_KSAN_MODULE*)0) {
        return;
    }
    idx = (uint32_t)(m - g_Modules);
    for (i = idx; i + 1U < g_ModuleCount; ++i) {
        g_Modules[i] = g_Modules[i + 1U];
    }
    g_ModuleCount--;
}

OW_STATUS OwKSanGetModule(const char* Name, OW_KSAN_MODULE* OutModule) {
    OW_KSAN_MODULE* m = ksan_find(Name);

    if (OutModule == (OW_KSAN_MODULE*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (m == (OW_KSAN_MODULE*)0) {
        return OW_ERR_NOT_FOUND;
    }
    *OutModule = *m;
    return OW_SUCCESS;
}

uint32_t OwKSanModuleCount(void) {
    return g_ModuleCount;
}

uint32_t OwKSanEnabledModuleCount(void) {
    uint32_t i;
    uint32_t n = 0U;

    for (i = 0U; i < g_ModuleCount; ++i) {
        if (g_Modules[i].Enabled) {
            n++;
        }
    }
    return n;
}

OW_STATUS OwKSanEnableModule(const char* Name) {
    OW_KSAN_MODULE* m = ksan_find(Name);

    if (m == (OW_KSAN_MODULE*)0) {
        return OW_ERR_NOT_FOUND;
    }
    m->Enabled = true;
    m->Inited = false;
    return OW_SUCCESS;
}

OW_STATUS OwKSanDisableModule(const char* Name) {
    OW_KSAN_MODULE* m = ksan_find(Name);

    if (m == (OW_KSAN_MODULE*)0) {
        return OW_ERR_NOT_FOUND;
    }
    m->Enabled = false;
    m->Inited = false;
    return OW_SUCCESS;
}

OW_STATUS OwKSanConfigureModule(const char* Name, bool Enabled) {
    OW_KSAN_MODULE* m = ksan_find(Name);

    if (m == (OW_KSAN_MODULE*)0) {
        return OW_ERR_NOT_FOUND;
    }
    m->Enabled = Enabled;
    m->Inited = false;
    return OW_SUCCESS;
}

void OwKSanSetMasterEnabled(bool On) {
    g_MasterEnabled = On;
}

bool OwKSanMasterEnabled(void) {
    return g_MasterEnabled;
}

OW_STATUS OwKSanInitializeEnabledModules(void) {
    uint32_t i;
    OW_STATUS st = OW_SUCCESS;

    /* g_Modules is kept sorted by ascending InitOrder, so a forward scan is a
     * dependency-friendly initialisation order.  DependsOn is honoured by the
     * registering module declaring the lower InitOrder of its dependency; the
     * core only guarantees deterministic ordering. */
    for (i = 0U; i < g_ModuleCount; ++i) {
        if (!g_Modules[i].Enabled) {
            continue;
        }
        if (g_Modules[i].Initialize == (int (*)(void))0) {
            g_Modules[i].Inited = true;
            g_Modules[i].InitStatus = OW_SUCCESS;
            continue;
        }
        g_Modules[i].InitStatus = (OW_STATUS)g_Modules[i].Initialize();
        g_Modules[i].Inited = true;
        if (!ow_status_success(g_Modules[i].InitStatus)) {
            st = g_Modules[i].InitStatus;
        }
    }
    return st;
}

OW_STATUS OwKSanInitialize(void) {
    uint32_t i;

    g_Initialized = true;
    /* Configuration is explicit: the suite starts inert and the master switch
     * is off until a boot path or host test turns it on. */
    g_MasterEnabled = false;
    g_ReportCount = 0U;
    g_FatalCount = 0U;
    for (i = 0U; i < g_ModuleCount; ++i) {
        g_Modules[i].Inited = false;
        g_Modules[i].InitStatus = OW_SUCCESS;
    }
    return OwKSanInitializeEnabledModules();
}

void OwKSanShutdown(void) {
    uint32_t i;

    /* Reverse scan of the InitOrder-sorted table == shutdown in reverse order. */
    for (i = g_ModuleCount; i > 0U; --i) {
        OW_KSAN_MODULE* m = &g_Modules[i - 1U];

        if (m->Inited && m->Enabled && m->Shutdown != (void (*)(void))0) {
            m->Shutdown();
            m->Inited = false;
        }
    }
    g_MasterEnabled = false;
    g_Initialized = false;
}

bool OwKSanReady(void) {
    return g_Initialized;
}

OW_KSAN_SEVERITY OwKSanReport(OW_KSAN_SEVERITY Severity, const char* Module,
                              const char* Format, ...) {
    OW_KSAN_MODULE* m;
    char text[OW_KSAN_REPORT_TEXT_MAX];
    va_list ap;

    if (!g_Initialized) {
        /* The suite is not active before OwKSanInitialize ran. */
        return OW_KSAN_SEVERITY_OK;
    }
    m = ksan_find(Module);
    if (m == (OW_KSAN_MODULE*)0) {
        /* Unknown module: an invalid diagnostic target, not a detected fault. */
        return OW_KSAN_SEVERITY_ERROR;
    }
    if (!g_MasterEnabled || !m->Enabled) {
        /* Disabled by configuration: the module is not running its check, so
         * no diagnostic is produced.  This is configuration, not a finding. */
        return OW_KSAN_SEVERITY_OK;
    }

    va_start(ap, Format);
    (void)ow_vsnprintf(text, OW_KSAN_REPORT_TEXT_MAX, Format, ap);
    va_end(ap);
    text[OW_KSAN_REPORT_TEXT_MAX - 1U] = '\0';

    ow_kprintf("[KSAN] module=%s severity=%s text=%s\r\n", Module,
               OwKSanSeverityName(Severity), text);

    g_ReportCount++;
    if (Severity == OW_KSAN_SEVERITY_FATAL) {
        g_FatalCount++;
    }
    return Severity;
}

uint32_t OwKSanReportCount(void) {
    return g_ReportCount;
}

uint32_t OwKSanFatalCount(void) {
    return g_FatalCount;
}

void OwKSanResetCounters(void) {
    g_ReportCount = 0U;
    g_FatalCount = 0U;
}

void OwKSanSetPanicHook(OW_KSAN_PANIC_HOOK Hook) {
    g_PanicHook = Hook;
}

void OwKSanPanic(const char* Module, const char* Detail, OW_STATUS Status) {
    if (g_PanicHook != (OW_KSAN_PANIC_HOOK)0) {
        g_PanicHook(Module, Detail, Status);
        return;
    }
    ow_kprintf("[KSAN][PANIC] module=%s detail=%s status=0x%X\r\n",
               Module ? Module : "-", Detail ? Detail : "-",
               (unsigned)Status);
}

const char* OwKSanSeverityName(OW_KSAN_SEVERITY Severity) {
    switch (Severity) {
    case OW_KSAN_SEVERITY_OK:
        return "OK";
    case OW_KSAN_SEVERITY_WARNING:
        return "WARNING";
    case OW_KSAN_SEVERITY_ERROR:
        return "ERROR";
    case OW_KSAN_SEVERITY_FATAL:
        return "FATAL";
    }
    return "UNKNOWN";
}

const char* OwKSanModuleName(uint32_t Index) {
    if (Index >= g_ModuleCount) {
        return (const char*)0;
    }
    return g_Modules[Index].Name;
}

OW_STATUS OwKSanSeverityToStatus(OW_KSAN_SEVERITY Severity) {
    switch (Severity) {
    case OW_KSAN_SEVERITY_OK:
        return OW_SUCCESS;
    case OW_KSAN_SEVERITY_WARNING:
        return OW_SUCCESS;
    case OW_KSAN_SEVERITY_ERROR:
        return OW_ERR_CORRUPT;
    case OW_KSAN_SEVERITY_FATAL:
        return OW_ERR_CORRUPT;
    }
    return OW_ERR_INVALID_PARAM;
}
