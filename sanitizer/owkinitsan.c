/* owkinitsan.c - OWKInitSan: initialization-order and initialization-state
 * validation (Phase 4) */
#include "../inc/owkinitsan.h"
#include "../inc/ow_string.h"

typedef struct _OW_KINIT_PHASE {
    char Name[OW_KINIT_NAME_MAX];
    uint32_t Order;
    uint32_t State;
} OW_KINIT_PHASE;

static OW_KINIT_PHASE g_Phases[OW_KINIT_MAX_PHASES];
static uint32_t g_PhaseCount;
static uint32_t g_HighestOrder;

static int owkinitsan_init(void) {
    OwKInitSanReset();
    return (int)OW_SUCCESS;
}

static void owkinitsan_shutdown(void) {
    /* The tracker keeps boot-flow state; it is not a resource to release. */
}

static OW_KSAN_MODULE g_InitModule = {
    OW_KSAN_MODULE_NAME_OWKINITSAN,
    80u,
    true,
    (const char*)0,
    owkinitsan_init,
    owkinitsan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKInitSanRegister(void) {
    return OwKSanRegisterModule(&g_InitModule);
}

void OwKInitSanReset(void) {
    uint32_t i;

    for (i = 0u; i < OW_KINIT_MAX_PHASES; ++i) {
        g_Phases[i].State = OW_KINIT_NOT_STARTED;
        g_Phases[i].Order = 0u;
        g_Phases[i].Name[0] = '\0';
    }
    g_PhaseCount = 0u;
    g_HighestOrder = 0u;
}

static OW_KINIT_PHASE* phase_find(const char* Name) {
    uint32_t i;

    if (Name == (const char*)0) {
        return (OW_KINIT_PHASE*)0;
    }
    for (i = 0u; i < g_PhaseCount; ++i) {
        if (ow_strcmp(g_Phases[i].Name, Name) == 0) {
            return &g_Phases[i];
        }
    }
    return (OW_KINIT_PHASE*)0;
}

static void phase_copy_name(OW_KINIT_PHASE* p, const char* Name) {
    uint32_t i;

    for (i = 0u; i < (OW_KINIT_NAME_MAX - 1u) && Name[i] != '\0'; ++i) {
        p->Name[i] = Name[i];
    }
    p->Name[i] = '\0';
}

OW_STATUS OwKInitSanPhaseBegin(const char* Name, uint32_t Order) {
    OW_KINIT_PHASE* p;

    if (Name == (const char*)0 || Name[0] == '\0') {
        return OW_ERR_INVALID_PARAM;
    }

    if (phase_find(Name) != (OW_KINIT_PHASE*)0) {
        if (OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKINITSAN)) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINITSAN,
                         "duplicate initialization of '%s'", Name);
        }
        return OW_ERR_ALREADY_EXISTS;
    }
    if (g_PhaseCount >= OW_KINIT_MAX_PHASES) {
        return OW_ERR_INSUFFICIENT;
    }

    if (Order < g_HighestOrder &&
        OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKINITSAN)) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINITSAN,
                     "initialization of '%s' out of order: %u follows %u",
                     Name, (unsigned)Order, (unsigned)g_HighestOrder);
        return OW_ERR_CORRUPT;
    }

    p = &g_Phases[g_PhaseCount];
    phase_copy_name(p, Name);
    p->Order = Order;
    p->State = OW_KINIT_RUNNING;
    g_PhaseCount++;

    if (Order > g_HighestOrder) {
        g_HighestOrder = Order;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKInitSanPhaseEnd(const char* Name, OW_STATUS Result) {
    OW_KINIT_PHASE* p = phase_find(Name);

    if (p == (OW_KINIT_PHASE*)0) {
        if (OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKINITSAN)) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINITSAN,
                         "end of '%s' without a begin", Name);
        }
        return OW_ERR_NOT_FOUND;
    }
    if (p->State == OW_KINIT_SKIPPED) {
        /* A skipped phase is already terminal; leave the state recorded. */
        return OW_SUCCESS;
    }
    if (p->State != OW_KINIT_RUNNING) {
        if (OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKINITSAN)) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINITSAN,
                         "end of '%s' that was not running", Name);
        }
        return OW_ERR_INVALID_PARAM;
    }

    p->State = ow_status_success(Result) ? OW_KINIT_DONE : OW_KINIT_FAILED;
    return OW_SUCCESS;
}

OW_STATUS OwKInitSanPhaseSkip(const char* Name) {
    OW_KINIT_PHASE* p = phase_find(Name);

    if (p == (OW_KINIT_PHASE*)0) {
        return OW_ERR_NOT_FOUND;
    }
    if (p->State != OW_KINIT_RUNNING) {
        return OW_ERR_INVALID_PARAM;
    }
    p->State = OW_KINIT_SKIPPED;
    return OW_SUCCESS;
}

bool OwKInitSanIsInitialized(const char* Name) {
    OW_KINIT_PHASE* p = phase_find(Name);

    return p != (OW_KINIT_PHASE*)0 && p->State == OW_KINIT_DONE;
}

bool OwKInitSanPhaseFailed(const char* Name) {
    OW_KINIT_PHASE* p = phase_find(Name);

    return p != (OW_KINIT_PHASE*)0 && p->State == OW_KINIT_FAILED;
}

uint32_t OwKInitSanPhaseCount(void) {
    return g_PhaseCount;
}

OW_STATUS OwKInitSanRequireInitialized(const char* Prerequisite,
                                       const char* Phase) {
    if (Prerequisite == (const char*)0 || Phase == (const char*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (!OwKInitSanIsInitialized(Prerequisite)) {
        if (OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKINITSAN)) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINITSAN,
                         "'%s' required before '%s' but it is not initialized",
                         Prerequisite, Phase);
        }
        return OW_ERR_NOT_INITIALIZED;
    }
    return OW_SUCCESS;
}
