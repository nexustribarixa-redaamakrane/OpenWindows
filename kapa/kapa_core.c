/* kapa_core.c - application-facing facade over the KDB management plane.
 *
 * The facade owns one bounded application table.  Every entry names the KDB
 * association it was created with and, once loaded, the KDB instance that
 * represents the associated kernel.  State is never cached as a second truth:
 * each observation refreshes it from OwKdbGetInstance(), so a fault, exit or
 * stop performed through KDB is visible here immediately.
 *
 * There is deliberately no call to OwKdbStartInstance() from Execute().  KDB's
 * STARTED state is a logical eligibility transition; a real execution backend
 * marks RUNNING only when the bound thread is actually dispatched.  Execute()
 * therefore asks the executor seam to run the instance and leaves the state
 * exactly as KDB reports it.
 */
#include "../inc/ow_kapa.h"
#include "../inc/ow_kprintf.h"

static OW_KAPA_APPLICATION g_Applications[OW_KAPA_MAX_APPLICATIONS];
static bool                g_ApplicationInUse[OW_KAPA_MAX_APPLICATIONS];
static bool                g_KapaReady = false;

static bool kapa_name_valid(const char* Name) {
    uint32_t i;

    if (Name == (const char*)0) {
        return false;
    }
    for (i = 0U; i < OW_KAPA_MAX_NAME; ++i) {
        if (Name[i] == '\0') {
            return i != 0U;
        }
    }
    return false;
}

static bool kapa_name_equal(const char* A, const char* B) {
    uint32_t i;

    if (A == (const char*)0 || B == (const char*)0) {
        return false;
    }
    for (i = 0U; i < OW_KAPA_MAX_NAME; ++i) {
        if (A[i] != B[i]) {
            return false;
        }
        if (A[i] == '\0') {
            return true;
        }
    }
    return false;
}

static bool kapa_copy_name(char* Dst, const char* Src) {
    uint32_t i;

    if (Dst == (char*)0 || !kapa_name_valid(Src)) {
        return false;
    }
    for (i = 0U; (i + 1U) < OW_KAPA_MAX_NAME && Src[i] != '\0'; ++i) {
        Dst[i] = Src[i];
    }
    Dst[i] = '\0';
    return Src[i] == '\0';
}

static void kapa_clear(uint32_t Index) {
    OW_KAPA_APPLICATION* app = &g_Applications[Index];

    app->Id = OW_KDB_INVALID_ID;
    app->Name[0] = '\0';
    app->AssociationId = OW_KDB_INVALID_ID;
    app->KernelId = OW_KDB_INVALID_ID;
    app->InstanceId = OW_KDB_INVALID_ID;
    app->Capabilities = 0U;
    app->State = OW_KAPA_STATE_ASSOCIATED;
    app->LastStatus = OW_SUCCESS;
    g_ApplicationInUse[Index] = false;
}

/* Refresh one application from the authoritative KDB instance.  If the instance
 * disappeared (destroyed or reset), the application falls back to ASSOCIATED
 * rather than retaining a dangling identifier. */
static void kapa_refresh(uint32_t Index) {
    OW_KAPA_APPLICATION* app = &g_Applications[Index];
    OW_KDB_INSTANCE instance;

    if (!g_ApplicationInUse[Index]) {
        return;
    }
    if (app->InstanceId == OW_KDB_INVALID_ID) {
        app->State = OW_KAPA_STATE_ASSOCIATED;
        return;
    }
    if (!ow_status_success(OwKdbGetInstance(app->InstanceId, &instance))) {
        app->InstanceId = OW_KDB_INVALID_ID;
        app->State = OW_KAPA_STATE_ASSOCIATED;
        return;
    }

    switch (instance.State) {
    case OW_KDB_INSTANCE_READY:
        app->State = OW_KAPA_STATE_LOADED;
        break;
    case OW_KDB_INSTANCE_RUNNING:
        app->State = OW_KAPA_STATE_RUNNING;
        break;
    case OW_KDB_INSTANCE_STOPPED:
        app->State = OW_KAPA_STATE_STOPPED;
        break;
    case OW_KDB_INSTANCE_FAULTED:
        app->State = OW_KAPA_STATE_FAULTED;
        app->LastStatus = instance.LastFault;
        break;
    default:
        app->State = OW_KAPA_STATE_ASSOCIATED;
        break;
    }
}

static bool kapa_slot(uint32_t ApplicationId, uint32_t* OutIndex) {
    if (ApplicationId == OW_KDB_INVALID_ID ||
        ApplicationId > OW_KAPA_MAX_APPLICATIONS) {
        return false;
    }
    if (!g_ApplicationInUse[ApplicationId - 1U]) {
        return false;
    }
    if (OutIndex != (uint32_t*)0) {
        *OutIndex = ApplicationId - 1U;
    }
    return true;
}

OW_STATUS OwKapaInitialize(void) {
    uint32_t i;

    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        kapa_clear(i);
    }

    if (!OwKdbIsReady()) {
        g_KapaReady = false;
        return OW_ERR_NOT_INITIALIZED;
    }

    g_KapaReady = true;
    ow_kprintf("[KAPA] ready: application facade over KDB (%u slots)\r\n",
               (unsigned)OW_KAPA_MAX_APPLICATIONS);
    return OW_SUCCESS;
}

bool OwKapaIsReady(void) {
    return g_KapaReady;
}

const char* OwKapaStateName(OW_KAPA_STATE State) {
    switch (State) {
    case OW_KAPA_STATE_ASSOCIATED: return "associated";
    case OW_KAPA_STATE_LOADED:     return "loaded";
    case OW_KAPA_STATE_RUNNING:    return "running";
    case OW_KAPA_STATE_STOPPED:    return "stopped";
    case OW_KAPA_STATE_FAULTED:    return "faulted";
    default:                       return "unknown";
    }
}

OW_STATUS OwKapaRegisterApplication(const char* Name, uint32_t KernelId,
                                   uint32_t Capabilities,
                                   uint32_t* OutApplicationId) {
    OW_STATUS status;
    uint32_t association = OW_KDB_INVALID_ID;
    uint32_t slot;
    uint32_t i;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_name_valid(Name) || OutApplicationId == (uint32_t*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        if (g_ApplicationInUse[i] &&
            kapa_name_equal(g_Applications[i].Name, Name)) {
            return OW_ERR_ALREADY_EXISTS;
        }
    }

    slot = OW_KAPA_MAX_APPLICATIONS;
    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        if (!g_ApplicationInUse[i]) {
            slot = i;
            break;
        }
    }
    if (slot == OW_KAPA_MAX_APPLICATIONS) {
        return OW_ERR_INSUFFICIENT;
    }

    /* The association is the authority boundary the bridge checks.  Creating
     * it first means a registration that fails compatibility leaves no KAPA
     * slot behind. */
    status = OwKdbAssociateApplication(Name, KernelId, Capabilities,
                                      &association);
    if (ow_status_error(status)) {
        return status;
    }

    g_Applications[slot].Id = slot + 1U;
    if (!kapa_copy_name(g_Applications[slot].Name, Name)) {
        (void)OwKdbDisassociateApplication(association);
        return OW_ERR_INVALID_PARAM;
    }
    g_Applications[slot].AssociationId = association;
    g_Applications[slot].KernelId = KernelId;
    g_Applications[slot].InstanceId = OW_KDB_INVALID_ID;
    g_Applications[slot].Capabilities = Capabilities;
    g_Applications[slot].State = OW_KAPA_STATE_ASSOCIATED;
    g_Applications[slot].LastStatus = OW_SUCCESS;
    g_ApplicationInUse[slot] = true;

    *OutApplicationId = g_Applications[slot].Id;
    return OW_SUCCESS;
}

OW_STATUS OwKapaUnregisterApplication(uint32_t ApplicationId) {
    uint32_t index;
    OW_STATUS status;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    if (g_Applications[index].InstanceId != OW_KDB_INVALID_ID) {
        (void)OwKdbDestroyInstance(g_Applications[index].InstanceId);
        g_Applications[index].InstanceId = OW_KDB_INVALID_ID;
    }

    status = OwKdbDisassociateApplication(
        g_Applications[index].AssociationId);
    if (status == OW_ERR_NOT_FOUND) {
        status = OW_SUCCESS;
    }

    kapa_clear(index);
    return status;
}

OW_STATUS OwKapaGetApplication(uint32_t ApplicationId,
                               OW_KAPA_APPLICATION* OutApplication) {
    uint32_t index;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutApplication == (OW_KAPA_APPLICATION*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    kapa_refresh(index);
    *OutApplication = g_Applications[index];
    return OW_SUCCESS;
}

OW_STATUS OwKapaFindApplication(const char* Name,
                                OW_KAPA_APPLICATION* OutApplication) {
    uint32_t i;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_name_valid(Name) || OutApplication == (OW_KAPA_APPLICATION*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        if (g_ApplicationInUse[i] &&
            kapa_name_equal(g_Applications[i].Name, Name)) {
            kapa_refresh(i);
            *OutApplication = g_Applications[i];
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

OW_STATUS OwKapaGetApplicationByIndex(uint32_t Index,
                                      OW_KAPA_APPLICATION* OutApplication) {
    uint32_t i;
    uint32_t seen = 0U;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutApplication == (OW_KAPA_APPLICATION*)0) {
        return OW_ERR_NULL_POINTER;
    }

    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        if (g_ApplicationInUse[i]) {
            if (seen == Index) {
                kapa_refresh(i);
                *OutApplication = g_Applications[i];
                return OW_SUCCESS;
            }
            ++seen;
        }
    }
    return OW_ERR_NOT_FOUND;
}

uint32_t OwKapaApplicationCount(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        if (g_ApplicationInUse[i]) {
            ++count;
        }
    }
    return count;
}

OW_STATUS OwKapaComposeAbi(const OW_KDB_MANIFEST_FILE* Files,
                           uint32_t FileCount, uint32_t* OutAbiId) {
    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbAbiComposeCustom(Files, FileCount, OutAbiId);
}

OW_STATUS OwKapaLoad(uint32_t ApplicationId, uint32_t PageLimit) {
    uint32_t index;
    uint32_t instance = OW_KDB_INVALID_ID;
    OW_STATUS status;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    kapa_refresh(index);
    if (g_Applications[index].InstanceId != OW_KDB_INVALID_ID) {
        return OW_ERR_ALREADY_EXISTS;
    }

    status = OwKdbLoadInstance(g_Applications[index].AssociationId,
                               PageLimit, &instance);
    g_Applications[index].LastStatus = status;
    if (ow_status_error(status)) {
        return status;
    }

    g_Applications[index].InstanceId = instance;
    g_Applications[index].State = OW_KAPA_STATE_LOADED;
    return OW_SUCCESS;
}

OW_STATUS OwKapaExecute(uint32_t ApplicationId) {
    uint32_t index;
    OW_STATUS status;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    kapa_refresh(index);
    if (g_Applications[index].InstanceId == OW_KDB_INVALID_ID) {
        return OW_ERR_NOT_FOUND;
    }

    /* OwKdbExecuteInstance() owns the no-fake-execution rule: without a
     * backend it returns OW_ERR_UNSUPPORTED and changes nothing. */
    status = OwKdbExecuteInstance(g_Applications[index].InstanceId);
    g_Applications[index].LastStatus = status;
    kapa_refresh(index);
    return status;
}

OW_STATUS OwKapaStop(uint32_t ApplicationId) {
    uint32_t index;
    OW_STATUS status;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    kapa_refresh(index);
    if (g_Applications[index].InstanceId == OW_KDB_INVALID_ID) {
        return OW_ERR_NOT_FOUND;
    }

    status = OwKdbStopInstance(g_Applications[index].InstanceId);
    g_Applications[index].LastStatus = status;
    kapa_refresh(index);
    return status;
}

OW_STATUS OwKapaFault(uint32_t ApplicationId, OW_STATUS FaultStatus) {
    uint32_t index;
    OW_STATUS status;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    kapa_refresh(index);
    if (g_Applications[index].InstanceId == OW_KDB_INVALID_ID) {
        return OW_ERR_NOT_FOUND;
    }

    status = OwKdbFaultInstance(g_Applications[index].InstanceId, FaultStatus);
    g_Applications[index].LastStatus = status;
    kapa_refresh(index);
    return status;
}

OW_STATUS OwKapaDestroy(uint32_t ApplicationId) {
    uint32_t index;
    OW_STATUS status = OW_SUCCESS;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    kapa_refresh(index);
    if (g_Applications[index].InstanceId == OW_KDB_INVALID_ID) {
        return OW_ERR_NOT_FOUND;
    }

    status = OwKdbDestroyInstance(g_Applications[index].InstanceId);
    if (status == OW_ERR_NOT_FOUND) {
        status = OW_SUCCESS;
    }
    g_Applications[index].LastStatus = status;
    if (ow_status_success(status)) {
        g_Applications[index].InstanceId = OW_KDB_INVALID_ID;
        g_Applications[index].State = OW_KAPA_STATE_ASSOCIATED;
    }
    return status;
}

OW_STATUS OwKapaBridgeCall(uint32_t ApplicationId, uint32_t TargetInstanceId,
                           uint32_t ServiceId,
                           const void* Request, uint32_t RequestLength,
                           void* Response, uint32_t ResponseCapacity,
                           uint32_t* ResponseLength) {
    uint32_t index;

    if (!g_KapaReady) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!kapa_slot(ApplicationId, &index)) {
        return OW_ERR_NOT_FOUND;
    }

    return OwKdbBridgeCall(g_Applications[index].AssociationId,
                           TargetInstanceId, ServiceId, Request,
                           RequestLength, Response, ResponseCapacity,
                           ResponseLength);
}

void OwKapaGetStats(OW_KAPA_STATS* OutStats) {
    uint32_t i;

    if (OutStats == (OW_KAPA_STATS*)0) {
        return;
    }

    OutStats->Applications = 0U;
    OutStats->Loaded = 0U;
    OutStats->Running = 0U;
    OutStats->Stopped = 0U;
    OutStats->Faulted = 0U;
    OutStats->BridgeCalls = 0U;

    if (!g_KapaReady) {
        return;
    }

    for (i = 0U; i < OW_KAPA_MAX_APPLICATIONS; ++i) {
        if (!g_ApplicationInUse[i]) {
            continue;
        }
        kapa_refresh(i);
        ++OutStats->Applications;
        switch (g_Applications[i].State) {
        case OW_KAPA_STATE_LOADED:  ++OutStats->Loaded;  break;
        case OW_KAPA_STATE_RUNNING: ++OutStats->Running; break;
        case OW_KAPA_STATE_STOPPED: ++OutStats->Stopped; break;
        case OW_KAPA_STATE_FAULTED: ++OutStats->Faulted; break;
        default: break;
        }
    }
}
