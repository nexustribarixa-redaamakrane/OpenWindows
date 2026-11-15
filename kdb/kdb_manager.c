/* kdb_manager.c - associated-kernel instance lifecycle and resource admission.
 *
 * An instance is the managed object created when a KAPA application actually
 * loads its associated kernel.  The manager owns the page budget, the stable
 * logical isolation-domain identifier and the state machine:
 *
 *   READY -> RUNNING -> STOPPED -> RUNNING
 *     |         |          |
 *     +---------+----------+--> FAULTED -> destroyed
 *
 * Fault cleanup is explicit: pages are released, the association link is
 * cleared and every service the instance provided is removed.  Destroy reuses
 * the same cleanup so there is no second, weaker teardown path.
 */
#include "kdb_internal.h"
#include "../inc/ow_kprintf.h"

static OW_KDB_INSTANCE g_Instances[OW_KDB_MAX_INSTANCES];
static bool            g_InstanceInUse[OW_KDB_MAX_INSTANCES];
static uint32_t        g_NextDomain = 1U;
static uint32_t        g_FaultCount = 0U;

void OwKdbManagerReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        g_InstanceInUse[i] = false;
    }
    g_NextDomain = 1U;
    g_FaultCount = 0U;
}

uint32_t OwKdbManagerNextDomain(void) {
    uint32_t domain = g_NextDomain;

    ++g_NextDomain;
    if (g_NextDomain == 0U) {
        g_NextDomain = 1U;
    }
    return domain;
}

bool OwKdbManagerExists(uint32_t InstanceId) {
    if (InstanceId == OW_KDB_INVALID_ID ||
        InstanceId > OW_KDB_MAX_INSTANCES) {
        return false;
    }
    return g_InstanceInUse[InstanceId - 1U];
}

bool OwKdbManagerIsRunning(uint32_t InstanceId) {
    if (!OwKdbManagerExists(InstanceId)) {
        return false;
    }
    return g_Instances[InstanceId - 1U].State == OW_KDB_INSTANCE_RUNNING;
}

void OwKdbManagerNoteBridgeCall(uint32_t InstanceId) {
    if (OwKdbManagerExists(InstanceId)) {
        ++g_Instances[InstanceId - 1U].BridgeCalls;
    }
}

uint32_t OwKdbManagerCount(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        if (g_InstanceInUse[i]) {
            ++count;
        }
    }
    return count;
}

uint32_t OwKdbManagerFaultCount(void) {
    return g_FaultCount;
}

uint32_t OwKdbManagerBridgeCalls(void) {
    uint32_t i;
    uint32_t calls = 0U;

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        if (g_InstanceInUse[i]) {
            calls += g_Instances[i].BridgeCalls;
        }
    }
    return calls;
}

OW_STATUS OwKdbLoadInstance(uint32_t AssociationId, uint32_t PageLimit,
                            uint32_t* OutInstanceId) {
    OW_KDB_ASSOCIATION association;
    OW_KDB_COMPAT_REPORT report;
    const OW_KDB_KERNEL_DESC* kernel;
    OW_STATUS status;
    uint32_t pages = 0U;
    uint64_t entry = 0U;
    uint64_t base = 0U;
    uint32_t limit;
    uint32_t i;
    uint32_t free_slot = OW_KDB_MAX_INSTANCES;
    uint32_t instance_id;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }

    status = OwKdbAssociationGet(AssociationId, &association);
    if (ow_status_error(status)) {
        return status;
    }
    if (association.InstanceId != OW_KDB_INVALID_ID) {
        return OW_ERR_ALREADY_EXISTS;
    }

    kernel = OwKdbRegistryPtr(association.KernelId);
    if (kernel == (const OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_NOT_FOUND;
    }

    status = OwKdbAssessCompatibility(kernel, &report);
    if (ow_status_error(status)) {
        return status;
    }

    limit = (PageLimit == 0U) ? OW_KDB_DEFAULT_PAGE_LIMIT : PageLimit;
    status = OwKdbLoaderPrepare(kernel, &pages, &entry, &base);
    if (ow_status_error(status)) {
        return status;
    }
    if (pages > limit) {
        return OW_ERR_INSUFFICIENT;
    }

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        if (!g_InstanceInUse[i]) {
            free_slot = i;
            break;
        }
    }
    if (free_slot == OW_KDB_MAX_INSTANCES) {
        return OW_ERR_INSUFFICIENT;
    }

    instance_id = free_slot + 1U;
    g_Instances[free_slot].Id = instance_id;
    g_Instances[free_slot].KernelId = association.KernelId;
    g_Instances[free_slot].AssociationId = AssociationId;
    (void)OwKdbCopyName(g_Instances[free_slot].Application, OW_KDB_MAX_NAME,
                        association.Application);
    (void)OwKdbCopyName(g_Instances[free_slot].Kernel, OW_KDB_MAX_NAME,
                        kernel->Name);
    g_Instances[free_slot].State = OW_KDB_INSTANCE_READY;
    g_Instances[free_slot].IsolationDomain = OwKdbManagerNextDomain();
    g_Instances[free_slot].ResidentPages = pages;
    g_Instances[free_slot].PageLimit = limit;
    g_Instances[free_slot].BridgeCalls = 0U;
    g_Instances[free_slot].LastFault = OW_SUCCESS;
    g_Instances[free_slot].EntryPoint = entry;
    g_Instances[free_slot].MappedBase = base;
    g_Instances[free_slot].Abi = kernel->Abi;
    g_Instances[free_slot].Format = kernel->Format;
    g_Instances[free_slot].ProcessId = 0U;
    g_Instances[free_slot].ThreadId = 0U;
    g_Instances[free_slot].ExitStatus = 0U;
    g_Instances[free_slot].ExecutionStarted = false;

    if (!OwKdbAssociationSetInstance(AssociationId, instance_id)) {
        g_Instances[free_slot].Id = OW_KDB_INVALID_ID;
        return OW_ERR_INSUFFICIENT;
    }
    g_InstanceInUse[free_slot] = true;

    OwKdbHistoryRecord(OW_KDB_EVENT_LOADED, instance_id, OW_SUCCESS, 0U, 0U,
                       entry);

    if (OutInstanceId != (uint32_t*)0) {
        *OutInstanceId = instance_id;
    }

    ow_kprintf("[KDB] instance %u: app '%s' loaded '%s' "
               "(%u page(s), domain %u)\r\n",
               (unsigned)instance_id, g_Instances[free_slot].Application,
               g_Instances[free_slot].Kernel, (unsigned)pages,
               (unsigned)g_Instances[free_slot].IsolationDomain);
    return OW_SUCCESS;
}

OW_STATUS OwKdbStartInstance(uint32_t InstanceId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    switch (g_Instances[InstanceId - 1U].State) {
    case OW_KDB_INSTANCE_READY:
    case OW_KDB_INSTANCE_STOPPED:
        g_Instances[InstanceId - 1U].State = OW_KDB_INSTANCE_RUNNING;
        OwKdbHistoryRecord(OW_KDB_EVENT_STARTED, InstanceId, OW_SUCCESS, 0U, 0U,
                           g_Instances[InstanceId - 1U].EntryPoint);
        return OW_SUCCESS;
    case OW_KDB_INSTANCE_RUNNING:
        return OW_ERR_ALREADY_EXISTS;
    case OW_KDB_INSTANCE_FAULTED:
    default:
        return OW_ERR_INVALID_PARAM;
    }
}

OW_STATUS OwKdbStopInstance(uint32_t InstanceId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    switch (g_Instances[InstanceId - 1U].State) {
    case OW_KDB_INSTANCE_RUNNING:
    case OW_KDB_INSTANCE_READY:
        /* A logical stop must also retire the concrete execution binding: if a
         * PS process/thread was prepared for this instance, leaving it alive
         * would make "STOPPED" a lie and leave the thread able to call the
         * bridge after the owner asked for it to stop.  Abandoning the binding
         * first means the transition below describes the real world. */
        OwKdbExecPsAbandonInstance(InstanceId,
                                   (uint64_t)OW_KDB_INSTANCE_STOPPED);
        g_Instances[InstanceId - 1U].State = OW_KDB_INSTANCE_STOPPED;
        OwKdbHistoryRecord(OW_KDB_EVENT_STOPPED, InstanceId, OW_SUCCESS,
                           g_Instances[InstanceId - 1U].ProcessId,
                           g_Instances[InstanceId - 1U].ThreadId,
                           g_Instances[InstanceId - 1U].EntryPoint);
        return OW_SUCCESS;
    case OW_KDB_INSTANCE_STOPPED:
        return OW_SUCCESS;
    case OW_KDB_INSTANCE_FAULTED:
    default:
        return OW_ERR_INVALID_PARAM;
    }
}

/* READY/STOPPED -> RUNNING.  Called only from the scheduler dispatch hook,
 * which is the first moment the bound thread is actually about to run. */
OW_STATUS OwKdbManagerMarkRunning(uint32_t InstanceId) {
    OW_KDB_INSTANCE* instance;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    instance = &g_Instances[InstanceId - 1U];
    switch (instance->State) {
    case OW_KDB_INSTANCE_READY:
    case OW_KDB_INSTANCE_STOPPED:
        instance->State = OW_KDB_INSTANCE_RUNNING;
        instance->ExecutionStarted = true;
        OwKdbHistoryRecord(OW_KDB_EVENT_RUNNING, InstanceId, OW_SUCCESS,
                           instance->ProcessId, instance->ThreadId,
                           instance->EntryPoint);
        ow_kprintf("[KDB] instance %u: bound thread resumed on CPU "
                   "(state=RUNNING)\r\n",
                   (unsigned)InstanceId);
        return OW_SUCCESS;
    case OW_KDB_INSTANCE_RUNNING:
        instance->ExecutionStarted = true;
        return OW_ERR_ALREADY_EXISTS;
    case OW_KDB_INSTANCE_FAULTED:
    default:
        return OW_ERR_INVALID_PARAM;
    }
}

/* Normal (non-fault) finish: the bound thread exited with ExitStatus.  The
 * process and its frame run are released by the executor's exit hook before
 * this runs; the manager only retires the logical instance.  It keeps the
 * instance queryable (including ExitStatus and the historical ProcessId/
 * ThreadId identifiers) but releases the page charge, drops the association
 * link and removes any services the instance owned. */
OW_STATUS OwKdbManagerFinish(uint32_t InstanceId, uint64_t ExitStatus) {
    OW_KDB_INSTANCE* instance;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    instance = &g_Instances[InstanceId - 1U];
    if (instance->State == OW_KDB_INSTANCE_FAULTED) {
        return OW_ERR_INVALID_PARAM;
    }

    instance->ExitStatus = ExitStatus;
    instance->State = OW_KDB_INSTANCE_STOPPED;
    instance->ResidentPages = 0U;

    OwKdbBridgeDropOwner(InstanceId);
    (void)OwKdbAssociationSetInstance(instance->AssociationId,
                                      OW_KDB_INVALID_ID);
    OwKdbHistoryRecord(OW_KDB_EVENT_STOPPED, InstanceId, OW_SUCCESS,
                       instance->ProcessId, instance->ThreadId,
                       instance->EntryPoint);
    return OW_SUCCESS;
}

/* Record the facts the executor produced for a prepared instance: the PS
 * identifiers of the process/thread that owns the execution, plus the entry the
 * real loader computed (which can differ from the header value a descriptor
 * carries, because a loader may relocate the entry onto a window base). */
OW_STATUS OwKdbManagerRecordExecution(uint32_t InstanceId, uint32_t ProcessId,
                                      uint32_t ThreadId, uint64_t EntryPoint) {
    OW_KDB_INSTANCE* instance;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    instance = &g_Instances[InstanceId - 1U];
    instance->ProcessId = ProcessId;
    instance->ThreadId = ThreadId;
    instance->ExecutionStarted = false;
    instance->EntryPoint = EntryPoint;
    OwKdbHistoryRecord(OW_KDB_EVENT_EXECUTED, InstanceId, OW_SUCCESS, ProcessId,
                       ThreadId, EntryPoint);
    return OW_SUCCESS;
}

OW_STATUS OwKdbFaultInstance(uint32_t InstanceId, OW_STATUS FaultStatus) {
    OW_KDB_INSTANCE* instance;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    instance = &g_Instances[InstanceId - 1U];
    if (instance->State == OW_KDB_INSTANCE_FAULTED) {
        return OW_ERR_ALREADY_EXISTS;
    }

    if (ow_status_success(FaultStatus)) {
        FaultStatus = OW_ERR_CORRUPT;
    }

    /* If the caller faulted an instance whose process is still prepared, tear
     * that process down first.  Doing it here, rather than trusting every
     * caller to have done it, is what keeps "faulted" from meaning "maybe a
     * stray thread is still runnable". */
    OwKdbExecPsAbandonInstance(InstanceId, (uint64_t)FaultStatus);

    instance->LastFault = FaultStatus;
    instance->State = OW_KDB_INSTANCE_FAULTED;
    instance->ResidentPages = 0U;

    OwKdbBridgeDropOwner(InstanceId);
    (void)OwKdbAssociationSetInstance(instance->AssociationId,
                                      OW_KDB_INVALID_ID);
    ++g_FaultCount;
    OwKdbHistoryRecord(OW_KDB_EVENT_FAULTED, InstanceId, FaultStatus,
                       instance->ProcessId, instance->ThreadId,
                       instance->EntryPoint);

    ow_kprintf("[KDB] instance %u faulted (0x%X); resources released\r\n",
               (unsigned)InstanceId, (unsigned)FaultStatus);
    return OW_SUCCESS;
}

OW_STATUS OwKdbDestroyInstance(uint32_t InstanceId) {
    OW_KDB_INSTANCE* instance;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!OwKdbManagerExists(InstanceId)) {
        return OW_ERR_NOT_FOUND;
    }

    instance = &g_Instances[InstanceId - 1U];

    OwKdbExecPsAbandonInstance(InstanceId, instance->ExitStatus);
    OwKdbBridgeDropOwner(InstanceId);
    (void)OwKdbAssociationSetInstance(instance->AssociationId,
                                      OW_KDB_INVALID_ID);
    OwKdbHistoryRecord(OW_KDB_EVENT_DESTROYED, InstanceId, OW_SUCCESS,
                       instance->ProcessId, instance->ThreadId,
                       instance->EntryPoint);
    instance->ResidentPages = 0U;
    instance->Id = OW_KDB_INVALID_ID;
    g_InstanceInUse[InstanceId - 1U] = false;
    return OW_SUCCESS;
}

OW_STATUS OwKdbGetInstance(uint32_t InstanceId, OW_KDB_INSTANCE* OutInstance) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (InstanceId == OW_KDB_INVALID_ID ||
        InstanceId > OW_KDB_MAX_INSTANCES ||
        OutInstance == (OW_KDB_INSTANCE*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (!g_InstanceInUse[InstanceId - 1U]) {
        return OW_ERR_NOT_FOUND;
    }

    *OutInstance = g_Instances[InstanceId - 1U];
    return OW_SUCCESS;
}

OW_STATUS OwKdbGetInstanceByIndex(uint32_t Index,
                                  OW_KDB_INSTANCE* OutInstance) {
    uint32_t i;
    uint32_t seen = 0U;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutInstance == (OW_KDB_INSTANCE*)0) {
        return OW_ERR_NULL_POINTER;
    }

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        if (g_InstanceInUse[i]) {
            if (seen == Index) {
                *OutInstance = g_Instances[i];
                return OW_SUCCESS;
            }
            ++seen;
        }
    }
    return OW_ERR_NOT_FOUND;
}

uint32_t OwKdbInstanceCount(void) {
    return OwKdbManagerCount();
}
