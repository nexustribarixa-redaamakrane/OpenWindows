/* kdb_exec.c - associated-kernel launch plans and executor handoff seam.
 *
 * Management half (always present): answers "is this instance admissible, and
 * what would an executor be handed?" by building a launch plan from live KDB
 * state and re-validating the caller-owned image at call time.
 *
 * Executor seam (interface only; no real backend registered by default): a
 * single backend slot can be registered.  OwKdbExecuteInstance() rebuilds the
 * authoritative plan, never trusts a caller-owned plan, validates invariants,
 * and hands the validated plan to the backend.  A missing backend returns
 * OW_ERR_UNSUPPORTED without changing instance state.  A backend failure faults
 * the instance (releasing charged resources via the manager's fault path) and
 * returns the error.  A backend success means the backend accepted the plan;
 * KDB does not invent a fake "executing on separate CPU" state.
 */
#include "kdb_internal.h"

static OW_KDB_EXECUTOR_BACKEND g_Executor = (OW_KDB_EXECUTOR_BACKEND)0;
static void*                   g_ExecutorContext = (void*)0;

static const char* blocker_reason(OW_KDB_EXEC_BLOCKER Blocker) {
    switch (Blocker) {
    case OW_KDB_BLOCKER_NONE:                    return "ready";
    case OW_KDB_BLOCKER_INSTANCE_NOT_FOUND:      return "no such instance";
    case OW_KDB_BLOCKER_INSTANCE_FAULTED:        return "instance faulted; resources released";
    case OW_KDB_BLOCKER_IMAGE_INVALID:           return "image no longer validates";
    case OW_KDB_BLOCKER_PAGE_BUDGET_EXCEEDED:    return "page charge exceeds the budget";
    case OW_KDB_BLOCKER_NO_ISOLATION_DOMAIN:     return "instance has no isolation domain";
    case OW_KDB_BLOCKER_NO_ENTRY_POINT:          return "image has no entry point";
    case OW_KDB_BLOCKER_EXECUTOR_UNAVAILABLE:
        return "no associated-kernel executor backend registered";
    case OW_KDB_BLOCKER_BACKEND_REJECTED:
        return "executor backend rejected the validated launch plan";
    default:                                     return "unknown blocker";
    }
}

void OwKdbExecReset(void) {
    g_Executor = (OW_KDB_EXECUTOR_BACKEND)0;
    g_ExecutorContext = (void*)0;
}

bool OwKdbExecutionAvailable(void) {
    return g_Executor != (OW_KDB_EXECUTOR_BACKEND)0;
}

OW_STATUS OwKdbRegisterExecutor(OW_KDB_EXECUTOR_BACKEND Backend, void* Context) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    g_Executor = Backend;
    g_ExecutorContext = (Backend != (OW_KDB_EXECUTOR_BACKEND)0) ? Context : (void*)0;
    return OW_SUCCESS;
}

void OwKdbUnregisterExecutor(void) {
    g_Executor = (OW_KDB_EXECUTOR_BACKEND)0;
    g_ExecutorContext = (void*)0;
}

OW_STATUS OwKdbBuildLaunchPlan(uint32_t InstanceId,
                               OW_KDB_LAUNCH_PLAN* OutPlan) {
    OW_KDB_INSTANCE instance;
    const OW_KDB_KERNEL_DESC* kernel;
    OW_STATUS status;
    uint32_t pages = 0U;
    uint64_t entry = 0U;
    uint64_t base = 0U;
    OW_KDB_EXEC_BLOCKER blocker;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutPlan == (OW_KDB_LAUNCH_PLAN*)0) {
        return OW_ERR_NULL_POINTER;
    }

    status = OwKdbGetInstance(InstanceId, &instance);
    if (ow_status_error(status)) {
        OutPlan->InstanceId = OW_KDB_INVALID_ID;
        OutPlan->KernelId = OW_KDB_INVALID_ID;
        OutPlan->AssociationId = OW_KDB_INVALID_ID;
        OutPlan->ImageSize = 0U;
        OutPlan->ResidentPages = 0U;
        OutPlan->PageLimit = 0U;
        OutPlan->EntryPoint = 0U;
        OutPlan->MappedBase = 0U;
        OutPlan->IsolationDomain = 0U;
        OutPlan->State = OW_KDB_INSTANCE_FAULTED;
        OutPlan->ManagementReady = false;
        OutPlan->ExecutionAvailable = false;
        OutPlan->Blocker = OW_KDB_BLOCKER_INSTANCE_NOT_FOUND;
        OutPlan->BlockerReason =
            blocker_reason(OW_KDB_BLOCKER_INSTANCE_NOT_FOUND);
        return status;
    }

    blocker = OW_KDB_BLOCKER_NONE;

    if (instance.State == OW_KDB_INSTANCE_FAULTED) {
        blocker = OW_KDB_BLOCKER_INSTANCE_FAULTED;
    } else {
        kernel = OwKdbRegistryPtr(instance.KernelId);
        if (kernel == (const OW_KDB_KERNEL_DESC*)0) {
            blocker = OW_KDB_BLOCKER_INSTANCE_NOT_FOUND;
        } else {
            /* Re-validate the image now: the registry holds a caller-owned
             * pointer, so admissibility at load time is not a guarantee that
             * the bytes are still loadable. */
            status = OwKdbLoaderPrepare(kernel, &pages, &entry, &base);
            if (ow_status_error(status)) {
                blocker = OW_KDB_BLOCKER_IMAGE_INVALID;
            } else if (pages > instance.PageLimit) {
                blocker = OW_KDB_BLOCKER_PAGE_BUDGET_EXCEEDED;
            } else if (instance.IsolationDomain == 0U) {
                blocker = OW_KDB_BLOCKER_NO_ISOLATION_DOMAIN;
            } else if (entry == 0U) {
                blocker = OW_KDB_BLOCKER_NO_ENTRY_POINT;
            }
        }
    }

    OutPlan->InstanceId = instance.Id;
    OutPlan->KernelId = instance.KernelId;
    OutPlan->AssociationId = instance.AssociationId;
    OutPlan->ResidentPages = instance.ResidentPages;
    OutPlan->PageLimit = instance.PageLimit;
    OutPlan->EntryPoint = instance.EntryPoint;
    OutPlan->MappedBase = instance.MappedBase;
    OutPlan->IsolationDomain = instance.IsolationDomain;
    OutPlan->State = instance.State;
    {
        const OW_KDB_KERNEL_DESC* descriptor =
            OwKdbRegistryPtr(instance.KernelId);
        OutPlan->ImageSize = (descriptor != (const OW_KDB_KERNEL_DESC*)0) ?
            descriptor->ImageSize : 0U;
    }

    if (blocker == OW_KDB_BLOCKER_NONE) {
        OutPlan->ManagementReady = true;
        if (g_Executor != (OW_KDB_EXECUTOR_BACKEND)0) {
            OutPlan->ExecutionAvailable = true;
            OutPlan->Blocker = OW_KDB_BLOCKER_NONE;
        } else {
            OutPlan->ExecutionAvailable = false;
            OutPlan->Blocker = OW_KDB_BLOCKER_EXECUTOR_UNAVAILABLE;
        }
    } else {
        OutPlan->ManagementReady = false;
        OutPlan->ExecutionAvailable = false;
        OutPlan->Blocker = blocker;
    }
    OutPlan->BlockerReason = blocker_reason(OutPlan->Blocker);
    return OW_SUCCESS;
}

OW_STATUS OwKdbExecuteInstance(uint32_t InstanceId) {
    OW_KDB_LAUNCH_PLAN plan;
    OW_STATUS status;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (g_Executor == (OW_KDB_EXECUTOR_BACKEND)0) {
        return OW_ERR_UNSUPPORTED;
    }

    status = OwKdbBuildLaunchPlan(InstanceId, &plan);
    if (ow_status_error(status)) {
        return status;
    }
    if (!plan.ManagementReady) {
        if (plan.State != OW_KDB_INSTANCE_FAULTED) {
            (void)OwKdbFaultInstance(InstanceId, OW_ERR_NOT_INITIALIZED);
        }
        return OW_ERR_NOT_INITIALIZED;
    }

    status = g_Executor(&plan, g_ExecutorContext);
    if (ow_status_error(status)) {
        (void)OwKdbFaultInstance(InstanceId, status);
        return status;
    }
    /* Backend accepted the validated plan.  KDB does not fabricate an
     * "executing on hardware" state; bridge eligibility remains governed by
     * the instance lifecycle (RUNNING). */
    return OW_SUCCESS;
}
