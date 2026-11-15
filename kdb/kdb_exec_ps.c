/* kdb_exec_ps.c - PS-backed associated-kernel executor backend.
 *
 * The management plane (kdb_exec.c) owns the plan; this file owns the execution
 * backend that binds a KDB instance to a real OpenWindows Process/Thread pair:
 *
 *   OwKdbExecuteInstance()
 *      -> OwKdbBuildLaunchPlan()   (KDB re-validates image + charge + policy)
 *      -> kdb_exec_backend()        (this file; CIS-gated PS load + launch)
 *      -> [scheduler resumes thread] -> OwKdbNotifyThreadDispatch -> RUNNING
 *      -> payload calls bridge / exits    -> OwKdbNotifyThreadExit  -> STOPPED
 *      -> terminal CPL3 fault on bound thr -> OwKdbNotifyThreadFault -> FAULTED
 *
 * Nothing here invents an executing state.  A backend success only means a PS
 * process/thread was created, the trusted OWX image mapped into its own guarded
 * user window and the thread published to the PS scheduler; RUNNING is set by
 * the dispatch hook, the first point at which the thread really will run.
 *
 * Ownership model: KDB holds *identifiers*, never process pointers.  The binding
 * table stores InstanceId/AssociationId and the PS ProcessId/Tid pair; objects
 * are resolved through PS accessors at event time, so a terminated process
 * cannot leave a dangling pointer behind.
 */
#include "kdb_internal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_ps.h"

static OW_KDB_BINDING g_Bindings[OW_KDB_MAX_INSTANCES];

/* ---- Binding table maintenance ---------------------------------------- */

void OwKdbExecPsReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        g_Bindings[i].InUse = false;
        g_Bindings[i].InstanceId = OW_KDB_INVALID_ID;
        g_Bindings[i].AssociationId = OW_KDB_INVALID_ID;
        g_Bindings[i].KernelId = OW_KDB_INVALID_ID;
        g_Bindings[i].ProcessId = 0U;
        g_Bindings[i].ThreadId = 0U;
        g_Bindings[i].EntryPoint = 0U;
        g_Bindings[i].MappedBase = 0U;
        g_Bindings[i].IsolationDomain = 0U;
    }
}

uint32_t OwKdbExecPsBindingCount(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        if (g_Bindings[i].InUse) {
            ++count;
        }
    }
    return count;
}

bool OwKdbExecPsInstanceBound(uint32_t InstanceId) {
    if (InstanceId == OW_KDB_INVALID_ID || InstanceId > OW_KDB_MAX_INSTANCES) {
        return false;
    }
    return g_Bindings[InstanceId - 1U].InUse;
}

static void binding_fill(uint32_t Slot, OW_KDB_BINDING* OutBinding) {
    OW_KDB_INSTANCE instance;

    *OutBinding = g_Bindings[Slot];
    OutBinding->InUse = true;

    /* The binding stores the essential identifiers; the rest is read from the
     * live instance so the view can never disagree with the manager. */
    if (ow_status_success(OwKdbGetInstance(g_Bindings[Slot].InstanceId,
                                           &instance))) {
        OutBinding->KernelId = instance.KernelId;
        OutBinding->EntryPoint = instance.EntryPoint;
        OutBinding->MappedBase = instance.MappedBase;
        OutBinding->IsolationDomain = instance.IsolationDomain;
    }
}

bool OwKdbExecPsGetBindingByThread(uint32_t ThreadId, uint32_t ProcessId,
                                   OW_KDB_BINDING* OutBinding) {
    uint32_t i;

    if (OutBinding == (OW_KDB_BINDING*)0) {
        return false;
    }
    for (i = 0U; i < OW_KDB_MAX_INSTANCES; ++i) {
        if (g_Bindings[i].InUse &&
            g_Bindings[i].ThreadId == ThreadId &&
            g_Bindings[i].ProcessId == ProcessId) {
            binding_fill(i, OutBinding);
            return true;
        }
    }
    return false;
}

bool OwKdbExecPsGetBindingByInstance(uint32_t InstanceId,
                                     OW_KDB_BINDING* OutBinding) {
    if (OutBinding == (OW_KDB_BINDING*)0) {
        return false;
    }
    if (InstanceId == OW_KDB_INVALID_ID || InstanceId > OW_KDB_MAX_INSTANCES) {
        return false;
    }
    if (!g_Bindings[InstanceId - 1U].InUse) {
        return false;
    }
    binding_fill(InstanceId - 1U, OutBinding);
    return true;
}

OW_STATUS OwKdbGetBinding(uint32_t InstanceId, OW_KDB_BINDING* OutBinding) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutBinding == (OW_KDB_BINDING*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (!OwKdbExecPsGetBindingByInstance(InstanceId, OutBinding)) {
        return OW_ERR_NOT_FOUND;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKdbFindBindingByThread(uint32_t ThreadId, uint32_t ProcessId,
                                   OW_KDB_BINDING* OutBinding) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutBinding == (OW_KDB_BINDING*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (!OwKdbExecPsGetBindingByThread(ThreadId, ProcessId, OutBinding)) {
        return OW_ERR_NOT_FOUND;
    }
    return OW_SUCCESS;
}

uint32_t OwKdbBindingCount(void) {
    if (!OwKdbIsReady()) {
        return 0U;
    }
    return OwKdbExecPsBindingCount();
}

/* ---- Event attribution ------------------------------------------------- */

bool OwKdbNotifyThreadDispatch(uint32_t ThreadId, uint32_t ProcessId) {
    OW_KDB_BINDING view;
    OW_STATUS status;

    if (ThreadId == OW_PS_TID_SYSTEM) {
        return false;
    }
    if (!OwKdbExecPsGetBindingByThread(ThreadId, ProcessId, &view)) {
        return false;
    }

    status = OwKdbManagerMarkRunning(view.InstanceId);
    if (ow_status_error(status)) {
        /* Already RUNNING is not a failure: the thread did resume. */
        return status == OW_ERR_ALREADY_EXISTS;
    }
    return true;
}

bool OwKdbNotifyThreadExit(uint32_t ThreadId, uint32_t ProcessId,
                           uint64_t ExitStatus) {
    OW_KDB_BINDING view;
    OW_STATUS status;

    if (!OwKdbExecPsGetBindingByThread(ThreadId, ProcessId, &view)) {
        return false;
    }
    if (view.InstanceId == OW_KDB_INVALID_ID) {
        return false;
    }

    status = OwKdbManagerFinish(view.InstanceId, ExitStatus);
    if (ow_status_error(status)) {
        return false;
    }

    OwKdbExecPsAbandonInstance(view.InstanceId, ExitStatus);
    return true;
}

bool OwKdbNotifyThreadFault(uint32_t ThreadId, uint32_t ProcessId,
                            OW_STATUS FaultStatus) {
    OW_KDB_BINDING view;
    OW_STATUS status;

    if (ThreadId == OW_PS_TID_SYSTEM) {
        return false;
    }
    if (!OwKdbExecPsGetBindingByThread(ThreadId, ProcessId, &view)) {
        return false;
    }
    if (view.InstanceId == OW_KDB_INVALID_ID) {
        return false;
    }

    status = OwKdbFaultInstance(view.InstanceId, FaultStatus);
    return ow_status_success(status);
}

/* ---- Backend ----------------------------------------------------------- */

static OW_STATUS kdb_exec_backend(const OW_KDB_LAUNCH_PLAN* Plan,
                                  void* Context) {
    const OW_KDB_KERNEL_DESC* kernel;
    OW_PROCESS_OBJECT* proc;
    OW_THREAD_OBJECT* thread;
    OW_STATUS status;
    uint32_t i;
    const char* argv[1];
    int argc = 1;

    (void)Context;

    if (Plan == (const OW_KDB_LAUNCH_PLAN*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (Plan->InstanceId == OW_KDB_INVALID_ID ||
        Plan->InstanceId > OW_KDB_MAX_INSTANCES) {
        return OW_ERR_INVALID_PARAM;
    }
    if (g_Bindings[Plan->InstanceId - 1U].InUse) {
        return OW_ERR_ALREADY_EXISTS;
    }

    kernel = OwKdbRegistryPtr(Plan->KernelId);
    if (kernel == (const OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_NOT_FOUND;
    }
    /* This backend executes OWX images only.  Foreign ELF/raw ABIs are already
     * blocked by the plan, but check again rather than trusting the caller. */
    if (kernel->Format != OW_KDB_FORMAT_OWX ||
        (kernel->Abi != OW_KDB_ABI_OPENWINDOWS_NATIVE &&
         kernel->Abi != OW_KDB_ABI_OPENWINDOWS_COMPAT)) {
        return OW_ERR_UNSUPPORTED;
    }
    if (kernel->Image == (const uint8_t*)0 || kernel->ImageSize == 0U) {
        return OW_ERR_NOT_FOUND;
    }
    if ((uint32_t)kernel->ImageSize != Plan->ImageSize) {
        return OW_ERR_INVALID_PARAM;
    }

    proc = OwPsCreateProcess(kernel->Name, OW_PS_PID_KERNEL);
    if (proc == (OW_PROCESS_OBJECT*)0) {
        return OW_ERR_INSUFFICIENT;
    }

    status = OwPsLoadImage(proc, kernel->Image, kernel->ImageSize,
                           OW_CIS_RECORD_SPAWN);
    if (ow_status_error(status)) {
        OwPsTerminateProcess(proc, (uint64_t)status);
        return status;
    }

    argv[0] = kernel->Name;
    /* The entry thread is created DORMANT and deliberately not published yet:
     * it must not be schedulable until the binding and association are in
     * place, or a preemption could enter the payload before KDB can recognize
     * it. */
    status = OwPsLaunchUserImageEx(proc, argc, argv, false);
    if (ow_status_error(status)) {
        OwPsTerminateProcess(proc, (uint64_t)status);
        return status;
    }

    thread = (OW_THREAD_OBJECT*)0;
    for (i = 0U; i < OW_PS_MAX_THREADS; ++i) {
        OW_THREAD_OBJECT* t = OwPsGetThreadByIndex(i);
        if (t && t->Tid == proc->PrimaryThreadId &&
            t->ProcessId == proc->ProcessId) {
            thread = t;
            break;
        }
    }
    if (thread == (OW_THREAD_OBJECT*)0) {
        OwPsTerminateProcess(proc, (uint64_t)OW_ERR_NOT_INITIALIZED);
        return OW_ERR_NOT_INITIALIZED;
    }

    g_Bindings[Plan->InstanceId - 1U].InUse = true;
    g_Bindings[Plan->InstanceId - 1U].InstanceId = Plan->InstanceId;
    g_Bindings[Plan->InstanceId - 1U].AssociationId = Plan->AssociationId;
    g_Bindings[Plan->InstanceId - 1U].KernelId = Plan->KernelId;
    g_Bindings[Plan->InstanceId - 1U].ProcessId = proc->ProcessId;
    g_Bindings[Plan->InstanceId - 1U].ThreadId = thread->Tid;
    g_Bindings[Plan->InstanceId - 1U].EntryPoint = proc->EntryPoint;
    g_Bindings[Plan->InstanceId - 1U].MappedBase = Plan->MappedBase;
    g_Bindings[Plan->InstanceId - 1U].IsolationDomain = Plan->IsolationDomain;

    ow_kprintf("[KDB] instance %u: backend prepared process %u (thread %u) "
               "for '%s'\r\n",
               (unsigned)Plan->InstanceId, (unsigned)proc->ProcessId,
               (unsigned)thread->Tid, kernel->Name);

    status = OwKdbManagerRecordExecution(Plan->InstanceId, proc->ProcessId,
                                         thread->Tid, proc->EntryPoint);
    if (ow_status_error(status)) {
        return status;
    }

    /* Everything the gateway and the scheduler attribution need is in place,
     * so the entry thread can finally be published to CPL3. */
    OwPsWakeThread(thread);
    return OW_SUCCESS;
}

OW_STATUS OwKdbExecPsInitialize(void) {
    return OwKdbRegisterExecutor(&kdb_exec_backend, (void*)0);
}

void OwKdbExecPsAbandonInstance(uint32_t InstanceId, uint64_t ExitStatus) {
    OW_KDB_BINDING* binding;
    uint32_t process_id;
    uint32_t thread_id;

    if (InstanceId == OW_KDB_INVALID_ID || InstanceId > OW_KDB_MAX_INSTANCES) {
        return;
    }
    binding = &g_Bindings[InstanceId - 1U];
    if (!binding->InUse) {
        return;
    }

    process_id = binding->ProcessId;
    thread_id = binding->ThreadId;

    binding->InUse = false;
    binding->InstanceId = OW_KDB_INVALID_ID;
    binding->AssociationId = OW_KDB_INVALID_ID;
    binding->KernelId = OW_KDB_INVALID_ID;
    binding->ProcessId = 0U;
    binding->ThreadId = 0U;
    binding->EntryPoint = 0U;
    binding->MappedBase = 0U;
    binding->IsolationDomain = 0U;

    if (thread_id != 0U) {
        /* A prepared-but-never-dispatched thread can still sit in the ready
         * queue; retire it so no stale scheduler entry survives abandonment. */
        OW_THREAD_OBJECT* t = (OW_THREAD_OBJECT*)0;
        uint32_t i;

        for (i = 0U; i < OW_PS_MAX_THREADS; ++i) {
            OW_THREAD_OBJECT* cand = OwPsGetThreadByIndex(i);
            if (cand && cand->Tid == thread_id &&
                cand->ProcessId == process_id) {
                t = cand;
                break;
            }
        }
        if (t && t->State == OW_THR_READY) {
            OwPsAbandonThread(t->Tid, t->ProcessId);
        }
    }

    if (process_id != 0U) {
        OW_PROCESS_OBJECT* proc = OwPsGetProcessById(process_id);
        if (proc) {
            OwPsTerminateProcess(proc, ExitStatus);
        }
    }
}
