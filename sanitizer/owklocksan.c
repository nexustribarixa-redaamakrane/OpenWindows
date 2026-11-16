/* owklocksan.c - OWKLockSan: kernel lock correctness and misuse detection */
#include "../inc/owklocksan.h"
#include "../inc/ow_sync.h"
#include "../inc/ow_ps.h"

static OW_KLCKSAN_LOCK g_Locks[OW_KLCKSAN_MAX_LOCKS];
static const OW_DISPATCHER_OBJECT* g_Want[OW_PS_MAX_THREADS];
static uint64_t g_Sequence;
static uint32_t g_Tracked;

static int owklocksan_init(void) {
    OwKLockSanReset();
    return (int)OW_SUCCESS;
}

static void owklocksan_shutdown(void) {
    /* Lock accounting is a snapshot; nothing to release. */
}

static OW_KSAN_MODULE g_LockModule = {
    OW_KSAN_MODULE_NAME_OWKLOCKSAN,
    100u,
    true,
    (const char*)0,
    owklocksan_init,
    owklocksan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKLockSanRegister(void) {
    return OwKSanRegisterModule(&g_LockModule);
}

void OwKLockSanReset(void) {
    uint32_t i;

    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        g_Locks[i].Obj = (const void*)0;
        g_Locks[i].OwnerTid = OW_KLCKSAN_TID_FREE;
        g_Locks[i].OwnCount = 0u;
        g_Locks[i].Abandoned = 0u;
        g_Locks[i].AcquiredAt = 0u;
        g_Locks[i].Seq = 0u;
        g_Locks[i].Used = false;
    }
    for (i = 0u; i < OW_PS_MAX_THREADS; ++i) {
        g_Want[i] = (const OW_DISPATCHER_OBJECT*)0;
    }
    g_Sequence = 0u;
    g_Tracked = 0u;
}

static OW_KLCKSAN_LOCK* find_or_create(const void* Obj) {
    uint32_t i;

    if (Obj == (const void*)0) {
        return (OW_KLCKSAN_LOCK*)0;
    }
    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (g_Locks[i].Used && g_Locks[i].Obj == Obj) {
            return &g_Locks[i];
        }
    }
    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (!g_Locks[i].Used) {
            g_Locks[i].Obj = Obj;
            g_Locks[i].OwnerTid = OW_KLCKSAN_TID_FREE;
            g_Locks[i].OwnCount = 0u;
            g_Locks[i].Abandoned = 0u;
            g_Locks[i].AcquiredAt = 0u;
            g_Locks[i].Seq = 0u;
            g_Locks[i].Used = true;
            g_Tracked++;
            return &g_Locks[i];
        }
    }
    return (OW_KLCKSAN_LOCK*)0;
}

static OW_KLCKSAN_LOCK* find(const void* Obj) {
    uint32_t i;

    if (Obj == (const void*)0) {
        return (OW_KLCKSAN_LOCK*)0;
    }
    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (g_Locks[i].Used && g_Locks[i].Obj == Obj) {
            return &g_Locks[i];
        }
    }
    return (OW_KLCKSAN_LOCK*)0;
}

static const char* lock_name(const void* Obj) {
    const OW_DISPATCHER_OBJECT* d = (const OW_DISPATCHER_OBJECT*)Obj;

    if (d == (const OW_DISPATCHER_OBJECT*)0 || d->Header.Name[0] == '\0') {
        return "?";
    }
    return d->Header.Name;
}

static bool locksan_enabled(void) {
    return OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKLOCKSAN);
}

void OwKLockSanNoteCreateMutex(const void* Obj) {
    if (!locksan_enabled()) {
        return;
    }
    if (find_or_create(Obj) == (OW_KLCKSAN_LOCK*)0) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "lock table full; mutex '%s' is untracked", lock_name(Obj));
    }
}

void OwKLockSanNoteAcquireMutex(const void* Obj, uint32_t Tid) {
    OW_KLCKSAN_LOCK* rec;

    if (!locksan_enabled()) {
        return;
    }
    rec = find_or_create(Obj);
    if (rec == (OW_KLCKSAN_LOCK*)0) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "lock table full; acquisition of '%s' by tid %u is untracked",
                     lock_name(Obj), (unsigned)Tid);
        return;
    }
    if (rec->OwnerTid == Tid) {
        /* Recursive acquisition. */
        if (rec->OwnCount + 1u > OW_KLCKSAN_MAX_DEPTH) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                         "recursive acquisition of '%s' beyond depth %u (tid %u)",
                         lock_name(Obj), (unsigned)OW_KLCKSAN_MAX_DEPTH,
                         (unsigned)Tid);
            return;
        }
        rec->OwnCount++;
        return;
    }
    if (rec->OwnerTid != OW_KLCKSAN_TID_FREE) {
        /* The synchronization layer never calls this for a mutex owned by a
         * different thread, so this means the tracked state has drifted. */
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "acquisition of '%s' while tracked as owned by tid %u (acquiring tid %u)",
                     lock_name(Obj), (unsigned)rec->OwnerTid, (unsigned)Tid);
    }
    rec->OwnerTid = Tid;
    rec->OwnCount = 1u;
    rec->Abandoned = 0u;
    rec->AcquiredAt = (uint64_t)OwPsGetTickCount();
    rec->Seq = ++g_Sequence;
}

void OwKLockSanNoteReleaseMutex(const void* Obj, uint32_t Tid) {
    OW_KLCKSAN_LOCK* rec;

    if (!locksan_enabled()) {
        return;
    }
    /* A mutex that was never tracked (created before the suite armed) gives us
     * no ownership baseline; adopt it silently rather than misreport a legal
     * release of a free mutex. */
    rec = find(Obj);
    if (rec == (OW_KLCKSAN_LOCK*)0) {
        (void)find_or_create(Obj);
        return;
    }
    if (rec->OwnerTid != Tid) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "release of '%s' by tid %u, tracked as owned by tid %u",
                     lock_name(Obj), (unsigned)Tid, (unsigned)rec->OwnerTid);
        return;
    }
    if (rec->OwnCount > 1u) {
        rec->OwnCount--;
        return;
    }
    rec->OwnerTid = OW_KLCKSAN_TID_FREE;
    rec->OwnCount = 0u;
}

void OwKLockSanNoteReleaseSemaphore(const void* Obj, uint32_t Count) {
    const OW_DISPATCHER_OBJECT* d = (const OW_DISPATCHER_OBJECT*)Obj;

    if (!locksan_enabled()) {
        return;
    }
    if (Count == 0u || d == (const OW_DISPATCHER_OBJECT*)0) {
        return;
    }
    /* The layer clamps the count silently; report the misuse instead. */
    if (d->Limit != 0u && Count > d->Limit - d->SignalState) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "semaphore '%s' over-released: state %u + %u > limit %u",
                     lock_name(Obj), (unsigned)d->SignalState,
                     (unsigned)Count, (unsigned)d->Limit);
    }
}

static uint32_t owner_of(const void* Obj) {
    const OW_KLCKSAN_LOCK* rec = find(Obj);

    return rec ? rec->OwnerTid : OW_KLCKSAN_TID_FREE;
}

static bool chain_closes(const OW_DISPATCHER_OBJECT* Want, uint32_t OriginTid) {
    const OW_DISPATCHER_OBJECT* cur = Want;
    uint32_t guard;

    if (cur == (const OW_DISPATCHER_OBJECT*)0) {
        return false;
    }
    for (guard = 0u; guard < OW_KLCKSAN_MAX_LOCKS; ++guard) {
        uint32_t owner = owner_of(cur);
        const OW_DISPATCHER_OBJECT* next;

        if (owner == OW_KLCKSAN_TID_FREE) {
            return false; /* unheld: the chain ends */
        }
        if (owner >= OW_PS_MAX_THREADS) {
            return false; /* out of range for the wait table */
        }
        if (owner == OriginTid) {
            return true;  /* the chain closed on the requester */
        }
        next = g_Want[owner];
        if (next == (const OW_DISPATCHER_OBJECT*)0) {
            return false; /* the owner is not blocked: no cycle */
        }
        cur = next;
    }
    return true; /* bound exhausted: treat as a potential cycle */
}

void OwKLockSanNoteWillBlock(const void* Obj, uint32_t Tid) {
    const OW_DISPATCHER_OBJECT* d = (const OW_DISPATCHER_OBJECT*)Obj;

    if (!locksan_enabled()) {
        return;
    }
    if (Tid < OW_PS_MAX_THREADS) {
        g_Want[Tid] = d;
    }
    if (chain_closes(d, Tid)) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "potential deadlock: circular wait on '%s' (tid %u)",
                     lock_name(Obj), (unsigned)Tid);
    }
}

void OwKLockSanNoteWake(uint32_t Tid) {
    if (Tid < OW_PS_MAX_THREADS) {
        g_Want[Tid] = (const OW_DISPATCHER_OBJECT*)0;
    }
}

void OwKLockSanNoteWaitResult(const void* Obj, uint32_t Tid, uint32_t Result) {
    if (!locksan_enabled()) {
        return;
    }
    if (Result == 2u /* OW_WAIT_ABANDONED */) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                     "tid %u acquired abandoned mutex '%s'",
                     (unsigned)Tid, lock_name(Obj));
    }
}

void OwKLockSanNoteThreadExit(uint32_t Tid) {
    uint32_t i;

    if (!locksan_enabled()) {
        return;
    }
    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (g_Locks[i].Used && g_Locks[i].OwnerTid == Tid) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLOCKSAN,
                         "mutex '%s' abandoned by exiting tid %u",
                         lock_name(g_Locks[i].Obj), (unsigned)Tid);
            g_Locks[i].OwnerTid = OW_KLCKSAN_TID_FREE;
            g_Locks[i].OwnCount = 0u;
            g_Locks[i].Abandoned = 1u;
        }
    }
}

const OW_KLCKSAN_LOCK* OwKLockSanLookup(const void* Obj) {
    return find(Obj);
}

uint32_t OwKLockSanTrackedLocks(void) {
    uint32_t i;
    uint32_t n = 0u;

    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (g_Locks[i].Used) {
            n++;
        }
    }
    return n;
}

void OwKLockSanForEach(int (*Callback)(const OW_KLCKSAN_LOCK* Lock, void* Ctx),
                       void* Ctx) {
    uint32_t i;

    if (Callback == (int (*)(const OW_KLCKSAN_LOCK*, void*))0) {
        return;
    }
    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (!g_Locks[i].Used) {
            continue;
        }
        if (!Callback(&g_Locks[i], Ctx)) {
            break;
        }
    }
}

void OwKLockSanGetStats(OW_KLCKSAN_STATS* Out) {
    uint32_t i;
    uint32_t owned = 0u;
    uint32_t max_recursion = 0u;
    uint32_t abandoned = 0u;

    if (Out == (OW_KLCKSAN_STATS*)0) {
        return;
    }
    for (i = 0u; i < OW_KLCKSAN_MAX_LOCKS; ++i) {
        if (!g_Locks[i].Used) {
            continue;
        }
        if (g_Locks[i].OwnerTid != OW_KLCKSAN_TID_FREE) {
            owned++;
            if (g_Locks[i].OwnCount > max_recursion) {
                max_recursion = g_Locks[i].OwnCount;
            }
        }
        if (g_Locks[i].Abandoned != 0u) {
            abandoned++;
        }
    }
    Out->Total = g_Tracked;
    Out->Owned = owned;
    Out->MaxRecursion = max_recursion;
    Out->Abandoned = abandoned;
    Out->Sequence = (uint32_t)(g_Sequence & 0xFFFFFFFFu);
}

void OwKLockSanTestSetAcquiredAt(const void* Obj, uint64_t Tick) {
    OW_KLCKSAN_LOCK* rec = find(Obj);

    if (rec != (OW_KLCKSAN_LOCK*)0) {
        rec->AcquiredAt = Tick;
    }
}
