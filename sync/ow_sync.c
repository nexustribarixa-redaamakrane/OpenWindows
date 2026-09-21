/* sync/ow_sync.c - NT-like Dispatcher Objects (Event, Semaphore, Timer)
 *
 * Non-POSIX counterpart of the Linux wait-queue / completion / hrtimer trio.
 * Threads block on a dispatcher object via KeWaitForSingleObject; the ready
 * queue integration lives in ps/ps.c (OW_THR_BLOCKED + OwPsScheduleNext +
 * OwPsWakeThread).  Wakeup comes from a signal (KeSetEvent /
 * KeReleaseSemaphore / timer expiry) or a tick-based timeout.
 *
 * A woken thread resumes at its caller with RAX = Context.Gpr[0], so the
 * wake paths stash the wait result there before re-enqueuing it.  All
 * resume contexts are forced to IF=1 so threads stay preemptable.
 *
 * Single-CPU, ring-0 only: cli/sti provides the atomicity a spinlock would
 * on SMP.  C99 freestanding.  Static object table, no dynamic heap.  */
#include "../inc/ow_sync.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_io.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_kprintf.h"

/* ---- Static dispatcher table ------------------------------------------ */
static OW_DISPATCHER_OBJECT  s_Dispatchers[OW_MAX_DISPATCHERS];
static OW_DISPATCHER_OBJECT* s_TimerListHead;

/* ====================================================================== */
/* Internal helpers                                                        */
/* ====================================================================== */

static OW_DISPATCHER_OBJECT* alloc_dispatcher(void) {
    uint32_t i;
    for (i = 0; i < OW_MAX_DISPATCHERS; i++) {
        OW_DISPATCHER_OBJECT* d = &s_Dispatchers[i];
        if (d->Header.ReferenceCount == 0 && d->Header.Name[0] == '\0') {
            ow_memset(d, 0, sizeof(*d));
            d->Header.ReferenceCount = 1;
            return d;
        }
    }
    return (OW_DISPATCHER_OBJECT*)0;
}

static void set_wait_result(OW_THREAD_OBJECT* Thr, uint32_t Result) {
    Thr->Context.Gpr[0] = (uint64_t)Result;
}

static void remove_from_wait_list(OW_DISPATCHER_OBJECT* Obj,
                                  OW_THREAD_OBJECT* Thr) {
    OW_THREAD_OBJECT** pp = &Obj->WaitListHead;
    while (*pp) {
        if (*pp == Thr) {
            *pp = Thr->NextWait;
            Thr->NextWait = (OW_THREAD_OBJECT*)0;
            if (Obj->WaitCount > 0) Obj->WaitCount--;
            return;
        }
        pp = &(*pp)->NextWait;
    }
}

static void wake_one_waiter(OW_DISPATCHER_OBJECT* Obj, uint32_t Result) {
    OW_THREAD_OBJECT* thr = Obj->WaitListHead;
    if (!thr) return;
    Obj->WaitListHead = thr->NextWait;
    if (Obj->WaitCount > 0) Obj->WaitCount--;
    thr->NextWait = (OW_THREAD_OBJECT*)0;
    thr->WaitObject = (OW_DISPATCHER_OBJECT*)0;
    thr->WaitTimeout = 0;
    /* A woken mutex waiter takes immediate ownership. */
    if (Obj->Type == OW_DISPATCH_MUTEX) {
        Obj->Owner = thr;
        Obj->OwnCount = 1;
    }
    set_wait_result(thr, Result);
    OwPsWakeThread(thr);
}

static void wake_all_waiters(OW_DISPATCHER_OBJECT* Obj, uint32_t Result) {
    while (Obj->WaitListHead) {
        wake_one_waiter(Obj, Result);
    }
}

/* ====================================================================== */
/* Object creation                                                         */
/* ====================================================================== */

OW_DISPATCHER_OBJECT* KeCreateEvent(const char* Name, uint8_t ManualReset,
                                    uint8_t InitialState) {
    OW_DISPATCHER_OBJECT* d = alloc_dispatcher();
    uint32_t len;

    if (!d) return (OW_DISPATCHER_OBJECT*)0;
    d->Type = OW_DISPATCH_EVENT;
    d->ManualReset = ManualReset;
    d->SignalState = InitialState ? 1u : 0u;
    len = 0;
    if (Name) {
        while (Name[len] && len < (uint32_t)OW_MAX_NAME - 1u) len++;
        ow_memcpy(d->Header.Name, Name, len);
        d->Header.Name[len] = '\0';
    }
    ow_kprintf("[SYNC] event '%s' created\r\n", d->Header.Name);
    return d;
}

OW_DISPATCHER_OBJECT* KeCreateSemaphore(const char* Name, uint32_t InitialCount,
                                        uint32_t Limit) {
    OW_DISPATCHER_OBJECT* d = alloc_dispatcher();
    uint32_t len;

    if (!d) return (OW_DISPATCHER_OBJECT*)0;
    d->Type = OW_DISPATCH_SEMAPHORE;
    d->SignalState = InitialCount;
    d->Limit = Limit ? Limit : 1u;
    len = 0;
    if (Name) {
        while (Name[len] && len < (uint32_t)OW_MAX_NAME - 1u) len++;
        ow_memcpy(d->Header.Name, Name, len);
        d->Header.Name[len] = '\0';
    }
    ow_kprintf("[SYNC] semaphore '%s' created (state %u, limit %u)\r\n",
               d->Header.Name, (unsigned)InitialCount, (unsigned)d->Limit);
    return d;
}

OW_DISPATCHER_OBJECT* KeCreateMutex(const char* Name, uint32_t InitialOwner) {
    OW_DISPATCHER_OBJECT* d = alloc_dispatcher();
    OW_THREAD_OBJECT* cur;
    uint32_t len;

    if (!d) return (OW_DISPATCHER_OBJECT*)0;
    d->Type = OW_DISPATCH_MUTEX;
    d->SignalState = 1u;                 /* free */
    d->Owner = (OW_THREAD_OBJECT*)0;
    d->OwnCount = 0;
    d->Abandoned = 0;
    if (InitialOwner) {
        cur = OwPsGetCurrentThread();
        if (cur) {
            d->Owner = cur;
            d->OwnCount = 1;
            d->SignalState = 0u;
        }
    }
    len = 0;
    if (Name) {
        while (Name[len] && len < (uint32_t)OW_MAX_NAME - 1u) len++;
        ow_memcpy(d->Header.Name, Name, len);
        d->Header.Name[len] = '\0';
    }
    ow_kprintf("[SYNC] mutex '%s' created\r\n", d->Header.Name);
    return d;
}

void KeInitializeTimer(OW_DISPATCHER_OBJECT* Obj) {
    if (!Obj) return;
    ow_memset(Obj, 0, sizeof(*Obj));
    Obj->Type = OW_DISPATCH_TIMER;
    Obj->Header.ReferenceCount = 1;
}

/* ====================================================================== */
/* Signaling                                                               */
/* ====================================================================== */

uint32_t KeSetEvent(OW_DISPATCHER_OBJECT* Obj) {
    uint32_t prev;
    uint32_t had_waiters;
    uint64_t flags;

    if (!Obj) return 0u;
    prev = Obj->SignalState;

    flags = ow_irq_save();
    had_waiters = Obj->WaitCount;
    Obj->SignalState = 1u;
    if (Obj->ManualReset) {
        wake_all_waiters(Obj, OW_WAIT_SIGNALED);
    } else {
        wake_one_waiter(Obj, OW_WAIT_SIGNALED);
        if (had_waiters > 0 && Obj->WaitCount < had_waiters) {
            /* A waiter was released: auto-reset to non-signaled. */
            Obj->SignalState = 0u;
        }
    }
    ow_irq_restore(flags);
    return prev;
}

uint32_t KeResetEvent(OW_DISPATCHER_OBJECT* Obj) {
    uint32_t prev;
    uint64_t flags;

    if (!Obj) return 0u;
    flags = ow_irq_save();
    prev = Obj->SignalState;
    Obj->SignalState = 0u;
    ow_irq_restore(flags);
    return prev;
}

void KeReleaseSemaphore(OW_DISPATCHER_OBJECT* Obj, uint32_t Count) {
    uint64_t flags;

    if (!Obj) return;
    flags = ow_irq_save();
    Obj->SignalState += Count;
    if (Obj->SignalState > Obj->Limit) Obj->SignalState = Obj->Limit;
    while (Obj->WaitListHead && Obj->SignalState > 0) {
        wake_one_waiter(Obj, OW_WAIT_SIGNALED);
        /* The woken waiter acquires one count. */
        if (Obj->SignalState > 0) Obj->SignalState--;
    }
    ow_irq_restore(flags);
}

uint32_t KeReleaseMutex(OW_DISPATCHER_OBJECT* Obj) {
    OW_THREAD_OBJECT* cur;
    uint64_t flags;

    if (!Obj) return 0u;
    cur = OwPsGetCurrentThread();

    flags = ow_irq_save();
    if (Obj->Type != OW_DISPATCH_MUTEX || !cur || Obj->Owner != cur) {
        ow_irq_restore(flags);
        return 0u;              /* not owned by the caller */
    }
    if (Obj->OwnCount > 1) {
        Obj->OwnCount--;        /* recursive release */
        ow_irq_restore(flags);
        return 1u;
    }
    Obj->OwnCount = 0;
    Obj->Owner = (OW_THREAD_OBJECT*)0;
    Obj->Abandoned = 0;
    Obj->SignalState = 1u;      /* free */
    if (Obj->WaitListHead) {
        wake_one_waiter(Obj, OW_WAIT_SIGNALED);
        Obj->SignalState = 0u;  /* the newly-woken owner now holds it */
    }
    ow_irq_restore(flags);
    return 1u;
}

/* ====================================================================== */
/* Waiting                                                                 */
/* ====================================================================== */

uint32_t KeWaitForSingleObject(OW_DISPATCHER_OBJECT* Obj,
                               uint64_t TimeoutTicks) {
    OW_THREAD_OBJECT* cur;
    uint64_t flags;

    if (!Obj) return OW_WAIT_CANCELLED;

    flags = ow_irq_save();
    cur = OwPsGetCurrentThread();

    /* Mutex acquisition is ownership-based, not signal-state based. */
    if (Obj->Type == OW_DISPATCH_MUTEX) {
        if (cur && Obj->Owner == cur) {
            Obj->OwnCount++;                    /* recursive acquisition */
            ow_irq_restore(flags);
            return OW_WAIT_SIGNALED;
        }
        if (Obj->SignalState > 0) {
            Obj->Owner = cur;
            Obj->OwnCount = 1;
            Obj->SignalState = 0;
            ow_irq_restore(flags);
            return Obj->Abandoned ? OW_WAIT_ABANDONED : OW_WAIT_SIGNALED;
        }
        /* Not ours and not free: fall through and block. */
        if (TimeoutTicks == 0) {
            ow_irq_restore(flags);
            return OW_WAIT_TIMEOUT;
        }
    }
    /* Already signaled: consume and return immediately. */
    else if (Obj->SignalState > 0) {
        if (Obj->Type == OW_DISPATCH_SEMAPHORE) {
            Obj->SignalState--;
        } else if (Obj->Type == OW_DISPATCH_EVENT && !Obj->ManualReset) {
            Obj->SignalState = 0u;
        }
        ow_irq_restore(flags);
        return OW_WAIT_SIGNALED;
    }

    /* Zero timeout: poll, no wait. */
    if (TimeoutTicks == 0) {
        ow_irq_restore(flags);
        return OW_WAIT_TIMEOUT;
    }

    if (!cur) {
        ow_irq_restore(flags);
        return OW_WAIT_CANCELLED;
    }

    /* Block on the dispatcher object. */
    cur->WaitObject = Obj;
    cur->NextWait = Obj->WaitListHead;
    Obj->WaitListHead = cur;
    Obj->WaitCount++;
    cur->State = OW_THR_BLOCKED;
    cur->WaitTimeout = (TimeoutTicks >= OW_TIMEOUT_INFINITE)
                           ? 0u
                           : (uint64_t)OwPsGetTickCount() + TimeoutTicks;

    ow_kprintf("[WAIT] tid=%u on '%s'\r\n", (unsigned)cur->Tid,
               Obj->Header.Name);
    ow_ps_capture_frame(&cur->Context);
    if (cur->State == OW_THR_BLOCKED) {
        cur->Context.Rflags |= 0x200u;   /* force IF on at resume */
        OwPsScheduleNext();
    }

    return cur->Context.Gpr[0] ? (uint32_t)cur->Context.Gpr[0] : OW_WAIT_SIGNALED;
}

uint32_t KeSleep(uint64_t Ticks) {
    OW_THREAD_OBJECT* cur;
    uint64_t flags;

    if (Ticks == 0) return OW_WAIT_SIGNALED;
    if (Ticks >= OW_TIMEOUT_INFINITE) Ticks = OW_TIMEOUT_INFINITE - 1u;

    flags = ow_irq_save();
    cur = OwPsGetCurrentThread();
    if (!cur) {
        ow_irq_restore(flags);
        return OW_WAIT_CANCELLED;
    }

    cur->WaitObject = (OW_DISPATCHER_OBJECT*)0;
    cur->NextWait = (OW_THREAD_OBJECT*)0;
    cur->State = OW_THR_BLOCKED;
    cur->WaitTimeout = (uint64_t)OwPsGetTickCount() + Ticks;

    ow_kprintf("[SLEEP] tid=%u ticks=%llu\r\n", (unsigned)cur->Tid,
               (unsigned long long)Ticks);
    ow_ps_capture_frame(&cur->Context);
    if (cur->State == OW_THR_BLOCKED) {
        cur->Context.Rflags |= 0x200u;
        OwPsScheduleNext();
    }

    return OW_WAIT_SIGNALED;
}

/* ====================================================================== */
/* Timers                                                                  */
/* ====================================================================== */

static uint8_t remove_timer_from_list(OW_DISPATCHER_OBJECT* Obj) {
    OW_DISPATCHER_OBJECT** pp = &s_TimerListHead;
    while (*pp) {
        if (*pp == Obj) {
            *pp = Obj->TimerFlink;
            Obj->TimerFlink = (OW_DISPATCHER_OBJECT*)0;
            return 1;
        }
        pp = &(*pp)->TimerFlink;
    }
    return 0;
}

uint8_t KeSetTimer(OW_DISPATCHER_OBJECT* Obj, uint64_t DueTime,
                   uint32_t Period) {
    uint8_t was_pending;
    uint64_t flags;

    if (!Obj) return 0;
    flags = ow_irq_save();
    was_pending = remove_timer_from_list(Obj);
    Obj->DueTime = DueTime;
    Obj->Period = Period;
    Obj->SignalState = 0u;
    Obj->TimerFlink = s_TimerListHead;
    s_TimerListHead = Obj;
    ow_irq_restore(flags);
    return was_pending;
}

uint8_t KeCancelTimer(OW_DISPATCHER_OBJECT* Obj) {
    uint8_t was_pending;
    uint64_t flags;

    if (!Obj) return 0;
    flags = ow_irq_save();
    was_pending = remove_timer_from_list(Obj);
    ow_irq_restore(flags);
    return was_pending;
}

/* ====================================================================== */
/* Tick helpers (called from OwPsSchedulerTick, IF already cleared)        */
/* ====================================================================== */

void OwPsTickTimers(void) {
    OW_DISPATCHER_OBJECT** pp = &s_TimerListHead;
    uint64_t now = (uint64_t)OwPsGetTickCount();

    while (*pp) {
        OW_DISPATCHER_OBJECT* t = *pp;
        if (now >= t->DueTime) {
            t->SignalState = 1u;
            if (t->Period == 0) {
                *pp = t->TimerFlink;
                t->TimerFlink = (OW_DISPATCHER_OBJECT*)0;
            } else {
                t->DueTime = now + t->Period;
                pp = &t->TimerFlink;
            }
            wake_all_waiters(t, OW_WAIT_SIGNALED);
        } else {
            pp = &t->TimerFlink;
        }
    }
}

void OwPsCheckTimeouts(void) {
    uint32_t i;
    uint64_t now = (uint64_t)OwPsGetTickCount();

    for (i = 0; i < OW_PS_MAX_THREADS; i++) {
        OW_THREAD_OBJECT* thr = OwPsGetThreadByIndex(i);
        if (!thr) continue;
        if (thr->Tid == 0) continue;
        if (thr->State != OW_THR_BLOCKED) continue;
        if (thr->WaitTimeout == 0) continue;   /* infinite wait */
        if (now >= thr->WaitTimeout) {
            /* A pure sleep (no WaitObject) completes successfully; a wait on
             * a dispatcher object that never got signaled times out. */
            uint32_t result = thr->WaitObject ? OW_WAIT_TIMEOUT : OW_WAIT_SIGNALED;
            if (thr->WaitObject) {
                remove_from_wait_list(thr->WaitObject, thr);
                thr->WaitObject = (OW_DISPATCHER_OBJECT*)0;
            }
            thr->NextWait = (OW_THREAD_OBJECT*)0;
            thr->WaitTimeout = 0;
            set_wait_result(thr, result);
            OwPsWakeThread(thr);
        }
    }
}

/* ====================================================================== */
/* Thread exit hook - abandon every mutex the terminating thread owns.     */
/* ====================================================================== */
void KeOnThreadExit(OW_THREAD_OBJECT* Thr) {
    uint32_t i;

    if (!Thr) return;
    for (i = 0; i < OW_MAX_DISPATCHERS; i++) {
        OW_DISPATCHER_OBJECT* d = &s_Dispatchers[i];
        if (d->Type != OW_DISPATCH_MUTEX) continue;
        if (d->Owner != Thr) continue;
        d->Owner = (OW_THREAD_OBJECT*)0;
        d->OwnCount = 0;
        d->Abandoned = 1;
        d->SignalState = 1u;
        if (d->WaitListHead) {
            /* Hand the object to the first waiter, flagged as abandoned. */
            wake_one_waiter(d, OW_WAIT_ABANDONED);
            d->SignalState = 0u;
        }
    }
}

/* ====================================================================== */
/* Boot-time self-test (host-safe: never uses blocking waits)              */
/* ====================================================================== */
void KeSyncSelfTest(void) {
    OW_DISPATCHER_OBJECT* ev;
    OW_DISPATCHER_OBJECT* sem;
    OW_DISPATCHER_OBJECT* mtx;
    uint32_t r;

    ev = KeCreateEvent("_st-event", 0, 1);   /* auto-reset, initially set */
    if (!ev) { ow_kprintf("[SELFTEST SYNC] FAIL: create event\r\n"); return; }
    r = KeWaitForSingleObject(ev, 0);        /* immediate acquire, no block */
    if (r != OW_WAIT_SIGNALED) { ow_kprintf("[SELFTEST SYNC] FAIL: event wait\r\n"); return; }

    sem = KeCreateSemaphore("_st-sem", 1, 1);
    if (!sem) { ow_kprintf("[SELFTEST SYNC] FAIL: create semaphore\r\n"); return; }
    r = KeWaitForSingleObject(sem, 0);
    if (r != OW_WAIT_SIGNALED) { ow_kprintf("[SELFTEST SYNC] FAIL: sem acquire\r\n"); return; }
    KeReleaseSemaphore(sem, 1);
    r = KeWaitForSingleObject(sem, 0);
    if (r != OW_WAIT_SIGNALED) { ow_kprintf("[SELFTEST SYNC] FAIL: sem reacquire\r\n"); return; }
    KeReleaseSemaphore(sem, 1);

    mtx = KeCreateMutex("_st-mtx", 0);
    if (!mtx) { ow_kprintf("[SELFTEST SYNC] FAIL: create mutex\r\n"); return; }
    r = KeWaitForSingleObject(mtx, 0);
    if (r != OW_WAIT_SIGNALED) { ow_kprintf("[SELFTEST SYNC] FAIL: mutex acquire\r\n"); return; }
    r = KeWaitForSingleObject(mtx, 0);       /* recursive acquisition */
    if (r != OW_WAIT_SIGNALED) { ow_kprintf("[SELFTEST SYNC] FAIL: mutex recursive\r\n"); return; }
    if (KeReleaseMutex(mtx) != 1 || KeReleaseMutex(mtx) != 1) {
        ow_kprintf("[SELFTEST SYNC] FAIL: mutex release\r\n"); return;
    }

    ow_kprintf("[SELFTEST SYNC] OK (event/semaphore/mutex)\r\n");
}