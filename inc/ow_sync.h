/* ow_sync.h - NT-like Dispatcher Objects (Event, Semaphore, Timer, Mutex)
 *
 * Non-POSIX counterpart of the Linux wait-queue / completion / hrtimer trio.
 * Threads block on a dispatcher object via KeWaitForSingleObject; the ready
 * queue integration lives in ps/ps.c (OW_THR_BLOCKED + OwPsWakeThread).
 * Wakeup comes from either a signal (KeSetEvent / KeReleaseSemaphore /
 * timer expiry) or a tick-based timeout.
 *
 * Single-CPU, ring-0 only: no spinlocks needed, cli/sti suffices.
 * C99 freestanding.  Static object table, no dynamic heap.  */
#ifndef OW_SYNC_H
#define OW_SYNC_H

#include "ow_object.h"

/* ---- Forward declarations ----------------------------------------------- */
struct _OW_THREAD_OBJECT;
struct _OW_DISPATCHER_OBJECT;

typedef struct _OW_THREAD_OBJECT OW_THREAD_OBJECT;
typedef struct _OW_DISPATCHER_OBJECT OW_DISPATCHER_OBJECT;

/* ---- Compile-time limits ------------------------------------------------ */
#define OW_MAX_DISPATCHERS 64U
#define OW_TIMEOUT_INFINITE 0xFFFFFFFFFFFFFFFFULL

/* ---- Wait result codes -------------------------------------------------- */
#define OW_WAIT_SIGNALED 0U
#define OW_WAIT_TIMEOUT 1U
#define OW_WAIT_ABANDONED 2U
#define OW_WAIT_CANCELLED 3U

/* ---- Dispatcher kinds ---------------------------------------------------- */
typedef enum _OW_DISPATCHER_TYPE {
  OW_DISPATCH_EVENT = 0,
  OW_DISPATCH_SEMAPHORE,
  OW_DISPATCH_TIMER,
  OW_DISPATCH_MUTEX
} OW_DISPATCHER_TYPE;

/* ---- Dispatcher Object (KDISPATCHER_OBJECT-like) ---------------------------
 */
struct _OW_DISPATCHER_OBJECT {
  OW_OBJECT_HEADER Header;
  uint32_t SignalState; /* 0 = not signaled, >0 = signaled */
  OW_DISPATCHER_TYPE Type;
  uint32_t WaitCount;             /* threads waiting on this object */
  OW_THREAD_OBJECT *WaitListHead; /* intrusive singly-linked waiters */

  /* Event fields */
  uint8_t ManualReset; /* 1 = manual, 0 = auto-reset */

  /* Semaphore fields */
  uint32_t Limit; /* max signal count */

  /* Mutex (mutant) fields */
  OW_THREAD_OBJECT *Owner; /* owning thread (NULL = free) */
  uint32_t OwnCount;       /* recursion depth */
  uint32_t Abandoned;      /* owner exited without release */

  /* Timer fields */
  uint64_t DueTime;                 /* absolute tick of expiry */
  uint32_t Period;                  /* repeat interval (0 = one-shot) */
  OW_DISPATCHER_OBJECT *TimerFlink; /* next in active timer list */
};

/* ---- Object creation ------------------------------------------------------
 */
OW_DISPATCHER_OBJECT *KeCreateEvent(const char *Name, uint8_t ManualReset,
                                    uint8_t InitialState);
OW_DISPATCHER_OBJECT *KeCreateSemaphore(const char *Name, uint32_t InitialCount,
                                        uint32_t Limit);
OW_DISPATCHER_OBJECT *KeCreateMutex(const char *Name, uint32_t InitialOwner);
void KeInitializeTimer(OW_DISPATCHER_OBJECT *Obj);

/* ---- Signaling -------------------------------------------------------------
 */
uint32_t KeSetEvent(OW_DISPATCHER_OBJECT *Obj);
uint32_t KeResetEvent(OW_DISPATCHER_OBJECT *Obj);
void KeReleaseSemaphore(OW_DISPATCHER_OBJECT *Obj, uint32_t Count);
uint32_t KeReleaseMutex(OW_DISPATCHER_OBJECT *Obj);

/* ---- Waiting ---------------------------------------------------------------
 */
uint32_t KeWaitForSingleObject(OW_DISPATCHER_OBJECT *Obj,
                               uint64_t TimeoutTicks);
uint32_t KeSleep(uint64_t Ticks);

/* ---- Timer -----------------------------------------------------------------
 */
uint8_t KeSetTimer(OW_DISPATCHER_OBJECT *Obj, uint64_t DueTime,
                   uint32_t Period);
uint8_t KeCancelTimer(OW_DISPATCHER_OBJECT *Obj);

/* ---- Tick helpers (called from OwPsSchedulerTick) ---------------------------
 */
void OwPsTickTimers(void);
void OwPsCheckTimeouts(void);

/* ---- Thread exit hook (abandons mutexes owned by a terminating thread) ------
 */
void KeOnThreadExit(OW_THREAD_OBJECT *Thr);

/* ---- Boot-time self-test of the synchronization primitives ------------------
 */
void KeSyncSelfTest(void);

#endif /* OW_SYNC_H */