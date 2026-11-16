/* owklocksan.h - OWKLockSan: kernel lock correctness and misuse detection
 * (Phase 5)
 *
 * Validates the actual locking architecture of this kernel, which is:
 *   - NT-like dispatcher objects (events, semaphores, mutexes, timers) in
 *     libsync/ow_sync.c, and
 *   - cli/sti critical sections (ow_irq_save/ow_irq_restore),
 *   - single-CPU, so atomicity comes from interrupt masking.
 *
 * Checking hooks are wired into sync/ow_sync.c at the mutex acquisition,
 * release, blocking-wait and thread-exit sites, gated on the master/module
 * switches (disabled path costs one branch).
 *
 * IMPLEMENTED (all validated with host-side negative tests):
 *   - release of a mutex the caller does not own (previously silent),
 *   - recursive acquisition beyond the depth ceiling,
 *   - semaphore release that would exceed its limit (previously silently
 *     clamped),
 *   - circular-wait (potential deadlock) detection over the mutex wait-for
 *     graph, computed when a thread is about to block,
 *   - mutex reported as abandoned when the owning thread exits without
 *     releasing it,
 *   - wait realizing an abandoned mutex (owner left it half-done).
 *
 * NOT IMPLEMENTED / deliberate limits:
 *   - lock-order inversions that never close a cycle (A-before-B vs B-before-A
 *     without a live cycle): order is not tracked, only cycles,
 *   - deadlocks that do not pass through dispatcher objects (raw cli/sti
 *     critical sections are not waits),
 *   - ISR-vs-thread races (the uniprocessor model cannot attribute an
 *     interrupt to a distinct thread),
 *   - any detection for code the suite was not asked to check.
 */
#ifndef OW_KLOCKSAN_H
#define OW_KLOCKSAN_H

#include "owksan.h"

#define OW_KLCKSAN_MAX_LOCKS 64U
#define OW_KLCKSAN_MAX_DEPTH 16U
#define OW_KLCKSAN_TID_FREE  0xFFFFu /* sentinel: no owner (tid 0 is valid) */
#define OW_KLCKSAN_TID_NONE  0xFFFEu /* sentinel: no thread recorded */

/* One tracked mutex. */
typedef struct _OW_KLCKSAN_LOCK {
    const void* Obj;       /* dispatcher object being tracked */
    uint32_t OwnerTid;     /* owning thread (0 = free) */
    uint32_t OwnCount;     /* recursion depth */
    uint32_t Abandoned;    /* owner exited without releasing */
    uint64_t AcquiredAt;   /* tick at outermost acquisition */
    uint64_t Seq;          /* sequence number of outermost acquisition */
    bool Used;
} OW_KLCKSAN_LOCK;

typedef struct _OW_KLCKSAN_STATS {
    uint32_t Total;
    uint32_t Owned;
    uint32_t MaxRecursion;
    uint32_t Abandoned;
    uint32_t Sequence;   /* monotonically increasing acquire sequence */
} OW_KLCKSAN_STATS;

OW_STATUS OwKLockSanRegister(void);

void OwKLockSanReset(void);

/* ---- Instrumentation (called from the synchronization layer) --------------- */
void OwKLockSanNoteCreateMutex(const void* Obj);
void OwKLockSanNoteAcquireMutex(const void* Obj, uint32_t Tid);
void OwKLockSanNoteReleaseMutex(const void* Obj, uint32_t Tid);
void OwKLockSanNoteReleaseSemaphore(const void* Obj, uint32_t Count);
void OwKLockSanNoteWillBlock(const void* Obj, uint32_t Tid);
void OwKLockSanNoteWake(uint32_t Tid);
void OwKLockSanNoteWaitResult(const void* Obj, uint32_t Tid, uint32_t Result);
void OwKLockSanNoteThreadExit(uint32_t Tid);

/* ---- Read-only surface (consumed by OWKLSan and host tests) ---------------- */
const OW_KLCKSAN_LOCK* OwKLockSanLookup(const void* Obj);
uint32_t OwKLockSanTrackedLocks(void);
void OwKLockSanGetStats(OW_KLCKSAN_STATS* Out);

/* Visit every live record; Callback returning non-zero continues, zero stops. */
void OwKLockSanForEach(int (*Callback)(const OW_KLCKSAN_LOCK* Lock, void* Ctx),
                       void* Ctx);

/* Test-only hook: backdate a held lock's acquisition tick (host tests). */
void OwKLockSanTestSetAcquiredAt(const void* Obj, uint64_t Tick);

#endif /* OW_KLOCKSAN_H */
