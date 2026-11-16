/* owklsan.h - OWKLSan: lock-state and synchronization diagnostics (Phase 5)
 *
 * OWKLockSan answers "is this lock operation legal?"  OWKLSan answers "is the
 * kernel's lock state sane right now?"  It installs no hooks of its own; it
 * audits the lock table that OWKLockSan maintains, plus its own findings.
 *
 * IMPLEMENTED (all validated with host-side negative tests):
 *   - held-lock census: how many mutexes are currently owned, deepest
 *     recursive depth, total tracked records,
 *   - lock leak detection for a handoff point: mutexes still owned when the
 *     caller declares a quiescent point (e.g. just before entering userspace),
 *   - long-hold detection: mutexes owned longer than a tick budget,
 *   - abandoned-mutex reporting (owner exited without releasing).
 *
 * NOT IMPLEMENTED / deliberate limits:
 *   - anything that requires knowing which critical sections are active
 *     (cli/sti regions are not tracked, by design of the architecture),
 *   - priority-inversion or scheduling diagnostics (the scheduler is out of
 *     scope and not instrumented),
 *   - a verdict on WHY a lock is held (context is not recorded).
 */
#ifndef OW_KLSAN_H
#define OW_KLSAN_H

#include "owksan.h"
#include "owklocksan.h"

typedef struct _OW_KLSAN_AUDIT {
    uint32_t TotalTracked;    /* records ever created */
    uint32_t Owned;           /* currently owned */
    uint32_t MaxRecursion;
    uint32_t Abandoned;
    uint32_t LiveRecords;     /* records with a non-null object */
} OW_KLSAN_AUDIT;

OW_STATUS OwKLSanRegister(void);

/* Census of held locks.  Findings are reported through the core. */
OW_STATUS OwKLSanAuditHeldLocks(OW_KLSAN_AUDIT* Out);

/* Flag mutexes whose outermost acquisition is older than MaxTicks (ticks are
 * the scheduler tick count, 100 Hz).  OutFlagged receives the count. */
OW_STATUS OwKLSanAuditLongHolds(uint64_t MaxTicks, uint32_t* OutFlagged);

/* Call at a point where no kernel mutex may be held.  Reports each held
 * mutex as ERROR and returns OW_ERR_CORRUPT if any are held. */
OW_STATUS OwKLSanAuditQuiescent(const char* Where);

#endif /* OW_KLSAN_H */
