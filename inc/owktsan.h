/* owktsan.h - OWKTSan: data-race detection (Phase 5)
 *
 * A shadow-based happens-before detector over the kernel heap arena, built on
 * a global synchronization epoch: every synchronization event (see below)
 * bumps one counter, and every tracked access stamps its group with the
 * current epoch and accessing thread.  Two accesses to the same group by
 * different threads in the same epoch, with at least one write, constitute a
 * race.  An epoch boundary is a happens-before edge, so synchronized accesses
 * fall into different epochs and never conflict.
 *
 * IMPLEMENTED (all validated with host-side negative tests):
 *   - shadow tracking of the 8 MiB kalloc arena (4 bytes per 8 data bytes:
 *     epoch:16, tid:8, flags:8),
 *   - synchronization-event hooks wired into sync/ow_sync.c at dispatcher
 *     operations (create/wait/signal/release) and into KeWaitForSingleObject
 *     on block and on wake,
 *   - track/check API used at checked call sites,
 *   - conflict reporting with both tids and the address group.
 *
 * NOT IMPLEMENTED / deliberate limits (no claim of reliable race detection):
 *   - plain loads/stores that bypass the tracked APIs are invisible to the
 *     detector (no compiler instrumentation exists in this kernel),
 *   - accesses to memory outside the kalloc arena are untracked,
 *   - interrupt-vs-thread races cannot be attributed to distinct threads
 *     (an ISR sees the interrupted thread's tid),
 *   - this is not TSan-compatible and provides no false-negative guarantees
 *     for code that does not go through the tracked paths.  The epoch does
 *     not wrap: on overflow the shadow is invalidated and epochs restart.
 */
#ifndef OW_KTSAN_H
#define OW_KTSAN_H

#include "owksan.h"
#include "../lib/kalloc.h"

#define OW_KTSAN_GROUPS   (KALLOC_HEAP_SIZE / 8u)
#define OW_KTSAN_SHADOW_SIZE (OW_KTSAN_GROUPS * 4u)

typedef struct _OW_KTSAN_STATS {
    uint64_t Accesses;
    uint64_t Races;
    uint64_t Syncs;
} OW_KTSAN_STATS;

OW_STATUS OwKTSanRegister(void);

/* Bump the global synchronization epoch.  The synchronization layer calls
 * this at every sync boundary; host tests use it to separate epochs. */
void OwKTSanSyncPoint(void);

/* Tracked access checks for verified/checked call sites. */
void OwKTSanRead(const void* Ptr, size_t Size, const char* Label);
void OwKTSanWrite(const void* Ptr, size_t Size, const char* Label);

/* Core tracking primitive: callers (including the host tests) may supply an
 * explicit accessing tid; the Read/Write wrappers use the current thread. */
void OwKTSanTrackAccess(const void* Ptr, size_t Size, bool Write, uint32_t Tid);

void OwKTSanGetStats(OW_KTSAN_STATS* Out);
void OwKTSanReset(void);

#endif /* OW_KTSAN_H */
