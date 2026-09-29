/* ow_pgfault.h - Page-fault triage: the decision layer that per-process
 * isolation and demand paging sit on top of.
 *
 * This module owns the *decision*: it decodes the CPU error code plus CR2,
 * classifies the fault, consults the faulting process's VAD tree, and either
 * installs a private mapping or refuses.  Only OW_PF_RESOLVED is resumable --
 * everything else escalates, so a bug in the resolver degrades to a crash
 * banner instead of a re-fault livelock.
 *
 * The HAL frame type is deliberately NOT exposed here: like OwPsSchedulerTick
 * (see inc/ow_ps.h) the dispatcher hands the frame over as an opaque void*.
 */
#ifndef OW_PGFAULT_H
#define OW_PGFAULT_H

#include "ow_types.h"

/* Opaque process type, shared with inc/ow_ps.h.  Guarded because C99 forbids
 * redefining a typedef and both headers may land in one translation unit. */
#ifndef OW_PROCESS_TYPEDEF_DEFINED
#define OW_PROCESS_TYPEDEF_DEFINED
typedef struct _OW_PROCESS_OBJECT OW_PROCESS_OBJECT;
#endif

/* Bits of the x86-64 page-fault error code (vector 14), SDM Vol 3 Table 4-1.
 * Namespaced OW_PF_EC_* to stay clear of the OW_PF_* classification enum
 * below.  Note bit 0 is the "P" (present) bit, so the polarity is the
 * opposite of what the name suggests: 0 means the page was absent. */
#define OW_PF_EC_NOTPRESENT 0x1u /* P: 0 = page absent, 1 = protection violation */
#define OW_PF_EC_WRITE      0x2u /* W/R: 0 = read or fetch, 1 = write             */
#define OW_PF_EC_USER       0x4u /* US: 0 = fault at CPL<3, 1 = fault at CPL3     */
#define OW_PF_EC_RESERVED   0x8u /* RSVD: a reserved bit was set in a PTE        */

/* Classification of one page fault.  OW_PF_RESOLVED is the only member that
 * permits the dispatcher to retry the faulting instruction. */
typedef enum _OW_PF_KIND {
    OW_PF_RESOLVED = 0, /* a mapping was installed: safe to retry          */
    OW_PF_NOTMAPPED,    /* CPL3, no VAD covers the address                 */
    OW_PF_PROTECTION,   /* present but permissions/NX refused the access   */
    OW_PF_RESERVED,     /* CPU set the RSVD bit: a corrupt page table     */
    OW_PF_NONCANONICAL, /* CR2 is not a canonical 48-bit address           */
    OW_PF_KERNEL,       /* Ring 0 fault: never demand-paged, escalate     */
    OW_PF_NO_PROCESS,   /* no owning process to resolve against            */
    OW_PF_STARVED,      /* no free frame: retrying would fault again       */
    OW_PF_GUARD,        /* hit a declared guard page: task is killed       */
    OW_PF_KIND_COUNT    /* sentinel                                      */
} OW_PF_KIND;

/* Cumulative fault counters.  Cheap to maintain: a tight loop on a bad
 * pointer can fault millions of times and the log is rate limited. */
typedef struct _OW_PF_STATS {
    uint64_t Total;
    uint64_t Resolved;
    uint64_t NotMapped;
    uint64_t Protection;
    uint64_t Reserved;
    uint64_t NonCanonical;
    uint64_t Kernel;
    uint64_t NoProcess;
    uint64_t Starved;
    uint64_t Guard;
} OW_PF_STATS;

/* Verdict on a single virtual address, before any mapping is considered.
 *
 * This is deliberately a pure function of (process VAD tree, address) so the
 * same decision can be made by the real fault path and by the boot-time
 * audit, rather than the audit re-implementing the policy. */
typedef enum _OW_VA_VERDICT {
    OW_VA_FAULTABLE = 0, /* legal, user, may be demand paged              */
    OW_VA_GUARD,         /* declared guard: the task must be killed       */
    OW_VA_OUT_OF_WINDOW, /* outside the one permitted user window         */
    OW_VA_NO_VAD         /* no VAD covers it: wild pointer or a hole      */
} OW_VA_VERDICT;

/* Classify one fault.  Frame is the CPU-pushed ow_hal_frame_t (opaque);
 * FaultAddr is CR2 and Err is Frame->ErrorCode.  Pure with respect to global
 * state apart from the counters, so it is unit-testable on the host. */
OW_PF_KIND   OwPfClassify(const void* Frame, uint64_t FaultAddr, uint32_t Err);

/* Handle one vector-14 entry.  Returns true only when the faulting
 * instruction was made retryable and the dispatcher should iretq back into
 * it.  A false return means the fault was terminal and the caller should
 * escalate. */
bool         OwPfDispatch(void* Frame);

/* Attempt to satisfy a fault by demand paging: locate the address in the
 * faulting process's VAD tree, charge a private frame from that process's
 * frame run, map it, and flush the TLB.
 *
 * Returns OW_PF_RESOLVED only when a mapping was actually installed, which is
 * the sole condition under which the dispatcher may retry the instruction.
 * Every refusal is a distinct, reportable kind: OW_PF_NOTMAPPED (no VAD, a
 * guard, or kernel space), OW_PF_PROTECTION (already mapped, or a corrupt VAD),
 * OW_PF_STARVED (frame run or global commit ceiling exhausted). */
OW_PF_KIND   OwPfTryResolve(void* Frame, uint64_t FaultAddr, uint32_t Err);

const char*  OwPfKindName(OW_PF_KIND Kind);
void         OwPfGetStats(OW_PF_STATS* Out);
void         OwPfResetStats(void);

/* Decide whether FaultAddr is a legal, faultable user address for Proc, and
 * whether it is a declared guard.  Pure with respect to Proc (read-only), so
 * both the fault path and the boot-time audit share one implementation. */
OW_VA_VERDICT OwPfClassifyUserAddress(const OW_PROCESS_OBJECT* Proc,
                                      uint64_t FaultAddr);

/* True when CR2 is a canonical 48-bit linear address (bits 63:48 all equal
 * bit 47).  Exposed for the host tests. */
bool         OwPfIsCanonical(uint64_t Addr);

/* Read CR2.  Returns 0 under OW_HOST_HAL, where no fault can be taken. */
uint64_t     OwPfReadCr2(void);

#endif /* OW_PGFAULT_H */
