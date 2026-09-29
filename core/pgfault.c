/* pgfault.c - Page-fault triage and demand paging.
 *
 * Every process has its own CR3 root and its own private run of physical
 * frames, so a user page is no longer an alias of the boot identity map.  This
 * file turns a vector-14 entry into a decision: decode the fault, ask the
 * faulting process's VAD tree whether the address is real, and if so charge a
 * private frame, map it, and let the instruction be retried.
 *
 * Answering the retry question wrongly is the only way to make things worse
 * than a crash, because retrying an unfixed fault triple faults.  So the rule
 * enforced here is deliberately conservative:
 *
 *   retry  <=>  we just installed a mapping that answers this access
 *
 * A resolver that is merely hopeful returns false and we fall back to the
 * crash banner, which is exactly the pre-Phase-1 behaviour.
 */
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_pgfault.h"
#include "../inc/ow_ps.h"
#include "../hal/idt.h"

static OW_PF_STATS s_Stats;
static bool         s_Audited;   /* one-shot NX/U-S/window audit, see resolver */

/* A null-pointer dereference in a loop can fault millions of times.  Polled
 * serial writes cost ~1.7ms each (measured: the [SW] context-switch trace
 * starved the run and blew the QEMU harness timeout), so the per-fault log is
 * hard-capped rather than merely rate limited.  Counters are uncapped. */
#define OW_PF_LOG_BUDGET 8u

/* ---------------------------------------------------------------------- */
/* CR2 and canonical-address helpers                                        */
/* ---------------------------------------------------------------------- */
uint64_t OwPfReadCr2(void) {
#ifndef OW_HOST_HAL
    uint64_t cr2;
    __asm__ volatile("movq %%cr2, %0" : "=r"(cr2));
    return cr2;
#else
    /* No CPU, no CR2: the host build only exercises the classifier. */
    return 0;
#endif
}

bool OwPfIsCanonical(uint64_t Addr) {
    /* bits 63:48 must all replicate bit 47 */
    if ((Addr >> 47) & 1ull) {
        return (Addr >> 48) == 0xFFFFull;
    }
    return (Addr >> 48) == 0ull;
}

/* ---------------------------------------------------------------------- */
/* Classification                                                          */
/* ---------------------------------------------------------------------- */
OW_PF_KIND OwPfClassify(const void* Frame, uint64_t FaultAddr, uint32_t Err) {
    const ow_hal_frame_t* F = (const ow_hal_frame_t*)Frame;
    uint32_t              Cpl;

    (void)Err;

    if (!F) {
        return OW_PF_NO_PROCESS;
    }

    /* Bit 2 of CS is the RPL, so this is the faulting privilege level.  The
     * US bit of the error code says the same thing; CS is authoritative
     * because the frame is the thing we will actually retry. */
    Cpl = (uint32_t)(F->Cs & 3ull);

    if (!OwPfIsCanonical(FaultAddr)) {
        return OW_PF_NONCANONICAL;
    }

    /* Ring 0 faults are never demand-paged: the kernel half is a recursive
     * identity map, so a not-present kernel page means a corrupt table. */
    if (Cpl != 3u) {
        return OW_PF_KERNEL;
    }

    if (Err & OW_PF_EC_RESERVED) {
        return OW_PF_RESERVED;
    }

    /* Bit 0 is the present bit: CLEAR means the page was absent.  A set bit
     * means the page is mapped and something else refused the access -- most
     * often a U/S violation, since the CPU checks that at every level. */
    if ((Err & OW_PF_EC_NOTPRESENT) == 0) {
        /* Absent at CPL3.  Only the VAD layer knows whether this address is a
         * legitimate lazy region, a guard page, or garbage -- that answer is
         * Phase 2/3. */
        return OW_PF_NOTMAPPED;
    }

    /* Present but the access was refused: a U/S violation, a write to a
     * read-only mapping, or an NX hit.  Distinguishing those needs the VAD,
     * so it escalates. */
    return OW_PF_PROTECTION;
}

const char* OwPfKindName(OW_PF_KIND Kind) {
    switch (Kind) {
        case OW_PF_RESOLVED:     return "RESOLVED";
        case OW_PF_NOTMAPPED:    return "NOT-MAPPED";
        case OW_PF_PROTECTION:   return "PROTECTION";
        case OW_PF_RESERVED:     return "RESERVED-PTE";
        case OW_PF_NONCANONICAL: return "NON-CANONICAL";
        case OW_PF_KERNEL:       return "KERNEL";
        case OW_PF_NO_PROCESS:   return "NO-PROCESS";
        case OW_PF_STARVED:      return "STARVED";
        case OW_PF_GUARD:        return "GUARD";
        default:                 return "UNKNOWN";
    }
}

/* ---------------------------------------------------------------------- */
/* Guard and window policy                                                  */
/* ---------------------------------------------------------------------- */
/* One implementation of "what does this address mean for this process?",
 * shared by the fault path and the boot-time audit so the two cannot drift
 * apart.  Read-only with respect to Proc.
 *
 * A guard page is a VAD declared with no PRESENT bit: it exists precisely so
 * the access is denied.  That makes it distinguishable from a wild pointer
 * (no VAD at all) and from a legal lazy region (PRESENT set), which is the
 * distinction that lets the kernel kill a stack-overflowing task instead of
 * either silently mapping a page below the stack or crashing the machine. */
OW_VA_VERDICT OwPfClassifyUserAddress(const OW_PROCESS_OBJECT* Proc,
                                      uint64_t FaultAddr) {
    const OW_VAD_NODE* Vad;

    if (!Proc || !Proc->Pml4Phys) return OW_VA_OUT_OF_WINDOW;

    /* Test the containing PAGE, not the raw fault address.  CR2 is a byte
     * address, so a perfectly legal access to 0x41FEFF8 arrives here unaligned;
     * requiring page alignment would reject the middle of a page that is inside
     * the window and turn every demand fault into NOT-MAPPED. */
    if (!OwMemIsUserWindow(FaultAddr & ~(uint64_t)(OW_PAGE_SIZE - 1u))) {
        return OW_VA_OUT_OF_WINDOW;
    }

    Vad = OwMemFindVad((OW_VAD_NODE*)Proc->VadRoot, FaultAddr);
    if (!Vad) return OW_VA_NO_VAD;
    /* OwMemFindVad returns the subtree root for an out-of-range address, so
     * the range must be confirmed explicitly. */
    if (FaultAddr < Vad->StartingAddress || FaultAddr > Vad->EndingAddress) {
        return OW_VA_NO_VAD;
    }
    if ((Vad->Protection & OW_PAGE_PRESENT) == 0u) return OW_VA_GUARD;
    /* A non-user VAD describes kernel space; a CPL3 fault on it is invalid
     * whatever the page table happens to hold. */
    if ((Vad->Protection & OW_PAGE_USER) == 0u) return OW_VA_NO_VAD;
    return OW_VA_FAULTABLE;
}

/* ---------------------------------------------------------------------- */
/* Resolution: demand paging                                               */
/* ---------------------------------------------------------------------- */
/* The contract is unchanged from Phase 1 and is the whole point of this
 * function: it may return OW_PF_RESOLVED if and only if it actually installed
 * a mapping that answers the faulting access.  A "should be fine" answer
 * re-faults, and a re-faulting instruction with a bad RIP is a triple fault,
 * so every failure path below is a distinct, reportable non-RESOLVED kind.
 *
 * The order of the checks is the safety argument:
 *   1. own the fault        -- without a process there is no VadRoot to ask
 *   2. prove it is absent   -- a page that IS mapped means a permissions
 *                              problem, and handing a permissions fault a
 *                              brand new frame would silently convert a
 *                              deliberate guard into writable memory
 *   3. prove it is valid    -- a VAD must cover the address, so random and
 *                              guard addresses are refused
 *   4. pay for it           -- commit charge, which can legitimately fail
 *   5. install + flush      -- OwMemMapPage ends with invlpg
 * Only after step 5 does this function say RESOLVED.
 */
OW_PF_KIND OwPfTryResolve(void* Frame, uint64_t FaultAddr, uint32_t Err) {
    OW_THREAD_OBJECT*  Thr;
    OW_PROCESS_OBJECT* Proc;
    OW_VAD_NODE*       Vad;
    uint64_t           PageBase;
    uint64_t           FramePa = 0;
    uint64_t           LeafFlags = 0;
    uint64_t           Prot;
    OW_VA_VERDICT      Verdict;

    (void)Frame;
    (void)Err;

    Thr = OwPsGetCurrentThread();
    if (!Thr) return OW_PF_NO_PROCESS;

    Proc = OwPsGetProcessById(Thr->ProcessId);
    if (!Proc) return OW_PF_NO_PROCESS;
    if (!Proc->Pml4Phys) return OW_PF_NOTMAPPED;

    /* Demand paging works in whole frames: one 4 KiB page may straddle the end
     * of the faulting VAD, and the VAD is the authority on the protection. */
    PageBase = FaultAddr & ~(uint64_t)(OW_PAGE_SIZE - 1u);

    /* Step 2: an already-mapped, already-US page is never a demand-paging
     * opportunity.  The CPU refused the access for a permissions reason (a
     * write to a read-only mapping, or an NX hit), and handing that a brand new
     * RW frame would silently override a protection the VAD asked for.
     *
     * The US test is what makes this correct.  Splitting a 2 MiB huge page --
     * which the first 4 KiB mapping in a process always forces -- leaves 512
     * *supervisor* placeholders across the whole window, so a legitimate user
     * region that simply has not been demand paged yet already translates
     * successfully.  Its error code is a U/S violation, and treating that as
     * "present" would make every demand fault look like a permissions error
     * and none of them would ever resolve. */
    if (OwMemTranslate(Proc->Pml4Phys, PageBase, NULL, &LeafFlags) ==
        OW_SUCCESS) {
        if (LeafFlags & OW_PAGE_USER) return OW_PF_PROTECTION;
        /* Present only as a split placeholder: the VAD below is the authority
         * on whether this address is real, so fall through and install the
         * process's own frame over it. */
    }

    /* Step 3: the VAD tree is the authority on "is this a valid virtual
     * address for this process".  Anything without a VAD -- unmapped heap, a
     * wild pointer, a non-canonical hole -- is refused here, and a declared
     * guard page is answered with its own kind so the caller can kill the task
     * rather than just refusing to map it. */
    Verdict = OwPfClassifyUserAddress(Proc, FaultAddr);
    if (Verdict == OW_VA_GUARD) return OW_PF_GUARD;
    if (Verdict != OW_VA_FAULTABLE) return OW_PF_NOTMAPPED;

    Vad = OwMemFindVad(Proc->VadRoot, FaultAddr);
    Prot = Vad->Protection;
    /* Reject a VAD that claims hardware-owned bits; mapping those is a bug
     * and OwMemMapPage would refuse it anyway. */
    if (Prot & (OW_PAGE_HUGE | OW_PAGE_ACCESSED | OW_PAGE_DIRTY)) {
        return OW_PF_PROTECTION;
    }

    /* Step 4: charge a private frame.  This is where exhaustion is caught --
     * both the process's own run and the global commit ceiling.  Refusing is
     * reported as STARVED, which is not resumable, so a thrashing process
     * cannot spin forever pretending to make progress. */
    if (ow_status_error(OwMemRunCharge(&Proc->FrameRun, &FramePa))) {
        return OW_PF_STARVED;
    }

    /* Step 5: install it.  OwMemMapPage creates the intermediate levels, and
     * ends with invlpg so the retry cannot hit a cached negative translation.
     * On failure the charge is given back: a charge without a mapping is
     * exactly the leak this accounting exists to prevent. */
    if (ow_status_error(OwMemMapPage(Proc->Pml4Phys, PageBase, FramePa, Prot))) {
        (void)OwMemRunRelease(&Proc->FrameRun, FramePa);
        return OW_PF_STARVED;
    }

    Vad->CommitCharge++;
    if (Vad->FirstFrame == 0u) Vad->FirstFrame = FramePa;

    /* One-shot audit once the first user page is really resident.  The boot-time
     * audit in the launcher can only check declared policy and the eagerly
     * mapped code page; NX on a demand-paged data page cannot be verified until
     * the page exists, so it is checked here exactly once to keep the fault path
     * free of per-fault work. */
    if (!s_Audited) {
        s_Audited = true;
        if (OwMemAuditUserWindow(Proc->Pml4Phys, Proc->VadRoot) != 0u) {
            ow_kprintf("[PF] USER WINDOW AUDIT FAILED after first resolve\r\n");
        }
    }

    return OW_PF_RESOLVED;
}

/* ---------------------------------------------------------------------- */
/* Dispatch entry                                                          */
/* ---------------------------------------------------------------------- */
static void pf_account(OW_PF_KIND Kind) {
    s_Stats.Total++;
    switch (Kind) {
        case OW_PF_RESOLVED:     s_Stats.Resolved++;     break;
        case OW_PF_NOTMAPPED:    s_Stats.NotMapped++;    break;
        case OW_PF_PROTECTION:   s_Stats.Protection++;   break;
        case OW_PF_RESERVED:     s_Stats.Reserved++;     break;
        case OW_PF_NONCANONICAL: s_Stats.NonCanonical++; break;
        case OW_PF_KERNEL:       s_Stats.Kernel++;       break;
        case OW_PF_NO_PROCESS:   s_Stats.NoProcess++;    break;
        case OW_PF_STARVED:      s_Stats.Starved++;      break;
        case OW_PF_GUARD:        s_Stats.Guard++;        break;
        default:                                          break;
    }
}

static void pf_log(const ow_hal_frame_t* F, uint64_t Addr, uint32_t Err,
                   OW_PF_KIND Kind) {
    static uint32_t s_Logged;

    if (s_Logged >= OW_PF_LOG_BUDGET) return;
    s_Logged++;

    ow_kprintf("[PF] %s err=%u cr2=%llX rip=%llX cs=%X cr3=%llX%s\r\n",
               OwPfKindName(Kind),
               (unsigned)Err,
               (unsigned long long)Addr,
               (unsigned long long)F->Rip,
               (unsigned)F->Cs,
               (unsigned long long)OwMemGetCurrentPml4(),
               (s_Logged == OW_PF_LOG_BUDGET) ? " (log capped)" : "");
}

/* A guard hit is a killed process, not a failed page-in.  The access was
 * refused on purpose, so the only correct action is to stop the task.
 *
 * Retrying is NOT an option: the faulting instruction is the overflow itself,
 * and returning true would iretq straight back into it.  Demand-mapping the
 * page would be worse -- it would silently hand the overflowing stack more
 * memory and hide the bug that the guard exists to catch.  So the process is
 * torn down and the thread is retired through the normal exit path, which
 * iretqs to the next ready thread and never comes back here. */
static void pf_kill_guard(OW_THREAD_OBJECT* Thr, uint64_t Addr) {
    OW_PROCESS_OBJECT* Proc;

    if (!Thr) return;
    Proc = OwPsGetProcessById(Thr->ProcessId);
    if (Proc) {
        const OW_VAD_NODE* g = OwMemFindVad(Proc->VadRoot, Addr);
        ow_kprintf("[PF] GUARD: killing tid=%u pid=%u (stack overflow at "
                   "%llX, guard %llX-%llX)\r\n",
                   (unsigned)Thr->Tid, (unsigned)Proc->ProcessId,
                   (unsigned long long)Addr,
                   (unsigned long long)(g ? g->StartingAddress : 0ull),
                   (unsigned long long)(g ? g->EndingAddress : 0ull));
        /* Release the frame run first so the charge is not stranded, then let
         * the thread exit switch away.  The whole process dies: the guard
         * marks the boundary of its address space, and anything else running
         * in it shares the same broken stack discipline. */
        OwPsTerminateProcess(Proc, (uint64_t)OW_PF_GUARD);
    } else {
        ow_kprintf("[PF] GUARD: no owning process for tid=%u, halting\r\n",
                   (unsigned)Thr->Tid);
        return;
    }
    OwPsExitThread((uint64_t)OW_PF_GUARD);
}

bool OwPfDispatch(void* Frame) {
    ow_hal_frame_t* F = (ow_hal_frame_t*)Frame;
    uint64_t        Addr;
    uint32_t        Err;
    OW_PF_KIND      Kind;
    OW_THREAD_OBJECT* Thr;

    if (!F) {
        return false;
    }

    Addr = OwPfReadCr2();
    Err  = (uint32_t)F->ErrorCode;

    /* An ownable fault must belong to a live process, otherwise there is no
     * VAD tree to consult and no thread to kill.  Checked before
     * classification so the counter reflects "unresolvable" honestly. */
    Thr = OwPsGetCurrentThread();
    if (!Thr) {
        Kind = OW_PF_NO_PROCESS;
    } else {
        Kind = OwPfClassify(F, Addr, Err);
    }

    /* Ask the resolver last, and only for faults it could plausibly fix.
     * A kernel or corrupt-table fault must never be handed to a mapper. */
    if (Kind == OW_PF_NOTMAPPED || Kind == OW_PF_PROTECTION) {
        Kind = OwPfTryResolve(F, Addr, Err);
    }

    pf_account(Kind);
    pf_log(F, Addr, Err, Kind);

    /* A guard hit ends the task.  Everything else that reaches here is either
     * resolved (retry) or terminal (crash banner). */
    if (Kind == OW_PF_GUARD) {
        pf_kill_guard(Thr, Addr);
        /* Only reached if there was no process to kill, in which case nothing
         * can retire the thread and retrying would loop forever. */
        return false;
    }

    /* The single safety-critical line of this file.  Only a resolver that
     * installed a mapping earns the right to retry the instruction. */
    return (Kind == OW_PF_RESOLVED);
}

/* ---------------------------------------------------------------------- */
/* Accessors                                                               */
/* ---------------------------------------------------------------------- */
void OwPfGetStats(OW_PF_STATS* Out) {
    if (!Out) return;
    *Out = s_Stats;
}

void OwPfResetStats(void) {
    ow_memset(&s_Stats, 0, sizeof(s_Stats));
}
