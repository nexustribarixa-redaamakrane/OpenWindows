/* ow_memory.h - Memory Manager (PML4 + VAD AVL Tree) */
#ifndef OW_MEMORY_H
#define OW_MEMORY_H

#include "ow_types.h"

#define OW_PAGE_SIZE            4096U
#define OW_PML4_ENTRY_COUNT     512U

/* ---- x86-64 page-table entry bits (leaf PTEs and the upper levels) -------- */
#define OW_PAGE_PRESENT  0x001ull            /* P: entry is valid            */
#define OW_PAGE_WRITE    0x002ull            /* W: writable                  */
#define OW_PAGE_USER     0x004ull            /* US: accessible from CPL3     */
#define OW_PAGE_PWT      0x008ull            /* write-through                */
#define OW_PAGE_PCD      0x010ull            /* cache-disable                */
#define OW_PAGE_ACCESSED 0x020ull            /* A: set by hardware           */
#define OW_PAGE_DIRTY    0x040ull            /* D: set by hardware           */
#define OW_PAGE_HUGE     0x080ull            /* PS: maps a 2/4 MiB page      */
#define OW_PAGE_GLOBAL   0x100ull            /* G: exempt from CR3 flush     */
/* NX lives in bit 63, OUTSIDE OW_PAGE_ADDR_MASK, so it is a policy flag
 * rather than part of the frame number and survives masking.  It only means
 * anything once EFER.NXE is set (OwHalEnableMemoryNx); until then the same
 * bit is reserved and the CPU raises #PF with RSVD set for any access. */
#define OW_PAGE_NO_EXECUTE 0x8000000000000000ull
#define OW_PAGE_ADDR_MASK 0x000FFFFFFFFFF000ull
#define OW_PAGE_HUGE_ADDR_MASK 0x000FFFFFFFE00000ull

/* Permission bits a caller may set on a leaf mapping.  P is always forced on
 * by the mapper, and PS/A/D are hardware-owned, so they are not accepted. */
#define OW_PAGE_USER_RW  (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_USER)
#define OW_PAGE_KERN_RW  (OW_PAGE_PRESENT | OW_PAGE_WRITE)

/* Data-side permissions.  Every non-code user page MUST carry
 * OW_PAGE_NO_EXECUTE, so that the only executable bytes a process can reach
 * are the ones deliberately mapped as code.  Without it, a stack or scratch
 * page holding attacker-influenced bytes could be jumped to. */
#define OW_PAGE_USER_RW_NX \
    (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_USER | OW_PAGE_NO_EXECUTE)
#define OW_PAGE_USER_RO \
    (OW_PAGE_PRESENT | OW_PAGE_USER | OW_PAGE_NO_EXECUTE)
#define OW_PAGE_KERN_RW_NX \
    (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_NO_EXECUTE)

/* Number of entries in one page-table page, and the index shifts. */
#define OW_PAGE_TABLE_ENTRIES 512U
#define OW_PML4_SHIFT 39
#define OW_PDPT_SHIFT 30
#define OW_PD_SHIFT   21
#define OW_PT_SHIFT   12

typedef struct _OW_PML4_ENTRY {
    uint64_t Present         : 1;
    uint64_t ReadWrite       : 1;
    uint64_t UserSupervisor  : 1;
    uint64_t WriteThrough    : 1;
    uint64_t CacheDisable    : 1;
    uint64_t Accessed        : 1;
    uint64_t Reserved0       : 6;
    uint64_t PageFrameNumber : 40;
    uint64_t Reserved1       : 11;
    uint64_t NoExecute       : 1;
} OW_PML4_ENTRY;

typedef struct _OW_VAD_NODE {
    uint64_t                StartingAddress;
    uint64_t                EndingAddress;
    uint64_t                FirstFrame;    /* PA of the first backed page  */
    uint64_t                Protection;   /* full 64-bit PTE bits, incl. NX */
    uint32_t                CommitCharge;
    struct _OW_VAD_NODE*    LeftChild;
    struct _OW_VAD_NODE*    RightChild;
    int32_t                 BalanceFactor;
} OW_VAD_NODE;

OW_STATUS    OwMemInitialize(void);
void*        OwMemAllocatePage(void);
OW_VAD_NODE* OwMemCreateVad(uint64_t Start, uint64_t End, uint64_t Protect);
void         OwMemFreeVad(OW_VAD_NODE* Node);
OW_STATUS    OwMemInsertVad(OW_VAD_NODE** Root, OW_VAD_NODE* Node);
OW_VAD_NODE* OwMemFindVad(OW_VAD_NODE* Root, uint64_t Address);
void         OwMemWalkPml4(uint64_t VirtualAddress);
uint32_t     OwMemPagesUsed(void);
uint32_t     OwMemPagesTotal(void);

/* ---- Per-process address spaces (Phase 2) -------------------------------
 *
 * A PML4 "physical address" here is just the identity-mapped virtual address
 * of the table page: the boot identity map makes VA == PA for all of RAM, so
 * no PA conversion is needed while the map is identity.  Every address space
 * mirrors the boot kernel mappings, so switching CR3 can never leave the
 * kernel without a page table (the triple-fault failure mode).
 *
 * All of these are no-ops returning OW_ERR_NOT_INITIALIZED under
 * OW_HOST_HAL, where there is no CR3 and no page tables to build. */

/* Allocate a zeroed page-table page from the frame arena.  Returns a
 * virtual (== physical) address, or 0 when the arena is exhausted. */
uint64_t     OwMemAllocPageTable(void);

/* Current CR3, cached at init so new address spaces can mirror it. */
uint64_t     OwMemGetCurrentPml4(void);

/* Load CR3.  Skips the write (and therefore the TLB flush) when the requested
 * root is already active, which is the common case for kernel threads. */
void         OwMemSetCurrentPml4(uint64_t Pml4Phys);

/* Allocate a PML4 whose kernel-space mappings are identical to the boot
 * ones, with a private PDPT/PD/PT chain under PDPT slot 0 so that user
 * mappings can diverge per process.  Returns 0 on failure. */
uint64_t     OwMemCreateAddressSpace(void);

/* Install a 4 KiB leaf mapping.  Splits a covering 2 MiB huge page if needed.
 * Creates the intermediate levels.  pa == 0 maps va identity.
 *
 * A mapping that carries OW_PAGE_USER is a USER mapping and is rejected unless
 * Va lies inside the user window (see OwMemIsUserWindow): user space may never
 * be scattered across the address space, or a single stray U/S bit turns the
 * whole low 1 GiB into a user-accessible view of kernel RAM.
 *
 * A mapping that carries OW_PAGE_USER without OW_PAGE_NO_EXECUTE is accepted
 * only because the code page genuinely must be executable; every data page is
 * expected to carry NX. */
OW_STATUS    OwMemMapPage(uint64_t Pml4Phys, uint64_t Va, uint64_t Pa,
                          uint64_t Flags);
OW_STATUS    OwMemUnmapPage(uint64_t Pml4Phys, uint64_t Va);

/* Raise U/S on the single 4 KiB page at Va in Pml4Phys, creating the mapping
 * if absent.  This is the per-process replacement for the boot-time
 * OwHalMemSetUserAccessible(), which could only patch the live CR3. */
OW_STATUS    OwMemSetUserAccessibleIn(uint64_t Pml4Phys, uint64_t Va);

/* Resolve Va in Pml4Phys.  Returns OW_ERR_NOT_FOUND when any level is absent.
 * Does not allocate.  Used by the self-tests and by demand paging.
 * OutFlags receives the software-controllable PTE bits, NX (bit 63) included,
 * so a caller can tell "executable" from "not executable" without re-walking. */
OW_STATUS    OwMemTranslate(uint64_t Pml4Phys, uint64_t Va,
                            uint64_t* OutPa, uint64_t* OutFlags);

/* Translate through the *active* CR3. */
OW_STATUS    OwMemTranslateActive(uint64_t Va, uint64_t* OutPa,
                                  uint64_t* OutFlags);

/* True when the two roots resolve Va to the same physical page with the same
 * permissions -- the invariant that makes a CR3 switch safe. */
bool         OwMemVerifyMirror(uint64_t Pml4A, uint64_t Pml4B, uint64_t Va);

/* ---- Guarded user window (Phase 4) --------------------------------------
 *
 * All user space lives in one designated low-memory window.  Confining it to a
 * single 2 MiB range inside the private pdpt[0] chain means the region a
 * process can possibly reach is auditable in one place, and it is disjoint
 * from the kernel image, the frame arena and the boot identity window that
 * every root mirrors. */
#define OW_USER_WINDOW_BASE 0x4000000ULL
#define OW_USER_WINDOW_END  0x4200000ULL   /* exclusive */
#define OW_USER_WINDOW_SIZE (OW_USER_WINDOW_END - OW_USER_WINDOW_BASE)

/* Canonical user-space layout, shared by every process that gets an image.
 *
 * A single definition matters here: the loader, the syscall heap and the test
 * harness all have to agree on where the stack ends and where the guard band
 * begins, or a "guard" that one component believes is at 0x41FD000 silently
 * becomes ordinary stack to the next.  Growing the guard or the stack is then
 * a one-line change instead of a hunt through three files.
 *
 *   base                                                        end
 *   |  image / heap  |  free  |  guard band  |  stack lo |  stack top  |
 *   0x4000000                                        0x41FE000  0x41FF000
 */
#define OW_USER_IMAGE_BASE   OW_USER_WINDOW_BASE
#define OW_USER_STACK_PAGES  2ULL
#define OW_USER_STACK_TOP    (OW_USER_WINDOW_END - OW_PAGE_SIZE)
#define OW_USER_STACK_LO     (OW_USER_STACK_TOP -                 \
                              (OW_USER_STACK_PAGES - 1ULL) * OW_PAGE_SIZE)
/* Guard pages sit IMMEDIATELY below the stack: no gap, so the first page past
 * the low stack bound is always a guard and never unclaimed address space. */
#define OW_USER_GUARD_PAGES  4ULL
#define OW_USER_GUARD_TOP    (OW_USER_STACK_LO - OW_PAGE_SIZE)
#define OW_USER_GUARD_BASE   (OW_USER_GUARD_TOP -                \
                              OW_USER_GUARD_PAGES * OW_PAGE_SIZE)
#define OW_USER_HEAP_BASE    (OW_USER_WINDOW_BASE + 0x100000ULL)

/* True when the 4 KiB page CONTAINING Va lies wholly inside the user window.
 * Use this for page-granular decisions: mapping targets and VAD endpoints. */
bool         OwMemIsUserWindow(uint64_t Va);

/* True when the byte address Va itself lies inside the user window, aligned or
 * not.  Use this for anything that is a real instruction/data address rather
 * than a page: an entry point, a return address, a stack pointer, or a CR2
 * fault address.  Those are routinely mid-page (an entry at base+0x40, an RSP
 * 48 bytes below a page top), and testing them with the page-aligned predicate
 * would reject perfectly legal addresses. */
bool         OwMemInUserWindow(uint64_t Va);

/* True when U/S is set on ALL FOUR present tiers (PML4E, PDPTE, PDE, PTE) of
 * the path to Va.  This is the generalized form of the hal/htl.c invariant,
 * exposed as a predicate so it can be asserted rather than assumed. */
bool         OwMemVerifyUserPath(uint64_t Pml4Phys, uint64_t Va);

/* Audit a whole user window against the guardrail policy.  Walks VadRoot and
 * checks, for every node: the range is inside the user window; a VAD with the
 * PRESENT bit is a legal, user-accessible, non-reserved range; and a resident
 * leaf matches the VAD's NX intent.  Returns the number of violations found
 * (0 == clean) and logs each one. */
uint32_t     OwMemAuditUserWindow(uint64_t Pml4Phys, OW_VAD_NODE* VadRoot);

/* ---- Dedicated per-process frame runs + commit charge (Phase 3) ---------
 *
 * A process's private pages are no longer aliases of the boot identity map.
 * At creation each process reserves a *run*: one contiguous, exclusively
 * owned span of physical frames.  Demand paging then carves 4 KiB frames out
 * of that run, so two processes mapping the same virtual address receive
 * different physical pages and neither can observe or corrupt the other.
 *
 * Commit charge is the accounting that keeps this from turning a runaway
 * process into an allocator panic.  Every frame handed out is charged against
 * both the owning run and a global ceiling; when either is exhausted the
 * charge is *refused* (OW_ERR_INSUFFICIENT), which demand paging turns into
 * OW_PF_STARVED -- a clean, reported fault rather than a panic or a silent
 * overcommit. */

/* Default private run size, in 4 KiB frames. */
#define OW_FRAME_RUN_PAGES 64u

/* Global commit ceiling as a percentage of the physical arena, leaving
 * headroom for page-table pages and the boot image. */
#define OW_COMMIT_LIMIT_PCT 75u

typedef struct _OW_FRAME_RUN {
    uint64_t    Base;      /* first frame (VA == PA); 0 = not reserved      */
    uint32_t    Pages;     /* capacity in frames                            */
    uint32_t    Committed; /* frames currently charged to this run          */
} OW_FRAME_RUN;

/* Contiguous frame allocation from the physical arena.  Returns the first
 * frame or 0 when the arena cannot satisfy the request. */
uint64_t     OwMemAllocatePages(uint32_t Count);

/* Reserve `Pages` contiguous frames exclusively for one process.  Zeroes the
 * run descriptor first, so a failed reservation leaves an empty run rather
 * than a stale one.  Returns the run base, or 0 on failure. */
uint64_t     OwMemReserveFrameRun(OW_FRAME_RUN* Run, uint32_t Pages);

/* Frames still chargeable in this run (0 when the run is full or unreserved). */
uint32_t     OwMemRunAvailable(const OW_FRAME_RUN* Run);

/* Charge the next frame of the run: allocates, zero-fills, and books it
 * against both the run and the global commit ceiling.  Returns the frame in
 * OutFrame, or OW_ERR_INSUFFICIENT when the run or the ceiling is exhausted
 * (in which case nothing is charged). */
OW_STATUS    OwMemRunCharge(OW_FRAME_RUN* Run, uint64_t* OutFrame);

/* Uncharge one frame previously returned by OwMemRunCharge and zero it, so a
 * later process cannot inherit stale contents.  Recycles nothing inside the
 * run yet: the arena is a bump allocator, so the frame is simply returned to
 * the global pool. */
OW_STATUS    OwMemRunRelease(OW_FRAME_RUN* Run, uint64_t Frame);

/* Uncharge an entire run (process teardown). */
void         OwMemRunReleaseAll(OW_FRAME_RUN* Run);

/* Global commit accounting, for the shell/diagnostics and for tests. */
uint32_t     OwMemCommitTotal(void);
uint32_t     OwMemCommitLimit(void);

#endif /* OW_MEMORY_H */
