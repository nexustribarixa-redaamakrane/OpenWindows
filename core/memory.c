/* memory.c - Memory Manager (PML4 + VAD AVL Tree) */
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../lib/kalloc.h"

/* Static 16MB physical frame allocator.
 *
 * The 4096-byte alignment is mandatory, not cosmetic: page-table pages are
 * consumed as CR3 roots, and the CPU masks CR3[11:0] before using the value as
 * a physical address.  An arena that starts mid-page therefore yields roots
 * whose entries are read from the wrong offset, and every walk comes back
 * not-present -- which shows up as a triple fault on the first CR3 switch,
 * with no page-fault report at all. */
static uint8_t g_PhysicalRam[16U * 1024U * 1024U] __attribute__((aligned(4096)));
static size_t g_RamPointer = 0;

#define OW_TOTAL_PAGES (sizeof(g_PhysicalRam) / OW_PAGE_SIZE)

/* Kernel-wide committed-page count (Phase 3).  Declared up here because
 * OwMemInitialize resets it before the run/commit code below is reached. */
static uint32_t s_CommitTotal;

#ifndef OW_HOST_HAL
/* CR3 of the running kernel, captured once at init and used as the template
 * every new address space mirrors.  Declared up here because OwMemInitialize
 * fills it before the per-process code below is reached. */
static uint64_t s_BootPml4;
#endif

/* VAD lookaside pool (slab for the fixed-size OW_VAD_NODE).  Free nodes are
 * chained through RightChild (freed VADs are not part of any tree). */
#define OW_VAD_POOL_SIZE 1024U
static OW_VAD_NODE s_VadPool[OW_VAD_POOL_SIZE];
static OW_VAD_NODE *s_VadFreeList = (void *)0;
static uint8_t s_VadPoolReady = 0;

static void vad_pool_build(void) {
  uint32_t i;
  s_VadFreeList = (void *)0;
  for (i = 0; i < OW_VAD_POOL_SIZE; i++) {
    s_VadPool[i].RightChild = s_VadFreeList;
    s_VadFreeList = &s_VadPool[i];
  }
  s_VadPoolReady = 1;
}

OW_STATUS OwMemInitialize(void) {
  g_RamPointer = 0;
  s_CommitTotal = 0;
  vad_pool_build();
#ifndef OW_HOST_HAL
  /* Capture the running root while CR3 still holds the loader's identity map;
   * every per-process address space mirrors this one. */
  s_BootPml4 = 0;
  {
    uint64_t cr3;
    __asm__ volatile("movq %%cr3, %0" : "=r"(cr3));
    s_BootPml4 = cr3;
  }
#endif
  return OW_SUCCESS;
}

void *OwMemAllocatePage(void) {
  void *page;
  if (g_RamPointer + OW_PAGE_SIZE > sizeof(g_PhysicalRam))
    return (void *)0;
  page = &g_PhysicalRam[g_RamPointer];
  g_RamPointer += OW_PAGE_SIZE;
  return page;
}

uint64_t OwMemAllocatePages(uint32_t Count) {
  void *pages;
  size_t span;

  if (Count == 0u) return (uint64_t)0;
  span = (size_t)Count * OW_PAGE_SIZE;
  if (g_RamPointer + span > sizeof(g_PhysicalRam)) return (uint64_t)0;
  pages = &g_PhysicalRam[g_RamPointer];
  g_RamPointer += span;
  return (uint64_t)(uintptr_t)pages;
}

/* ---------------------------------------------------------------------- */
/* Per-process frame runs and commit charge accounting                      */
/* ---------------------------------------------------------------------- */
/*
 * These live outside the page-table guards on purpose: they are pure frame
 * accounting and need no CR3, so the host tests can exercise the exhaustion
 * and ceiling logic for real instead of stubbing it out.
 *
 * s_CommitTotal is the kernel-wide committed-page count.  The arena itself is
 * a bump allocator and cannot be overrun by construction (every request is
 * bounds checked against sizeof(g_PhysicalRam)), so this counter is not an
 * anti-overrun guard -- it is a *policy* limit that turns memory pressure into
 * a reportable, per-process fault instead of silent global exhaustion where
 * one process starves every other process.
 */
uint32_t OwMemCommitLimit(void) {
  return (uint32_t)(((uint64_t)OW_TOTAL_PAGES * OW_COMMIT_LIMIT_PCT) / 100u);
}

uint32_t OwMemCommitTotal(void) { return s_CommitTotal; }

uint64_t OwMemReserveFrameRun(OW_FRAME_RUN *Run, uint32_t Pages) {
  uint64_t base;

  if (!Run) return (uint64_t)0;
  /* Clear first: a failed reservation must leave an inert run, never a stale
   * base that OwMemRunCharge would happily keep handing out. */
  Run->Base = 0;
  Run->Pages = 0;
  Run->Committed = 0;

  if (Pages == 0u) return (uint64_t)0;
  base = OwMemAllocatePages(Pages);
  if (!base) return (uint64_t)0;

  Run->Base = base;
  Run->Pages = Pages;
  return base;
}

uint32_t OwMemRunAvailable(const OW_FRAME_RUN *Run) {
  if (!Run || Run->Base == 0u || Run->Committed >= Run->Pages) return 0u;
  return Run->Pages - Run->Committed;
}

OW_STATUS OwMemRunCharge(OW_FRAME_RUN *Run, uint64_t *OutFrame) {
  uint64_t frame;

  if (!Run || !OutFrame) return OW_ERR_NULL_POINTER;
  if (Run->Base == 0u || Run->Pages == 0u) return OW_ERR_NOT_INITIALIZED;
  /* Per-run exhaustion first, then the global ceiling.  Both are refusal
   * paths, never partial charges. */
  if (Run->Committed >= Run->Pages) return OW_ERR_INSUFFICIENT;
  if (s_CommitTotal >= OwMemCommitLimit()) return OW_ERR_INSUFFICIENT;

  frame = Run->Base + (uint64_t)Run->Committed * OW_PAGE_SIZE;
  /* A demand-paged page must read as zero before any CPL3 instruction can
   * observe it: the CPU can retry the faulting store the instant we return. */
  ow_memset((void *)(uintptr_t)frame, 0, OW_PAGE_SIZE);
  Run->Committed++;
  s_CommitTotal++;
  *OutFrame = frame;
  return OW_SUCCESS;
}

OW_STATUS OwMemRunRelease(OW_FRAME_RUN *Run, uint64_t Frame) {
  if (!Run || Run->Base == 0u) return OW_ERR_NULL_POINTER;
  if (Run->Committed == 0u) return OW_ERR_NOT_FOUND;
  if (Frame < Run->Base ||
      Frame >= Run->Base + (uint64_t)Run->Pages * OW_PAGE_SIZE) {
    return OW_ERR_INVALID_PARAM;
  }
  ow_memset((void *)(uintptr_t)Frame, 0, OW_PAGE_SIZE);
  Run->Committed--;
  if (s_CommitTotal > 0u) s_CommitTotal--;
  return OW_SUCCESS;
}

void OwMemRunReleaseAll(OW_FRAME_RUN *Run) {
  if (!Run || Run->Base == 0u) return;
  while (Run->Committed > 0u) {
    uint64_t frame = Run->Base + (uint64_t)(Run->Committed - 1u) * OW_PAGE_SIZE;
    Run->Committed--;
    if (s_CommitTotal > 0u) s_CommitTotal--;
    ow_memset((void *)(uintptr_t)frame, 0, OW_PAGE_SIZE);
  }
}

OW_VAD_NODE *OwMemCreateVad(uint64_t Start, uint64_t End, uint64_t Protect) {
  OW_VAD_NODE *node;

  if (!s_VadPoolReady)
    vad_pool_build();
  if (s_VadFreeList) {
    node = s_VadFreeList;
    s_VadFreeList = node->RightChild; /* free-link lives in RightChild */
    node->RightChild = (void *)0;
  } else {
    node = (OW_VAD_NODE *)kcalloc(1, sizeof(OW_VAD_NODE));
    if (!node)
      return (void *)0;
  }
  node->StartingAddress = Start;
  node->EndingAddress = End;
  node->Protection = Protect;
  node->CommitCharge = (uint32_t)((End - Start) / OW_PAGE_SIZE);
  node->LeftChild = (void *)0;
  node->RightChild = (void *)0;
  node->BalanceFactor = 0;
  return node;
}

void OwMemFreeVad(OW_VAD_NODE *Node) {
  if (!Node)
    return;
  if (Node >= &s_VadPool[0] && Node < &s_VadPool[OW_VAD_POOL_SIZE]) {
    Node->RightChild = s_VadFreeList; /* push back onto the pool */
    s_VadFreeList = Node;
  } else {
    kfree(Node); /* bump pool: no-op, as before */
  }
}

static int32_t vad_height(OW_VAD_NODE *n) {
  int32_t lh, rh;
  if (!n)
    return 0;
  lh = vad_height(n->LeftChild);
  rh = vad_height(n->RightChild);
  return (lh > rh ? lh : rh) + 1;
}

static OW_VAD_NODE *rotate_right(OW_VAD_NODE *y) {
  OW_VAD_NODE *x = y->LeftChild;
  OW_VAD_NODE *t2 = x->RightChild;
  x->RightChild = y;
  y->LeftChild = t2;
  return x;
}

static OW_VAD_NODE *rotate_left(OW_VAD_NODE *x) {
  OW_VAD_NODE *y = x->RightChild;
  OW_VAD_NODE *t2 = y->LeftChild;
  y->LeftChild = x;
  x->RightChild = t2;
  return y;
}

static OW_VAD_NODE *rebalance(OW_VAD_NODE *node) {
  int32_t balance;
  if (!node)
    return (void *)0;
  balance = vad_height(node->LeftChild) - vad_height(node->RightChild);
  node->BalanceFactor = balance;

  if (balance > 1 && vad_height(node->LeftChild->LeftChild) >=
                         vad_height(node->LeftChild->RightChild))
    return rotate_right(node);
  if (balance > 1 && vad_height(node->LeftChild->LeftChild) <
                         vad_height(node->LeftChild->RightChild)) {
    node->LeftChild = rotate_left(node->LeftChild);
    return rotate_right(node);
  }
  if (balance < -1 && vad_height(node->RightChild->RightChild) >=
                          vad_height(node->RightChild->LeftChild))
    return rotate_left(node);
  if (balance < -1 && vad_height(node->RightChild->RightChild) <
                          vad_height(node->RightChild->LeftChild)) {
    node->RightChild = rotate_right(node->RightChild);
    return rotate_left(node);
  }
  return node;
}

OW_STATUS OwMemInsertVad(OW_VAD_NODE **Root, OW_VAD_NODE *Node) {
  if (!Node)
    return OW_ERR_NULL_POINTER;
  if (!(*Root)) {
    *Root = Node;
    return OW_SUCCESS;
  }

  if (Node->StartingAddress < (*Root)->StartingAddress) {
    if (!(*Root)->LeftChild)
      (*Root)->LeftChild = Node;
    else
      OwMemInsertVad(&(*Root)->LeftChild, Node);
  } else if (Node->StartingAddress > (*Root)->StartingAddress) {
    if (!(*Root)->RightChild)
      (*Root)->RightChild = Node;
    else
      OwMemInsertVad(&(*Root)->RightChild, Node);
  } else {
    return OW_ERR_ALREADY_EXISTS;
  }

  *Root = rebalance(*Root);
  return OW_SUCCESS;
}

/* First VAD whose [Start,End] span contains Address, or NULL.  The tree is
 * ordered by StartingAddress, so the search can prune: if we have passed the
 * address on the way down, no subtree on the left can contain it. */
OW_VAD_NODE *OwMemFindVad(OW_VAD_NODE *Root, uint64_t Address) {
  while (Root) {
    if (Address < Root->StartingAddress) {
      Root = Root->LeftChild;
    } else if (Address > Root->EndingAddress) {
      Root = Root->RightChild;
    } else {
      return Root;
    }
  }
  return (OW_VAD_NODE *)0;
}

/* ======================================================================== */
/* Per-process address spaces (Phase 2)                                     */
/* ======================================================================== */
/*
 * The boot loader (boot/qboot.S) leaves a 1 GiB identity map built from 2 MiB
 * huge pages: pml4[0] -> pdpt, pdpt[0..3] all aliasing one pd0 whose 512 PDEs
 * cover VA==PA for 0..1 GiB.  Two consequences drive this whole section:
 *
 *  1. There are no 4 KiB page tables to inherit, so any 4 KiB mapping must
 *     SPLIT the covering 2 MiB PDE (ow_mem_split_huge below).
 *
 *  2. The kernel lives at 0x200000 and the user window at 0x4000000 -- both
 *     under pdpt slot 0.  So slot 0 cannot simply be shared if the user
 *     window is to differ per process: sharing one PD would mean one process
 *     unmapping a page out from under another.  A new root therefore gets a
 *     private pdpt[0] -> pd -> pt chain, while every *physical* frame and
 *     permission in it is copied from boot, so the kernel stays reachable
 *     from every CR3.  pdpt slots 1..3 are copied verbatim and keep aliasing
 *     the shared pd0, exactly as boot has them.
 *
 * Because the kernel half is byte-identical in content and shared in physical
 * pages, a CR3 reload cannot leave the CPU without a mapping for the code it
 * is currently executing -- which is the classic triple-fault trap.
 */

#ifdef OW_HOST_HAL
/* No CPU, no CR3, no page tables.  The host harness runs as an ordinary
 * process, so every entry point declines cleanly instead of faking state. */
uint64_t  OwMemAllocPageTable(void) { return 0; }
uint64_t  OwMemGetCurrentPml4(void) { return 0; }
void      OwMemSetCurrentPml4(uint64_t Pml4Phys) { (void)Pml4Phys; }
uint64_t  OwMemCreateAddressSpace(void) { return 0; }
OW_STATUS OwMemMapPage(uint64_t Pml4, uint64_t Va, uint64_t Pa, uint64_t F) {
  (void)Pml4; (void)Va; (void)Pa; (void)F; return OW_ERR_NOT_INITIALIZED;
}
OW_STATUS OwMemUnmapPage(uint64_t Pml4, uint64_t Va) {
  (void)Pml4; (void)Va; return OW_ERR_NOT_INITIALIZED;
}
OW_STATUS OwMemSetUserAccessibleIn(uint64_t Pml4, uint64_t Va) {
  (void)Pml4; (void)Va; return OW_ERR_NOT_INITIALIZED;
}
OW_STATUS OwMemTranslate(uint64_t Pml4, uint64_t Va, uint64_t* Pa, uint64_t* F) {
  (void)Pml4; (void)Va; (void)Pa; (void)F; return OW_ERR_NOT_INITIALIZED;
}

/* Host builds have no page tables, so the window predicates answer from the
 * constants alone: the confinement policy is still testable without a CPU. */
bool OwMemIsUserWindow(uint64_t Va) {
  if (Va & (OW_PAGE_SIZE - 1u)) return false;
  return (Va >= OW_USER_WINDOW_BASE) &&
         (Va <= (OW_USER_WINDOW_END - OW_PAGE_SIZE));
}
bool OwMemInUserWindow(uint64_t Va) {
  return (Va >= OW_USER_WINDOW_BASE) && (Va < OW_USER_WINDOW_END);
}
bool     OwMemVerifyUserPath(uint64_t Pml4, uint64_t Va) {
  (void)Pml4; (void)Va; return true;
}
uint32_t OwMemAuditUserWindow(uint64_t Pml4, OW_VAD_NODE* VadRoot) {
  (void)Pml4; (void)VadRoot; return 0u;
}
bool      OwMemVerifyMirror(uint64_t A, uint64_t B, uint64_t Va) {
  (void)A; (void)B; (void)Va; return true;
}
#else

static uint64_t mem_read_cr3(void) {
  uint64_t cr3;
  __asm__ volatile("movq %%cr3, %0" : "=r"(cr3));
  return cr3;
}

uint64_t OwMemGetCurrentPml4(void) { return mem_read_cr3(); }

void OwMemSetCurrentPml4(uint64_t Pml4Phys) {
  if (!Pml4Phys) return;
  /* Reloading CR3 flushes every non-global TLB entry, which is expensive and
   * happens on every scheduler switch.  The common case is resuming a thread
   * that already owns the active root, so compare first. */
  if (mem_read_cr3() == Pml4Phys) return;
  __asm__ volatile("movq %0, %%cr3" : : "r"(Pml4Phys) : "memory");
}

uint64_t OwMemAllocPageTable(void) {
  void *page = OwMemAllocatePage();
  if (!page) return (uint64_t)0;
  ow_memset(page, 0, OW_PAGE_SIZE);
  /* Identity mapped, so the VA we can dereference IS the physical address. */
  return (uint64_t)(uintptr_t)page;
}

/* Replace the 2 MiB huge PDE at pd[idx] with a page table that reproduces the
 * same mapping in 4 KiB granules.  The leaf permissions are inherited from
 * the parent PDE, so splitting never silently widens access: a supervisor huge
 * page yields 512 supervisor pages. */
static uint64_t *ow_mem_split_huge(uint64_t *pd, uint32_t idx) {
  uint64_t pde = pd[idx];
  uint64_t base = pde & OW_PAGE_HUGE_ADDR_MASK;
  uint64_t leaf = pde & (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_USER);
  uint64_t *pt = (uint64_t *)(uintptr_t)OwMemAllocPageTable();
  uint32_t i;

  if (!pt) return (uint64_t *)0;
  /* A huge page is 512 contiguous 4 KiB frames.  NX is bit 63, which is NOT
   * part of the frame number, so the whole window inherits the parent's
   * execute/execute-disable decision. */
  if (pde & OW_PAGE_NO_EXECUTE) leaf |= OW_PAGE_NO_EXECUTE;
  for (i = 0; i < OW_PAGE_TABLE_ENTRIES; i++) {
    pt[i] = (base + (uint64_t)i * OW_PAGE_SIZE) | leaf;
  }
  /* The PDE itself must be user-accessible too: x86-64 checks U/S on EVERY
   * level of the walk, not just the leaf. */
  pd[idx] = (uint64_t)(uintptr_t)pt | OW_PAGE_USER_RW;
  return pt;
}

/* Walk to the leaf PTE slot for Va, optionally creating the levels and
 * splitting huge pages on the way.  Returns NULL on allocation failure.
 *
 * `user` generalises the U/S invariant from hal/htl.c across every tier of the
 * walk.  When it is set, EVERY present tier is stamped user-accessible -- not
 * merely the ones this call happens to allocate:
 *
 *   - a tier that is ABSENT is created with U/S already set (as before), and
 *   - a tier that is ALREADY PRESENT also gets U/S raised.
 *
 * The second case is the one that matters in practice.  Splitting a 2 MiB huge
 * page leaves 512 SUPERVISOR placeholders across the entire window, so a
 * declared, legal, not-yet-faulted user region already resolves as "present".
 * The CPU then rejects the CPL3 access at a tier whose U/S is clear and
 * reports a protection violation -- present bit SET -- which is precisely how
 * a missing upper-tier U/S bit disguises itself as a permissions error.  That
 * is also why the resolver must read the leaf's U/S bit rather than simply
 * asking whether the page is present. */
static uint64_t *ow_mem_walk(uint64_t pml4, uint64_t va, bool create, bool user) {
  uint64_t *t;
  uint32_t i4, i3, i2, i1;
  uint32_t lvl;
  uint32_t idx[4];

  if (!pml4) return (uint64_t *)0;
  if ((va >> 47) != ((va >> 47) & 1ull ? 0xFFFFull : 0ull)) return (uint64_t *)0;

  t = (uint64_t *)(uintptr_t)pml4;
  i4 = (uint32_t)((va >> OW_PML4_SHIFT) & 0x1FFull);
  i3 = (uint32_t)((va >> OW_PDPT_SHIFT) & 0x1FFull);
  i2 = (uint32_t)((va >> OW_PD_SHIFT) & 0x1FFull);
  i1 = (uint32_t)((va >> OW_PT_SHIFT) & 0x1FFull);
  idx[0] = i4; idx[1] = i3; idx[2] = i2; idx[3] = i1;

  for (lvl = 0; lvl < 3; lvl++) {
    if ((t[idx[lvl]] & OW_PAGE_PRESENT) == 0) {
      uint64_t fresh;
      if (!create) return (uint64_t *)0;
      fresh = OwMemAllocPageTable();
      if (!fresh) return (uint64_t *)0;
      /* U/S is required on the upper levels for a CPL3 access to succeed. */
      t[idx[lvl]] = fresh | OW_PAGE_USER_RW;
    } else {
      if ((t[idx[lvl]] & OW_PAGE_HUGE) != 0) {
        /* A huge page at this level: split it into the next-lower granularity. */
        if (!ow_mem_split_huge(t, idx[lvl])) return (uint64_t *)0;
      }
      /* Raise U/S on a tier that was already present.  Without this a user walk
       * can pass through a supervisor tier inherited from the boot map and fail
       * one or two levels above a perfectly good leaf. */
      if (user && (t[idx[lvl]] & OW_PAGE_USER) == 0) {
        t[idx[lvl]] |= OW_PAGE_USER;
      }
    }
    t = (uint64_t *)(uintptr_t)(t[idx[lvl]] & OW_PAGE_ADDR_MASK);
  }
  return &t[i1];
}

bool OwMemIsUserWindow(uint64_t Va) {
  if (Va & (OW_PAGE_SIZE - 1u)) return false;
  return (Va >= OW_USER_WINDOW_BASE) &&
         (Va <= (OW_USER_WINDOW_END - OW_PAGE_SIZE));
}

/* Any byte address, aligned or not.  Entry points, return addresses, stack
 * pointers and CR2 fault addresses are routinely mid-page, and they must be
 * tested against the window as addresses rather than as page bases. */
bool OwMemInUserWindow(uint64_t Va) {
  return (Va >= OW_USER_WINDOW_BASE) && (Va < OW_USER_WINDOW_END);
}

OW_STATUS OwMemMapPage(uint64_t pml4, uint64_t va, uint64_t pa, uint64_t flags) {
  uint64_t *pte;
  bool      user;

  if (!pml4) return OW_ERR_NULL_POINTER;
  if (va & (OW_PAGE_SIZE - 1u)) return OW_ERR_INVALID_PARAM;
  /* PS/A/D are hardware-owned; a caller asking for them is a bug. */
  if (flags & (OW_PAGE_HUGE | OW_PAGE_ACCESSED | OW_PAGE_DIRTY)) {
    return OW_ERR_INVALID_PARAM;
  }

  user = (flags & OW_PAGE_USER) != 0u;
  /* Guardrail 1: user mappings may exist ONLY inside the designated window.
   * Enforced here, at the one choke point every mapping passes through, rather
   * than trusted to each caller: a single stray U/S bit outside the window
   * turns part of the mirrored 0-1 GiB identity map into a user view of kernel
   * RAM, and that is not something a comment can prevent. */
  if (user && !OwMemIsUserWindow(va)) return OW_ERR_INVALID_PARAM;

  pte = ow_mem_walk(pml4, va, true, user);
  if (!pte) return OW_ERR_INSUFFICIENT;
  *pte = (pa & OW_PAGE_ADDR_MASK) | ((uint64_t)flags | OW_PAGE_PRESENT);
  __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
  return OW_SUCCESS;
}

OW_STATUS OwMemUnmapPage(uint64_t pml4, uint64_t va) {
  uint64_t *pte;
  if (!pml4) return OW_ERR_NULL_POINTER;
  pte = ow_mem_walk(pml4, va, false, false);
  if (!pte || (*pte & OW_PAGE_PRESENT) == 0) return OW_ERR_NOT_FOUND;
  *pte = 0;
  __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
  return OW_SUCCESS;
}

OW_STATUS OwMemSetUserAccessibleIn(uint64_t pml4, uint64_t va) {
  uint64_t *pte;
  if (!pml4) return OW_ERR_NULL_POINTER;
  if (va & (OW_PAGE_SIZE - 1u)) return OW_ERR_INVALID_PARAM;
  /* Same window confinement as OwMemMapPage: this helper creates a user
   * mapping, so it is exactly as much of a hole as a direct map. */
  if (!OwMemIsUserWindow(va)) return OW_ERR_INVALID_PARAM;
  pte = ow_mem_walk(pml4, va, true, true);
  if (!pte) return OW_ERR_INSUFFICIENT;
  /* If the page was never mapped, materialise it identity first: the caller
   * has told us this address belongs to a user process.  NX is set, because a
   * page created by this path is data by definition -- the one page that must
   * stay executable is mapped explicitly by the caller as code. */
  if ((*pte & OW_PAGE_PRESENT) == 0) {
    *pte = (va & OW_PAGE_ADDR_MASK) | OW_PAGE_USER_RW_NX;
  } else {
    *pte |= OW_PAGE_USER;
  }
  __asm__ volatile("invlpg (%0)" : : "r"(va) : "memory");
  return OW_SUCCESS;
}

/* The software-controllable PTE bits, NX included.  The A/D bits are dropped:
 * the CPU sets them, and a caller comparing them against a VAD would see
 * spurious mismatches. */
#define OW_PTE_SOFTWARE_BITS                                          \
  (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_USER | OW_PAGE_PWT |     \
   OW_PAGE_PCD | OW_PAGE_HUGE | OW_PAGE_GLOBAL | OW_PAGE_NO_EXECUTE)

static OW_STATUS ow_mem_translate(uint64_t pml4, uint64_t va, uint64_t *out_pa,
                                  uint64_t *out_flags) {
  uint64_t *t;
  uint32_t i4, i3, i2, i1;
  uint64_t e;

  if (!pml4) return OW_ERR_NULL_POINTER;
  t = (uint64_t *)(uintptr_t)pml4;
  i4 = (uint32_t)((va >> OW_PML4_SHIFT) & 0x1FFull);
  i3 = (uint32_t)((va >> OW_PDPT_SHIFT) & 0x1FFull);
  i2 = (uint32_t)((va >> OW_PD_SHIFT) & 0x1FFull);
  i1 = (uint32_t)((va >> OW_PT_SHIFT) & 0x1FFull);

  e = t[i4]; if (!(e & OW_PAGE_PRESENT)) return OW_ERR_NOT_FOUND;
  t = (uint64_t *)(uintptr_t)(e & OW_PAGE_ADDR_MASK);
  e = t[i3]; if (!(e & OW_PAGE_PRESENT)) return OW_ERR_NOT_FOUND;
  t = (uint64_t *)(uintptr_t)(e & OW_PAGE_ADDR_MASK);
  e = t[i2]; if (!(e & OW_PAGE_PRESENT)) return OW_ERR_NOT_FOUND;
  /* A huge PDE still resolves: the PA is the aligned 2 MiB base. */
  if (e & OW_PAGE_HUGE) {
    uint64_t pa = (e & OW_PAGE_HUGE_ADDR_MASK) + (va & 0x1FFFFFull);
    if (out_pa) *out_pa = pa;
    if (out_flags) *out_flags = e & OW_PTE_SOFTWARE_BITS;
    return OW_SUCCESS;
  }
  t = (uint64_t *)(uintptr_t)(e & OW_PAGE_ADDR_MASK);
  e = t[i1]; if (!(e & OW_PAGE_PRESENT)) return OW_ERR_NOT_FOUND;
  if (out_pa) *out_pa = (e & OW_PAGE_ADDR_MASK) + (va & (OW_PAGE_SIZE - 1u));
  if (out_flags) *out_flags = e & OW_PTE_SOFTWARE_BITS;
  return OW_SUCCESS;
}

OW_STATUS OwMemTranslate(uint64_t pml4, uint64_t va, uint64_t *out_pa,
                         uint64_t *out_flags) {
  return ow_mem_translate(pml4, va, out_pa, out_flags);
}

bool OwMemVerifyUserPath(uint64_t pml4, uint64_t va) {
  uint64_t *t;
  uint32_t  i4, i3, i2, i1;
  uint32_t  lvl;
  uint32_t  idx[4];
  uint64_t  e;

  if (!pml4) return false;
  t = (uint64_t *)(uintptr_t)pml4;
  i4 = (uint32_t)((va >> OW_PML4_SHIFT) & 0x1FFull);
  i3 = (uint32_t)((va >> OW_PDPT_SHIFT) & 0x1FFull);
  i2 = (uint32_t)((va >> OW_PD_SHIFT) & 0x1FFull);
  i1 = (uint32_t)((va >> OW_PT_SHIFT) & 0x1FFull);
  idx[0] = i4; idx[1] = i3; idx[2] = i2; idx[3] = i1;

  /* Check all FOUR tiers, and check the leaf's U/S too.  A path that stops at
   * the PDE would still pass a mapping whose own PTE lacks U/S, which is the
   * case that turns a legal user page into a permanent fault. */
  for (lvl = 0; lvl < 4u; lvl++) {
    e = t[idx[lvl]];
    if ((e & OW_PAGE_PRESENT) == 0) return false;   /* absent tier */
    if ((e & OW_PAGE_USER) == 0) return false;     /* supervisor tier */
    if (lvl == 3u) return true;                    /* leaf reached, all US */
    if ((e & OW_PAGE_HUGE) != 0) return false;     /* leaf at the wrong tier */
    t = (uint64_t *)(uintptr_t)(e & OW_PAGE_ADDR_MASK);
  }
  return true;
}

/* Guardrail 2/3 audit.  Deliberately a real check over real state rather than
 * a comment: it walks the VAD tree and the page tables together and reports
 * every disagreement with the policy.  Returns the number of violations. */
uint32_t OwMemAuditUserWindow(uint64_t pml4, OW_VAD_NODE *vad_root) {
  OW_VAD_NODE *stack[16];
  uint32_t     violations = 0;
  uint32_t     nodes = 0;
  uint32_t     guards = 0;
  uint32_t     code_pages = 0;
  uint32_t     nx_data_pages = 0;
  uint32_t     sp = 0;

  if (!pml4) return 1u;

  /* Iterative AVL walk: the tree can be deep and this must not risk the
   * kernel stack, which is the same stack a fault handler is already using. */
  if (vad_root) stack[sp++] = vad_root;
  while (sp > 0u) {
    OW_VAD_NODE *n = stack[--sp];
    uint64_t     pa = 0;
    uint64_t     fl = 0;
    bool         present;
    bool         resident;

    if (!n) continue;
    nodes++;

    if (n->EndingAddress < n->StartingAddress) {
      ow_kprintf("[AUDIT] inverted VAD %llX-%llX\r\n",
                 (unsigned long long)n->StartingAddress,
                 (unsigned long long)n->EndingAddress);
      violations++;
    } else if (n->RightChild) stack[sp++] = n->RightChild;
    if (n->LeftChild) stack[sp++] = n->LeftChild;

    /* Every VAD, guard or not, must lie wholly inside the window. */
    if (!OwMemIsUserWindow(n->StartingAddress) ||
        !OwMemIsUserWindow(n->EndingAddress & ~(uint64_t)(OW_PAGE_SIZE - 1u))) {
      ow_kprintf("[AUDIT] VAD %llX-%llX OUTSIDE user window\r\n",
                 (unsigned long long)n->StartingAddress,
                 (unsigned long long)n->EndingAddress);
      violations++;
      continue;
    }

    if ((n->Protection & OW_PAGE_PRESENT) == 0u) {
      /* A declared guard: it must NOT be backed, or it is not a guard. */
      guards++;
      if (ow_mem_translate(pml4, n->StartingAddress, &pa, &fl) == OW_SUCCESS &&
          (fl & OW_PAGE_USER) != 0u) {
        ow_kprintf("[AUDIT] GUARD %llX IS MAPPED -- not a guard!\r\n",
                   (unsigned long long)n->StartingAddress);
        violations++;
      }
      continue;
    }

    if ((n->Protection & OW_PAGE_USER) == 0u) {
      ow_kprintf("[AUDIT] VAD %llX is not user-accessible\r\n",
                 (unsigned long long)n->StartingAddress);
      violations++;
      continue;
    }

    /* "Present" in the page table is NOT the same as "resident for this
     * process".  Splitting the covering 2 MiB huge page leaves 512 supervisor
     * placeholders, so a declared, legal, not-yet-faulted VAD already
     * translates successfully.  Only a leaf that is itself user-accessible is a
     * real mapping; anything else is a placeholder awaiting its first touch and
     * has no permissions to compare against yet. */
    present = (ow_mem_translate(pml4, n->StartingAddress, &pa, &fl) ==
               OW_SUCCESS) &&
              (fl & OW_PAGE_PRESENT) != 0u;
    resident = present && (fl & OW_PAGE_USER) != 0u;
    if (!resident) continue;   /* declared, not materialized: nothing to check */

    /* Guardrail 2: U/S must be set on every tier of a real user path. */
    if (!OwMemVerifyUserPath(pml4, n->StartingAddress)) {
      ow_kprintf("[AUDIT] U/S missing on a tier for VAD %llX\r\n",
                 (unsigned long long)n->StartingAddress);
      violations++;
    }

    /* Guardrail 3: NX policy must match the VAD's intent. */
    {
      bool want_nx = (n->Protection & OW_PAGE_NO_EXECUTE) != 0u;
      bool have_nx = (fl & OW_PAGE_NO_EXECUTE) != 0u;
      if (want_nx != have_nx) {
        ow_kprintf("[AUDIT] NX mismatch at %llX (vad=%u pte=%u)\r\n",
                   (unsigned long long)n->StartingAddress,
                   (unsigned)want_nx, (unsigned)have_nx);
        violations++;
      }
      if (want_nx) nx_data_pages++; else code_pages++;
    }
  }

  ow_kprintf("[AUDIT] user window %llX-%llX: %u VAD(s), %u guard VAD(s), "
             "%u code page(s), %u NX data page(s), NXE=%u, violations=%u\r\n",
             (unsigned long long)OW_USER_WINDOW_BASE,
             (unsigned long long)OW_USER_WINDOW_END,
             (unsigned)nodes, (unsigned)guards, (unsigned)code_pages,
             (unsigned)nx_data_pages, (unsigned)(OwHalMemoryNxEnabled() ? 1u : 0u),
             (unsigned)violations);
  return violations;
}

bool OwMemVerifyMirror(uint64_t a, uint64_t b, uint64_t va) {
  uint64_t pa = 0, pb = 0;
  uint64_t fa = 0, fb = 0;
  if (ow_mem_translate(a, va, &pa, &fa) != OW_SUCCESS) return false;
  if (ow_mem_translate(b, va, &pb, &fb) != OW_SUCCESS) return false;
  /* Compare the permission bits the CPU actually enforces (P/W/US/NX); A/D/G
   * are hardware-scratch and may legitimately differ. */
  return pa == pb &&
         (fa & (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_USER)) ==
         (fb & (OW_PAGE_PRESENT | OW_PAGE_WRITE | OW_PAGE_USER));
}

uint64_t OwMemCreateAddressSpace(void) {
  const uint64_t *boot_pdpt;
  const uint64_t *boot_pd;
  uint64_t *pml4;
  uint64_t *pdpt;
  uint64_t *pd;
  uint32_t i;

  if (!s_BootPml4) s_BootPml4 = mem_read_cr3();
  if (!s_BootPml4) return (uint64_t)0;

  pml4 = (uint64_t *)(uintptr_t)OwMemAllocPageTable();
  if (!pml4) return (uint64_t)0;

  /* Mirror every PML4 slot so nothing the kernel relies on is lost. */
  {
    const uint64_t *src = (const uint64_t *)(uintptr_t)s_BootPml4;
    for (i = 0; i < OW_PAGE_TABLE_ENTRIES; i++) pml4[i] = src[i];
  }

  /* Give slot 0 a private PDPT/PD chain.  pml4[0] is the only populated slot
   * in the boot map, but the loop keeps this correct if that ever changes. */
  if ((pml4[0] & OW_PAGE_PRESENT) == 0) return (uint64_t)0;
  boot_pdpt = (const uint64_t *)(uintptr_t)(pml4[0] & OW_PAGE_ADDR_MASK);
  pdpt = (uint64_t *)(uintptr_t)OwMemAllocPageTable();
  if (!pdpt) return (uint64_t)0;
  for (i = 0; i < OW_PAGE_TABLE_ENTRIES; i++) pdpt[i] = boot_pdpt[i];

  if ((pdpt[0] & OW_PAGE_PRESENT) == 0) return (uint64_t)0;
  boot_pd = (const uint64_t *)(uintptr_t)(pdpt[0] & OW_PAGE_ADDR_MASK);
  pd = (uint64_t *)(uintptr_t)OwMemAllocPageTable();
  if (!pd) return (uint64_t)0;
  /* Copy all 512 PDEs: same physical frames, same permissions, so the whole
   * 1 GiB identity window behaves identically to boot.  Slot 0's PDEs are
   * still huge; the first 4 KiB mapping under this root splits the one it
   * needs, privately. */
  for (i = 0; i < OW_PAGE_TABLE_ENTRIES; i++) pd[i] = boot_pd[i];

  /* Link the private chain with U/S SET on every level.
   *
   * x86-64 checks the user/supervisor bit at EVERY level of the walk, not
   * just the leaf (the rule hal/htl.c relies on).  Copying boot's raw 0x3
   * (P|W, supervisor) onto the new PDPTE/PDE would therefore make a CPL3
   * access fail the U/S test one or two levels above a perfectly good leaf,
   * and the CPU reports that as a *protection violation* even though the leaf
   * is present.
   *
   * Permissive upper levels are safe here precisely because the leaves still
   * gate: kernel PDEs in the private PD are verbatim copies of boot's
   * supervisor huge pages, so no supervisor RAM is handed to CPL3 by raising
   * U/S here. */
  pdpt[0] = (uint64_t)(uintptr_t)pd | OW_PAGE_USER_RW;
  pml4[0] = (uint64_t)(uintptr_t)pdpt | OW_PAGE_USER_RW;

  return (uint64_t)(uintptr_t)pml4;
}
#endif /* OW_HOST_HAL */

OW_STATUS OwMemTranslateActive(uint64_t Va, uint64_t* OutPa, uint64_t* OutFlags) {
  uint64_t pml4 = OwMemGetCurrentPml4();
  if (!pml4) return OW_ERR_NOT_INITIALIZED;
  return OwMemTranslate(pml4, Va, OutPa, OutFlags);
}

void OwMemWalkPml4(uint64_t VirtualAddress) {
  uint16_t pml4_idx = (uint16_t)((VirtualAddress >> 39) & 0x1FF);
  uint16_t pdpt_idx = (uint16_t)((VirtualAddress >> 30) & 0x1FF);
  uint16_t pd_idx = (uint16_t)((VirtualAddress >> 21) & 0x1FF);
  uint16_t pt_idx = (uint16_t)((VirtualAddress >> 12) & 0x1FF);
  uint16_t offset = (uint16_t)(VirtualAddress & 0xFFF);

  ow_kprintf(
      "[PML4-WALK] VA: 0x%llX -> PML4[%u] PDPT[%u] PD[%u] PT[%u] Off[0x%X]\r\n",
      (unsigned long long)VirtualAddress, (unsigned)pml4_idx,
      (unsigned)pdpt_idx, (unsigned)pd_idx, (unsigned)pt_idx, (unsigned)offset);
}

uint32_t OwMemPagesUsed(void) {
  return (uint32_t)(g_RamPointer / OW_PAGE_SIZE);
}

uint32_t OwMemPagesTotal(void) { return (uint32_t)OW_TOTAL_PAGES; }
