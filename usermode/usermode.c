/* usermode.c - Standalone Ring 3 hello-world application.
 *
 * This file hosts simple user-mode applications and is not owinit. The kernel
 * boot path launches the real Essentials owinit.owx process separately; this
 * application is available to an explicit application-launch path only.
 *
 * Host builds keep the launcher as a no-op because they do not establish a
 * real CPL3 address space. */
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_usermode.h"
#include <stdint.h>

#ifdef OW_HOST_HAL

void OwUmLaunchHello(void) {}

#else

/* User layout inside the private pdpt[0] chain (VA 0-1 GiB window).
 *
 * CODE is mapped eagerly into a private frame and is the ONLY executable page
 * the process owns.  SCRATCH and the two stack pages are declared as VADs only,
 * are faulted in on first touch, and carry OW_PAGE_NO_EXECUTE: a stack or data
 * page that can be executed is a page an attacker-supplied pointer can jump to,
 * so execute permission is granted per-page and never by default.
 *
 * GUARD is a band of pages declared with protection 0 immediately below the
 * stack.  One page is not enough to catch a burst: a compiler that spills in a
 * loop, or a red-zone style overrun, can cross a single 4 KiB page between two
 * instructions and land in valid stack memory, so the band is several pages
 * wide to make a miss land inside it.  A declared VAD with no PRESENT bit can
 * never be faulted in (OwPfClassifyUserAddress), so a hit ends the task via
 * OW_PF_GUARD instead of silently succeeding. */
#define OW_USER_HELLO_BASE       0x4000000ULL
#define OW_USER_HELLO_CODE       OW_USER_HELLO_BASE
#define OW_USER_HELLO_STR_OFF    0x200ULL
#define OW_USER_HELLO_SCRATCH    (OW_USER_HELLO_BASE + 0x20000ULL)
#define OW_USER_HELLO_STACK_TOP  (OW_USER_HELLO_BASE + 0x1FF000ULL)
#define OW_USER_HELLO_STACK_LO   (OW_USER_HELLO_STACK_TOP - OW_PAGE_SIZE)
#define OW_USER_HELLO_GUARD_PAGES 4ULL
#define OW_USER_HELLO_GUARD_TOP  (OW_USER_HELLO_STACK_LO - OW_PAGE_SIZE)
#define OW_USER_HELLO_GUARD_BASE (OW_USER_HELLO_GUARD_TOP -            \
                                  OW_USER_HELLO_GUARD_PAGES * OW_PAGE_SIZE)

static const char s_hello[] = "Hello from Ring 3!\r\n";

/* The CPL3 image is assembled at launch instead of being a hand-written byte
 * array.  The addresses below are 28-bit values, and a hand-encoded
 * `mov rcx, imm32` spells them as four little-endian bytes -- an easy thing to
 * get subtly wrong (0x04020000 and 0x4020000 are the same number, and
 * transposing two bytes yields a plausible-looking address in the same 2 MiB
 * window that faults on the first store).  Emitting from the address macros
 * makes the payload impossible to desynchronise from the layout it targets. */
static uint8_t s_code[512];
static uint32_t s_code_len;

static uint8_t* put32(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFFu);
  p[1] = (uint8_t)((v >> 8) & 0xFFu);
  p[2] = (uint8_t)((v >> 16) & 0xFFu);
  p[3] = (uint8_t)((v >> 24) & 0xFFu);
  return p + 4;
}

static uint8_t* emit_mov_eax(uint8_t* p, uint32_t v) {
  *p++ = 0xB8;
  return put32(p, v);
}

static uint8_t* emit_mov_ecx(uint8_t* p, uint32_t v) {
  *p++ = 0xB9;
  return put32(p, v);
}

static uint8_t* emit_mov_rcx32(uint8_t* p, uint32_t v) {
  *p++ = 0x48; *p++ = 0xC7; *p++ = 0xC1;
  return put32(p, v);
}

static uint8_t* emit_mov_rax32(uint8_t* p, uint32_t v) {
  *p++ = 0x48; *p++ = 0xC7; *p++ = 0xC0;
  return put32(p, v);
}

static uint8_t* emit_store_eax(uint8_t* p, uint32_t v) {
  *p++ = 0xC7; *p++ = 0x00;
  return put32(p, v);
}

static uint8_t* um_build_payload(void) {
  uint8_t* p = s_code;
  uint32_t print_str = (uint32_t)(OW_USER_HELLO_CODE + OW_USER_HELLO_STR_OFF);
  uint32_t scratch   = (uint32_t)OW_USER_HELLO_SCRATCH;

  /* Touch the demand-paged user STACK from CPL3.  This has to be done by the
   * user program itself: the iretq frame the switcher builds is written by
   * the CPU while still at CPL0, so it lands in a supervisor page without
   * faulting and proves nothing about demand paging.  These three
   * immediateless instructions are safe to hand-encode. */
  *p++ = 0x50;                               /* push rax            */
  *p++ = 0x48; *p++ = 0x8B; *p++ = 0x04; *p++ = 0x24; /* mov rax,[rsp] */
  *p++ = 0x58;                               /* pop rax             */

  /* Touch the demand-paged SCRATCH VAD from CPL3.  This store is the first
   * instruction to fault: the VAD exists, no mapping does, so the handler
   * charges a private frame, maps it, and this store is retried. */
  p = emit_mov_rax32(p, scratch);
  p = emit_store_eax(p, 0x5Au);

  /* Print the string that lives in the eager code frame. */
  p = emit_mov_eax(p, 0x1Bu);
  p = emit_mov_rcx32(p, print_str);
  *p++ = 0xCD; *p++ = 0x80;

  /* Long CPL3 compute spin with NO syscall and NO cli: only the PIT tick
   * preempting this thread can let the kernel keep making progress.  It also
   * proves the demand-paged page survives a CR3 round trip, because the
   * mapping lives in this process's root and not in any global table. */
  p = emit_mov_ecx(p, 1000000u);
  *p++ = 0xFF; *p++ = 0xC9;                   /* spin: dec ecx */
  *p++ = 0x75; *p++ = 0xFC;                   /*       jnz spin    */

  p = emit_mov_eax(p, 0x1Bu);
  p = emit_mov_rcx32(p, print_str);
  *p++ = 0xCD; *p++ = 0x80;

  p = emit_mov_eax(p, 0x18u);                  /* OW_SYS_PS_SLEEP */
  p = emit_mov_rcx32(p, 8u);
  *p++ = 0xCD; *p++ = 0x80;

  p = emit_mov_eax(p, 0x0Eu);                  /* OW_SYS_PS_EXIT_THREAD */
  *p++ = 0xCD; *p++ = 0x80;

  *p++ = 0xEB; *p++ = 0xFE;                    /* jmp $ : cli/hlt are
                                                   privileged and would #GP */
  s_code_len = (uint32_t)(p - s_code);
  return p;
}

/* Declare a demand-paged VAD: the region is legal, but nothing is mapped yet.
 * This is what makes the address space sparse on purpose -- the whole point of
 * the VAD tree is to describe virtual space that does not have a frame until
 * an instruction actually asks for one. */
static OW_STATUS um_declare_vad(OW_PROCESS_OBJECT* P, uint64_t Start,
                                uint64_t End, uint64_t Prot) {
  OW_VAD_NODE* vad;

  /* Confine the declaration to the one user window at the point it is made, so
   * a VAD can never describe user space outside the window even if a later
   * mapping check were relaxed. */
  if (!OwMemIsUserWindow(Start) ||
      !OwMemIsUserWindow(End & ~(uint64_t)(OW_PAGE_SIZE - 1u))) {
    return OW_ERR_INVALID_PARAM;
  }
  if (End < Start) return OW_ERR_INVALID_PARAM;

  vad = OwMemCreateVad(Start, End, Prot);
  if (!vad) return OW_ERR_INSUFFICIENT;
  return OwMemInsertVad(&P->VadRoot, vad);
}

/* Map the code page EAGERLY into a private frame charged from this process's
 * run, then seed it.
 *
 * Code cannot be demand paged the way data can: there is no backing store to
 * fault it in from, so a zero-filled frame would hand the CPU an instruction
 * fetch full of zeros and turn a page fault into undefined behaviour.  So the
 * one page that must be resident is charged and populated up front -- which
 * still satisfies isolation, because the frame comes from the process's own
 * run and no other process can map it. */
static OW_STATUS um_map_code_page(OW_PROCESS_OBJECT* P) {
  uint64_t     frame = 0;
  OW_STATUS    st;
  OW_VAD_NODE* vad;

  st = OwMemRunCharge(&P->FrameRun, &frame);
  if (ow_status_error(st)) return st;

  /* Charge hands back a zeroed frame; seed payload and string into it. */
  ow_memcpy((void*)(uintptr_t)frame, s_code, s_code_len);
  ow_memcpy((void*)(uintptr_t)(frame + OW_USER_HELLO_STR_OFF), s_hello,
            sizeof(s_hello));

  st = OwMemMapPage(P->Pml4Phys, OW_USER_HELLO_CODE, frame,
                   OW_PAGE_USER_RW);
  if (ow_status_error(st)) {
    (void)OwMemRunRelease(&P->FrameRun, frame);
    return st;
  }

  /* The one VAD in this process that is deliberately executable. */
  vad = OwMemCreateVad(OW_USER_HELLO_CODE,
                       OW_USER_HELLO_CODE + OW_PAGE_SIZE - 1u,
                       OW_PAGE_USER_RW);
  if (!vad) return OW_ERR_INSUFFICIENT;
  vad->FirstFrame = frame;
  return OwMemInsertVad(&P->VadRoot, vad);
}

void OwUmLaunchHello(void) {
    OW_PROCESS_OBJECT* process;

    (void)um_build_payload();

    process = OwPsCreateProcess("user-hello", 0);
    if (!process) {
        ow_kprintf("[USER] hello process creation FAILED\r\n");
        return;
    }
    if (!process->Pml4Phys || process->FrameRun.Base == 0) {
        ow_kprintf("[USER] no address space or frame run for this process\r\n");
        return;
    }

    /* Resident: the code page, in a private frame from this process's run. */
    if (ow_status_error(um_map_code_page(process))) {
        ow_kprintf("[USER] code page mapping FAILED\r\n");
        return;
    }

    /* Demand-paged: declared, not mapped.  SCRATCH is written by the payload
     * itself; the two stack pages are first touched by the iretq that enters
     * CPL3, so the very act of resuming the thread faults its own stack in.
     *
     * All three carry OW_PAGE_NO_EXECUTE.  The data/execute split is
     * per-VAD, so a future heap or scratch VAD is NX unless it explicitly asks
     * not to be -- the safe direction is the default one. */
    if (ow_status_error(um_declare_vad(process, OW_USER_HELLO_SCRATCH,
                                       OW_USER_HELLO_SCRATCH + OW_PAGE_SIZE - 1u,
                                       OW_PAGE_USER_RW_NX)) ||
        ow_status_error(um_declare_vad(process, OW_USER_HELLO_STACK_LO,
                                       OW_USER_HELLO_STACK_LO + OW_PAGE_SIZE - 1u,
                                       OW_PAGE_USER_RW_NX)) ||
        ow_status_error(um_declare_vad(process, OW_USER_HELLO_STACK_TOP,
                                       OW_USER_HELLO_STACK_TOP + OW_PAGE_SIZE - 1u,
                                       OW_PAGE_USER_RW_NX))) {
        ow_kprintf("[USER] demand-paged VAD declaration FAILED\r\n");
        return;
    }

    /* The guard band: declared with no PRESENT bit, so it is present in the
     * tree and permanently unbackable.  A range VAD is used rather than one
     * node per page so the band cannot be widened by a page-granularity slip
     * in the declaration itself. */
    if (ow_status_error(um_declare_vad(process, OW_USER_HELLO_GUARD_BASE,
                                       OW_USER_HELLO_GUARD_TOP, 0u))) {
        ow_kprintf("[USER] guard VAD declaration FAILED\r\n");
        return;
    }

    if (!OwPsCreateUserThread(process, OW_USER_HELLO_CODE,
                              OW_USER_HELLO_STACK_TOP)) {
        ow_kprintf("[USER] hello thread creation FAILED\r\n");
        return;
    }

    /* Prove the policy instead of asserting it in a comment.  At this point the
     * code page is resident and the data/guard VADs are declared, so the audit
     * can check: every VAD is inside the window, the guard band is unbacked,
     * U/S is set on all four tiers of the code path, and the resident code page
     * is the only executable mapping.  Violations are counted and logged, never
     * silently ignored -- a guardrail that cannot fail cannot be trusted. */
    if (OwMemAuditUserWindow(process->Pml4Phys, process->VadRoot) != 0u) {
        ow_kprintf("[USER] USER WINDOW AUDIT FAILED\r\n");
    }
    ow_kprintf("[USER] standalone Ring 3 hello application queued\r\n");
}

#endif /* OW_HOST_HAL */