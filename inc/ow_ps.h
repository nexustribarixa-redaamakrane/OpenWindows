/* ow_ps.h - NT-like Process / Thread subsystem + Round-Robin Scheduler
 *
 * Non-POSIX, zero-allocation design: static tables sized at compile time.
 * All code runs in Ring 0 for now; Ring 3 user-mode separation is deferred.
 * The scheduler is a simple round-robin with configurable quantum (ticks).
 * Preemption is provided by the PIT IRQ0 tick (100 Hz); cooperative yield
 * is available via OwPsYield() and the OW_SYS_PS_YIELD system call.
 *
 * Processes are NT-inspired "executive objects" with a Name, ProcessId,
 * VadRoot (virtual address-space bookkeeping), exit status and a thread
 * list.  Threads are kernel-mode "executive threads" with their own
 * saved context (Rip/Rsp/callee-saved), kernel stack, entry function
 * and timeslice.
 *
 * C99 freestanding.  No dynamic heap allocation.  */
#ifndef OW_PS_H
#define OW_PS_H

#include "ow_types.h"
#include "ow_object.h"
#include "ow_memory.h"

/* ---- Compile-time limits ------------------------------------------------ */
#define OW_PS_MAX_PROCESSES     64U
#define OW_PS_MAX_THREADS       256U
#define OW_PS_KERNEL_STACK      (16U * 1024U)  /* 16 KiB per thread */
#define OW_PS_DEFAULT_QUANTUM   10U            /* 100 ms at 100 Hz tick */

#define OW_PS_PID_KERNEL        0U
#define OW_PS_PID_INIT          1U
#define OW_PS_TID_SYSTEM        0U

/* ---- Process / thread states (NT-flavored, non-POSIX) ------------------- */
typedef enum _OW_PROCESS_STATE {
    OW_PS_PROC_CREATED = 0,
    OW_PS_PROC_RUNNING,
    OW_PS_PROC_TERMINATED
} OW_PROCESS_STATE;

typedef enum _OW_THREAD_STATE {
    OW_THR_DORMANT = 0,
    OW_THR_READY,
    OW_THR_RUNNING,
    OW_THR_BLOCKED,
    OW_THR_TERMINATED
} OW_THREAD_STATE;

/* ---- Thread register context ----------------------------------------------
 * Every thread's resume point is stored as a full ISR-style frame mirror
 * (identical layout to ow_hal_frame_t's interesting fields) plus an explicit
 * ResumeRsp so iretq can land anywhere (cold threads go straight to their
 * kernel stack).  All switching is funneled through this one structure.
 *
 *   +0x00 ResumeRsp          (desired RSP right after iretq restores us)
 *   +0x08 Frame[RAX..R15]    (15 GP registers, 8 bytes each: +0x08..+0x78)
 *   +0x80 vector             (always 0)
 *   +0x88 error_code         (always 0)
 *   +0x90 rip                (resume RIP)
 *   +0x98 cs                 (kernel code selector 0x08)
 *   +0xA0 rflags             (IF kept set so resumed threads stay preemptable)
 *   +0xA8 rsp (unused by ring0 resume), +0xB0 ss (unused)
 *   -> total 184 bytes                                                       */
#define OW_THREAD_FRAME_GPS   15U
typedef struct _OW_THREAD_CONTEXT {
    uint64_t ResumeRsp;                              /* +0x00 */
    uint64_t Gpr[OW_THREAD_FRAME_GPS];               /* +0x08 rax..r15 */
    uint64_t Vector;                                 /* +0x80 */
    uint64_t ErrorCode;                              /* +0x88 */
    uint64_t Rip;                                    /* +0x90 */
    uint64_t Cs;                                     /* +0x98 */
    uint64_t Rflags;                                 /* +0xA0 */
    uint64_t RspSlot;                                /* +0xA8 (unused) */
    uint64_t SsSlot;                                 /* +0xB0 (unused) */
} OW_THREAD_CONTEXT;                                 /* 184 bytes */

/* ---- Forward declarations ----------------------------------------------- */
#ifndef OW_PROCESS_TYPEDEF_DEFINED
#define OW_PROCESS_TYPEDEF_DEFINED
typedef struct _OW_PROCESS_OBJECT OW_PROCESS_OBJECT;
#endif
typedef struct _OW_THREAD_OBJECT  OW_THREAD_OBJECT;
struct _OW_DISPATCHER_OBJECT;                /* defined in ow_sync.h */

/* ---- Thread Object (ETHREAD-like) --------------------------------------- */
struct _OW_THREAD_OBJECT {
    OW_OBJECT_HEADER    Header;
    uint32_t            Tid;
    uint32_t            ProcessId;
    OW_THREAD_STATE     State;
    OW_THREAD_CONTEXT   Context;
    uint64_t            StackBase;
    uint64_t            StackSize;
    uint64_t            EntryFunction;
    uint64_t            EntryArg;
    uint32_t            Quantum;
    OW_THREAD_OBJECT*   NextReady;

    /* Dispatcher-wait linkage (see ow_sync.h / sync/ow_sync.c). */
    struct _OW_DISPATCHER_OBJECT* WaitObject; /* object this thread blocks on */
    OW_THREAD_OBJECT*   NextWait;             /* next waiter in object's list */
    uint64_t            WaitTimeout;          /* absolute tick (0 = infinite) */
};

/* ---- Process Object (EPROCESS-like) ------------------------------------- */
struct _OW_PROCESS_OBJECT {
    OW_OBJECT_HEADER    Header;
    uint32_t            ProcessId;
    OW_PROCESS_STATE    State;
    uint32_t            ParentProcessId;
    uint64_t            ExitStatus;
    uint64_t            EntryPoint;      /* Loaded image entry (nonzero for valid owinit) */
    uint64_t            Pml4Phys;        /* Per-process CR3 root (VA==PA); 0 = use boot root */
    OW_VAD_NODE*        VadRoot;
    /* Private, exclusively owned physical frames for this process.  Demand
     * paging charges 4 KiB frames out of this run, which is what makes a
     * user page a real private page instead of an alias of the boot identity
     * map.  Unreserved (Base == 0) on host builds. */
    OW_FRAME_RUN        FrameRun;
    uint32_t            ThreadCount;
    uint32_t            PrimaryThreadId;

    /* ---- Per-process user-space state (no global counterpart) -------------
     * These used to be kernel globals in the syscall dispatcher, which meant
     * two processes shared one VAD tree and one heap cursor.  They are per
     * process precisely so a CPL3 request can only ever reach the address
     * space of the process that made it. */
    uint64_t            UserBrk;        /* next free user heap byte       */
    uint64_t            UserStackTop;   /* top of this process's user stack */
    uint64_t            EntryReturn;    /* C-ABI return address for the image entry */
};

/* ---- API ---------------------------------------------------------------- */

/* Boot-time init: clears tables, builds idle process/thread 0 (the current
 * boot context).  Does NOT start the timer IRQ; call OwPsStartScheduler()
 * after OwPsInitialize() + OwPsCaptureBootContext(). */
OW_STATUS    OwPsInitialize(void);
void          OwPsStartScheduler(void);

/* Called once from _start() after OwPsInitialize() to snapshot the current
 * CPU context into Thread 0 (the system/shell thread) so that if the
 * scheduler later switches away, it can switch back here. */
void          OwPsCaptureBootContext(void);

/* Process / Thread management */
OW_PROCESS_OBJECT* OwPsCreateProcess(const char* Name, uint32_t ParentPid);
OW_THREAD_OBJECT*  OwPsCreateThread(OW_PROCESS_OBJECT* Proc,
                                    uint64_t EntryFunction,
                                    uint64_t EntryArg);
OW_THREAD_OBJECT*  OwPsCreateUserThread(OW_PROCESS_OBJECT* Proc,
                                        uint64_t EntryAddress,
                                        uint64_t UserStackTop);

/* Variant that seeds a C-ABI landing frame.  ResumeRsp is the stack pointer the
 * thread holds once iretq retires; ow_ps_resume_thread builds the 5-word
 * [rip][cs][rflags][rsp][ss] operand itself at ResumeRsp-40, so nothing is
 * pre-written into user memory here.  ReturnAddress, when non-zero, must
 * already sit at [ResumeRsp] so a `ret` out of the image entry lands on a real
 * target: a loaded executable that returns from its entry point must land
 * somewhere defined, or the process jumps into garbage. */
OW_THREAD_OBJECT*  OwPsCreateUserThreadFrame(OW_PROCESS_OBJECT* Proc,
                                             uint64_t EntryAddress,
                                             uint64_t ResumeRsp,
                                             uint64_t ReturnAddress);

/* Bring a loaded image to CPL3: declares/maps this process's stack and guard
 * band, writes the initial return address, and enqueues the entry thread. */
OW_STATUS    OwPsLaunchUserImage(OW_PROCESS_OBJECT* Proc);

void          OwPsExitThread(uint64_t ExitStatus);
void          OwPsTerminateProcess(OW_PROCESS_OBJECT* Proc, uint64_t ExitStatus);

/* OWX image loader: parses a raw OWX1 buffer and maps its sections into the
 * process's OWN address space inside the guarded user window.  Every page is
 * charged from the process's private frame run -- there is no shared exec
 * arena any more -- code lands executable and every data section lands
 * execute-disabled.  On success Proc->EntryPoint is a user-window virtual
 * address ready for OwPsLaunchUserImage. */
OW_STATUS    OwPsLoadImage(OW_PROCESS_OBJECT* Proc,
                           const uint8_t* OwxBuffer,
                           uint32_t OwxSize);

/* Scheduler.  Frame is a pointer to the ISR frame (ow_hal_frame_t*) cast to
 * void* to avoid pulling in hal/idt.h into this public header. */
void          OwPsYield(void);
void          OwPsSchedulerTick(void* Frame);
void          OwPsScheduleNext(void);     /* block current thread, run next */
void          OwPsWakeThread(OW_THREAD_OBJECT* Thr);
OW_THREAD_OBJECT* OwPsGetCurrentThread(void);
OW_THREAD_OBJECT* OwPsGetThreadByIndex(uint32_t Index);
OW_PROCESS_OBJECT* OwPsGetProcessById(uint32_t ProcessId);
uint32_t      OwPsGetTickCount(void);

/* ---- Assembly primitives (ps/switch.S) ---------------------------------- */
void          ow_ps_capture_frame(OW_THREAD_CONTEXT* Dst);
void          ow_ps_resume_thread(OW_THREAD_CONTEXT* Ctx);
void          ow_ps_switch(OW_THREAD_CONTEXT* Old, OW_THREAD_CONTEXT* New);
void          ow_ps_cold_thread_entry(void);  /* Noreturn trampoline */

/* Internal C entry for cold threads (called from ow_ps_cold_thread_entry). */
void          OwPsThreadBootstrap(struct _OW_THREAD_OBJECT* Thread);

#endif /* OW_PS_H */
