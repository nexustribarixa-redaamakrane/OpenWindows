/* ps.c - NT-like Process / Thread subsystem + Round-Robin Scheduler
 *
 * Non-POSIX, zero-allocation design: all tables and stacks are static.
 * The scheduler is a simple round-robin with configurable quantum (ticks).
 * Preemption is provided by the PIT IRQ0 tick (100 Hz); cooperative yield
 * is available via OwPsYield() and the OW_SYS_PS_YIELD system call.
 *
 * C99 freestanding.  No dynamic heap allocation.  */
#include "../inc/ow_ps.h"
#include "../inc/ow_sync.h"
#include "../inc/ow_dpc.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_io.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_diag.h"
#include "../hal/idt.h"

/* ---- Static tables ---------------------------------------------------- */
static OW_PROCESS_OBJECT s_Procs[OW_PS_MAX_PROCESSES];
static OW_THREAD_OBJECT  s_Threads[OW_PS_MAX_THREADS];

/* Per-thread kernel stacks (16 KiB each, 16-byte aligned).
 * 256 * 16 KiB = 4 MiB in BSS.  */
static uint8_t s_StackPool[OW_PS_MAX_THREADS][OW_PS_KERNEL_STACK]
    __attribute__((aligned(4096)));

/* ---- Scheduler state -------------------------------------------------- */
static OW_THREAD_OBJECT*  s_CurrentThread;
static OW_THREAD_OBJECT*  s_ReadyHead;
static OW_THREAD_OBJECT*  s_ReadyTail;
static uint32_t           s_TickCount;
static uint32_t           s_NextTid = 1;   /* TID 0 = system thread */
static uint32_t           s_NextPid  = OW_PS_PID_INIT; /* PID 0 = kernel, PID 1 = owinit */

/* ---- Ready queue (intrusive singly-linked via NextReady) -------------- */
static void ready_enqueue(OW_THREAD_OBJECT* Thr) {
    Thr->NextReady = (void*)0;
    if (!s_ReadyTail) {
        s_ReadyHead = Thr;
        s_ReadyTail = Thr;
    } else {
        s_ReadyTail->NextReady = Thr;
        s_ReadyTail = Thr;
    }
}

static OW_THREAD_OBJECT* ready_dequeue(void) {
    OW_THREAD_OBJECT* Thr = s_ReadyHead;
    if (!Thr) return (void*)0;
    s_ReadyHead = Thr->NextReady;
    if (!s_ReadyHead) s_ReadyTail = (void*)0;
    Thr->NextReady = (void*)0;
    return Thr;
}

/* ---- ISR-frame -> context copy ---------------------------------------- */
static void OwPsFrameToContext(void* Frame, OW_THREAD_CONTEXT* Ctx) {
    const ow_hal_frame_t* f = (const ow_hal_frame_t*)Frame;
    Ctx->Gpr[0]  = f->Rax;
    Ctx->Gpr[1]  = f->Rcx;
    Ctx->Gpr[2]  = f->Rdx;
    Ctx->Gpr[3]  = f->Rsi;
    Ctx->Gpr[4]  = f->Rdi;
    Ctx->Gpr[5]  = f->R8;
    Ctx->Gpr[6]  = f->R9;
    Ctx->Gpr[7]  = f->R10;
    Ctx->Gpr[8]  = f->R11;
    Ctx->Gpr[9]  = f->Rbp;
    Ctx->Gpr[10] = f->Rbx;
    Ctx->Gpr[11] = f->R12;
    Ctx->Gpr[12] = f->R13;
    Ctx->Gpr[13] = f->R14;
    Ctx->Gpr[14] = f->R15;
    Ctx->Rip     = f->Rip;
    Ctx->Cs      = f->Cs;
    Ctx->Rflags  = f->Rflags | 0x200u;  /* force IF on */
    Ctx->Vector     = 0;
    Ctx->ErrorCode  = 0;
    Ctx->ResumeRsp = f->Rsp;
    if ((f->Cs & 0xFFF8u) == 0x18u) {
        /* User-mode capture: the hardware pushed the CPL3 frame onto the
         * kernel stack (f->Rsp); resume must land back on that user stack
         * with the user data selector (RPL3 stamped on selectors so iretq
         * re-enters ring 3). */
        Ctx->SsSlot    = f->Ss ? f->Ss : 0x23u;
    } else {
        /* Kernel-mode capture: ResumeRsp points back into the interrupted
         * thread's kernel stack (f->Rsp). */
        Ctx->SsSlot    = 0x10u;
    }
    Ctx->RspSlot = 0;
}

/* ---- Internal: cold-thread context init --------------------------------
 * Sets up a brand-new thread context so that ow_ps_resume_thread will
 * jump to ow_ps_cold_thread_entry on the thread's kernel stack.         */
static void OwPsInitColdContext(OW_THREAD_OBJECT* Thr) {
    OW_THREAD_CONTEXT* C = &Thr->Context;
    uint64_t stack_top = Thr->StackBase + Thr->StackSize;

    ow_memset(C, 0, sizeof(*C));

    /* ResumeRsp: top of kernel stack minus 8 for ABI alignment.
     * After iretq, RSP = ResumeRsp.  The cold entry does "call" which
     * pushes 8 bytes, so RSP needs to be 8-above a 16-byte boundary. */
    C->ResumeRsp = stack_top - 8u;

    /* Rip = cold trampoline. */
    C->Rip = (uint64_t)(uintptr_t)ow_ps_cold_thread_entry;
    C->Cs  = 0x08u;
    C->SsSlot = 0x10u;
    C->Rflags = 0x202u;  /* IF set */

    /* Gpr[11] = R12 = thread object pointer (cold entry passes it as
     * first C argument via r12 -> rdi). */
    C->Gpr[11] = (uint64_t)(uintptr_t)Thr;
}

/* ====================================================================== */
/* OwPsInitialize - clear tables, build idle process/thread 0             */
/* ====================================================================== */
OW_STATUS OwPsInitialize(void) {
    ow_memset(s_Procs,   0, sizeof(s_Procs));
    ow_memset(s_Threads, 0, sizeof(s_Threads));

    s_CurrentThread = (void*)0;
    s_ReadyHead     = (void*)0;
    s_ReadyTail     = (void*)0;
    s_TickCount     = 0;
    s_NextTid       = 1;
    /* PID 0 = kernel, PID 1 reserved for owinit (the first process
     * created after the subsystem comes up), then 2, 3, ... */
    s_NextPid       = OW_PS_PID_INIT;

    /* Process 0: kernel (boot context). */
    {
        OW_PROCESS_OBJECT* P = &s_Procs[0];
        P->ProcessId      = OW_PS_PID_KERNEL;
        P->State          = OW_PS_PROC_RUNNING;
        P->ParentProcessId= OW_PS_PID_KERNEL;
        P->ExitStatus     = 0;
        P->EntryPoint     = 0;
        P->VadRoot        = (void*)0;
        P->ThreadCount    = 1;
        P->PrimaryThreadId= OW_PS_TID_SYSTEM;
        ow_memcpy(P->Header.Name, "Kernel", 7);
    }

    /* Thread 0: system / shell thread (boot context). */
    {
        OW_THREAD_OBJECT* T = &s_Threads[0];
        T->Tid          = OW_PS_TID_SYSTEM;
        T->ProcessId    = OW_PS_PID_KERNEL;
        T->State        = OW_THR_RUNNING;
        T->StackBase    = 0;
        T->StackSize    = 0;
        T->EntryFunction= 0;
        T->EntryArg     = 0;
        T->Quantum      = OW_PS_DEFAULT_QUANTUM;
        T->NextReady    = (void*)0;
        ow_memcpy(T->Header.Name, "System", 7);
        s_CurrentThread = T;
    }

    /* Zero the stack pool (it's in BSS, but be explicit). */
    ow_memset(s_StackPool, 0, sizeof(s_StackPool));

    OwDiagLogFinished("PS Init", OW_C_PS_READY);
    ow_kprintf("[PS] process/thread subsystem initialized (max %u procs, %u threads)\r\n",
               (unsigned)OW_PS_MAX_PROCESSES, (unsigned)OW_PS_MAX_THREADS);
    return OW_SUCCESS;
}

/* ====================================================================== */
/* OwPsCaptureBootContext - snapshot current CPU state into Thread 0      */
/* ====================================================================== */
void OwPsCaptureBootContext(void) {
    OW_THREAD_OBJECT* T = &s_Threads[0];
    ow_ps_capture_frame(&T->Context);
    ow_kprintf("[PS] boot context captured (thread 0)\r\n");
}

/* ====================================================================== */
/* OwPsStartScheduler - unmask PIC IRQ0, arm PIT, enable interrupts      */
/* ====================================================================== */
void OwPsStartScheduler(void) {
#ifndef OW_HOST_HAL
    /* Remap the 8259 PIC so IRQ0-7 -> vectors 0x20-0x27 and IRQ8-15 ->
     * 0x28-0x2F (nothing in the kernel did this yet; without it IRQ0 would
     * collide with CPU exception vectors). Standard ICW1..ICW4 sequence. */
    ow_outb(0x20u, 0x11u);            /* ICW1: init, expect ICW4 */
    ow_outb(0xA0u, 0x11u);
    ow_outb(0x21u, 0x20u);            /* ICW2: master base 0x20 */
    ow_outb(0xA1u, 0x28u);            /* ICW2: slave base 0x28  */
    ow_outb(0x21u, 0x04u);            /* ICW3: slave on IRQ2    */
    ow_outb(0xA1u, 0x02u);            /* ICW3: slave identity   */
    ow_outb(0x21u, 0x01u);            /* ICW4: 8086 mode        */
    ow_outb(0xA1u, 0x01u);

    /* Unmask IRQ0 (timer) in the 8259 PIC master, mask everything else. */
    ow_outb(0x21u, 0xFEu);
    ow_outb(0xA1u, 0xFFu);

    /* Arm PIT channel 0: mode 3 (square wave), lobyte/hibyte.
     * Divisor = 1193180 / 100 = 11931  -> 100 Hz tick. */
    ow_outb(0x43u, 0x36u);            /* ch0, lobyte/hibyte, mode 3 */
    ow_outb(0x40u, (uint8_t)(11931u & 0xFFu));
    ow_outb(0x40u, (uint8_t)(11931u >> 8));

    /* Enable interrupts - the PIT will start firing immediately. */
    ow_sti();
#endif

    OwDiagLogFinished("PS Scheduler", OW_C_PS_SCHEDULER_RUNNING);
    ow_kprintf("[PS] scheduler started (100 Hz)\r\n");
}

/* ====================================================================== */
/* OwPsCreateProcess - allocate a process slot, set up header             */
/* ====================================================================== */
OW_PROCESS_OBJECT* OwPsCreateProcess(const char* Name, uint32_t ParentPid) {
    uint32_t i;
    OW_PROCESS_OBJECT* P = (void*)0;

    for (i = 0; i < OW_PS_MAX_PROCESSES; i++) {
        if (s_Procs[i].ProcessId == 0 && s_Procs[i].State == OW_PS_PROC_CREATED) {
            P = &s_Procs[i];
            break;
        }
    }
    if (!P) {
        ow_kprintf("[PS] process table full\r\n");
        return (void*)0;
    }

    P->ProcessId      = s_NextPid++;
    P->State          = OW_PS_PROC_CREATED;
    P->ParentProcessId= ParentPid;
    P->ExitStatus     = 0;
    P->EntryPoint     = 0;
    P->VadRoot        = (void*)0;
    P->ThreadCount    = 0;
    P->PrimaryThreadId= 0;

    if (Name) {
        uint32_t len = 0;
        while (Name[len] && len < OW_MAX_NAME - 1) { len++; }
        ow_memcpy(P->Header.Name, Name, len);
        P->Header.Name[len] = '\0';
    }

    ow_kprintf("[PS] %s: process created (PID %u)\r\n",
               Name ? Name : "?", (unsigned)P->ProcessId);
    return P;
}

/* ====================================================================== */
/* OwPsCreateThread - allocate a thread slot, set up cold context         */
/* ====================================================================== */
OW_THREAD_OBJECT* OwPsCreateThread(OW_PROCESS_OBJECT* Proc,
                                   uint64_t EntryFunction,
                                   uint64_t EntryArg) {
    uint32_t i;
    OW_THREAD_OBJECT* T = (void*)0;

    if (!Proc) return (void*)0;

    for (i = 0; i < OW_PS_MAX_THREADS; i++) {
        if (s_Threads[i].Tid == 0 && s_Threads[i].State == OW_THR_DORMANT) {
            T = &s_Threads[i];
            break;
        }
    }
    if (!T) {
        ow_kprintf("[PS] thread table full\r\n");
        return (void*)0;
    }

    T->Tid           = s_NextTid++;
    T->ProcessId     = Proc->ProcessId;
    T->State         = OW_THR_READY;
    T->EntryFunction = EntryFunction;
    T->EntryArg      = EntryArg;
    T->Quantum       = OW_PS_DEFAULT_QUANTUM;
    T->NextReady     = (void*)0;

    /* Assign kernel stack from the static pool. */
    T->StackBase = (uint64_t)(uintptr_t)&s_StackPool[i][0];
    T->StackSize = OW_PS_KERNEL_STACK;

    /* Build the cold-thread context so ow_ps_resume_thread will land at
     * ow_ps_cold_thread_entry on the thread's own kernel stack. */
    OwPsInitColdContext(T);

    if (Proc->ThreadCount == 0) {
        Proc->PrimaryThreadId = T->Tid;
    }
    Proc->ThreadCount++;

    /* Name the thread object. */
    {
        uint32_t nlen = 0;
        const char* pname = Proc->Header.Name;
        while (pname && pname[nlen] && nlen < OW_MAX_NAME - 8) { nlen++; }
        ow_memcpy(T->Header.Name, pname ? pname : "?", nlen);
        T->Header.Name[nlen] = 'T';
        /* Append TID as a simple decimal (max 5 digits). */
        {
            uint32_t v = T->Tid;
            char digits[6];
            int d = 0, j;
            do { digits[d++] = '0' + (char)(v % 10u); v /= 10u; } while (v > 0 && d < 6);
            for (j = 0; j < d; j++) T->Header.Name[nlen + 1 + j] = digits[d - 1 - j];
            T->Header.Name[nlen + 1 + (uint32_t)d] = '\0';
        }
    }

    /* Enqueue into the ready queue so the scheduler picks it up. */
    ready_enqueue(T);

    ow_kprintf("[PS] %s: thread %u created, entry 0x%llX\r\n",
               Proc->Header.Name, (unsigned)T->Tid,
               (unsigned long long)EntryFunction);
    return T;
}

/* ---- Resume precondition ------------------------------------------------
 * Before the CPU iretq's a user-mode thread into CPL3, point TSS.RSP0 at
 * that thread's kernel stack so its next trap (syscall or IRQ) lands on a
 * clean stack.  Kernel-mode resumes don't cross privilege levels and must
 * NOT touch RSP0. */
static void OwPsPrepResume(OW_THREAD_OBJECT* Thr) {
    if (!Thr) return;
    if ((Thr->Context.Cs & 0xFFF8u) == 0x18u) {
#ifndef OW_HOST_HAL
        OwHalTssSetRsp0(Thr->StackBase + Thr->StackSize);
#endif
    }
}

/* ====================================================================== */
/* OwPsCreateUserThread - allocate a thread slot whose cold context boots  */
/* DIRECTLY into Ring 3 at EntryAddress with a user-mode stack.            */
/* ====================================================================== */
OW_THREAD_OBJECT* OwPsCreateUserThread(OW_PROCESS_OBJECT* Proc,
                                       uint64_t EntryAddress,
                                       uint64_t UserStackTop) {
#ifdef OW_HOST_HAL
    /* The host harness is a normal ring-3 process; no CPL3 machinery. */
    (void)Proc; (void)EntryAddress; (void)UserStackTop;
    return (OW_THREAD_OBJECT*)0;
#else
    uint32_t i;
    OW_THREAD_OBJECT* T = (void*)0;

    if (!Proc) return (void*)0;

    for (i = 0; i < OW_PS_MAX_THREADS; i++) {
        if (s_Threads[i].Tid == 0 && s_Threads[i].State == OW_THR_DORMANT) {
            T = &s_Threads[i];
            break;
        }
    }
    if (!T) {
        ow_kprintf("[PS] thread table full\r\n");
        return (void*)0;
    }

    T->Tid           = s_NextTid++;
    T->ProcessId     = Proc->ProcessId;
    T->State         = OW_THR_READY;
    T->EntryFunction = EntryAddress;
    T->EntryArg      = UserStackTop;
    T->Quantum       = OW_PS_DEFAULT_QUANTUM;
    T->NextReady     = (void*)0;

    T->StackBase = (uint64_t)(uintptr_t)&s_StackPool[i][0];
    T->StackSize = OW_PS_KERNEL_STACK;

    /* No cold trampoline: the very first resume iretq's straight into the
     * user program.  Context is pre-stamped for CPL3. */
    ow_memset(&T->Context, 0, sizeof(T->Context));
    T->Context.ResumeRsp = UserStackTop;   /* where the 5-word iretq frame goes */
    T->Context.Rip       = EntryAddress;
    T->Context.Cs        = 0x1Bu;          /* user code  (DPL3, RPL3) */
    T->Context.SsSlot    = 0x23u;          /* user data  (DPL3, RPL3) */
    T->Context.Rflags    = 0x202u;         /* IF on: user thread is preemptable */

    if (Proc->ThreadCount == 0) {
        Proc->PrimaryThreadId = T->Tid;
    }
    Proc->ThreadCount++;

    {
        uint32_t nlen = 0;
        const char* pname = Proc->Header.Name;
        while (pname && pname[nlen] && nlen < OW_MAX_NAME - 8) { nlen++; }
        ow_memcpy(T->Header.Name, pname ? pname : "?", nlen);
        T->Header.Name[nlen] = 'T';
        {
            uint32_t v = T->Tid;
            char digits[6];
            int d = 0, j;
            do { digits[d++] = '0' + (char)(v % 10u); v /= 10u; } while (v > 0 && d < 6);
            for (j = 0; j < d; j++) T->Header.Name[nlen + 1 + j] = digits[d - 1 - j];
            T->Header.Name[nlen + 1 + (uint32_t)d] = '\0';
        }
    }

    ready_enqueue(T);

    ow_kprintf("[PS] %s: USER thread %u created, ring3 entry 0x%llX stack 0x%llX\r\n",
               Proc->Header.Name, (unsigned)T->Tid,
               (unsigned long long)EntryAddress,
               (unsigned long long)UserStackTop);
    return T;
#endif
}

/* ====================================================================== */
/* OwPsExitThread - terminate current thread, resume next or halt         */
/* ====================================================================== */
void OwPsExitThread(uint64_t ExitStatus) {
    OW_THREAD_OBJECT* cur;
    OW_THREAD_OBJECT* next;

    /* FIX: make the entire terminate+switch critical section atomic against
     * the preemption tick.  While IF=1, a tick whose quantum slice has just
     * expired could preempt the dying thread here, capture the exit code as
     * if it were a live preemption, and re-queue this terminated thread. */
    ow_cli();

    cur = s_CurrentThread;
    if (!cur) {
        ow_kprintf("[PS] exit: no current thread\r\n");
        ow_hlt_loop();
    }

    (void)ExitStatus;
    cur->State = OW_THR_TERMINATED;
    ow_kprintf("[EX] tid=%u\r\n", (unsigned)cur->Tid);

    /* Abandon any mutexes this thread still owns (NT mutant semantics:
     * waiters wake with OW_WAIT_ABANDONED). */
    KeOnThreadExit(cur);

    /* Decrement the owning process' thread count. */
    {
        uint32_t i;
        for (i = 0; i < OW_PS_MAX_PROCESSES; i++) {
            if (s_Procs[i].ProcessId == cur->ProcessId) {
                if (s_Procs[i].ThreadCount > 0)
                    s_Procs[i].ThreadCount--;
                break;
            }
        }
    }

    next = ready_dequeue();
    if (next) {
        s_CurrentThread = next;
        next->State = OW_THR_RUNNING;
        next->Quantum = OW_PS_DEFAULT_QUANTUM;
        OwPsPrepResume(next);
        ow_ps_resume_thread(&next->Context);
        /* Never returns. */
    }

    /* No ready threads left. */
    ow_kprintf("[PS] last thread terminated, halting\r\n");
    ow_hlt_loop();
}

/* ====================================================================== */
/* OwPsTerminateProcess - mark process terminated (MVP: just log)         */
/* ====================================================================== */
void OwPsTerminateProcess(OW_PROCESS_OBJECT* Proc, uint64_t ExitStatus) {
    if (!Proc) return;
    Proc->State = OW_PS_PROC_TERMINATED;
    Proc->ExitStatus = ExitStatus;
    ow_kprintf("[PS] %s: process terminated (PID %u, exit %llu)\r\n",
               Proc->Header.Name, (unsigned)Proc->ProcessId,
               (unsigned long long)ExitStatus);
}

/* ====================================================================== */
/* OwPsYield - cooperative yield to next ready thread                     */
/* ====================================================================== */
void OwPsYield(void) {
    OW_THREAD_OBJECT* cur = s_CurrentThread;
    OW_THREAD_OBJECT* next;

    if (!cur) return;

    /* Peek at the head of the ready queue. */
    next = s_ReadyHead;
    if (!next || next == cur) return;

    /* Pull the next thread out of the queue, then re-queue ourselves. */
    (void)ready_dequeue();

    cur->State = OW_THR_READY;
    ready_enqueue(cur);

    s_CurrentThread = next;
    next->State = OW_THR_RUNNING;
    next->Quantum = OW_PS_DEFAULT_QUANTUM;

    OwPsPrepResume(next);
    ow_ps_switch(&cur->Context, &next->Context);
    /* Returns here when this thread is later resumed. */
    cur->Quantum = OW_PS_DEFAULT_QUANTUM;
}

/* ====================================================================== */
/* OwPsSchedulerTick - called from PIT IRQ0 ISR (vector 0x20)            */
/*   Frame = pointer to the ow_hal_frame_t on the interrupt stack.        */
/* ====================================================================== */
void OwPsSchedulerTick(void* Frame) {
    OW_THREAD_OBJECT* cur;
    OW_THREAD_OBJECT* next;

    s_TickCount++;

    /* Fire due dispatcher timers and wake waiters. */
    OwPsTickTimers();
    /* Wake threads whose block timeout expired. */
    OwPsCheckTimeouts();
    /* Drain the deferred-procedure-call queue (softirq/workqueue analog). */
    OwDpcProcessPending();

    cur = s_CurrentThread;
    if (!cur) return;

    /* A blocked current thread must never be preempted through the
     * frame-capture path (its Context already holds a clean captured frame
     * from KeWaitForSingleObject, and overwriting it with the ISR frame of
     * an idle hlt would corrupt the resume point).  Instead, hand the CPU
     * to any ready thread directly. */
    if (cur->State != OW_THR_RUNNING) {
        next = ready_dequeue();
        if (next) {
            s_CurrentThread = next;
            next->State = OW_THR_RUNNING;
            next->Quantum = OW_PS_DEFAULT_QUANTUM;
            OwPsPrepResume(next);
            ow_ps_resume_thread(&next->Context);
            /* Never returns. */
        }
        return;
    }

    if (cur->Quantum > 0) cur->Quantum--;

    if (cur->Quantum == 0) {
        next = ready_dequeue();
        if (next && next != cur) {
            /* Save the ISR frame into the outgoing thread's context. */
            OwPsFrameToContext(Frame, &cur->Context);
            cur->State = OW_THR_READY;
            ready_enqueue(cur);
            ow_kprintf("[SW] %u->%u\r\n", (unsigned)cur->Tid, (unsigned)next->Tid);

            s_CurrentThread = next;
            next->State = OW_THR_RUNNING;
            next->Quantum = OW_PS_DEFAULT_QUANTUM;
            OwPsPrepResume(next);
            ow_ps_resume_thread(&next->Context);
            /* Never returns. */
        }
        if (next == cur) ready_enqueue(next);  /* invariant guard: put it back */
        /* No switch: reset quantum. */
        cur->Quantum = OW_PS_DEFAULT_QUANTUM;
    }
}

/* ====================================================================== */
/* OwPsThreadBootstrap - C entry for cold threads (called from asm)       */
/* ====================================================================== */
void OwPsThreadBootstrap(OW_THREAD_OBJECT* Thread) {
    typedef void (*entry_fn)(uint64_t);
    entry_fn fn;
    uint64_t arg;

    if (!Thread) {
        OwPsExitThread(1);
        return;
    }

    fn  = (entry_fn)Thread->EntryFunction;
    arg = Thread->EntryArg;

    ow_kprintf("[PSB] tid=%u\r\n", (unsigned)Thread->Tid);
    ow_kprintf("[PS] thread %u: entering user function 0x%llX\r\n",
               (unsigned)Thread->Tid, (unsigned long long)Thread->EntryFunction);

    if (fn) {
        fn(arg);
    }

    /* Thread function returned (or was NULL): exit cleanly. */
    OwPsExitThread(0);
    /* OwPsExitThread never returns (or halts if last thread). */
}

/* ====================================================================== */
/* OwPsScheduleNext - block current thread (context already captured),    */
/* run the next ready thread.                                             */
/* ====================================================================== */
void OwPsScheduleNext(void) {
    OW_THREAD_OBJECT* next;

    /* The caller (KeWaitForSingleObject / OW_SYS_PS_SLEEP) has already set
     * s_CurrentThread->State = OW_THR_BLOCKED and captured its context, so
     * it must NOT be re-enqueued into the ready queue. */
    next = ready_dequeue();
    if (next) {
        s_CurrentThread = next;
        next->State = OW_THR_RUNNING;
        next->Quantum = OW_PS_DEFAULT_QUANTUM;
        OwPsPrepResume(next);
        ow_ps_resume_thread(&next->Context);
        /* Never returns. */
    }

    /* No ready threads: idle until a timer fires and wakes someone. A tick
     * will then take the "current thread not RUNNING" path above and switch
     * straight to the freshly-woken thread. */
#ifndef OW_HOST_HAL
    for (;;) {
        __asm__ volatile("sti; hlt");
    }
#else
    for (;;) { }
#endif
}

/* ====================================================================== */
/* OwPsWakeThread - mark a thread ready and enqueue it.                   */
/* ====================================================================== */
void OwPsWakeThread(OW_THREAD_OBJECT* Thr) {
    if (!Thr) return;
    if (Thr->State == OW_THR_READY || Thr->State == OW_THR_RUNNING) return;
    Thr->State = OW_THR_READY;
    ready_enqueue(Thr);
}

/* ====================================================================== */
/* Accessors                                                               */
/* ====================================================================== */
OW_THREAD_OBJECT* OwPsGetCurrentThread(void) { return s_CurrentThread; }
OW_THREAD_OBJECT* OwPsGetThreadByIndex(uint32_t Index) {
    if (Index >= OW_PS_MAX_THREADS) return (void*)0;
    return &s_Threads[Index];
}
uint32_t OwPsGetTickCount(void) { return s_TickCount; }
