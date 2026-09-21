/* switch.S - OpenWindows context-switch primitives (GNU as, long mode)
 *
 * Uniform captured-frame model.  Every thread resume point is stored as an
 * OW_THREAD_CONTEXT (inc/ow_ps.h, 184 bytes):
 *
 *   +0x00 ResumeRsp
 *   +0x08 Gpr[0]=rax  +0x10 rcx  +0x18 rdx  +0x20 rsi  +0x28 rdi
 *   +0x30 r8   +0x38 r9   +0x40 r10  +0x48 r11  +0x50 rbp
 *   +0x58 rbx  +0x60 r12  +0x68 r13  +0x70 r14  +0x78 r15
 *   +0x80 vector   +0x88 error_code
 *   +0x90 rip      +0x98 cs   +0xA0 rflags
 *   +0xA8 rsp(slot) +0xB0 ss(slot)
 *
 * Three primitives:
 *   ow_ps_capture_frame(ctx)  - save current caller context into ctx
 *   ow_ps_resume_thread(ctx)  - load ctx and iretq into it (never returns)
 *   ow_ps_switch(old, new)    - capture old, then resume new (new returns)
 *
 * One trampoline:
 *   ow_ps_cold_thread_entry   - cold-thread bootstrap (r12 = thread ptr)
 *
 * File-format offsets replicated here so the asm never needs layout
 * knowledge beyond what this file declares. */
.code64
.section .text

.equ CTX_RESUME_RSP, 0x00
.equ CTX_RAX,        0x08
.equ CTX_RCX,        0x10
.equ CTX_RDX,        0x18
.equ CTX_RSI,        0x20
.equ CTX_RDI,        0x28
.equ CTX_R8,         0x30
.equ CTX_R9,         0x38
.equ CTX_R10,        0x40
.equ CTX_R11,        0x48
.equ CTX_RBP,        0x50
.equ CTX_RBX,        0x58
.equ CTX_R12,        0x60
.equ CTX_R13,        0x68
.equ CTX_R14,        0x70
.equ CTX_R15,        0x78
.equ CTX_VECTOR,     0x80
.equ CTX_ERROR_CODE, 0x88
.equ CTX_RIP,        0x90
.equ CTX_CS,         0x98
.equ CTX_RFLAGS,     0xA0
.equ CTX_SS,         0xB0   /* OW_THREAD_CONTEXT.SsSlot: 0x10 kernel / 0x20 user */

/* ====================================================================== */
/* ow_ps_capture_frame(OW_THREAD_CONTEXT* ctx)                            */
/*   rcx = ctx (MS x64 ABI - the kernel C code uses the Microsoft x64      */
/*   calling convention, NOT SysV).  Saves the caller's registers +        */
/*   return address + RFLAGS.  Returns normally to the caller.             */
/* ====================================================================== */
.balign 16
.global ow_ps_capture_frame
    .def    ow_ps_capture_frame
    .scl    2
    .type   32
    .endef
ow_ps_capture_frame:
    /* r8 = ctx (scratch: r8's own value is snapshotted below before any
     * further use; every other source register is read before it dies). */
    movq  %rcx,  %r8

    /* Snapshot volatile callee-clobbered regs first, plus everything MS
     * treats as nonvolatile (r12-r15/rbx/rbp MUST be preserved by us, and
     * rdi/rsi are nonvolatile in the MS ABI - read them before clobbering). */
    movq  %r12,  CTX_R12(%r8)
    movq  %r13,  CTX_R13(%r8)
    movq  %r14,  CTX_R14(%r8)
    movq  %r15,  CTX_R15(%r8)
    movq  %rbx,  CTX_RBX(%r8)
    movq  %rbp,  CTX_RBP(%r8)
    movq  %r10,  CTX_R10(%r8)
    movq  %r9,   CTX_R9(%r8)
    movq  %r11,  CTX_R11(%r8)
    movq  %rdx,  CTX_RDX(%r8)
    movq  %rsi,  CTX_RSI(%r8)    /* caller's rsi */
    movq  %rdi,  CTX_RDI(%r8)    /* caller's rdi */
    movq  %rcx,  CTX_RCX(%r8)    /* caller's rcx (= ctx) */
    movq  %r8,   CTX_R8(%r8)     /* r8's own value (r8 == ctx) */
    movq  %rax,  CTX_RAX(%r8)    /* caller's rax */

    /* Rip = return address (will resume here after switch back). */
    movq  (%rsp), %rax
    movq  %rax,  CTX_RIP(%r8)

    /* ResumeRsp = rsp + 8 (where RSP should be when we "return"). */
    leaq  8(%rsp), %rax
    movq  %rax,  CTX_RESUME_RSP(%r8)

    /* Rflags with IF forced on so resumed threads stay preemptable. */
    pushfq
    popq  %rax
    orq   $0x200, %rax
    movq  %rax,  CTX_RFLAGS(%r8)

    /* Fixed fields. */
    movq  $0x08, CTX_CS(%r8)     /* kernel code selector */
    movq  $0x10, CTX_SS(%r8)     /* kernel data selector */
    movq  $0,    CTX_VECTOR(%r8)
    movq  $0,    CTX_ERROR_CODE(%r8)

    ret

/* ====================================================================== */
/* ow_ps_resume_thread(OW_THREAD_CONTEXT* ctx)                            */
/*   rcx = ctx (MS x64 ABI).  Loads ctx and iretq's into it.  NEVER        */
/*   RETURNS.  Works for both cold threads (synthetic iretq frame) and     */
/*   preempted threads (original ISR frame still on stack).                */
/* ====================================================================== */
.balign 16
.global ow_ps_resume_thread
    .def    ow_ps_resume_thread
    .scl    2
    .type   32
    .endef
ow_ps_resume_thread:
    /* FIX(critical): mask interrupts for the whole resume.  A PIT tick
     * arriving inside the iretq/landing window corrupted the iretq frame
     * (and its own parked frame got overwritten by the recovered thread's
     * stack growth), causing garbage SS:RSP pops, #PF at 0xFFFF...FFF8 and
     * triple faults.  IF is restored by the iretq itself via the target
     * context's RFLAGS, so the switch is fully atomic. */
    cli

    movq  %rcx, %rsi             /* rsi = ctx (preserved across restores) */

    /* Set RSP to ResumeRsp - 40 and build a FULL five-word iretq operand
     * [rip][cs][rflags][rsp][ss].  QEMU (verified empirically: cold resume
     * left RSP = [ResumeRsp], i.e. a 5-word pop) loads SS:RSP too, so the
     * frame must always carry valid values at +24/+32.  +24 reuses the
     * context's own ResumeRsp semantics (target RSP) and +32 uses the kernel
     * data selector, so the recovered thread lands on a valid kernel stack. */
    movq  CTX_RESUME_RSP(%rsi), %r8 /* r8 = target RSP (clobber-free until
                                       * the GPR restore section below) */
    leaq  -40(%r8), %rsp
    movq  CTX_RIP(%rsi), %rax
    movq  %rax, 0(%rsp)
    movq  CTX_CS(%rsi), %rax
    movq  %rax, 8(%rsp)
    movq  CTX_RFLAGS(%rsi), %rax
    movq  %rax, 16(%rsp)
    movq  %r8, 24(%rsp)               /* SS:RSP pair: new RSP             */
    movq  CTX_SS(%rsi), %rax          /* 0x10 kernel / 0x20 user data     */
    movq  %rax, 32(%rsp)

    /* Restore 15 GP registers (rsi/rdi saved for last). */
    movq  CTX_RAX(%rsi), %rax
    movq  CTX_RCX(%rsi), %rcx
    movq  CTX_RDX(%rsi), %rdx
    movq  CTX_R8(%rsi),  %r8
    movq  CTX_R9(%rsi),  %r9
    movq  CTX_R10(%rsi), %r10
    movq  CTX_R11(%rsi), %r11
    movq  CTX_RBP(%rsi), %rbp
    movq  CTX_RBX(%rsi), %rbx
    movq  CTX_R12(%rsi), %r12
    movq  CTX_R13(%rsi), %r13
    movq  CTX_R14(%rsi), %r14
    movq  CTX_R15(%rsi), %r15
    /* Restore rdi, then rsi (last - ctx pointer no longer needed). */
    movq  CTX_RDI(%rsi), %rdi
    movq  CTX_RSI(%rsi), %rsi

    iretq

/* ====================================================================== */
/* ow_ps_switch(OW_THREAD_CONTEXT* old, OW_THREAD_CONTEXT* new)           */
/*   rcx = old, rdx = new (MS x64 ABI).  Captures current context into    */
/*   old, then resumes new.  When old is later resumed, it returns from   */
/*   here.                                                                */
/* ====================================================================== */
.balign 16
.global ow_ps_switch
    .def    ow_ps_switch
    .scl    2
    .type   32
    .endef
ow_ps_switch:
    cli                     /* atomic switch: IF comes back via the iretq */

    /* --- Capture current context into old (inline, rsi = old base) ---
     * rsi is nonvolatile in the MS ABI - snapshot its incoming value, then
     * reuse it as the ctx carrier (r8/r9/r10/r11 stay untouched here and
     * are read into the ctx while they still hold the preempted values). */
    movq  %rsi, CTX_RSI(%rcx)     /* caller's rsi */
    movq  %rdi, CTX_RDI(%rcx)     /* caller's rdi */
    movq  %rdx, CTX_RDX(%rcx)     /* caller's rdx (= new ptr) */
    movq  %rcx, CTX_RCX(%rcx)     /* caller's rcx (= old ptr) */

    movq  %rcx, %rsi             /* rsi = old */

    movq  %r12, CTX_R12(%rsi)
    movq  %r13, CTX_R13(%rsi)
    movq  %r14, CTX_R14(%rsi)
    movq  %r15, CTX_R15(%rsi)
    movq  %rbx, CTX_RBX(%rsi)
    movq  %rbp, CTX_RBP(%rsi)
    movq  %r10, CTX_R10(%rsi)
    movq  %r9,  CTX_R9(%rsi)
    movq  %r8,  CTX_R8(%rsi)
    movq  %r11, CTX_R11(%rsi)
    movq  %rax, CTX_RAX(%rsi)

    /* Rip = return address. */
    movq  (%rsp), %rax
    movq  %rax, CTX_RIP(%rsi)

    /* ResumeRsp = rsp + 8. */
    leaq  8(%rsp), %rax
    movq  %rax, CTX_RESUME_RSP(%rsi)

    /* Rflags with IF set. */
    pushfq
    popq  %rax
    orq   $0x200, %rax
    movq  %rax, CTX_RFLAGS(%rsi)

    movq  $0x08, CTX_CS(%rsi)
    movq  $0x10, CTX_SS(%rsi)
    movq  $0,    CTX_VECTOR(%rsi)
    movq  $0,    CTX_ERROR_CODE(%rsi)

    /* --- Resume new (rdx still holds new dest from the caller) --- */
    movq  %rdx, %rsi             /* rsi = new */

    /* Full five-word iretq operand (see ow_ps_resume_thread). */
    movq  CTX_RESUME_RSP(%rsi), %r8
    leaq  -40(%r8), %rsp
    movq  CTX_RIP(%rsi), %rax
    movq  %rax, 0(%rsp)
    movq  CTX_CS(%rsi), %rax
    movq  %rax, 8(%rsp)
    movq  CTX_RFLAGS(%rsi), %rax
    movq  %rax, 16(%rsp)
    movq  %r8, 24(%rsp)
    movq  CTX_SS(%rsi), %rax
    movq  %rax, 32(%rsp)

    movq  CTX_RAX(%rsi), %rax
    movq  CTX_RCX(%rsi), %rcx
    movq  CTX_RDX(%rsi), %rdx
    movq  CTX_R8(%rsi),  %r8
    movq  CTX_R9(%rsi),  %r9
    movq  CTX_R10(%rsi), %r10
    movq  CTX_R11(%rsi), %r11
    movq  CTX_RBP(%rsi), %rbp
    movq  CTX_RBX(%rsi), %rbx
    movq  CTX_R12(%rsi), %r12
    movq  CTX_R13(%rsi), %r13
    movq  CTX_R14(%rsi), %r14
    movq  CTX_R15(%rsi), %r15
    movq  CTX_RDI(%rsi), %rdi
    movq  CTX_RSI(%rsi), %rsi

    iretq

/* ====================================================================== */
/* ow_ps_cold_thread_entry - cold-thread bootstrap trampoline.            */
/*   On first resume: r12 = thread object pointer (set via Gpr[11]).      */
/*   Forwards to OwPsThreadBootstrap(thread) which must not return.        */
/* ====================================================================== */
.balign 16
.global ow_ps_cold_thread_entry
    .def    ow_ps_cold_thread_entry
    .scl    2
    .type   32
    .endef
ow_ps_cold_thread_entry:
    cld
    movq  %r12, %rcx             /* thread object -> first C argument (MS ABI) */
    call  OwPsThreadBootstrap
    /* OwPsThreadBootstrap must not return; belt-and-braces: */
1:  hlt
    jmp   1b
