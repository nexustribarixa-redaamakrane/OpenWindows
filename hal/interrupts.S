/* interrupts.S - OpenWindows long-mode ISR entry stubs (GNU as)
 *
 * One stub per CPU exception vector 0-31. Each stub normalises the frame:
 *   - vectors with NO hardware error code push a synthetic 0 in the
 *     error-code slot, then push their vector number;
 *   - vectors the CPU decorates with an error code (8, 10-14, 17, 21) simply
 *     push their vector on top of the hardware error code.
 * Every stub then falls into the shared 64-bit root below, which pushes the
 * 15 GP registers and routes the frame into common. C code handles the dump
 * and halts the machine, so the restore/iretq path here is the normalised
 * counterpart kept so the frame contract stays honest.
 *
 * Resulting uniform stack (from RSP, low -> high):
 *   [vector][error_code][rip][cs][rflags]   (+ss/rsp for a CPL change)
 * followed by the 15 saved GP registers, saved so the C frame ends at
 * offset 0 = RAX ... offset 112 = R15. */
.code64
.section .text

/* ---------------------------------------------------------------------- */
/* One stub per vector. Control flow:                                   stub */
/*   [hw frame] -> push synthetic error(0) -> push vector -> jmp <-+      */
/*                                                       (shared below)  */
/* ---------------------------------------------------------------------- */
.macro ISR_STUB vector, has_ec
    .balign 16
    .global OwIsr\vector
    .def    OwIsr\vector
    .scl    2
    .type   32
    .endef
OwIsr\vector:
    .if \has_ec
        pushq $\vector
    .else
        pushq $0         /* no hardware error code: synthesize one */
        pushq $\vector
    .endif
    jmp  ow_generic_isr_entry
.endm

ISR_STUB 0,  0
ISR_STUB 1,  0
ISR_STUB 2,  0
ISR_STUB 3,  0
ISR_STUB 4,  0
ISR_STUB 5,  0
ISR_STUB 6,  0
ISR_STUB 7,  0
ISR_STUB 8,  1
ISR_STUB 9,  0
ISR_STUB 10, 1
ISR_STUB 11, 1
ISR_STUB 12, 1
ISR_STUB 13, 1
ISR_STUB 14, 1
ISR_STUB 15, 0
ISR_STUB 16, 0
ISR_STUB 17, 1
ISR_STUB 18, 0
ISR_STUB 19, 0
ISR_STUB 20, 0
ISR_STUB 21, 0
ISR_STUB 22, 0
ISR_STUB 23, 0
ISR_STUB 24, 0
ISR_STUB 25, 0
ISR_STUB 26, 0
ISR_STUB 27, 0
ISR_STUB 28, 0
ISR_STUB 29, 0
ISR_STUB 30, 0
ISR_STUB 31, 0

/* Vector 32: PIT timer IRQ0 (periodic, used by the PS scheduler tick). */
ISR_STUB 32, 0

/* Vector 128 (0x80): ring-3 system call gate.  The IDT entry carries DPL3,
 * so `int $0x80` is the only privileged instruction a CPL3 program may
 * execute; the handler dispatches through OwSyscallDispatch on the frame's
 * register bank (rax=id, rcx/rdx/r8=args) and iretq's the result back in
 * rax along with the untouched user context. */
ISR_STUB 128, 0

/* ---------------------------------------------------------------------- */
/* Shared 64-bit entry. The stubs leave RSP at the top of [vector]. We push */
/* R15 first, ..., RAX last so that RAX is at the LOWEST address = offset 0 */
/* of the C frame and R15 at +112. The C handler (OwHalCommonInterrupt-     */
/* Handler) never returns: it diagnoses the fault and halts. The restore    */
/* path below remains as a correctness contract for iretq.                  */
/*                                                                          */
/* Frame offsets (ow_hal_frame_t in hal/idt.h):                             */
/*   +0   RAX   +8 RCX   +16 RDX   +24 RSI   +32 RDI                        */
/*   +40  R8    +48 R9   +56 R10   +64 R11   +72 RBP   +80 RBX              */
/*   +88  R12   +96 R13  +104 R14  +112 R15                                 */
/*   +120 Vector  +128 ErrorCode                                           */
/*   +136 Rip +144 Cs +152 Rflags  (+160 Rsp +168 Ss on CPL change)        */
/* ------------------------------------------------------------------------ */
.balign 16
.global ow_generic_isr_entry
    .def    ow_generic_isr_entry
    .scl    2
    .type   32
    .endef
ow_generic_isr_entry:
    pushq %r15          /* first push  -> highest offset (+112) */
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %rbx
    pushq %rbp
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rax          /* last push   -> offset 0 (RAX)         */
    movq  %rsp, %rcx
    cld
    /* Leave a 0x30 pad below the register bank before calling C.  Without
     * it the C prologue stores its arg1 home at [rbp+0x10], and since
     * rbp == base-0x10 that lands EXACTLY on frame offset 0 - i.e. the C
     * code clobbers the user's RAX slot with the frame pointer, so the
     * syscall id read back as the frame base (constant across calls) and
     * preemption captures lost the user RAX too. */
    subq  $0x30, %rsp
    testq $0x0F, %rsp
    jz    ow_isr_call_aligned
    subq  $8, %rsp          /* interrupted RSP was 8 mod 16: pad to align */
    call  OwHalCommonInterruptHandler
    addq  $8, %rsp
    jmp   ow_isr_regs_pop
ow_isr_call_aligned:
    call  OwHalCommonInterruptHandler
ow_isr_regs_pop:
    addq  $0x30, %rsp       /* drop the spare pad, back to the register bank */
    popq  %rax
    popq  %rcx
    popq  %rdx
    popq  %rsi
    popq  %rdi
    popq  %r8
    popq  %r9
    popq  %r10
    popq  %r11
    popq  %rbp
    popq  %rbx
    popq  %r12
    popq  %r13
    popq  %r14
    popq  %r15
    addq  $16, %rsp     /* drop [vector][error_code] */
    iretq
