/* ow_gate.h - the Ring 3 system call gateway, as an emergency user program sees it
 *
 * Every OpenWindows user-mode program reaches the kernel the same way: load the
 * call number into RAX, the three arguments into RCX/RDX/R8, and `int $0x80`.
 * The vector is the kernel's OW_IDT_SYSCALL_VEC, and the handler is
 * OwHalCommonInterruptHandler(), which pulls the arguments out of the interrupt
 * frame and hands them to OwSyscallDispatch() (hal/idt.c).
 *
 * This header exists so that owinitv.owx and owrs.owx cannot disagree with the
 * kernel about any of that.  There is exactly one copy of the ABI here rather
 * than one per program, and the numbers are the same literals the kernel's
 * inc/ow_syscall.h uses -- asserted by the host test, which is the only place
 * that can see both sides at once.
 *
 * C99 freestanding.  No libc, no heap, no CRT: these images run in a Ring 3
 * window with nothing in it but the image's own sections. */
#ifndef OW_GATE_H
#define OW_GATE_H

#include <stdint.h>

/* ---- System call numbers (must match inc/ow_syscall.h) -------------------- */
#define OW_GATE_UART_WRITE   0x01BL
#define OW_GATE_PS_YIELD     0x00DL
#define OW_GATE_PS_EXIT      0x00EL
#define OW_GATE_PS_GET_PID   0x00FU
#define OW_GATE_PS_SLEEP     0x018L
#define OW_GATE_PS_SPAWN_OWX 0x020L
#define OW_GATE_UART_READ    0x021L

/* The one gateway call.
 *
 * `int $0x80` rather than SYSENTER/SYSCALL on purpose: the kernel installs vector
 * 0x80 with a DPL of 3, so it is the only gate a CPL3 thread can actually
 * reach, and it is the gate the other twelve .owx images already use.
 *
 * P3 is bound to R8 by an explicit local register variable, because the ABI fixes
 * it there and no general-purpose operand constraint names R8.  This is not
 * pedantry: with a plain `"r"` constraint GCC is free to allocate P3 to RAX or
 * RCX, which silently destroys an argument the handler is about to read, and it
 * does exactly that whenever the allocator has a spare register -- the bug
 * appears only in builds that happened to have register pressure, which is the
 * worst possible failure mode for it.  A general constraint cannot express "R8
 * and not another one"; a fixed register variable can.
 *
 * hal/interrupts.S pushes and pops R8 with the rest of the register bank, so R8
 * survives the trap and the same local can be reused across calls.  That is the
 * handler's business, not this stub's, and R8 is declared an input only: if a
 * future frame ever stopped preserving it, the conservative reading is to reload
 * it, which is what the compiler will do. */
static inline int64_t ow_gate_call(int64_t id, int64_t p1, int64_t p2,
                                   int64_t p3) {
    register int64_t p3_r8 __asm__("r8") = p3;
    int64_t ret;
    __asm__ __volatile__ ("int $0x80"
                          : "=a"(ret)
                          : "a"(id), "c"(p1), "d"(p2), "r"(p3_r8)
                          : "memory", "cc");
    return ret;
}

/* ---- Console output ------------------------------------------------------- */

/* Ring 3 has no console of its own.  OW_SYS_UART_WRITE takes a NUL-terminated
 * string in the caller's own memory and returns 1; that is the entire console
 * API, and it is why every banner below is one call rather than a formatting
 * layer: there is nothing here to format into. */
static inline int ow_gate_puts(const char* s) {
    return (int)ow_gate_call(OW_GATE_UART_WRITE, (int64_t)(uintptr_t)s, 0, 0);
}

/* Byte at a time, for text that is assembled rather than stored. */
static inline void ow_gate_putc(char c) {
    char one[2];
    one[0] = c;
    one[1] = '\0';
    (void)ow_gate_puts(one);
}

static inline int64_t ow_gate_getpid(void) {
    return ow_gate_call(OW_GATE_PS_GET_PID, 0, 0, 0);
}

static inline void ow_gate_yield(void) {
    (void)ow_gate_call(OW_GATE_PS_YIELD, 0, 0, 0);
}

/* Blocking sleep, in scheduler ticks (100 Hz, so 10 ticks is 100 ms). */
static inline void ow_gate_sleep(int64_t ticks) {
    (void)ow_gate_call(OW_GATE_PS_SLEEP, ticks, 0, 0);
}

/* ---- Console input -------------------------------------------------------- */

/* Non-blocking by contract.  Returns 0..255, or -1 when nothing is waiting.
 * The kernel gates on "is there a byte" before touching the UART at all, because
 * the read itself spins; a caller that did not poll would park a preemptible
 * CPL3 thread inside the kernel with no way to yield. */
static inline int ow_gate_getc(void) {
    return (int)ow_gate_call(OW_GATE_UART_READ, 0, 0, 0);
}

/* Poll until a byte arrives.  Used only by owrs, which is the interactive half
 * of the emergency userspace and has nothing else to do while it waits. */
static inline int ow_gate_getc_wait(void) {
    for (;;) {
        int c = ow_gate_getc();
        if (c >= 0) return c;
        ow_gate_sleep(1);
    }
}

/* ---- Loading another image ------------------------------------------------ */

/* Spawn a named OWX1 image from the primary OWFS volume as a new process.
 * Returns the new PID, or -1.
 *
 * This is the call the whole emergency path is built on.  The kernel's job in
 * state 2 ends at entering owinitv; everything after that -- including getting
 * a rescue shell in front of a human -- is owinitv doing what any user program
 * does, through the same loader and the same OWFS read the kernel already used
 * a moment earlier.  Nothing in the rescue path is privileged. */
static inline int64_t ow_gate_spawn(const char* image) {
    return ow_gate_call(OW_GATE_PS_SPAWN_OWX, (int64_t)(uintptr_t)image, 0, 0);
}

static inline void ow_gate_exit(void) {
    (void)ow_gate_call(OW_GATE_PS_EXIT, 0, 0, 0);
}

#endif /* OW_GATE_H */
