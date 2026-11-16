/* owkstacksan.h - OWStackSan: kernel stack integrity diagnostics (Phase 4)
 *
 * Two layers of protection:
 *
 * 1. Compiler instrumentation, for real.  The kernel and the host harness are
 *    built with -fstack-protector-strong, so every function whose stack frame
 *    holds an array (or takes the address of a local) carries a canary.  A
 *    stack smash is caught by the compiler at the epilogue -- that is actual
 *    compiler-instrumented detection, not a checked call site.  This module
 *    provides the guard symbol (__stack_chk_guard) and the failure handler
 *    (__stack_chk_fail) the compiler requires; on a canary mismatch the boot
 *    is halted through the BANhammer path.
 *
 * 2. Explicit checks:
 *    - OwStackSanAudit(): verifies the guard symbol in memory still matches
 *      the value this module wrote (a write into the guard's own storage
 *      corrupts every subsequent cookie check),
 *    - OwStackSanCheckStackRange(): validates a caller-declared stack region
 *      against the kalloc arena (a stack inside the heap arena is corruption),
 *      span wraparound, and the obvious sanity bounds.
 *
 * What it does NOT detect:
 *   - stack-buffer overflows in functions the compiler did not protect
 *     (leaf functions without arrays),
 *   - stack leaks of uninitialized locals (a write-before-read check, not a
 *     stack-protection check),
 *   - return-address overwrites that bypass the epilogue check (e.g. an
 *     overflow that stops exactly at the cookie and corrupts no canary
 *     function, the classic canary-bypass; undetectable without shadow),
 *   - stack-smashing in the assembly paths (ISR stubs call C but are not
 *     themselves instrumented).
 */
#ifndef OW_KSTACKSAN_H
#define OW_KSTACKSAN_H

#include "owksan.h"

OW_STATUS OwStackSanRegister(void);

/* Module audit: the guard symbol must still equal the value this module
 * wrote; a torn cookie means something corrupted the guard's storage. */
OW_STATUS OwStackSanAudit(void);

/* Validate a declared stack region: non-zero, aligned, span does not wrap, and
 * the region does not overlap the kernel heap arena. */
OW_STATUS OwStackSanCheckStackRange(const void* StackBase, size_t StackSize);

#endif /* OW_KSTACKSAN_H */
