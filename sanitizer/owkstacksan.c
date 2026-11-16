/* owkstacksan.c - OWStackSan: kernel stack integrity diagnostics (Phase 4)
 *
 * Provides the stack-guard symbol and failure handler that the compiler
 * inserts when the kernel is built with -fstack-protector-strong (see
 * Makefile / CMakeLists).  A mismatch inside a protected function's epilogue
 * calls __stack_chk_fail() below, which reports FATAL and halts the machine
 * through the BANhammer crash path.
 */
#include "../inc/owkstacksan.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_kprintf.h"
#include "../lib/kalloc.h"

/* Distinctive non-zero cookie.  GCC reads this symbol in every protected
 * prologue/epilogue; it must remain readable for the whole boot.  Never
 * re-initialized at run time: every protected function reads the same value,
 * so changing it mid-boot would fault every function that entered before the
 * change. */
#define OW_STACK_GUARD_CONSTANT 0x7A4C9E3B10000001ull

uint64_t __stack_chk_guard = OW_STACK_GUARD_CONSTANT;

static int owkstacksan_init(void) {
    return (int)OW_SUCCESS;
}

static void owkstacksan_shutdown(void) {
    /* The cookie lives in .data for the whole boot; nothing to release. */
}

static OW_KSAN_MODULE g_StackModule = {
    OW_KSAN_MODULE_NAME_OWSTACKSAN,
    90u,
    true,
    (const char*)0,
    owkstacksan_init,
    owkstacksan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwStackSanRegister(void) {
    return OwKSanRegisterModule(&g_StackModule);
}

void __stack_chk_fail(void) {
    if (OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWSTACKSAN)) {
        OwKSanReport(OW_KSAN_SEVERITY_FATAL, OW_KSAN_MODULE_NAME_OWSTACKSAN,
                     "kernel stack cookie corrupted");
    } else {
        /* The suite may be disarmed; the corruption must still halt loudly. */
        ow_kprintf("[KSAN][stack] kernel stack cookie corrupted\r\n");
    }
    OwDiagBanHammer(OW_ERR_CORRUPT, "owkstacksan",
                    "kernel stack cookie corrupted");
    /* Not reached; keep the function genuinely noreturn. */
    for (;;) {
    }
}

OW_STATUS OwStackSanAudit(void) {
    volatile uint64_t live;

    live = __stack_chk_guard;
    if (live != OW_STACK_GUARD_CONSTANT) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWSTACKSAN,
                     "stack guard symbol corrupted in memory");
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

OW_STATUS OwStackSanCheckStackRange(const void* StackBase, size_t StackSize) {
    uintptr_t base = (uintptr_t)StackBase;
    uintptr_t end;
    uintptr_t heap_base = OwKAllocArenaBase();
    uintptr_t heap_end = heap_base + (uintptr_t)KALLOC_HEAP_SIZE;

    if (StackBase == (const void*)0 || StackSize == 0u) {
        return OW_ERR_INVALID_PARAM;
    }
    if ((base & (uintptr_t)(KALLOC_ALIGN - 1u)) != 0u) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWSTACKSAN,
                     "stack base misaligned: %p", StackBase);
        return OW_ERR_CORRUPT;
    }
    if (StackSize > ~(uintptr_t)0 - base) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWSTACKSAN,
                     "stack span wraps the address space");
        return OW_ERR_CORRUPT;
    }
    end = base + (uintptr_t)StackSize;
    if (base < heap_end && end > heap_base) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWSTACKSAN,
                     "stack region [%p, %p) overlaps the kernel heap arena",
                     StackBase, (const void*)end);
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}
