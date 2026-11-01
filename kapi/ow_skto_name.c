/* ow_skto_name.c - SKTO name admission for the OpenWindows kernel
 *
 * Freestanding C99. No libc string functions, no allocation, no retention of
 * the caller's pointer. See kapi/ow_skto_name.h for the contract.
 */

#include "ow_skto_name.h"

#include "../inc/ow_io.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"

typedef struct _OW_SKTO_NAME_LIMITS {
    skto_limits_t limits;
} ow_skto_name_limits_t;

static void name_limits(ow_skto_name_limits_t *out) {
    out->limits.max_admit_bytes = OW_SKTO_NAME_MAX_BYTES;
    out->limits.max_name_bytes = OW_SKTO_NAME_MAX_BYTES;
}

/* Make a failed result unusable rather than leaving the previous name in place.
 * The bytes are not cleared: no caller may read them after a failure, and
 * clearing a 128-byte buffer on every rejection would be pure overhead. */
static void name_clear(ow_skto_name_t *out) {
    ow_memset(&out->text, 0, sizeof(out->text));
    out->bytes[0] = 0u;
}

static skto_status_t name_finish(ow_skto_name_t *out,
                                 const ow_skto_name_limits_t *limits,
                                 skto_status_t st) {
    if (st != SKTO_OK) {
        name_clear(out);
        return st;
    }
    if (out->text.len == 0u) {
        name_clear(out);
        return SKTO_E_POLICY;
    }
    st = suas_skto_name_check(&out->text, &limits->limits);
    if (st != SKTO_OK) {
        name_clear(out);
        return st;
    }
    return SKTO_OK;
}

skto_status_t OwSktoNameAdmitUser(ow_skto_name_t *Out, const char *Src,
                                  size_t ScanCap, skto_range_fn Range,
                                  void *RangeCtx) {
    const uint8_t *base;
    ow_skto_name_limits_t limits;
    size_t limit;
    size_t n;
    size_t written = 0u;
    skto_status_t st;

    if (Out == NULL || Src == NULL || Range == NULL)
        return SKTO_E_NULL;
    name_clear(Out);

    limit = (ScanCap < OW_SKTO_NAME_STORAGE_BYTES) ? ScanCap
                                                   : OW_SKTO_NAME_STORAGE_BYTES;
    if (limit == 0u)
        return SKTO_E_RANGE;

    /* Reject pointer arithmetic that wraps before validating any page. */
    if ((uintptr_t)Src > (uintptr_t)(~(uintptr_t)0) - (uintptr_t)limit)
        return SKTO_E_OVERFLOW;

    base = (const uint8_t *)(const void *)Src;

    /* Validate the page that holds each byte before reading that byte. This is
     * the same rule as the gateway's range check, applied at the smallest
     * granularity so a name that ends near a page boundary is not rejected
     * merely because a fixed window would run past the mapping. */
    for (n = 0u; n < limit; ++n) {
        if (!Range(RangeCtx, (const void *)(base + n), 1u))
            return SKTO_E_RANGE;
        if (base[n] == 0u)
            break;
    }
    if (n == limit)
        return SKTO_E_TERMINATOR;

    name_limits(&limits);
    st = suas_skto_admit(base, n, Range, RangeCtx, &limits.limits, Out->bytes,
                         sizeof(Out->bytes), &Out->text, &written);
    return name_finish(Out, &limits, st);
}

skto_status_t OwSktoNameAdmitTrusted(ow_skto_name_t *Out, const char *Src,
                                     size_t ScanCap) {
    const uint8_t *base;
    ow_skto_name_limits_t limits;
    size_t limit;
    size_t n;
    size_t written = 0u;
    skto_status_t st;

    if (Out == NULL || Src == NULL)
        return SKTO_E_NULL;
    name_clear(Out);

    limit = (ScanCap < OW_SKTO_NAME_STORAGE_BYTES) ? ScanCap
                                                   : OW_SKTO_NAME_STORAGE_BYTES;
    if (limit == 0u)
        return SKTO_E_RANGE;
    if ((uintptr_t)Src > (uintptr_t)(~(uintptr_t)0) - (uintptr_t)limit)
        return SKTO_E_OVERFLOW;

    base = (const uint8_t *)(const void *)Src;
    for (n = 0u; n < limit; ++n) {
        if (base[n] == 0u)
            break;
    }
    if (n == limit)
        return SKTO_E_TERMINATOR;

    name_limits(&limits);
    st = suas_skto_admit(base, n, (skto_range_fn)0, (void *)0, &limits.limits,
                         Out->bytes, sizeof(Out->bytes), &Out->text, &written);
    return name_finish(Out, &limits, st);
}

const char *OwSktoNameCstr(const ow_skto_name_t *Name) {
    if (Name == NULL || Name->text.bytes == NULL)
        return (const char *)0;
    return (const char *)(const void *)Name->text.bytes;
}

size_t OwSktoNameLength(const ow_skto_name_t *Name) {
    if (Name == NULL || Name->text.bytes == NULL)
        return 0u;
    return Name->text.len;
}

void OwSktoLockAcquire(void *Ctx) {
    ow_skto_irq_lock_t *lock = (ow_skto_irq_lock_t *)Ctx;

    if (lock == NULL)
        return;
    lock->flags = ow_irq_save();
}

void OwSktoLockRelease(void *Ctx) {
    ow_skto_irq_lock_t *lock = (ow_skto_irq_lock_t *)Ctx;

    if (lock == NULL)
        return;
    ow_irq_restore(lock->flags);
}
