/* owklsan.c - OWKLSan: lock-state and synchronization diagnostics (Phase 5) */
#include "../inc/owklsan.h"
#include "../inc/ow_ps.h"

static int owklsan_init(void) {
    return (int)OW_SUCCESS;
}

static void owklsan_shutdown(void) {
    /* Read-only audits; nothing to release. */
}

static OW_KSAN_MODULE g_LSanModule = {
    OW_KSAN_MODULE_NAME_OWKLSAN,
    110u,
    true,
    (const char*)0,
    owklsan_init,
    owklsan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKLSanRegister(void) {
    return OwKSanRegisterModule(&g_LSanModule);
}

OW_STATUS OwKLSanAuditHeldLocks(OW_KLSAN_AUDIT* Out) {
    OW_KLCKSAN_STATS stats;

    if (Out == (OW_KLSAN_AUDIT*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    OwKLockSanGetStats(&stats);

    Out->TotalTracked = stats.Total;
    Out->Owned = stats.Owned;
    Out->MaxRecursion = stats.MaxRecursion;
    Out->Abandoned = stats.Abandoned;
    Out->LiveRecords = stats.Total;
    return OW_SUCCESS;
}

typedef struct _OW_KLSAN_WALK_CTX {
    uint64_t MaxTicks;
    uint64_t Now;
    uint32_t Flagged;
    const char* Where;
    bool Quiescent;
} OW_KLSAN_WALK_CTX;

static int owklsan_walk(const OW_KLCKSAN_LOCK* Lock, void* Ctx) {
    OW_KLSAN_WALK_CTX* ctx = (OW_KLSAN_WALK_CTX*)Ctx;
    uint64_t duration;

    if (Lock->OwnerTid == OW_KLCKSAN_TID_FREE) {
        return 1; /* not owned */
    }
    duration = ctx->Now - Lock->AcquiredAt; /* wraps cleanly on a stalled harness */

    if (ctx->Quiescent) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLSAN,
                     "mutex held at quiescent point '%s' (tid %u)",
                     ctx->Where ? ctx->Where : "?", (unsigned)Lock->OwnerTid);
        ctx->Flagged++;
        return 1;
    }
    if (duration > ctx->MaxTicks) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKLSAN,
                     "mutex held for %llu tick(s) by tid %u (budget %llu)",
                     (unsigned long long)duration, (unsigned)Lock->OwnerTid,
                     (unsigned long long)ctx->MaxTicks);
        ctx->Flagged++;
    }
    return 1;
}

OW_STATUS OwKLSanAuditLongHolds(uint64_t MaxTicks, uint32_t* OutFlagged) {
    OW_KLSAN_WALK_CTX ctx;

    ctx.MaxTicks = MaxTicks;
    ctx.Now = (uint64_t)OwPsGetTickCount();
    ctx.Flagged = 0u;
    ctx.Where = (const char*)0;
    ctx.Quiescent = false;

    OwKLockSanForEach(owklsan_walk, &ctx);

    if (OutFlagged != (uint32_t*)0) {
        *OutFlagged = ctx.Flagged;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKLSanAuditQuiescent(const char* Where) {
    OW_KLSAN_WALK_CTX ctx;

    ctx.MaxTicks = 0u;
    ctx.Now = (uint64_t)OwPsGetTickCount();
    ctx.Flagged = 0u;
    ctx.Where = Where;
    ctx.Quiescent = true;

    OwKLockSanForEach(owklsan_walk, &ctx);

    return ctx.Flagged == 0u ? OW_SUCCESS : OW_ERR_CORRUPT;
}
