/* owkheapsan.c - OWKHeapSan: kernel heap integrity diagnostics (Phase 2+) */
#include "../inc/owkheapsan.h"
#include "../lib/kalloc.h"

static uint32_t g_ForeignFreeCount;
static uint32_t g_DoubleFreeCount;

static int owkheap_init(void) {
    OwKHeapSanReset();
    return (int)OW_SUCCESS;
}

static void owkheap_shutdown(void) {
    /* Read-only counters/canaries; nothing to release. */
}

static OW_KSAN_MODULE g_HeapModule = {
    OW_KSAN_MODULE_NAME_OWKHEAPSAN,
    10u,
    true,            /* enabled: ready when the master switch is on */
    (const char*)0,  /* no dependency */
    owkheap_init,
    owkheap_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKHeapSanRegister(void) {
    return OwKSanRegisterModule(&g_HeapModule);
}

typedef struct _OW_KHEAPSAN_WALK_CTX {
    uint64_t Sum;
    uint32_t Blocks;
    uint32_t Live;
    uint32_t Free;
    uint32_t Errors;
} OW_KHEAPSAN_WALK_CTX;

static int owkheap_walk(const void* Block, size_t Size, const void* Payload,
                        uint64_t Magic, void* Ctx) {
    OW_KHEAPSAN_WALK_CTX* ctx = (OW_KHEAPSAN_WALK_CTX*)Ctx;
    size_t aligned;
    uintptr_t payload = (uintptr_t)Payload;
    const uint8_t* redzone;
    uint32_t i;

    (void)Block;

    if ((payload & ((uintptr_t)KALLOC_ALIGN - 1u)) != 0u) {
        ctx->Errors++;
    }
    if (Size == 0u) {
        /* An intact block never carries a zero size. */
        ctx->Errors++;
        return 0;
    }
    aligned = (Size + ((size_t)KALLOC_ALIGN - 1u)) & ~(size_t)(KALLOC_ALIGN - 1u);
    if (Magic != KALLOC_MAGIC_LIVE && Magic != KALLOC_MAGIC_FREE) {
        ctx->Errors++;
    } else if (Magic == KALLOC_MAGIC_LIVE) {
        ctx->Live++;
    } else {
        ctx->Free++;
    }
    /* Every block carries a 16-byte 0xA5 redzone right after its payload. */
    redzone = (const uint8_t*)Payload + aligned;
    for (i = 0u; i < KALLOC_REDZONE; ++i) {
        if (redzone[i] != KALLOC_REDZONE_BYTE) {
            ctx->Errors++;
            break;
        }
    }

    ctx->Sum += (uint64_t)KALLOC_HEADER_SIZE + (uint64_t)aligned + KALLOC_REDZONE;
    ctx->Blocks++;
    return 1;
}

OW_STATUS OwKHeapSanAuditArena(OW_KHEAPSAN_REPORT* Out) {
    OW_KHEAPSAN_WALK_CTX ctx;
    uint64_t walked;
    uint64_t used;

    if (Out == (OW_KHEAPSAN_REPORT*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    ctx.Sum = 0u;
    ctx.Blocks = 0u;
    ctx.Live = 0u;
    ctx.Free = 0u;
    ctx.Errors = 0u;

    OwKAllocWalk(owkheap_walk, &ctx);
    walked = ctx.Sum;
    used = (uint64_t)kalloc_used();

    Out->BytesWalked = walked;
    Out->Blocks = ctx.Blocks;
    Out->LiveBlocks = ctx.Live;
    Out->FreeBlocks = ctx.Free;
    Out->ForeignFrees = g_ForeignFreeCount;
    Out->DoubleFrees = g_DoubleFreeCount;
    Out->Errors = ctx.Errors;

    if (walked != used) {
        /* Header chain length mismatch: either a header was overwritten or the
         * committed byte counter no longer agrees with the arena. */
        Out->Errors += 1u;
    }
    if (Out->Errors != 0u) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKHEAPSAN,
                     "arena inconsistent: %u error(s), walked %llu of %llu bytes",
                     (unsigned)Out->Errors, (unsigned long long)walked,
                     (unsigned long long)used);
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

typedef struct _OW_KHEAPSAN_FIND_CTX {
    const void* Target;
    bool Found;
    bool Live;
} OW_KHEAPSAN_FIND_CTX;

static int owkheap_find(const void* Block, size_t Size, const void* Payload,
                        uint64_t Magic, void* Ctx) {
    OW_KHEAPSAN_FIND_CTX* ctx = (OW_KHEAPSAN_FIND_CTX*)Ctx;

    (void)Block;
    (void)Size;

    if (Payload == ctx->Target) {
        ctx->Found = true;
        ctx->Live = (Magic == KALLOC_MAGIC_LIVE);
        return 0; /* stop */
    }
    return 1;
}

static bool owkheap_find_live(const void* Ptr, bool* OutLive) {
    OW_KHEAPSAN_FIND_CTX ctx;

    if (Ptr == (const void*)0 || !OwKAllocContains(Ptr)) {
        return false;
    }
    ctx.Target = Ptr;
    ctx.Found = false;
    ctx.Live = false;
    (void)OwKAllocWalk(owkheap_find, &ctx);
    if (OutLive) {
        *OutLive = ctx.Live;
    }
    return ctx.Found;
}

bool OwKHeapSanValidateBlock(const void* Ptr) {
    return owkheap_find_live(Ptr, (void*)0);
}

bool OwKHeapSanIsTracked(const void* Ptr) {
    bool live = false;

    return owkheap_find_live(Ptr, &live) && live;
}

void OwKHeapSanNoteFree(const void* Ptr, uint32_t Verdict) {
    if (Ptr == (const void*)0) {
        return;
    }
    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKHEAPSAN)) {
        return;
    }
    switch (Verdict) {
    case KALLOC_FREE_FOREIGN:
        g_ForeignFreeCount++;
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKHEAPSAN,
                     "kfree of pointer outside the kernel arena: %p", Ptr);
        break;
    case KALLOC_FREE_DOUBLE:
        g_DoubleFreeCount++;
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKHEAPSAN,
                     "kfree of an already-freed allocation: %p", Ptr);
        break;
    default:
        break;
    }
}

void OwKHeapSanReset(void) {
    g_ForeignFreeCount = 0u;
    g_DoubleFreeCount = 0u;
}

uint32_t OwKHeapSanLiveCount(void) {
    OW_KHEAPSAN_WALK_CTX ctx;

    ctx.Sum = 0u;
    ctx.Blocks = 0u;
    ctx.Live = 0u;
    ctx.Free = 0u;
    ctx.Errors = 0u;

    (void)OwKAllocWalk(owkheap_walk, &ctx);
    return ctx.Live;
}
