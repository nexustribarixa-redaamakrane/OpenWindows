/* owkasan.c - OWKAsan: address-access validation (Phase 3) */
#include "../inc/owkasan.h"
#include "../lib/kalloc.h"

static int owkasan_init(void) {
    return (int)OW_SUCCESS;
}

static void owkasan_shutdown(void) {
    /* Read-only metadata validation; nothing to release. */
}

static OW_KSAN_MODULE g_AsanModule = {
    OW_KSAN_MODULE_NAME_OWKASAN,
    50u,
    true,
    (const char*)0,
    owkasan_init,
    owkasan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKAsanRegister(void) {
    return OwKSanRegisterModule(&g_AsanModule);
}

static OW_STATUS owkasan_check(const void* Ptr, size_t Size, const char* Label,
                               bool Write) {
    const uint8_t* block;
    uint64_t tag;
    uintptr_t payload;
    uintptr_t end;
    uintptr_t access_end;
    size_t payload_size;

    (void)Label;
    (void)Write;

    if (Ptr == (const void*)0 || Size == 0u) {
        return OW_SUCCESS;
    }
    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKASAN)) {
        return OW_SUCCESS; /* module disabled: not checked */
    }
    if (!OwKAllocContains(Ptr)) {
        return OW_SUCCESS; /* not heap: outside this module's domain */
    }

    block = (const uint8_t*)OwKAllocBlockFind(Ptr);
    if (block == (const uint8_t*)0) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKASAN,
                     "%s: heap pointer matched no block (arena corrupt)",
                     Label ? Label : "?");
        return OW_ERR_CORRUPT;
    }
    tag = *(((const uint64_t*)block) + 1);
    payload_size = (size_t)(*(const uint64_t*)block);
    payload_size = (payload_size + ((size_t)KALLOC_ALIGN - 1u)) &
                   ~(size_t)(KALLOC_ALIGN - 1u);
    payload = (uintptr_t)block + KALLOC_HEADER_SIZE;
    end = payload + (uintptr_t)payload_size;
    access_end = (uintptr_t)Ptr + (uintptr_t)Size;

    if ((uintptr_t)Ptr < payload || access_end > end) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKASAN,
                     "%s: heap access crosses its block boundary [%p, %p)",
                     Label ? Label : "?", Ptr, (const void*)access_end);
        return OW_ERR_CORRUPT;
    }
    if (tag != KALLOC_MAGIC_LIVE) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKASAN,
                     "%s: use-after-free access to %p",
                     Label ? Label : "?", Ptr);
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKAsanCheckRead(const void* Ptr, size_t Size, const char* Label) {
    return owkasan_check(Ptr, Size, Label, false);
}

OW_STATUS OwKAsanCheckWrite(const void* Ptr, size_t Size, const char* Label) {
    return owkasan_check(Ptr, Size, Label, true);
}

typedef struct _OW_KASAN_WALK_CTX {
    uint64_t Sum;
    uint32_t Blocks;
    uint32_t Live;
    uint32_t Free;
    uint32_t Errors;
} OW_KASAN_WALK_CTX;

static int owkasan_walk(const void* Block, size_t Size, const void* Payload,
                        uint64_t Magic, void* Ctx) {
    OW_KASAN_WALK_CTX* ctx = (OW_KASAN_WALK_CTX*)Ctx;
    size_t aligned;
    const uint8_t* redzone;
    uint32_t i;

    (void)Block;

    if (Size == 0u || (Magic != KALLOC_MAGIC_LIVE && Magic != KALLOC_MAGIC_FREE)) {
        ctx->Errors++;
        return 0;
    }
    aligned = (Size + ((size_t)KALLOC_ALIGN - 1u)) & ~(size_t)(KALLOC_ALIGN - 1u);
    redzone = (const uint8_t*)Payload + aligned;
    for (i = 0u; i < KALLOC_REDZONE; ++i) {
        if (redzone[i] != KALLOC_REDZONE_BYTE) {
            ctx->Errors++;
            break;
        }
    }
    ctx->Sum += (uint64_t)KALLOC_HEADER_SIZE + (uint64_t)aligned + KALLOC_REDZONE;
    if (Magic == KALLOC_MAGIC_LIVE) {
        ctx->Live++;
    } else {
        ctx->Free++;
    }
    ctx->Blocks++;
    return 1;
}

OW_STATUS OwKAsanAudit(OW_KASAN_REPORT* Out) {
    OW_KASAN_WALK_CTX ctx;
    uint32_t quarantine;
    uint32_t i;
    uint64_t used;

    if (Out == (OW_KASAN_REPORT*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    ctx.Sum = 0u;
    ctx.Blocks = 0u;
    ctx.Live = 0u;
    ctx.Free = 0u;
    ctx.Errors = 0u;

    OwKAllocWalk(owkasan_walk, &ctx);

    used = (uint64_t)kalloc_used();
    if (ctx.Sum != used) {
        ctx.Errors += 1u;
    }

    /* Quarantine integrity: every quarantined block must still carry the FREE
     * tag, an intact redzone, and a fully poisoned payload.  Any byte other
     * than the poison means the freed block was written after free. */
    quarantine = OwKAllocQuarantineCount();
    for (i = 0u; i < quarantine; ++i) {
        const uint8_t* block = (const uint8_t*)OwKAllocQuarantineAt(i);
        uint64_t tag = *(((const uint64_t*)block) + 1);
        size_t size = (size_t)*(const uint64_t*)block;
        size_t aligned;
        size_t j;
        const uint8_t* redzone;
        uint32_t k;

        if (block == (const uint8_t*)0) {
            ctx.Errors++;
            continue;
        }
        if (tag != KALLOC_MAGIC_FREE) {
            ctx.Errors++;
            continue;
        }
        aligned = (size + ((size_t)KALLOC_ALIGN - 1u)) & ~(size_t)(KALLOC_ALIGN - 1u);
        redzone = block + KALLOC_HEADER_SIZE + aligned;
        for (k = 0u; k < KALLOC_REDZONE; ++k) {
            if (redzone[k] != KALLOC_REDZONE_BYTE) {
                ctx.Errors++;
                break;
            }
        }
        for (j = 0u; j < aligned; ++j) {
            if (block[KALLOC_HEADER_SIZE + j] != KALLOC_POISON_BYTE) {
                ctx.Errors++;
                break;
            }
        }
    }

    Out->BytesWalked = ctx.Sum;
    Out->Blocks = ctx.Blocks;
    Out->LiveBlocks = ctx.Live;
    Out->FreeBlocks = ctx.Free;
    Out->QuarantinedBlocks = quarantine;
    Out->Errors = ctx.Errors;
    Out->QuarantinedBytes = 0u;
    for (i = 0u; i < quarantine; ++i) {
        const uint8_t* block = (const uint8_t*)OwKAllocQuarantineAt(i);

        if (block != (const uint8_t*)0) {
            Out->QuarantinedBytes += (uint32_t)*(const uint64_t*)block + KALLOC_HEADER_SIZE + KALLOC_REDZONE;
        }
    }

    if (ctx.Errors != 0u) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKASAN,
                     "sanity check failed: %u error(s)",
                     (unsigned)ctx.Errors);
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

uint32_t OwKAsanQuarantineBlocks(void) {
    return OwKAllocQuarantineCount();
}

uint32_t OwKAsanSetQuarantineLimit(uint32_t Blocks) {
    return OwKAllocQuarantineSetLimit(Blocks);
}

uint32_t OwKAsanQuarantineLimit(void) {
    return OwKAllocQuarantineLimit();
}
