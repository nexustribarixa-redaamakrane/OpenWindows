/* owkheapsan.c - OWKHeapSan: kernel heap integrity diagnostics (Phase 2) */
#include "../inc/owkheapsan.h"
#include "../lib/kalloc.h"

typedef struct _OW_KHEAPSAN_ENTRY {
    const void* Ptr;
    size_t Size;
    bool Used;
} OW_KHEAPSAN_ENTRY;

/* Live-allocation registry: bounded snapshot of every allocation observed since
 * the last reset.  It exists so kfree() can be checked against what the
 * allocator actually handed out. */
static OW_KHEAPSAN_ENTRY g_Registry[OW_KHEAPSAN_REGISTRY_MAX];
/* Freed-pointer set: bounded snapshot of frees since the last reset, used to
 * report double-free of a tracked block. */
static OW_KHEAPSAN_ENTRY g_Freed[OW_KHEAPSAN_REGISTRY_MAX];
static uint32_t g_ForeignFreeCount;
static uint32_t g_UntrackedFreeCount;
static uint32_t g_DoubleFreeCount;
static bool g_RegistryOverflow;
static bool g_FreedOverflow;

static int owkheap_init(void) {
    OwKHeapSanRegistryReset();
    return (int)OW_SUCCESS;
}

static void owkheap_shutdown(void) {
    /* The registry is a bounded snapshot, not a resource to release. */
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
    uint32_t Errors;
} OW_KHEAPSAN_WALK_CTX;

static int owkheap_walk(const void* Block, size_t Size, const void* Payload,
                        void* Ctx) {
    OW_KHEAPSAN_WALK_CTX* ctx = (OW_KHEAPSAN_WALK_CTX*)Ctx;
    size_t aligned;
    uintptr_t payload = (uintptr_t)Payload;

    (void)Block;

    /* Every payload address the allocator returns is 8-byte aligned. */
    if ((payload & ((uintptr_t)KALLOC_ALIGN - 1u)) != 0u) {
        ctx->Errors++;
    }
    if (Size == 0u) {
        /* An intact block never carries a zero size; stop rather than
         * accumulate garbage into the walk. */
        ctx->Errors++;
        return 0;
    }
    aligned = (Size + ((size_t)KALLOC_ALIGN - 1u)) & ~(size_t)(KALLOC_ALIGN - 1u);
    ctx->Sum += (uint64_t)KALLOC_HEADER_SIZE + (uint64_t)aligned;
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
    ctx.Errors = 0u;

    OwKAllocWalk(owkheap_walk, &ctx);
    walked = ctx.Sum;
    used = (uint64_t)kalloc_used();

    Out->BytesWalked = walked;
    Out->Blocks = ctx.Blocks;
    Out->Errors = ctx.Errors;
    Out->ForeignFrees = g_ForeignFreeCount;
    Out->UntrackedFrees = g_UntrackedFreeCount;
    Out->DoubleFrees = g_DoubleFreeCount;

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
} OW_KHEAPSAN_FIND_CTX;

static int owkheap_find(const void* Block, size_t Size, const void* Payload,
                        void* Ctx) {
    OW_KHEAPSAN_FIND_CTX* ctx = (OW_KHEAPSAN_FIND_CTX*)Ctx;

    (void)Block;
    (void)Size;

    if (Payload == ctx->Target) {
        ctx->Found = true;
        return 0; /* stop the walk */
    }
    return 1;
}

bool OwKHeapSanValidateBlock(const void* Ptr) {
    OW_KHEAPSAN_FIND_CTX ctx;

    if (Ptr == (const void*)0 || !OwKAllocContains(Ptr)) {
        return false;
    }
    ctx.Target = Ptr;
    ctx.Found = false;
    (void)OwKAllocWalk(owkheap_find, &ctx);
    return ctx.Found;
}

bool OwKHeapSanIsTracked(const void* Ptr) {
    uint32_t i;

    if (Ptr == (const void*)0) {
        return false;
    }
    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        if (g_Registry[i].Used && g_Registry[i].Ptr == Ptr) {
            return true;
        }
    }
    return false;
}

void OwKHeapSanNoteAlloc(const void* Ptr, size_t Size) {
    uint32_t i;

    if (Ptr == (const void*)0) {
        return;
    }
    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKHEAPSAN)) {
        return;
    }
    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        if (!g_Registry[i].Used) {
            g_Registry[i].Ptr = Ptr;
            g_Registry[i].Size = Size;
            g_Registry[i].Used = true;
            return;
        }
    }
    g_RegistryOverflow = true;
}

static bool owkheap_in_freed(const void* Ptr) {
    uint32_t i;

    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        if (g_Freed[i].Used && g_Freed[i].Ptr == Ptr) {
            return true;
        }
    }
    return false;
}

static void owkheap_note_freed(const void* Ptr) {
    uint32_t i;

    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        if (!g_Freed[i].Used) {
            g_Freed[i].Ptr = Ptr;
            g_Freed[i].Size = 0u;
            g_Freed[i].Used = true;
            return;
        }
    }
    g_FreedOverflow = true;
}

void OwKHeapSanNoteFree(const void* Ptr) {
    uint32_t i;

    if (Ptr == (const void*)0) {
        return;
    }
    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKHEAPSAN)) {
        return;
    }
    /* Tracked live allocation: a legitimate free. */
    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        if (g_Registry[i].Used && g_Registry[i].Ptr == Ptr) {
            g_Registry[i].Used = false;
            owkheap_note_freed(Ptr);
            return;
        }
    }
    /* Not live.  Pointer outside the arena is a foreign pointer, full stop. */
    if (!OwKAllocContains(Ptr)) {
        g_ForeignFreeCount++;
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKHEAPSAN,
                     "kfree of pointer outside the kernel arena: %p", Ptr);
        return;
    }
    /* Pointer inside the arena but not a live tracked allocation.  If this is a
     * block we have already freed, that is a double free. */
    if (owkheap_in_freed(Ptr)) {
        g_DoubleFreeCount++;
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKHEAPSAN,
                     "kfree of an already-freed allocation: %p", Ptr);
        return;
    }
    if (!g_RegistryOverflow && !g_FreedOverflow) {
        /* Both sets never filled: every arena allocation and every free was
         * tracked, so this is a genuine invalid free, not a blind spot. */
        g_UntrackedFreeCount++;
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKHEAPSAN,
                     "kfree of untracked arena allocation: %p", Ptr);
        return;
    }
    g_UntrackedFreeCount++;
}

void OwKHeapSanRegistryReset(void) {
    uint32_t i;

    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        g_Registry[i].Used = false;
        g_Registry[i].Ptr = (const void*)0;
        g_Registry[i].Size = 0u;
        g_Freed[i].Used = false;
        g_Freed[i].Ptr = (const void*)0;
        g_Freed[i].Size = 0u;
    }
    g_RegistryOverflow = false;
    g_FreedOverflow = false;
    g_ForeignFreeCount = 0u;
    g_UntrackedFreeCount = 0u;
    g_DoubleFreeCount = 0u;
}

uint32_t OwKHeapSanTrackedCount(void) {
    uint32_t i;
    uint32_t n = 0u;

    for (i = 0u; i < OW_KHEAPSAN_REGISTRY_MAX; ++i) {
        if (g_Registry[i].Used) {
            n++;
        }
    }
    return n;
}
