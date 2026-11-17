/* owktsan.c - OWKTSan: data-race detection (Phase 5) */
#include "../inc/owktsan.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_ps.h"

/* Shadow: 8 bytes of data per 4-byte entry { Epoch:16, Tid:8, Flags:8 }. */
#define KTSAN_FLAG_WRITE 0x01u

typedef struct _OW_KTSAN_SHADOW {
    uint16_t Epoch;
    uint8_t Tid;
    uint8_t Flags;
} OW_KTSAN_SHADOW;

static OW_KTSAN_SHADOW g_Shadow[OW_KTSAN_GROUPS];
static uint32_t g_Epoch;
static uint64_t g_AccessCount;
static uint64_t g_RaceCount;
static uint64_t g_SyncCount;

static int owktsan_init(void) {
    OwKTSanReset();
    return (int)OW_SUCCESS;
}

static void owktsan_shutdown(void) {
    /* Shadow is static backing store; nothing to release. */
}

static OW_KSAN_MODULE g_TModule = {
    OW_KSAN_MODULE_NAME_OWKTSAN,
    120u,
    true,
    (const char*)0,
    owktsan_init,
    owktsan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKTSanRegister(void) {
    return OwKSanRegisterModule(&g_TModule);
}

void OwKTSanReset(void) {
    ow_memset(g_Shadow, 0, sizeof g_Shadow);
    g_Epoch = 1u;
    g_AccessCount = 0u;
    g_RaceCount = 0u;
    g_SyncCount = 0u;
}

void OwKTSanSyncPoint(void) {
    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKTSAN)) {
        return;
    }
    g_SyncCount++;
    g_Epoch++;
    if (g_Epoch > 0xFFFFu) {
        g_Epoch = 1u;
        /* Epoch wrap would make stale entries compare equal to new epochs;
         * invalidate the whole shadow instead of wrapping. */
        ow_memset(g_Shadow, 0, sizeof g_Shadow);
    }
}

void OwKTSanTrackAccess(const void* Ptr, size_t Size, bool Write, uint32_t Tid) {
    uintptr_t base = OwKAllocArenaBase();
    uintptr_t a = (uintptr_t)Ptr;
    size_t i;
    size_t groups;
    bool reported = false;

    if (Ptr == (const void*)0 || Size == 0u) {
        return;
    }
    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKTSAN)) {
        return;
    }
    if (a < base || Size > KALLOC_HEAP_SIZE) {
        return; /* outside the tracked heap arena */
    }
    if ((size_t)(a - base) > KALLOC_HEAP_SIZE - Size) {
        return;
    }

    g_AccessCount++;
    groups = (size_t)(((a - base) + Size + 7u) >> 3);

    for (i = (size_t)((a - base) >> 3); i < groups; ++i) {
        OW_KTSAN_SHADOW* s = &g_Shadow[i];
        bool conflict = false;

        if (s->Tid != 0u && s->Tid != (uint8_t)Tid && s->Epoch == g_Epoch) {
            conflict = Write || (s->Flags & KTSAN_FLAG_WRITE) != 0u;
        }
        if (conflict && !reported) {
            /* Report once per access, naming the first conflicting group. */
            reported = true;
            g_RaceCount++;
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKTSAN,
                         "data race at heap offset 0x%llx (%s), tid %u vs tid %u, epoch %u",
                         (unsigned long long)(i * 8u),
                         Write ? "write" : "read",
                         (unsigned)Tid, (unsigned)s->Tid,
                         (unsigned)g_Epoch);
        }
        s->Tid = (uint8_t)Tid;
        s->Epoch = (uint16_t)(g_Epoch & 0xFFFFu);
        if (Write) {
            s->Flags |= KTSAN_FLAG_WRITE;
        }
    }
}

void OwKTSanRead(const void* Ptr, size_t Size, const char* Label) {
    OW_THREAD_OBJECT* cur = OwPsGetCurrentThread();
    uint32_t tid = cur ? (uint32_t)cur->Tid : 0u;

    (void)Label;
    OwKTSanTrackAccess(Ptr, Size, false, tid);
}

void OwKTSanWrite(const void* Ptr, size_t Size, const char* Label) {
    OW_THREAD_OBJECT* cur = OwPsGetCurrentThread();
    uint32_t tid = cur ? (uint32_t)cur->Tid : 0u;

    (void)Label;
    OwKTSanTrackAccess(Ptr, Size, true, tid);
}

void OwKTSanGetStats(OW_KTSAN_STATS* Out) {
    if (Out == (OW_KTSAN_STATS*)0) {
        return;
    }
    Out->Accesses = g_AccessCount;
    Out->Races = g_RaceCount;
    Out->Syncs = g_SyncCount;
}
