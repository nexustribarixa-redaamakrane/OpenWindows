/* owkmsan.c - OWKMSan: memory-initialization tracking (Phase 3) */
#include "../inc/owkmsan.h"
#include "../inc/ow_mem.h"
#include "../lib/kalloc.h"

/* 1 shadow byte per 8 arena bytes; bit i of a shadow byte marks payload byte
 * (8*shadow_index + i) as uninitialized.  The shadow covers the kalloc arena
 * only, so non-heap memory is outside this module's tracking domain. */
#define KMSAN_SHADOW_SIZE (KALLOC_HEAP_SIZE / 8u)

static uint8_t g_Shadow[KMSAN_SHADOW_SIZE];

static uintptr_t s_Base;

static int owkmsan_init(void) {
    OwKMSanReset();
    return (int)OW_SUCCESS;
}

static void owkmsan_shutdown(void) {
    /* Shadow is static backing store; nothing to release. */
}

static OW_KSAN_MODULE g_MSModule = {
    OW_KSAN_MODULE_NAME_OWKMSAN,
    40u,
    true,
    (const char*)0,
    owkmsan_init,
    owkmsan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKMSanRegister(void) {
    return OwKSanRegisterModule(&g_MSModule);
}

static void shadow_set_range(size_t Off, size_t Size, bool Uninit) {
    size_t i;

    for (i = 0u; i < Size; ++i) {
        size_t bit = Off + i;
        size_t shadow = bit >> 3;
        uint8_t mask = (uint8_t)(1u << (bit & 7u));

        if (Uninit) {
            g_Shadow[shadow] |= mask;
        } else {
            g_Shadow[shadow] &= ~mask;
        }
    }
}

static int shadow_find_uninit(size_t Off, size_t Size) {
    size_t i;

    for (i = 0u; i < Size; ++i) {
        size_t bit = Off + i;
        size_t shadow = bit >> 3;
        uint8_t mask = (uint8_t)(1u << (bit & 7u));

        if ((g_Shadow[shadow] & mask) != 0u) {
            return (int)i;
        }
    }
    return -1;
}

static bool shadow_span(const void* Ptr, size_t Size, size_t* OutOff) {
    uintptr_t base = s_Base;
    uintptr_t a = (uintptr_t)Ptr;

    if (a < base || Size > KALLOC_HEAP_SIZE) {
        return false;
    }
    if ((size_t)(a - base) > KALLOC_HEAP_SIZE - Size) {
        return false;
    }
    *OutOff = (size_t)(a - base);
    return true;
}

void OwKMSanReset(void) {
    s_Base = OwKAllocArenaBase();
    /* Everything looks initialized at reset: tracking applies from here on,
     * and older blocks are not provably uninitialized. */
    ow_memset(g_Shadow, 0x00, sizeof(g_Shadow));
}

void OwKMSanNoteAlloc(const void* Ptr, size_t Size) {
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    if (!shadow_span(Ptr, Size, &off)) {
        return;
    }
    shadow_set_range(off, Size, true);
}

void OwKMSanNoteInit(const void* Ptr, size_t Size) {
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    if (!shadow_span(Ptr, Size, &off)) {
        return;
    }
    shadow_set_range(off, Size, false);
}

void OwKMSanNoteCopy(void* Dst, const void* Src, size_t CopyBytes, size_t NewBytes) {
    size_t dst_off;
    size_t src_off;
    size_t i;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    if (!shadow_span(Dst, NewBytes, &dst_off)) {
        return;
    }
    if (!shadow_span(Src, CopyBytes, &src_off)) {
        /* Copying from non-tracked memory: mark the copied prefix
         * initialized, as there is no shadow to propagate. */
        shadow_set_range(dst_off, CopyBytes, false);
        shadow_set_range(dst_off + CopyBytes, NewBytes - CopyBytes, true);
        return;
    }
    for (i = 0u; i < CopyBytes; ++i) {
        size_t dbit = dst_off + i;
        size_t sbit = src_off + i;
        uint8_t bit = (uint8_t)(1u << (sbit & 7u));
        size_t dshadow = dbit >> 3;
        bool uninit = (g_Shadow[sbit >> 3] & bit) != 0u;

        if (uninit) {
            g_Shadow[dshadow] |= (uint8_t)(1u << (dbit & 7u));
        } else {
            g_Shadow[dshadow] &= (uint8_t)~(1u << (dbit & 7u));
        }
    }
    if (NewBytes > CopyBytes) {
        shadow_set_range(dst_off + CopyBytes, NewBytes - CopyBytes, true);
    }
}

void OwKMSanNoteFree(const void* Ptr, size_t Size) {
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    if (!shadow_span(Ptr, Size, &off)) {
        return;
    }
    shadow_set_range(off, Size, true); /* freed == uninitialized again */
}

OW_STATUS OwKMSanCheckRead(const void* Ptr, size_t Size, const char* Label) {
    size_t off;
    int at;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return OW_SUCCESS; /* module disabled: not tracked, not checked */
    }
    if (!shadow_span(Ptr, Size, &off)) {
        return OW_SUCCESS; /* outside the tracked arena */
    }
    at = shadow_find_uninit(off, Size);
    if (at < 0) {
        return OW_SUCCESS;
    }
    OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKMSAN,
                 "%s: read of uninitialized byte %d of the allocation at %p",
                 Label ? Label : "?", at, Ptr);
    return OW_ERR_CORRUPT;
}

void OwKMSanMarkInit(const void* Ptr, size_t Size) {
    size_t off;

    if (!shadow_span(Ptr, Size, &off)) {
        return;
    }
    shadow_set_range(off, Size, false);
}

void OwKMSanMarkUninit(const void* Ptr, size_t Size) {
    size_t off;

    if (!shadow_span(Ptr, Size, &off)) {
        return;
    }
    shadow_set_range(off, Size, true);
}
