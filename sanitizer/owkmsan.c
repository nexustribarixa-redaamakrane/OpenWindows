/* owkmsan.c - OWKMSan: memory-initialization tracking (Phase 3+) */
#include "../inc/owkmsan.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../lib/kalloc.h"

/* 1 shadow byte per 8 tracked bytes; bit i of a shadow byte marks tracked byte
 * (8*shadow_index + i) as uninitialized.  Two regions are tracked: the 8 MiB
 * kalloc arena and the 16 MiB physical frame arena.  Non-heap memory (stack,
 * statics, MMIO) is outside the tracking domain. */
#define KMSAN_HEAP_SHADOW_SIZE  (KALLOC_HEAP_SIZE / 8u)   /* 1 MiB */
#define KMSAN_FRAME_SHADOW_SIZE (16u * 1024u * 1024u / 8u) /* 2 MiB */

static uint8_t g_HeapShadow[KMSAN_HEAP_SHADOW_SIZE];
static uint8_t g_FrameShadow[KMSAN_FRAME_SHADOW_SIZE];
static uintptr_t s_HeapBase;
static uintptr_t s_FrameBase;
static uint64_t s_FrameSize;

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

static uint8_t* region_shadow(const void* Ptr, size_t Size, size_t* OutOff) {
    uintptr_t a = (uintptr_t)Ptr;

    if (a >= s_HeapBase && (size_t)(a - s_HeapBase) < KALLOC_HEAP_SIZE &&
        Size <= KALLOC_HEAP_SIZE - (size_t)(a - s_HeapBase)) {
        *OutOff = (size_t)(a - s_HeapBase);
        return g_HeapShadow;
    }
    if (a >= s_FrameBase && (uint64_t)(a - s_FrameBase) < s_FrameSize &&
        (uint64_t)Size <= s_FrameSize - (uint64_t)(a - s_FrameBase)) {
        *OutOff = (size_t)(a - s_FrameBase);
        return g_FrameShadow;
    }
    return (uint8_t*)0;
}

static void shadow_set_range(uint8_t* shadow, size_t Off, size_t Size, bool Uninit) {
    size_t i;

    for (i = 0u; i < Size; ++i) {
        size_t bit = Off + i;
        size_t shadow_i = bit >> 3;
        uint8_t mask = (uint8_t)(1u << (bit & 7u));

        if (Uninit) {
            shadow[shadow_i] |= mask;
        } else {
            shadow[shadow_i] &= (uint8_t)~mask;
        }
    }
}

static int shadow_find_uninit(const uint8_t* shadow, size_t Off, size_t Size) {
    size_t i;

    for (i = 0u; i < Size; ++i) {
        size_t bit = Off + i;
        size_t shadow_i = bit >> 3;
        uint8_t mask = (uint8_t)(1u << (bit & 7u));

        if ((shadow[shadow_i] & mask) != 0u) {
            return (int)i;
        }
    }
    return -1;
}

void OwKMSanReset(void) {
    s_HeapBase = OwKAllocArenaBase();
    s_FrameBase = OwMemArenaBase();
    s_FrameSize = OwMemArenaSize();
    /* Everything looks initialized at reset: tracking applies from here on,
     * and older untracked regions are not provably uninitialized. */
    ow_memset(g_HeapShadow, 0x00, sizeof(g_HeapShadow));
    ow_memset(g_FrameShadow, 0x00, sizeof(g_FrameShadow));
}

void OwKMSanNoteAlloc(const void* Ptr, size_t Size) {
    uint8_t* shadow;
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return;
    }
    shadow_set_range(shadow, off, Size, true);
}

void OwKMSanNoteInit(const void* Ptr, size_t Size) {
    uint8_t* shadow;
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return;
    }
    shadow_set_range(shadow, off, Size, false);
}

void OwKMSanNoteCopy(void* Dst, const void* Src, size_t CopyBytes, size_t NewBytes) {
    uint8_t* dshadow;
    uint8_t* sshadow;
    size_t dst_off;
    size_t src_off;
    size_t i;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    dshadow = region_shadow(Dst, NewBytes, &dst_off);
    if (!dshadow) {
        return;
    }
    sshadow = region_shadow(Src, CopyBytes, &src_off);
    for (i = 0u; i < CopyBytes; ++i) {
        size_t dbit = dst_off + i;
        size_t sbit = i + src_off;
        uint8_t bit = (uint8_t)(1u << (sbit & 7u));
        size_t dshadow_i = dbit >> 3;
        bool uninit = sshadow && ((sshadow[sbit >> 3] & bit) != 0u);

        if (uninit) {
            dshadow[dshadow_i] |= (uint8_t)(1u << (dbit & 7u));
        } else {
            dshadow[dshadow_i] &= (uint8_t)~(1u << (dbit & 7u));
        }
    }
    if (NewBytes > CopyBytes) {
        shadow_set_range(dshadow, dst_off + CopyBytes, NewBytes - CopyBytes, true);
    }
}

void OwKMSanNoteFree(const void* Ptr, size_t Size) {
    uint8_t* shadow;
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return;
    }
    shadow_set_range(shadow, off, Size, true); /* freed == uninitialized again */
}

void OwKMSanNoteUninit(const void* Ptr, size_t Size) {
    uint8_t* shadow;
    size_t off;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return;
    }
    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return;
    }
    shadow_set_range(shadow, off, Size, true);
}

OW_STATUS OwKMSanCheckRead(const void* Ptr, size_t Size, const char* Label) {
    uint8_t* shadow;
    size_t off;
    int at;

    if (!OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKMSAN)) {
        return OW_SUCCESS; /* module disabled: not tracked, not checked */
    }
    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return OW_SUCCESS; /* outside the tracked regions */
    }
    at = shadow_find_uninit(shadow, off, Size);
    if (at < 0) {
        return OW_SUCCESS;
    }
    OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKMSAN,
                 "%s: read of uninitialized byte %d of the allocation at %p",
                 Label ? Label : "?", at, Ptr);
    return OW_ERR_CORRUPT;
}

void OwKMSanMarkInit(const void* Ptr, size_t Size) {
    uint8_t* shadow;
    size_t off;

    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return;
    }
    shadow_set_range(shadow, off, Size, false);
}

void OwKMSanMarkUninit(const void* Ptr, size_t Size) {
    uint8_t* shadow;
    size_t off;

    shadow = region_shadow(Ptr, Size, &off);
    if (!shadow) {
        return;
    }
    shadow_set_range(shadow, off, Size, true);
}
