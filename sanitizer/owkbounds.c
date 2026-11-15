/* owkbounds.c - OWKBoundsSan: index/region/bounds diagnostics (Phase 2) */
#include "../inc/owkbounds.h"
#include "../inc/ow_mem.h"

static int owkbounds_init(void) {
    return (int)OW_SUCCESS;
}

static void owkbounds_shutdown(void) {
    /* Stateless diagnostics; nothing to release. */
}

static OW_KSAN_MODULE g_BoundsModule = {
    OW_KSAN_MODULE_NAME_OWKBOUNDSAN,
    30u,
    true,
    (const char*)0,
    owkbounds_init,
    owkbounds_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKBoundsSanRegister(void) {
    return OwKSanRegisterModule(&g_BoundsModule);
}

OW_STATUS OwKBoundsSanCheckIndex(const char* Label, uint32_t Index,
                                 uint32_t Count) {
    if (Index >= Count) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKBOUNDSAN,
                     "%s: index %u out of bounds (count %u)",
                     Label ? Label : "?", (unsigned)Index, (unsigned)Count);
        return OW_ERR_INVALID_PARAM;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKBoundsSanCheckRegion(const char* Label,
                                  const void* Base, size_t Size,
                                  const void* Access, size_t AccessSize) {
    uintptr_t base = (uintptr_t)Base;
    uintptr_t access = (uintptr_t)Access;
    uintptr_t access_end;
    uintptr_t base_end;

    if (Base == (const void*)0 && Size != 0u) {
        return OW_ERR_INVALID_PARAM;
    }
    if (Access == (const void*)0 && AccessSize != 0u) {
        return OW_ERR_INVALID_PARAM;
    }
    if (Base != (const void*)0) {
        base_end = base + Size;
        if (base_end < base) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKBOUNDSAN,
                         "%s: base+size wraps", Label ? Label : "?");
            return OW_ERR_INVALID_PARAM;
        }
        if (AccessSize == 0u) {
            return OW_SUCCESS;
        }
        access_end = access + AccessSize;
        if (access_end < access) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKBOUNDSAN,
                         "%s: access+size wraps", Label ? Label : "?");
            return OW_ERR_INVALID_PARAM;
        }
        if (access < base || access_end > base_end) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKBOUNDSAN,
                         "%s: access span [%p, %p) outside region [%p, %p)",
                         Label ? Label : "?", Access, (const void*)access_end,
                         Base, (const void*)base_end);
            return OW_ERR_INVALID_PARAM;
        }
        return OW_SUCCESS;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKBoundsSanCopy(void* Dst, size_t DstCapacity,
                           const void* Src, size_t CopyBytes) {
    if (Dst == (void*)0 || Src == (const void*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (CopyBytes > DstCapacity) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKBOUNDSAN,
                     "copy of %llu byte(s) into %llu-entry destination",
                     (unsigned long long)CopyBytes, (unsigned long long)DstCapacity);
        return OW_ERR_INVALID_PARAM;
    }
    ow_memcpy(Dst, Src, CopyBytes);
    return OW_SUCCESS;
}
