/* owkintsan.c - OWKIntSan: integer overflow / arithmetic diagnostics (Phase 4) */
#include "../inc/owkintsan.h"

static int owkintsan_init(void) {
    return (int)OW_SUCCESS;
}

static void owkintsan_shutdown(void) {
    /* Stateless checks; nothing to release. */
}

static OW_KSAN_MODULE g_IntModule = {
    OW_KSAN_MODULE_NAME_OWKINTSAN,
    70u,
    true,
    (const char*)0,
    owkintsan_init,
    owkintsan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKIntSanRegister(void) {
    return OwKSanRegisterModule(&g_IntModule);
}

static bool owkintsan_enabled(void) {
    return OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKINTSAN);
}

OW_STATUS OwKIntSanAdd(uint64_t A, uint64_t B, uint64_t* Out) {
    uint64_t result;

    if (__builtin_add_overflow(A, B, &result)) {
        if (owkintsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINTSAN,
                         "unsigned add overflow: %llu + %llu",
                         (unsigned long long)A, (unsigned long long)B);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (uint64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKIntSanSub(uint64_t A, uint64_t B, uint64_t* Out) {
    uint64_t result;

    if (__builtin_sub_overflow(A, B, &result)) {
        if (owkintsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINTSAN,
                         "unsigned subtract overflow: %llu - %llu",
                         (unsigned long long)A, (unsigned long long)B);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (uint64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKIntSanMul(uint64_t A, uint64_t B, uint64_t* Out) {
    uint64_t result;

    if (__builtin_mul_overflow(A, B, &result)) {
        if (owkintsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINTSAN,
                         "unsigned multiply overflow: %llu * %llu",
                         (unsigned long long)A, (unsigned long long)B);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (uint64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKIntSanAllocSize(uint64_t Count, uint64_t Size, uint64_t* Out) {
    return OwKIntSanMul(Count, Size, Out);
}

OW_STATUS OwKIntSanPointerOffset(uint64_t Base, uint64_t Offset, uint64_t* Out) {
    return OwKIntSanAdd(Base, Offset, Out);
}

OW_STATUS OwKIntSanAddScaled(uint64_t Base, uint64_t Index, uint64_t Scale,
                             uint64_t* Out) {
    uint64_t scaled;
    uint64_t result;

    if (__builtin_mul_overflow(Index, Scale, &scaled)) {
        if (owkintsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINTSAN,
                         "scaled index overflow: %llu * %llu",
                         (unsigned long long)Index, (unsigned long long)Scale);
        }
        return OW_ERR_CORRUPT;
    }
    if (__builtin_add_overflow(Base, scaled, &result)) {
        if (owkintsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKINTSAN,
                         "indexed add overflow: %llu + %llu",
                         (unsigned long long)Base, (unsigned long long)scaled);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (uint64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKIntSanRangeSpan(uint64_t Base, uint64_t Size, uint64_t* OutEnd) {
    return OwKIntSanAdd(Base, Size, OutEnd);
}
