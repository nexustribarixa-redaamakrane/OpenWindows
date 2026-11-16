/* owkubsan.c - OWKUbSan: undefined-behavior detection (Phase 4) */
#include "../inc/owkubsan.h"

static int owkubsan_init(void) {
    return (int)OW_SUCCESS;
}

static void owkubsan_shutdown(void) {
    /* Stateless checks; nothing to release. */
}

static OW_KSAN_MODULE g_UbModule = {
    OW_KSAN_MODULE_NAME_OWKUBSAN,
    60u,
    true,
    (const char*)0,
    owkubsan_init,
    owkubsan_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKUbSanRegister(void) {
    return OwKSanRegisterModule(&g_UbModule);
}

static bool owkubsan_enabled(void) {
    return OwKSanIsEnabled(OW_KSAN_MODULE_NAME_OWKUBSAN);
}

OW_STATUS OwKUbSanShiftLeft(uint64_t Value, uint64_t Shift, uint32_t Width) {
    (void)Value;

    if (Width == 0u || Width > 64u) {
        return OW_ERR_INVALID_PARAM;
    }
    if (Shift >= (uint64_t)Width) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "shift left by %llu of a %u-bit value",
                         (unsigned long long)Shift, (unsigned)Width);
        }
        return OW_ERR_INVALID_PARAM;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanShiftRight(uint64_t Value, uint64_t Shift, uint32_t Width) {
    (void)Value;

    if (Width == 0u || Width > 64u) {
        return OW_ERR_INVALID_PARAM;
    }
    if (Shift >= (uint64_t)Width) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "shift right by %llu of a %u-bit value",
                         (unsigned long long)Shift, (unsigned)Width);
        }
        return OW_ERR_INVALID_PARAM;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanSignedAdd(int64_t A, int64_t B, int64_t* Out) {
    int64_t result;

    if (__builtin_add_overflow(A, B, &result)) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "signed add overflow: %lld + %lld",
                         (long long)A, (long long)B);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (int64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanSignedSub(int64_t A, int64_t B, int64_t* Out) {
    int64_t result;

    if (__builtin_sub_overflow(A, B, &result)) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "signed subtract overflow: %lld - %lld",
                         (long long)A, (long long)B);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (int64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanSignedMul(int64_t A, int64_t B, int64_t* Out) {
    int64_t result;

    if (__builtin_mul_overflow(A, B, &result)) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "signed multiply overflow: %lld * %lld",
                         (long long)A, (long long)B);
        }
        return OW_ERR_CORRUPT;
    }
    if (Out != (int64_t*)0) {
        *Out = result;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanDiv(int64_t Dividend, int64_t Divisor, int64_t* OutQuotient) {
    if (Divisor == 0) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "division by zero: %lld / 0", (long long)Dividend);
        }
        return OW_ERR_INVALID_PARAM;
    }
    if (Dividend == INT64_MIN && Divisor == -1) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "division overflow: INT64_MIN / -1");
        }
        return OW_ERR_CORRUPT;
    }
    if (OutQuotient != (int64_t*)0) {
        *OutQuotient = Dividend / Divisor;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanMod(int64_t Dividend, int64_t Divisor, int64_t* OutRemainder) {
    if (Divisor == 0) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "modulo by zero: %lld %% 0", (long long)Dividend);
        }
        return OW_ERR_INVALID_PARAM;
    }
    if (Dividend == INT64_MIN && Divisor == -1) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "modulo overflow: INT64_MIN % -1");
        }
        return OW_ERR_CORRUPT;
    }
    if (OutRemainder != (int64_t*)0) {
        *OutRemainder = Dividend % Divisor;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanAlign(const void* Ptr, uint64_t Alignment) {
    uintptr_t a = (uintptr_t)Ptr;

    if (Alignment == 0u || (Alignment & (Alignment - 1u)) != 0u) {
        return OW_ERR_INVALID_PARAM; /* alignment must be a non-zero power of two */
    }
    if ((a & (Alignment - 1u)) != 0u) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "misaligned pointer %p for alignment %llu",
                         Ptr, (unsigned long long)Alignment);
        }
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanEnum(int64_t Value, int64_t Min, int64_t Max) {
    if (Min > Max) {
        return OW_ERR_INVALID_PARAM;
    }
    if (Value < Min || Value > Max) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "enum value %lld outside range [%lld, %lld]",
                         (long long)Value, (long long)Min, (long long)Max);
        }
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKUbSanNull(const void* Ptr) {
    if (Ptr == (const void*)0) {
        if (owkubsan_enabled()) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKUBSAN,
                         "null pointer where non-null required");
        }
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}
