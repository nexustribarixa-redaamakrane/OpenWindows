/* owkpagesan.c - OWKPageSan: physical/virtual page-management diagnostics (Phase 2) */
#include "../inc/owkpagesan.h"
#include "../inc/ow_memory.h"

/* x86-64, LA48.  Leaf physical-address bits are [51:12] for 4K pages,
 * [51:21] for 2 MiB pages and [51:30] for 1 GiB pages; bits above page-frame
 * bit 51 are architectural-reserved and must be clear (NX bit 63 excluded). */
#define OW_PAGESAN_RSVD_ABOVE_51 0x7FF0000000000000ull /* bits [62:52] */
#define OW_PAGESAN_RSVD_9_10     0x0000000000000600ull /* bits [10:9]   */
#define OW_PAGESAN_ADDR_MASK     OW_PAGE_ADDR_MASK    /* bits [51:12] */

static int owkpage_init(void) {
    return (int)OW_SUCCESS;
}

static void owkpage_shutdown(void) {
    /* Read-only diagnostics; nothing to release. */
}

static OW_KSAN_MODULE g_PageModule = {
    OW_KSAN_MODULE_NAME_OWKPageSan,
    20u,
    true,
    (const char*)0,
    owkpage_init,
    owkpage_shutdown,
    false,
    OW_SUCCESS
};

OW_STATUS OwKPageSanRegister(void) {
    return OwKSanRegisterModule(&g_PageModule);
}

OW_STATUS OwKPageSanCheckPte(uint64_t Entry, uint32_t Level) {
    bool huge;
    uint64_t phys;
    uint64_t alignment;

    if (Level < OW_PAGESAN_LEVEL_PT || Level > OW_PAGESAN_LEVEL_PDPTE) {
        return OW_ERR_INVALID_PARAM;
    }
    if (!(Entry & OW_PAGE_PRESENT)) {
        /* A non-present entry carries no page-frame state to validate. */
        return OW_SUCCESS;
    }

    /* Reserved bits above physical bit 51 must be clear (NX bit 63 is legal). */
    if ((Entry & OW_PAGESAN_RSVD_ABOVE_51) != 0ull) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "leaf entry with reserved bits above PF bit 51: 0x%llX",
                     (unsigned long long)Entry);
        return OW_ERR_CORRUPT;
    }
    /* Bits [10:9] are reserved in every leaf. */
    if ((Entry & OW_PAGESAN_RSVD_9_10) != 0ull) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "leaf entry with reserved bits [10:9] set: 0x%llX",
                     (unsigned long long)Entry);
        return OW_ERR_CORRUPT;
    }

    huge = ((Level == OW_PAGESAN_LEVEL_PD || Level == OW_PAGESAN_LEVEL_PDPTE) &&
            ((Entry & OW_PAGE_HUGE) != 0ull));

    if (Level == OW_PAGESAN_LEVEL_PT && (Entry & OW_PAGE_HUGE) != 0ull) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "4K entry with PS bit set: 0x%llX",
                     (unsigned long long)Entry);
        return OW_ERR_CORRUPT;
    }

    phys = Entry & OW_PAGESAN_ADDR_MASK;

    if (!huge) {
        alignment = OW_PAGE_SIZE;
    } else if (Level == OW_PAGESAN_LEVEL_PD) {
        alignment = (uint64_t)OW_PAGE_SIZE * 512ull; /* 2 MiB */
    } else {
        alignment = (uint64_t)OW_PAGE_SIZE * 512ull * 512ull; /* 1 GiB */
    }

    if ((phys % alignment) != 0ull) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "huge-page frame base unaligned for level %u: 0x%llX",
                     (unsigned)Level, (unsigned long long)phys);
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKPageSanCheckFrameRange(uint64_t Base, uint32_t Pages) {
    uint64_t base = Base;
    uint64_t arena = (uint64_t)OwMemArenaBase();
    uint64_t total_bytes = (uint64_t)OwMemPagesTotal() * OW_PAGE_SIZE;
    uint64_t span;
    uint64_t end;
    uint32_t i;
    uint32_t windows;

    if (Pages == 0u) {
        return OW_ERR_INVALID_PARAM;
    }
    if ((base & (OW_PAGE_SIZE - 1u)) != 0ull) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "frame range base unaligned: 0x%llX",
                     (unsigned long long)base);
        return OW_ERR_CORRUPT;
    }
    span = (uint64_t)Pages * OW_PAGE_SIZE;
    if (span > ~(uint64_t)0 - base) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "frame range wraps the address space: base=0x%llX pages=%u",
                     (unsigned long long)base, (unsigned)Pages);
        return OW_ERR_CORRUPT;
    }
    end = base + span;

    if (base < arena || end > arena + total_bytes) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "frame range outside the kernel arena: base=0x%llX pages=%u",
                     (unsigned long long)base, (unsigned)Pages);
        return OW_ERR_CORRUPT;
    }

    windows = OwMemNonRamWindowCount();
    for (i = 0u; i < windows; ++i) {
        uint64_t lo = 0ull, hi = 0ull;

        if (OwMemNonRamWindow(i, &lo, &hi) != OW_SUCCESS) {
            return OW_ERR_INVALID_PARAM;
        }
        if (base < hi && end > lo) {
            OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                         "frame range overlaps a non-RAM window [0x%llX, 0x%llX)",
                         (unsigned long long)lo, (unsigned long long)hi);
            return OW_ERR_CORRUPT;
        }
    }
    return OW_SUCCESS;
}

OW_STATUS OwKPageSanAudit(OW_PAGESAN_REPORT* Out) {
    uint32_t total;
    uint32_t used;
    uint32_t commit;
    uint32_t limit;
    uint64_t arena;

    if (Out == (OW_PAGESAN_REPORT*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    total = OwMemPagesTotal();
    used = OwMemPagesUsed();
    commit = OwMemCommitTotal();
    limit = OwMemCommitLimit();
    arena = (uint64_t)OwMemArenaBase();

    Out->TotalPages = total;
    Out->UsedPages = used;
    Out->CommitTotal = commit;
    Out->CommitLimit = limit;
    Out->ArenaBytes = (uint64_t)total * OW_PAGE_SIZE;
    Out->Errors = 0u;

    if (used > total) {
        Out->Errors++;
    }
    if (commit > limit) {
        Out->Errors++;
    }
    if ((arena & (OW_PAGE_SIZE - 1u)) != 0ull) {
        Out->Errors++;
    }
    if (Out->Errors != 0u) {
        OwKSanReport(OW_KSAN_SEVERITY_ERROR, OW_KSAN_MODULE_NAME_OWKPageSan,
                     "frame allocator invariant violated: %u error(s)",
                     (unsigned)Out->Errors);
        return OW_ERR_CORRUPT;
    }
    return OW_SUCCESS;
}
