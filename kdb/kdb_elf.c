/* kdb_elf.c - ELF64 x86-64 image inspection for foreign associated kernels.
 *
 * The ELF path is a validator, not a linker and not an emulator.  It answers
 * the questions KDB must answer before a foreign image may be admitted:
 *
 *   - is the header structurally sound and the declared class/machine what the
 *     ABI says it is?
 *   - do all PT_LOAD segments lie inside the caller-provided image and inside
 *     the guarded user window?
 *   - is the entry point inside an executable load segment?
 *   - how many pages does the image occupy?
 *
 * Refusing to answer is always safe; inventing a mapping is not.  Every read is
 * bounded by ImageSize and every addition is checked for overflow.
 */
#include "kdb_internal.h"
#include "../inc/ow_memory.h"

#define ELF_PT_LOAD 1U
#define ELF_PF_X    1U
#define ELF_MACHINE_X86_64 0x3EU

static uint16_t rd16(const uint8_t* p) {
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t* p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static bool add_overflow_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (a > (uint64_t)0xFFFFFFFFFFFFFFFFULL - b) {
        return true;
    }
    *out = a + b;
    return false;
}

static bool is_power_of_two(uint64_t v) {
    return v != 0U && (v & (v - 1U)) == 0U;
}

static void elfinfo_zero(OW_KDB_ELF_INFO* Info) {
    Info->Valid = false;
    Info->Class = 0U;
    Info->Data = 0U;
    Info->OsAbi = 0U;
    Info->Type = 0U;
    Info->Machine = 0U;
    Info->EntryInExecutable = false;
    Info->Entry = 0U;
    Info->PreferredBase = 0U;
    Info->Limit = 0U;
    Info->SegmentCount = 0U;
    Info->LoadSegments = 0U;
    Info->ResidentPages = 0U;
}

OW_STATUS OwKdbElfParse(const uint8_t* Image, uint32_t ImageSize,
                        uint32_t ExpectedOsAbi, OW_KDB_ELF_INFO* OutInfo) {
    uint64_t phoff;
    uint64_t phnum;
    uint64_t phentsize;
    uint64_t ph_end;
    uint64_t min_va = 0U;
    uint64_t max_va = 0U;
    uint64_t entry;
    uint64_t bias = 0U;
    uint32_t load_count = 0U;
    uint32_t i;
    bool have_load = false;
    bool entry_ok = false;

    if (OutInfo == (OW_KDB_ELF_INFO*)0) {
        return OW_ERR_NULL_POINTER;
    }
    elfinfo_zero(OutInfo);

    if (Image == (const uint8_t*)0 || ImageSize < 64U) {
        return OW_ERR_CORRUPT;
    }
    if (Image[0] != 0x7FU || Image[1] != 'E' ||
        Image[2] != 'L' || Image[3] != 'F') {
        return OW_ERR_CORRUPT;
    }

    OutInfo->Class = Image[4];
    OutInfo->Data = Image[5];
    OutInfo->OsAbi = Image[7];
    OutInfo->Type = rd16(Image + 16);
    OutInfo->Machine = rd16(Image + 18);

    if (OutInfo->Class != OW_KDB_ELF_CLASS_64 ||
        OutInfo->Data != OW_KDB_ELF_DATA_LSB) {
        return OW_ERR_UNSUPPORTED;
    }
    if (ExpectedOsAbi != 0xFFU && (uint32_t)OutInfo->OsAbi != ExpectedOsAbi) {
        return OW_ERR_UNSUPPORTED;
    }
    if (OutInfo->Type != OW_KDB_ELF_TYPE_EXEC &&
        OutInfo->Type != OW_KDB_ELF_TYPE_DYN) {
        return OW_ERR_UNSUPPORTED;
    }
    if (OutInfo->Machine != ELF_MACHINE_X86_64 ||
        rd32(Image + 20) != 1U) {
        return OW_ERR_UNSUPPORTED;
    }
    if (rd16(Image + 52) < 64U) {
        return OW_ERR_CORRUPT;
    }

    phoff = rd64(Image + 32);
    phentsize = rd16(Image + 54);
    phnum = rd16(Image + 56);
    if (phnum == 0U || phentsize < 56U) {
        return OW_ERR_CORRUPT;
    }
    if (phnum > 256U) {
        return OW_ERR_UNSUPPORTED;
    }

    /* phoff + phnum*phentsize must fit both the file and 64-bit arithmetic. */
    {
        uint64_t table_size;
        if (phnum != 0U &&
            phentsize > ((uint64_t)0xFFFFFFFFFFFFFFFFULL) / phnum) {
            return OW_ERR_CORRUPT;
        }
        table_size = phnum * phentsize;
        if (add_overflow_u64(phoff, table_size, &ph_end) ||
            ph_end > (uint64_t)ImageSize) {
            return OW_ERR_CORRUPT;
        }
    }

    OutInfo->SegmentCount = (uint32_t)phnum;

    for (i = 0U; i < (uint32_t)phnum; ++i) {
        const uint8_t* ph = Image + phoff + (uint64_t)i * phentsize;
        uint32_t type = rd32(ph);
        uint64_t off;
        uint64_t vaddr;
        uint64_t filesz;
        uint64_t memsz;
        uint64_t align;
        uint64_t seg_end;
        uint64_t file_end;

        if (type != ELF_PT_LOAD) {
            continue;
        }

        off = rd64(ph + 8);
        vaddr = rd64(ph + 16);
        filesz = rd64(ph + 32);
        memsz = rd64(ph + 40);
        align = rd64(ph + 48);

        if (memsz == 0U) {
            continue;
        }
        if (filesz > memsz) {
            return OW_ERR_CORRUPT;
        }
        if (add_overflow_u64(off, filesz, &file_end) ||
            file_end > (uint64_t)ImageSize) {
            return OW_ERR_CORRUPT;
        }
        if (add_overflow_u64(vaddr, memsz, &seg_end)) {
            return OW_ERR_CORRUPT;
        }
        if (align > 1U) {
            if (!is_power_of_two(align)) {
                return OW_ERR_CORRUPT;
            }
            if ((vaddr % align) != (off % align)) {
                return OW_ERR_CORRUPT;
            }
        }

        if (!have_load) {
            min_va = vaddr;
            max_va = seg_end;
            have_load = true;
        } else {
            if (vaddr < min_va) {
                min_va = vaddr;
            }
            if (seg_end > max_va) {
                max_va = seg_end;
            }
        }

        ++load_count;
    }

    if (!have_load || load_count == 0U) {
        return OW_ERR_CORRUPT;
    }

    /* ET_DYN images are position independent, so place them at the user image
     * base.  ET_EXEC images keep their own addresses. */
    if (OutInfo->Type == OW_KDB_ELF_TYPE_DYN) {
        bias = OW_USER_IMAGE_BASE - min_va;
    }

    {
        uint64_t base = min_va + bias;
        uint64_t limit = max_va + bias;
        uint64_t span;
        uint64_t pages;

        if (base > limit) {
            return OW_ERR_CORRUPT;
        }
        base &= ~((uint64_t)OW_PAGE_SIZE - 1U);
        limit = (limit + (uint64_t)OW_PAGE_SIZE - 1U) &
                ~((uint64_t)OW_PAGE_SIZE - 1U);
        if (limit < base) {
            return OW_ERR_CORRUPT;
        }
        span = limit - base;
        if (span == 0U) {
            return OW_ERR_CORRUPT;
        }
        pages = span / (uint64_t)OW_PAGE_SIZE;
        if (pages == 0U || pages > 0xFFFFFFFFULL) {
            return OW_ERR_CORRUPT;
        }

        OutInfo->PreferredBase = base;
        OutInfo->Limit = limit;
        OutInfo->ResidentPages = (uint32_t)pages;

        /* Every segment's effective range must be inside the guarded user
         * window.  A foreign image that wants to live outside it is refused
         * here, before any loader or executor sees it. */
        for (i = 0U; i < (uint32_t)phnum; ++i) {
            const uint8_t* ph = Image + phoff + (uint64_t)i * phentsize;
            uint64_t vaddr;
            uint64_t memsz;
            uint64_t eff;
            uint64_t end;

            if (rd32(ph) != ELF_PT_LOAD) {
                continue;
            }
            vaddr = rd64(ph + 16);
            memsz = rd64(ph + 40);
            if (memsz == 0U) {
                continue;
            }
            if (add_overflow_u64(vaddr, bias, &eff) ||
                add_overflow_u64(eff, memsz, &end) || end < eff) {
                return OW_ERR_CORRUPT;
            }
            if (eff < base || end > limit ||
                eff < OW_USER_WINDOW_BASE || end > OW_USER_WINDOW_END) {
                return OW_ERR_UNSUPPORTED;
            }
        }
    }

    entry = rd64(Image + 24);
    if (add_overflow_u64(entry, bias, &entry)) {
        return OW_ERR_CORRUPT;
    }
    if (entry == 0U) {
        return OW_ERR_CORRUPT;
    }
    OutInfo->Entry = entry;

    /* The entry must be inside an executable PT_LOAD segment, not merely inside
     * the window: an entry into data is not an executable image. */
    for (i = 0U; i < (uint32_t)phnum; ++i) {
        const uint8_t* ph = Image + phoff + (uint64_t)i * phentsize;
        uint64_t vaddr;
        uint64_t memsz;
        uint64_t eff;
        uint64_t end;

        if (rd32(ph) != ELF_PT_LOAD) {
            continue;
        }
        if ((rd32(ph + 4) & ELF_PF_X) == 0U) {
            continue;
        }
        vaddr = rd64(ph + 16);
        memsz = rd64(ph + 40);
        if (memsz == 0U) {
            continue;
        }
        if (add_overflow_u64(vaddr, bias, &eff) ||
            add_overflow_u64(eff, memsz, &end)) {
            return OW_ERR_CORRUPT;
        }
        if (entry >= eff && entry < end) {
            entry_ok = true;
            break;
        }
    }
    if (!entry_ok) {
        return OW_ERR_CORRUPT;
    }

    OutInfo->LoadSegments = load_count;
    OutInfo->EntryInExecutable = true;
    OutInfo->Valid = true;
    return OW_SUCCESS;
}

OW_STATUS OwKdbElfInspect(const uint8_t* Image, uint32_t ImageSize,
                          OW_KDB_ELF_INFO* OutInfo) {
    /* Public inspection does not impose an OSABI: it reports what the image
     * says.  A caller that needs an ABI check uses OwKdbElfValidate or the
     * loader. */
    return OwKdbElfParse(Image, ImageSize, 0xFFU, OutInfo);
}

OW_STATUS OwKdbElfValidate(const uint8_t* Image, uint32_t ImageSize,
                           uint32_t ExpectedOsAbi,
                           uint32_t* OutResidentPages) {
    OW_KDB_ELF_INFO info;
    OW_STATUS status;

    if (OutResidentPages == (uint32_t*)0) {
        return OW_ERR_NULL_POINTER;
    }
    status = OwKdbElfParse(Image, ImageSize, ExpectedOsAbi, &info);
    if (ow_status_error(status)) {
        return status;
    }
    if (!info.Valid || info.ResidentPages == 0U) {
        return OW_ERR_CORRUPT;
    }
    *OutResidentPages = info.ResidentPages;
    return OW_SUCCESS;
}
