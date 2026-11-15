/* kdb_loader.c - loader front-end for associated kernels.
 *
 * Three image families are admitted:
 *
 *   OWX  - OpenWindows native images, validated with the same structural and
 *          CRC32c tests the main userspace loader uses.
 *   ELF  - ELF64 x86-64 foreign images (Linux/BSD/Unix/custom), parsed and
 *          bounded by kdb_elf.c.
 *   RAW  - a flat image whose layout is supplied by a composed manifest.
 *
 * The loader answers only "is this image admissible, and what would it cost?".
 * Whether this build can *execute* the ABI is a separate question, answered by
 * the ABI descriptor's ExecutionSupported bit and surfaced by the launch plan
 * as an ABI blocker.
 */
#include "kdb_internal.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_owx.h"

bool OwKdbLoaderSupportsKind(OW_KDB_KERNEL_KIND Kind) {
    switch (Kind) {
    case OW_KDB_KIND_NATIVE_OPENWINDOWS:
    case OW_KDB_KIND_STRIPPED_OPENWINDOWS:
    case OW_KDB_KIND_MODIFIED_OPENWINDOWS:
    case OW_KDB_KIND_LINUX:
    case OW_KDB_KIND_CUSTOM:
    case OW_KDB_KIND_BSD:
    case OW_KDB_KIND_UNIX:
        return true;
    default:
        return false;
    }
}

static OW_STATUS prepare_owx(const OW_KDB_KERNEL_DESC* Desc,
                             uint32_t* OutPages, uint64_t* OutEntry,
                             uint64_t* OutBase) {
    const owx_header_t* header;
    uint64_t pages;
    uint32_t image_size;

    if (Desc->Format != OW_KDB_FORMAT_OWX) {
        return OW_ERR_UNSUPPORTED;
    }
    if (Desc->Image == (const uint8_t*)0 || Desc->ImageSize == 0U) {
        if ((Desc->Flags & OW_KDB_DESC_DECLARATIVE) != 0U) {
            return OW_ERR_UNSUPPORTED;
        }
        return OW_ERR_NOT_FOUND;
    }
    if (Desc->ImageSize < OWX_HEADER_SIZE) {
        return OW_ERR_CORRUPT;
    }

    if (!OwOwxImageIsLoadable((const owx_header_t*)(const void*)Desc->Image,
                              Desc->ImageSize)) {
        return OW_ERR_CORRUPT;
    }
    if (!OwOwxImageIsUsable(Desc->Image, Desc->ImageSize)) {
        return OW_ERR_CORRUPT;
    }

    header = (const owx_header_t*)(const void*)Desc->Image;
    if (header->entry_point == 0U) {
        return OW_ERR_CORRUPT;
    }

    image_size = Desc->ImageSize;
    pages = ((uint64_t)image_size + (uint64_t)OW_PAGE_SIZE - 1ULL) /
            (uint64_t)OW_PAGE_SIZE;
    if (pages == 0ULL || pages > 0xFFFFFFFFULL) {
        return OW_ERR_CORRUPT;
    }

    if (OutPages != (uint32_t*)0) {
        *OutPages = (uint32_t)pages;
    }
    if (OutEntry != (uint64_t*)0) {
        *OutEntry = header->entry_point;
    }
    if (OutBase != (uint64_t*)0) {
        *OutBase = header->preferred_base;
    }
    return OW_SUCCESS;
}

/* An ELF image may carry the generic SYSV OSABI even when the ABI is a specific
 * BSD or Linux environment.  The check below is intentionally explicit: it
 * documents exactly which header values each ABI family accepts. */
static bool elf_osabi_allowed(const OW_KDB_ABI_DESC* Abi, uint32_t OsAbi) {
    switch (Abi->Family) {
    case OW_KDB_ABI_FAMILY_OPENWINDOWS:
        return OsAbi == OW_KDB_ELF_OSABI_SYSV;
    case OW_KDB_ABI_FAMILY_LINUX:
        return OsAbi == OW_KDB_ELF_OSABI_SYSV ||
               OsAbi == OW_KDB_ELF_OSABI_LINUX;
    case OW_KDB_ABI_FAMILY_BSD:
        if (Abi->ElfOsAbi == OW_KDB_ELF_OSABI_SYSV) {
            /* Generic BSD ABI: accept any recognised BSD flavour. */
            return OsAbi == OW_KDB_ELF_OSABI_SYSV ||
                   OsAbi == OW_KDB_ELF_OSABI_NETBSD ||
                   OsAbi == OW_KDB_ELF_OSABI_FREEBSD ||
                   OsAbi == OW_KDB_ELF_OSABI_OPENBSD;
        }
        return OsAbi == Abi->ElfOsAbi;
    case OW_KDB_ABI_FAMILY_UNIX:
        return OsAbi == OW_KDB_ELF_OSABI_SYSV;
    default:
        return Abi->ElfOsAbi == 0xFFU || OsAbi == Abi->ElfOsAbi;
    }
}

static OW_STATUS prepare_elf(const OW_KDB_KERNEL_DESC* Desc,
                             const OW_KDB_ABI_DESC* Abi,
                             uint32_t* OutPages, uint64_t* OutEntry,
                             uint64_t* OutBase) {
    OW_KDB_ELF_INFO info;
    OW_STATUS status;

    if (Desc->Format != OW_KDB_FORMAT_ELF) {
        return OW_ERR_UNSUPPORTED;
    }
    if (Desc->Image == (const uint8_t*)0 || Desc->ImageSize == 0U) {
        if ((Desc->Flags & OW_KDB_DESC_DECLARATIVE) != 0U) {
            return OW_ERR_UNSUPPORTED;
        }
        return OW_ERR_NOT_FOUND;
    }

    status = OwKdbElfParse(Desc->Image, Desc->ImageSize, 0xFFU, &info);
    if (ow_status_error(status)) {
        return status;
    }
    if (!info.Valid || info.ResidentPages == 0U || info.Entry == 0U) {
        return OW_ERR_CORRUPT;
    }
    if (!elf_osabi_allowed(Abi, info.OsAbi)) {
        return OW_ERR_UNSUPPORTED;
    }

    /* If the manifest documented an expected base/entry, the image must match
     * it.  A mismatch means the manifest and the image describe different
     * things, which is exactly the case a loader must refuse to guess about. */
    if (Abi->LoadBase != 0U && Abi->LoadBase != info.PreferredBase) {
        return OW_ERR_CORRUPT;
    }
    if (Abi->EntryPoint != 0U && Abi->EntryPoint != info.Entry) {
        return OW_ERR_CORRUPT;
    }

    if (OutPages != (uint32_t*)0) {
        *OutPages = info.ResidentPages;
    }
    if (OutEntry != (uint64_t*)0) {
        *OutEntry = info.Entry;
    }
    if (OutBase != (uint64_t*)0) {
        *OutBase = info.PreferredBase;
    }
    return OW_SUCCESS;
}

static OW_STATUS prepare_raw(const OW_KDB_KERNEL_DESC* Desc,
                             const OW_KDB_ABI_DESC* Abi,
                             uint32_t* OutPages, uint64_t* OutEntry,
                             uint64_t* OutBase) {
    uint64_t image_pages;
    uint64_t pages;
    uint64_t span_end;
    uint32_t i;

    if (Desc->Format != OW_KDB_FORMAT_RAW) {
        return OW_ERR_UNSUPPORTED;
    }
    if (Abi->EntryPoint == 0U || Abi->LoadBase == 0U) {
        return OW_ERR_UNSUPPORTED;
    }
    if (Desc->Image == (const uint8_t*)0 || Desc->ImageSize == 0U) {
        if ((Desc->Flags & OW_KDB_DESC_DECLARATIVE) != 0U) {
            return OW_ERR_UNSUPPORTED;
        }
        return OW_ERR_NOT_FOUND;
    }

    image_pages = ((uint64_t)Desc->ImageSize + (uint64_t)OW_PAGE_SIZE - 1ULL) /
                  (uint64_t)OW_PAGE_SIZE;
    pages = image_pages;
    span_end = Abi->LoadBase + (uint64_t)Desc->ImageSize;
    if (span_end < Abi->LoadBase) {
        return OW_ERR_CORRUPT;
    }

    /* Manifest segments describe memory the flat image represents.  A BSS-like
     * segment can make the resident cost larger than the file size; charge the
     * larger of the two, never the smaller. */
    for (i = 0U; i < Abi->SegmentCount; ++i) {
        const OW_KDB_ABI_SEGMENT* seg = &Abi->Segments[i];
        uint64_t seg_end = seg->VirtualAddress + seg->MemorySize;

        if (seg_end < seg->VirtualAddress) {
            return OW_ERR_CORRUPT;
        }
        if (seg_end > span_end) {
            span_end = seg_end;
        }
    }

    if (span_end > Abi->LoadBase) {
        uint64_t span_pages =
            ((span_end - Abi->LoadBase) + (uint64_t)OW_PAGE_SIZE - 1ULL) /
            (uint64_t)OW_PAGE_SIZE;
        if (span_pages > pages) {
            pages = span_pages;
        }
    }

    if (pages == 0U || pages > 0xFFFFFFFFULL) {
        return OW_ERR_CORRUPT;
    }
    if (!OwMemInUserWindow(Abi->EntryPoint)) {
        return OW_ERR_UNSUPPORTED;
    }
    if (Abi->SegmentCount == 0U) {
        if (Abi->EntryPoint < Abi->LoadBase ||
            Abi->EntryPoint >= Abi->LoadBase + (uint64_t)Desc->ImageSize) {
            return OW_ERR_CORRUPT;
        }
    }

    if (OutPages != (uint32_t*)0) {
        *OutPages = (uint32_t)pages;
    }
    if (OutEntry != (uint64_t*)0) {
        *OutEntry = Abi->EntryPoint;
    }
    if (OutBase != (uint64_t*)0) {
        *OutBase = Abi->LoadBase;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKdbLoaderPrepare(const OW_KDB_KERNEL_DESC* Desc,
                             uint32_t* OutPages, uint64_t* OutEntry,
                             uint64_t* OutBase) {
    const OW_KDB_ABI_DESC* abi;

    if (Desc == (const OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    abi = OwKdbAbiPtr(Desc->Abi);
    if (abi == (const OW_KDB_ABI_DESC*)0) {
        return OW_ERR_UNSUPPORTED;
    }
    if (abi->Format != Desc->Format) {
        return OW_ERR_UNSUPPORTED;
    }

    switch (Desc->Format) {
    case OW_KDB_FORMAT_OWX:
        return prepare_owx(Desc, OutPages, OutEntry, OutBase);
    case OW_KDB_FORMAT_ELF:
        return prepare_elf(Desc, abi, OutPages, OutEntry, OutBase);
    case OW_KDB_FORMAT_RAW:
        return prepare_raw(Desc, abi, OutPages, OutEntry, OutBase);
    default:
        return OW_ERR_UNSUPPORTED;
    }
}

bool OwKdbLoaderSupports(OW_KDB_KERNEL_KIND Kind) {
    if (!OwKdbIsReady()) {
        return false;
    }
    return OwKdbLoaderSupportsKind(Kind);
}

OW_STATUS OwKdbLoaderValidate(const OW_KDB_KERNEL_DESC* Desc,
                              uint32_t* OutResidentPages) {
    OW_KDB_COMPAT_REPORT report;
    OW_STATUS status;
    uint32_t pages = 0U;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutResidentPages == (uint32_t*)0) {
        return OW_ERR_NULL_POINTER;
    }

    status = OwKdbAssessCompatibility(Desc, &report);
    if (ow_status_error(status)) {
        return status;
    }

    status = OwKdbLoaderPrepare(Desc, &pages, (uint64_t*)0, (uint64_t*)0);
    if (ow_status_error(status)) {
        return status;
    }

    *OutResidentPages = pages;
    return OW_SUCCESS;
}
