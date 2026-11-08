/* kdb_loader.c - loader front-end for associated kernels.
 *
 * There is one supported image family in this build: OWX1, validated with the
 * same structural and CRC32c tests the main userspace loader uses.  The kind
 * selects a policy label, not a different executable format.  Linux and custom
 * kinds are deliberately registered as unsupported backends: their descriptors
 * can be listed and assessed, but no image is ever accepted for them.
 */
#include "kdb_internal.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_owx.h"

bool OwKdbLoaderSupportsKind(OW_KDB_KERNEL_KIND Kind) {
    switch (Kind) {
    case OW_KDB_KIND_NATIVE_OPENWINDOWS:
    case OW_KDB_KIND_STRIPPED_OPENWINDOWS:
    case OW_KDB_KIND_MODIFIED_OPENWINDOWS:
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
    /* Usable implies loadable, but it is the stronger whole-image CRC32c
     * verdict and is what a load must act on.  Keeping both calls makes the
     * ordering explicit: structure first, contents second. */
    if (!OwOwxImageIsUsable(Desc->Image, Desc->ImageSize)) {
        return OW_ERR_CORRUPT;
    }

    header = (const owx_header_t*)(const void*)Desc->Image;
    if (header->entry_point == 0U) {
        return OW_ERR_CORRUPT;
    }

    /* Charge what the caller actually handed us, not a field inside the image:
     * the CIS block may live past header->image_size, and the caller's count is
     * the only size KDB can vouch for. */
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

OW_STATUS OwKdbLoaderPrepare(const OW_KDB_KERNEL_DESC* Desc,
                             uint32_t* OutPages, uint64_t* OutEntry,
                             uint64_t* OutBase) {
    if (Desc == (const OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    switch (Desc->Kind) {
    case OW_KDB_KIND_NATIVE_OPENWINDOWS:
    case OW_KDB_KIND_STRIPPED_OPENWINDOWS:
    case OW_KDB_KIND_MODIFIED_OPENWINDOWS:
        return prepare_owx(Desc, OutPages, OutEntry, OutBase);
    case OW_KDB_KIND_LINUX:
    case OW_KDB_KIND_CUSTOM:
        /* Recognised, not implemented.  Do not fall through to the OWX path:
         * an ELF or raw image is not an OWX image with a different label. */
        return OW_ERR_UNSUPPORTED;
    default:
        return OW_ERR_INVALID_PARAM;
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
