/* kdb_sweep.c - Sweep reference associated kernel.
 *
 * Sweep is the primary reference KAPA application: a stripped-down OpenWindows
 * kernel that belongs to an application and consumes a small, explicit set of
 * main-kernel services through the Service Bridge.  There is no Sweep
 * implementation in this repository, so KDB cannot load a checked-in Sweep
 * image.  What it can do -- and does -- is register the reference descriptor
 * during initialization and expose a fixture seam for a real OWX image.
 *
 * With no image the descriptor is DECLARATIVE: it appears in the registry and
 * is assessed as architecture/ABI compatible, but loading it is refused.  That
 * state is deliberate.  Pretending a metadata-only entry was runnable would be
 * exactly the kind of untested claim KDB is supposed to prevent.
 */
#include "kdb_internal.h"

OW_STATUS OwKdbRegisterSweep(const uint8_t* Image, uint32_t ImageSize,
                             uint32_t* OutKernelId) {
    OW_KDB_KERNEL_DESC desc;

    if ((Image == (const uint8_t*)0 && ImageSize != 0U) ||
        (Image != (const uint8_t*)0 && ImageSize == 0U)) {
        return OW_ERR_INVALID_PARAM;
    }

    (void)OwKdbCopyName(desc.Name, OW_KDB_MAX_NAME, OW_KDB_SWEEP_NAME);
    desc.Kind = OW_KDB_KIND_STRIPPED_OPENWINDOWS;
    desc.Abi = OW_KDB_ABI_OPENWINDOWS_COMPAT;
    desc.Format = OW_KDB_FORMAT_OWX;
    desc.MemoryModel = OW_KDB_MEMORY_PRIVATE;
    desc.PrivilegeModel = OW_KDB_PRIVILEGE_UNPRIVILEGED;
    desc.TargetArch = OW_KDB_ARCH_X86_64;
    desc.Flags = (Image == (const uint8_t*)0) ? OW_KDB_DESC_DECLARATIVE : 0U;
    desc.PreferredBase = 0U;
    desc.Image = Image;
    desc.ImageSize = ImageSize;

    return OwKdbRegistryStore(&desc, OutKernelId);
}

OW_STATUS OwKdbAttachSweepImage(const uint8_t* Image, uint32_t ImageSize) {
    uint32_t kernel_id;
    OW_STATUS status;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (Image == (const uint8_t*)0 || ImageSize == 0U) {
        return OW_ERR_INVALID_PARAM;
    }

    status = OwKdbRegistryFind(OW_KDB_SWEEP_NAME, &kernel_id);
    if (ow_status_error(status)) {
        return status;
    }
    return OwKdbRegistrySetImage(kernel_id, Image, ImageSize);
}
