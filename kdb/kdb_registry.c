/* kdb_registry.c - associated-kernel descriptors and compatibility policy.
 *
 * Registration is metadata only: it records what an associated kernel claims
 * to be.  Image validation belongs to the loader and resource admission to the
 * manager.  Keeping those apart is what lets KDB list an incompatible or
 * unimplemented kernel honestly instead of either pretending it is usable or
 * hiding it from an operator.
 */
#include "kdb_internal.h"

static OW_KDB_KERNEL_DESC g_Kernels[OW_KDB_MAX_KERNELS];
static bool               g_KernelInUse[OW_KDB_MAX_KERNELS];

static bool name_terminated(const char* Name) {
    uint32_t i;

    if (Name == (const char*)0) {
        return false;
    }
    for (i = 0U; i < OW_KDB_MAX_NAME; ++i) {
        if (Name[i] == '\0') {
            return i != 0U;
        }
    }
    return false;
}

static bool descriptor_valid(const OW_KDB_KERNEL_DESC* Desc) {
    if (Desc == (const OW_KDB_KERNEL_DESC*)0) {
        return false;
    }
    if (!name_terminated(Desc->Name)) {
        return false;
    }
    if (Desc->Kind < OW_KDB_KIND_NATIVE_OPENWINDOWS ||
        Desc->Kind > OW_KDB_KIND_CUSTOM) {
        return false;
    }
    if (Desc->Image == (const uint8_t*)0 && Desc->ImageSize != 0U) {
        return false;
    }
    if (Desc->Image != (const uint8_t*)0 && Desc->ImageSize == 0U) {
        return false;
    }
    return true;
}

void OwKdbRegistryReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_KERNELS; ++i) {
        g_KernelInUse[i] = false;
    }
}

OW_STATUS OwKdbRegistryStore(const OW_KDB_KERNEL_DESC* Desc,
                             uint32_t* OutKernelId) {
    uint32_t i;
    uint32_t free_slot = OW_KDB_MAX_KERNELS;

    if (!descriptor_valid(Desc)) {
        return OW_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < OW_KDB_MAX_KERNELS; ++i) {
        if (g_KernelInUse[i]) {
            if (OwKdbNameEqual(g_Kernels[i].Name, Desc->Name)) {
                return OW_ERR_ALREADY_EXISTS;
            }
        } else if (free_slot == OW_KDB_MAX_KERNELS) {
            free_slot = i;
        }
    }

    if (free_slot == OW_KDB_MAX_KERNELS) {
        return OW_ERR_INSUFFICIENT;
    }

    g_Kernels[free_slot] = *Desc;
    /* The copy is bounded by the descriptor's own contract above; re-copying
     * through the helper makes the NUL explicit even if a caller filled the
     * array exactly. */
    (void)OwKdbCopyName(g_Kernels[free_slot].Name, OW_KDB_MAX_NAME, Desc->Name);
    g_KernelInUse[free_slot] = true;

    if (OutKernelId != (uint32_t*)0) {
        *OutKernelId = free_slot + 1U;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKdbRegistryGet(uint32_t KernelId, OW_KDB_KERNEL_DESC* OutDesc) {
    if (KernelId == OW_KDB_INVALID_ID || OutDesc == (OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (KernelId > OW_KDB_MAX_KERNELS ||
        !g_KernelInUse[KernelId - 1U]) {
        return OW_ERR_NOT_FOUND;
    }

    *OutDesc = g_Kernels[KernelId - 1U];
    return OW_SUCCESS;
}

OW_STATUS OwKdbRegistryFind(const char* Name, uint32_t* OutKernelId) {
    uint32_t i;

    if (Name == (const char*)0 || OutKernelId == (uint32_t*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < OW_KDB_MAX_KERNELS; ++i) {
        if (g_KernelInUse[i] && OwKdbNameEqual(g_Kernels[i].Name, Name)) {
            *OutKernelId = i + 1U;
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

const OW_KDB_KERNEL_DESC* OwKdbRegistryPtr(uint32_t KernelId) {
    if (KernelId == OW_KDB_INVALID_ID || KernelId > OW_KDB_MAX_KERNELS ||
        !g_KernelInUse[KernelId - 1U]) {
        return (const OW_KDB_KERNEL_DESC*)0;
    }
    return &g_Kernels[KernelId - 1U];
}

OW_STATUS OwKdbRegistrySetImage(uint32_t KernelId, const uint8_t* Image,
                                uint32_t ImageSize) {
    if (KernelId == OW_KDB_INVALID_ID || KernelId > OW_KDB_MAX_KERNELS ||
        !g_KernelInUse[KernelId - 1U]) {
        return OW_ERR_NOT_FOUND;
    }
    if (Image == (const uint8_t*)0 || ImageSize == 0U) {
        return OW_ERR_INVALID_PARAM;
    }

    g_Kernels[KernelId - 1U].Image = Image;
    g_Kernels[KernelId - 1U].ImageSize = ImageSize;
    g_Kernels[KernelId - 1U].Flags &= ~OW_KDB_DESC_DECLARATIVE;
    return OW_SUCCESS;
}

OW_STATUS OwKdbRegistryRemove(uint32_t KernelId) {
    if (KernelId == OW_KDB_INVALID_ID || KernelId > OW_KDB_MAX_KERNELS ||
        !g_KernelInUse[KernelId - 1U]) {
        return OW_ERR_NOT_FOUND;
    }
    if (OwKdbAssociationKernelInUse(KernelId)) {
        return OW_ERR_INSUFFICIENT;
    }

    g_KernelInUse[KernelId - 1U] = false;
    return OW_SUCCESS;
}

uint32_t OwKdbRegistryCount(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KDB_MAX_KERNELS; ++i) {
        if (g_KernelInUse[i]) {
            ++count;
        }
    }
    return count;
}

/* ---- Compatibility policy ---------------------------------------------- */
static OW_STATUS report_set(OW_KDB_COMPAT_REPORT* Out,
                            OW_KDB_COMPATIBILITY Verdict,
                            OW_STATUS Status, const char* Reason) {
    if (Out != (OW_KDB_COMPAT_REPORT*)0) {
        Out->Verdict = Verdict;
        Out->Status = Status;
        Out->Reason = Reason;
    }
    return Status;
}

OW_STATUS OwKdbAssessCompatibility(const OW_KDB_KERNEL_DESC* Desc,
                                   OW_KDB_COMPAT_REPORT* OutReport) {
    if (OutReport == (OW_KDB_COMPAT_REPORT*)0) {
        return OW_ERR_NULL_POINTER;
    }

    if (!descriptor_valid(Desc)) {
        return report_set(OutReport, OW_KDB_COMPAT_INVALID_DESCRIPTOR,
                          OW_ERR_INVALID_PARAM,
                          "descriptor name or image metadata is malformed");
    }

    if (Desc->TargetArch != OW_KDB_ARCH_X86_64) {
        return report_set(OutReport, OW_KDB_COMPAT_ARCH_MISMATCH,
                          OW_ERR_UNSUPPORTED,
                          "target architecture is not x86-64");
    }

    switch (Desc->Kind) {
    case OW_KDB_KIND_NATIVE_OPENWINDOWS:
        if (Desc->Abi != OW_KDB_ABI_OPENWINDOWS_NATIVE) {
            return report_set(OutReport, OW_KDB_COMPAT_ABI_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "native OpenWindows kernel requires the native ABI");
        }
        break;
    case OW_KDB_KIND_STRIPPED_OPENWINDOWS:
        if (Desc->Abi != OW_KDB_ABI_OPENWINDOWS_NATIVE &&
            Desc->Abi != OW_KDB_ABI_OPENWINDOWS_COMPAT) {
            return report_set(OutReport, OW_KDB_COMPAT_ABI_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "stripped OpenWindows kernel requires an OpenWindows ABI");
        }
        break;
    case OW_KDB_KIND_MODIFIED_OPENWINDOWS:
        if (Desc->Abi != OW_KDB_ABI_OPENWINDOWS_COMPAT) {
            return report_set(OutReport, OW_KDB_COMPAT_ABI_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "modified OpenWindows kernel requires the compatibility ABI");
        }
        break;
    case OW_KDB_KIND_LINUX:
        if (Desc->Abi != OW_KDB_ABI_LINUX_X86_64) {
            return report_set(OutReport, OW_KDB_COMPAT_ABI_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "Linux descriptor does not carry the Linux x86-64 ABI");
        }
        break;
    case OW_KDB_KIND_CUSTOM:
        if (Desc->Abi != OW_KDB_ABI_CUSTOM) {
            return report_set(OutReport, OW_KDB_COMPAT_ABI_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "custom kernel descriptor does not carry the custom ABI");
        }
        break;
    default:
        return report_set(OutReport, OW_KDB_COMPAT_UNSUPPORTED_KIND,
                          OW_ERR_UNSUPPORTED,
                          "unknown associated-kernel kind");
    }

    if (Desc->Kind == OW_KDB_KIND_LINUX) {
        if (Desc->Format != OW_KDB_FORMAT_ELF) {
            return report_set(OutReport, OW_KDB_COMPAT_FORMAT_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "Linux associated kernel requires ELF");
        }
    } else if (Desc->Kind == OW_KDB_KIND_CUSTOM) {
        if (Desc->Format != OW_KDB_FORMAT_RAW) {
            return report_set(OutReport, OW_KDB_COMPAT_FORMAT_MISMATCH,
                              OW_ERR_UNSUPPORTED,
                              "custom associated kernel requires a raw image");
        }
    } else if (Desc->Format != OW_KDB_FORMAT_OWX) {
        return report_set(OutReport, OW_KDB_COMPAT_FORMAT_MISMATCH,
                          OW_ERR_UNSUPPORTED,
                          "OpenWindows associated kernel requires OWX");
    }

    /* No associated kernel is handed shared memory or kernel-equivalent
     * privilege by this build.  A descriptor that asks for either is refused
     * explicitly rather than being loaded under an isolation assumption the
     * implementation does not keep. */
    if (Desc->MemoryModel != OW_KDB_MEMORY_PRIVATE) {
        return report_set(OutReport, OW_KDB_COMPAT_MEMORY_MODEL,
                          OW_ERR_UNSUPPORTED,
                          "associated kernel must own a private memory model");
    }
    if (Desc->PrivilegeModel != OW_KDB_PRIVILEGE_UNPRIVILEGED) {
        return report_set(OutReport, OW_KDB_COMPAT_PRIVILEGE_MODEL,
                          OW_ERR_UNSUPPORTED,
                          "associated kernel must run unprivileged");
    }

    /* The metadata may be perfectly coherent and still have no adapter.  The
     * two verdicts stay distinct so an operator can tell "wrong ABI" from
     * "right ABI, not implemented yet". */
    if (Desc->Kind == OW_KDB_KIND_LINUX || Desc->Kind == OW_KDB_KIND_CUSTOM) {
        return report_set(OutReport, OW_KDB_COMPAT_UNSUPPORTED_KIND,
                          OW_ERR_UNSUPPORTED,
                          "this build has no loader adapter for that kernel kind");
    }

    return report_set(OutReport, OW_KDB_COMPATIBLE, OW_SUCCESS,
                      "compatible with the OpenWindows KDB loader");
}

/* ---- Public registry wrappers ------------------------------------------ */
OW_STATUS OwKdbRegisterKernel(const OW_KDB_KERNEL_DESC* Desc,
                              uint32_t* OutKernelId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbRegistryStore(Desc, OutKernelId);
}

OW_STATUS OwKdbUnregisterKernel(uint32_t KernelId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbRegistryRemove(KernelId);
}

OW_STATUS OwKdbGetKernel(uint32_t KernelId, OW_KDB_KERNEL_DESC* OutDesc) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbRegistryGet(KernelId, OutDesc);
}

OW_STATUS OwKdbFindKernel(const char* Name, uint32_t* OutKernelId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbRegistryFind(Name, OutKernelId);
}

OW_STATUS OwKdbGetKernelByIndex(uint32_t Index, OW_KDB_KERNEL_DESC* OutDesc) {
    uint32_t i;
    uint32_t seen = 0U;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutDesc == (OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_NULL_POINTER;
    }

    for (i = 0U; i < OW_KDB_MAX_KERNELS; ++i) {
        if (g_KernelInUse[i]) {
            if (seen == Index) {
                *OutDesc = g_Kernels[i];
                return OW_SUCCESS;
            }
            ++seen;
        }
    }
    return OW_ERR_NOT_FOUND;
}

uint32_t OwKdbKernelCount(void) {
    return OwKdbRegistryCount();
}
