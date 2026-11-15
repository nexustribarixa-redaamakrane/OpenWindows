/* kdb_abi.c - ABI registry for associated kernels.
 *
 * A kernel descriptor says *what the image is*; an ABI descriptor says what
 * environment that image expects and how this build treats it.  Keeping the two
 * apart is what lets KDB admit Linux/BSD/Unix/custom images as first-class
 * managed objects while still reporting honestly that this build has no
 * execution path for a foreign ABI.
 *
 * The registry is static and bounded.  Built-ins are installed during
 * OwKdbInitialize(); manifest-composed custom ABIs join the same table and are
 * removed with the rest of KDB state.
 */
#include "kdb_internal.h"

static OW_KDB_ABI_DESC g_Abis[OW_KDB_MAX_ABIS];
static bool            g_AbiInUse[OW_KDB_MAX_ABIS];

static void abi_zero(OW_KDB_ABI_DESC* Abi) {
    uint32_t i;

    Abi->Id = OW_KDB_INVALID_ID;
    for (i = 0U; i < OW_KDB_MAX_NAME; ++i) {
        Abi->Name[i] = '\0';
    }
    Abi->Family = OW_KDB_ABI_FAMILY_OPENWINDOWS;
    Abi->Kind = OW_KDB_KIND_NATIVE_OPENWINDOWS;
    Abi->Format = OW_KDB_FORMAT_OWX;
    Abi->TargetArch = OW_KDB_ARCH_X86_64;
    Abi->ElfOsAbi = OW_KDB_ELF_OSABI_SYSV;
    Abi->Origin = OW_KDB_ABI_ORIGIN_BUILTIN;
    Abi->Flags = 0U;
    Abi->LoadBase = 0U;
    Abi->EntryPoint = 0U;
    Abi->SegmentCount = 0U;
    for (i = 0U; i < OW_KDB_MAX_ABI_SEGMENTS; ++i) {
        Abi->Segments[i].Name[0] = '\0';
        Abi->Segments[i].VirtualAddress = 0U;
        Abi->Segments[i].FileOffset = 0U;
        Abi->Segments[i].FileSize = 0U;
        Abi->Segments[i].MemorySize = 0U;
        Abi->Segments[i].Flags = 0U;
    }
    Abi->ExecutionSupported = false;
}

static void abi_name(OW_KDB_ABI_DESC* Abi, const char* Name) {
    (void)OwKdbCopyName(Abi->Name, OW_KDB_MAX_NAME, Name);
}

static OW_STATUS abi_add(uint32_t Id, const char* Name,
                         OW_KDB_ABI_FAMILY Family, OW_KDB_KERNEL_KIND Kind,
                         uint32_t Format, uint32_t ElfOsAbi) {
    OW_KDB_ABI_DESC abi;
    uint32_t out_id = OW_KDB_INVALID_ID;

    abi_zero(&abi);
    abi.Id = Id;
    abi_name(&abi, Name);
    abi.Family = Family;
    abi.Kind = Kind;
    abi.Format = Format;
    abi.ElfOsAbi = ElfOsAbi;
    abi.Origin = OW_KDB_ABI_ORIGIN_BUILTIN;
    abi.ExecutionSupported = (Format == OW_KDB_FORMAT_OWX);
    return OwKdbAbiRegister(&abi, &out_id);
}

void OwKdbAbiReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        g_AbiInUse[i] = false;
    }
}

static bool abi_valid(const OW_KDB_ABI_DESC* Abi) {
    if (Abi == (const OW_KDB_ABI_DESC*)0) {
        return false;
    }
    if (Abi->Id == OW_KDB_INVALID_ID || Abi->Name[0] == '\0') {
        return false;
    }
    if (Abi->Family < OW_KDB_ABI_FAMILY_OPENWINDOWS ||
        Abi->Family > OW_KDB_ABI_FAMILY_CUSTOM) {
        return false;
    }
    if (Abi->Kind < OW_KDB_KIND_NATIVE_OPENWINDOWS ||
        Abi->Kind > OW_KDB_KIND_UNIX) {
        return false;
    }
    if (Abi->Format != OW_KDB_FORMAT_OWX &&
        Abi->Format != OW_KDB_FORMAT_ELF &&
        Abi->Format != OW_KDB_FORMAT_RAW) {
        return false;
    }
    if (Abi->TargetArch != OW_KDB_ARCH_X86_64) {
        return false;
    }
    if (Abi->SegmentCount > OW_KDB_MAX_ABI_SEGMENTS) {
        return false;
    }
    return true;
}

uint32_t OwKdbAbiAllocateCustomId(void) {
    uint32_t id;

    for (id = OW_KDB_ABI_CUSTOM_BASE + 2U; id <= OW_KDB_ABI_CUSTOM_MAX; ++id) {
        uint32_t i;
        bool used = false;

        for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
            if (g_AbiInUse[i] && g_Abis[i].Id == id) {
                used = true;
                break;
            }
        }
        if (!used) {
            return id;
        }
    }
    return OW_KDB_INVALID_ID;
}

OW_STATUS OwKdbAbiRegister(const OW_KDB_ABI_DESC* Abi, uint32_t* OutAbiId) {
    uint32_t i;
    uint32_t free_slot = OW_KDB_MAX_ABIS;

    if (!abi_valid(Abi)) {
        return OW_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i]) {
            if (g_Abis[i].Id == Abi->Id ||
                OwKdbNameEqual(g_Abis[i].Name, Abi->Name)) {
                return OW_ERR_ALREADY_EXISTS;
            }
        } else if (free_slot == OW_KDB_MAX_ABIS) {
            free_slot = i;
        }
    }
    if (free_slot == OW_KDB_MAX_ABIS) {
        return OW_ERR_INSUFFICIENT;
    }

    g_Abis[free_slot] = *Abi;
    (void)OwKdbCopyName(g_Abis[free_slot].Name, OW_KDB_MAX_NAME, Abi->Name);
    g_Abis[free_slot].ExecutionSupported =
        (Abi->Format == OW_KDB_FORMAT_OWX);
    g_AbiInUse[free_slot] = true;

    if (OutAbiId != (uint32_t*)0) {
        *OutAbiId = Abi->Id;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKdbAbiGet(uint32_t AbiId, OW_KDB_ABI_DESC* OutAbi) {
    uint32_t i;

    if (AbiId == OW_KDB_INVALID_ID || OutAbi == (OW_KDB_ABI_DESC*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i] && g_Abis[i].Id == AbiId) {
            *OutAbi = g_Abis[i];
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

const OW_KDB_ABI_DESC* OwKdbAbiPtr(uint32_t AbiId) {
    uint32_t i;

    if (AbiId == OW_KDB_INVALID_ID) {
        return (const OW_KDB_ABI_DESC*)0;
    }
    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i] && g_Abis[i].Id == AbiId) {
            return &g_Abis[i];
        }
    }
    return (const OW_KDB_ABI_DESC*)0;
}

static uint32_t abi_count_internal(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i]) {
            ++count;
        }
    }
    return count;
}

OW_STATUS OwKdbAbiInitializeBuiltins(void) {
    OW_STATUS status;

    status = abi_add(OW_KDB_ABI_OPENWINDOWS_NATIVE, "openwindows.native",
                     OW_KDB_ABI_FAMILY_OPENWINDOWS,
                     OW_KDB_KIND_NATIVE_OPENWINDOWS,
                     OW_KDB_FORMAT_OWX, OW_KDB_ELF_OSABI_SYSV);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_OPENWINDOWS_COMPAT, "openwindows.compat",
                     OW_KDB_ABI_FAMILY_OPENWINDOWS,
                     OW_KDB_KIND_MODIFIED_OPENWINDOWS,
                     OW_KDB_FORMAT_OWX, OW_KDB_ELF_OSABI_SYSV);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_LINUX_X86_64, "linux.x86_64",
                     OW_KDB_ABI_FAMILY_LINUX, OW_KDB_KIND_LINUX,
                     OW_KDB_FORMAT_ELF, OW_KDB_ELF_OSABI_LINUX);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_BSD_X86_64, "bsd.x86_64",
                     OW_KDB_ABI_FAMILY_BSD, OW_KDB_KIND_BSD,
                     OW_KDB_FORMAT_ELF, OW_KDB_ELF_OSABI_SYSV);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_FREEBSD_X86_64, "freebsd.x86_64",
                     OW_KDB_ABI_FAMILY_BSD, OW_KDB_KIND_BSD,
                     OW_KDB_FORMAT_ELF, OW_KDB_ELF_OSABI_FREEBSD);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_NETBSD_X86_64, "netbsd.x86_64",
                     OW_KDB_ABI_FAMILY_BSD, OW_KDB_KIND_BSD,
                     OW_KDB_FORMAT_ELF, OW_KDB_ELF_OSABI_NETBSD);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_OPENBSD_X86_64, "openbsd.x86_64",
                     OW_KDB_ABI_FAMILY_BSD, OW_KDB_KIND_BSD,
                     OW_KDB_FORMAT_ELF, OW_KDB_ELF_OSABI_OPENBSD);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_UNIX_SYSV_X86_64, "unix.sysv.x86_64",
                     OW_KDB_ABI_FAMILY_UNIX, OW_KDB_KIND_UNIX,
                     OW_KDB_FORMAT_ELF, OW_KDB_ELF_OSABI_SYSV);
    if (ow_status_error(status)) {
        return status;
    }
    status = abi_add(OW_KDB_ABI_CUSTOM, "custom.generic",
                     OW_KDB_ABI_FAMILY_CUSTOM, OW_KDB_KIND_CUSTOM,
                     OW_KDB_FORMAT_RAW, OW_KDB_ELF_OSABI_SYSV);
    if (ow_status_error(status)) {
        return status;
    }
    return OW_SUCCESS;
}

/* ---- Public queries ------------------------------------------------------ */
const char* OwKdbAbiFamilyName(OW_KDB_ABI_FAMILY Family) {
    switch (Family) {
    case OW_KDB_ABI_FAMILY_OPENWINDOWS: return "openwindows";
    case OW_KDB_ABI_FAMILY_LINUX:       return "linux";
    case OW_KDB_ABI_FAMILY_BSD:         return "bsd";
    case OW_KDB_ABI_FAMILY_UNIX:        return "unix";
    case OW_KDB_ABI_FAMILY_CUSTOM:      return "custom";
    default:                            return "unknown";
    }
}

const char* OwKdbAbiOriginName(OW_KDB_ABI_ORIGIN Origin) {
    switch (Origin) {
    case OW_KDB_ABI_ORIGIN_BUILTIN:  return "builtin";
    case OW_KDB_ABI_ORIGIN_MANIFEST: return "manifest";
    default:                         return "unknown";
    }
}

OW_STATUS OwKdbGetAbi(uint32_t AbiId, OW_KDB_ABI_DESC* OutAbi) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbAbiGet(AbiId, OutAbi);
}

OW_STATUS OwKdbGetAbiByIndex(uint32_t Index, OW_KDB_ABI_DESC* OutAbi) {
    uint32_t i;
    uint32_t seen = 0U;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (OutAbi == (OW_KDB_ABI_DESC*)0) {
        return OW_ERR_NULL_POINTER;
    }
    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i]) {
            if (seen == Index) {
                *OutAbi = g_Abis[i];
                return OW_SUCCESS;
            }
            ++seen;
        }
    }
    return OW_ERR_NOT_FOUND;
}

OW_STATUS OwKdbFindAbi(const char* Name, uint32_t* OutAbiId) {
    uint32_t i;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (Name == (const char*)0 || OutAbiId == (uint32_t*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i] && OwKdbNameEqual(g_Abis[i].Name, Name)) {
            *OutAbiId = g_Abis[i].Id;
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

uint32_t OwKdbAbiCount(void) {
    if (!OwKdbIsReady()) {
        return 0U;
    }
    return abi_count_internal();
}

OW_STATUS OwKdbAbiComposeCustom(const OW_KDB_MANIFEST_FILE* Files,
                                uint32_t FileCount, uint32_t* OutAbiId) {
    OW_KDB_ABI_DESC abi;
    OW_STATUS status;
    uint32_t id;
    uint32_t out_id = OW_KDB_INVALID_ID;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (Files == (const OW_KDB_MANIFEST_FILE*)0 || FileCount == 0U ||
        FileCount > OW_KDB_MAX_MANIFEST_FILES) {
        return OW_ERR_INVALID_PARAM;
    }

    abi_zero(&abi);
    status = OwKdbManifestCompose(Files, FileCount, &abi);
    if (ow_status_error(status)) {
        return status;
    }

    abi.Origin = OW_KDB_ABI_ORIGIN_MANIFEST;
    if (abi.Id == OW_KDB_INVALID_ID) {
        id = OwKdbAbiAllocateCustomId();
        if (id == OW_KDB_INVALID_ID) {
            return OW_ERR_INSUFFICIENT;
        }
        abi.Id = id;
    } else if (abi.Id < OW_KDB_ABI_CUSTOM_BASE ||
               abi.Id > OW_KDB_ABI_CUSTOM_MAX) {
        return OW_ERR_INVALID_PARAM;
    }

    status = OwKdbAbiRegister(&abi, &out_id);
    if (ow_status_error(status)) {
        return status;
    }
    if (OutAbiId != (uint32_t*)0) {
        *OutAbiId = out_id;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKdbUnregisterAbi(uint32_t AbiId) {
    uint32_t i;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    for (i = 0U; i < OW_KDB_MAX_ABIS; ++i) {
        if (g_AbiInUse[i] && g_Abis[i].Id == AbiId) {
            if (g_Abis[i].Origin == OW_KDB_ABI_ORIGIN_BUILTIN) {
                return OW_ERR_INSUFFICIENT;
            }
            g_AbiInUse[i] = false;
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}
