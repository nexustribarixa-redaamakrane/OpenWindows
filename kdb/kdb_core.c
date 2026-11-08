/* kdb_core.c - KDB initialization, naming and aggregate accounting.
 *
 * This file owns no table of its own beyond the ready flag.  Every table is
 * reset by its owner so the initialization order is explicit and a partial
 * failure cannot leave one module's stale entries behind another's fresh ones.
 */
#include "kdb_internal.h"
#include "../inc/ow_kprintf.h"

static bool g_KdbReady = false;

bool OwKdbCopyName(char* Dst, uint32_t DstSize, const char* Src) {
    uint32_t i;

    if (Dst == (char*)0 || Src == (const char*)0 || DstSize == 0U) {
        return false;
    }

    for (i = 0U; (i + 1U) < DstSize && Src[i] != '\0'; ++i) {
        Dst[i] = Src[i];
    }
    Dst[i] = '\0';

    return Src[i] == '\0';
}

bool OwKdbNameEqual(const char* A, const char* B) {
    uint32_t i;

    if (A == (const char*)0 || B == (const char*)0) {
        return false;
    }

    for (i = 0U; A[i] != '\0' || B[i] != '\0'; ++i) {
        if (A[i] != B[i]) {
            return false;
        }
    }
    return true;
}

OW_STATUS OwKdbInitialize(void) {
    OW_STATUS status;

    g_KdbReady = false;

    OwKdbAssociationReset();
    OwKdbManagerReset();
    OwKdbRegistryReset();
    OwKdbBridgeReset();
    OwKdbExecReset();

    /* From here on the public registration/service paths are usable. */
    g_KdbReady = true;

    status = OwKdbBridgeInitializeBuiltins();
    if (ow_status_error(status)) {
        g_KdbReady = false;
        ow_kprintf("[KDB] built-in service registration FAILED (0x%X)\r\n",
                   (unsigned)status);
        return status;
    }

    /* The reference associated kernel is always listed.  It stays declarative
     * until a real Sweep image is attached, which is the honest state in this
     * repository: Sweep's implementation is not present here. */
    status = OwKdbRegisterSweep((const uint8_t*)0, 0U, (uint32_t*)0);
    if (ow_status_error(status)) {
        g_KdbReady = false;
        ow_kprintf("[KDB] Sweep reference registration FAILED (0x%X)\r\n",
                   (unsigned)status);
        return status;
    }

    ow_kprintf("[KDB] ready: %u kernel descriptor(s), %u service(s)\r\n",
               (unsigned)OwKdbKernelCount(),
               (unsigned)OwKdbBridgeServiceCount());

    return OW_SUCCESS;
}

bool OwKdbIsReady(void) {
    return g_KdbReady;
}

const char* OwKdbKernelKindName(OW_KDB_KERNEL_KIND Kind) {
    switch (Kind) {
    case OW_KDB_KIND_NATIVE_OPENWINDOWS:   return "native-openwindows";
    case OW_KDB_KIND_STRIPPED_OPENWINDOWS: return "stripped-openwindows";
    case OW_KDB_KIND_MODIFIED_OPENWINDOWS: return "modified-openwindows";
    case OW_KDB_KIND_LINUX:                return "linux";
    case OW_KDB_KIND_CUSTOM:               return "custom";
    default:                               return "unknown";
    }
}

const char* OwKdbCompatibilityName(OW_KDB_COMPATIBILITY Verdict) {
    switch (Verdict) {
    case OW_KDB_COMPATIBLE:              return "compatible";
    case OW_KDB_COMPAT_INVALID_DESCRIPTOR:return "invalid-descriptor";
    case OW_KDB_COMPAT_UNSUPPORTED_KIND: return "unsupported-kind";
    case OW_KDB_COMPAT_ARCH_MISMATCH:    return "arch-mismatch";
    case OW_KDB_COMPAT_ABI_MISMATCH:     return "abi-mismatch";
    case OW_KDB_COMPAT_FORMAT_MISMATCH:  return "format-mismatch";
    case OW_KDB_COMPAT_MEMORY_MODEL:     return "memory-model";
    case OW_KDB_COMPAT_PRIVILEGE_MODEL:  return "privilege-model";
    default:                             return "unknown";
    }
}

const char* OwKdbInstanceStateName(OW_KDB_INSTANCE_STATE State) {
    switch (State) {
    case OW_KDB_INSTANCE_READY:    return "ready";
    case OW_KDB_INSTANCE_RUNNING:  return "running";
    case OW_KDB_INSTANCE_STOPPED:  return "stopped";
    case OW_KDB_INSTANCE_FAULTED:  return "faulted";
    default:                       return "unknown";
    }
}

void OwKdbGetStats(OW_KDB_STATS* OutStats) {
    if (OutStats == (OW_KDB_STATS*)0) {
        return;
    }

    OutStats->Kernels = OwKdbKernelCount();
    OutStats->Associations = OwKdbAssociationCount();
    OutStats->Instances = OwKdbManagerCount();
    OutStats->Services = OwKdbBridgeServiceCount();
    OutStats->IsolationDomains = OwKdbManagerCount();
    OutStats->BridgeCalls = OwKdbBridgeCallCount();
    OutStats->Faults = OwKdbManagerFaultCount();
}
