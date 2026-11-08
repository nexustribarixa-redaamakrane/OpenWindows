/* kdb_assoc.c - KAPA application to associated-kernel associations.
 *
 * An association is the authority boundary the Service Bridge consults: it
 * names the application, the kernel it may use, the capabilities it was granted,
 * and (once loaded) the one instance that belongs to it.  It is deliberately
 * separate from the instance table: associations may exist before a kernel is
 * loaded and survive a fault while the faulted descriptor remains inspectable.
 */
#include "kdb_internal.h"

static OW_KDB_ASSOCIATION g_Associations[OW_KDB_MAX_ASSOCIATIONS];
static bool               g_AssociationInUse[OW_KDB_MAX_ASSOCIATIONS];

static bool application_name_valid(const char* Name) {
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

void OwKdbAssociationReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_ASSOCIATIONS; ++i) {
        g_AssociationInUse[i] = false;
    }
}

OW_STATUS OwKdbAssociationCreate(const char* Application, uint32_t KernelId,
                                 uint32_t Capabilities,
                                 uint32_t* OutAssociationId) {
    const OW_KDB_KERNEL_DESC* kernel;
    OW_KDB_COMPAT_REPORT report;
    OW_STATUS status;
    uint32_t i;
    uint32_t free_slot = OW_KDB_MAX_ASSOCIATIONS;

    if (!application_name_valid(Application)) {
        return OW_ERR_INVALID_PARAM;
    }
    if ((Capabilities & ~(OW_KDB_CAP_CALL | OW_KDB_CAP_REGISTER_SERVICE |
                          OW_KDB_CAP_ADMIN)) != 0U) {
        return OW_ERR_INVALID_PARAM;
    }

    kernel = OwKdbRegistryPtr(KernelId);
    if (kernel == (const OW_KDB_KERNEL_DESC*)0) {
        return OW_ERR_NOT_FOUND;
    }

    status = OwKdbAssessCompatibility(kernel, &report);
    if (ow_status_error(status)) {
        return status;
    }

    for (i = 0U; i < OW_KDB_MAX_ASSOCIATIONS; ++i) {
        if (g_AssociationInUse[i]) {
            if (OwKdbNameEqual(g_Associations[i].Application, Application)) {
                return OW_ERR_ALREADY_EXISTS;
            }
        } else if (free_slot == OW_KDB_MAX_ASSOCIATIONS) {
            free_slot = i;
        }
    }

    if (free_slot == OW_KDB_MAX_ASSOCIATIONS) {
        return OW_ERR_INSUFFICIENT;
    }

    g_Associations[free_slot].Id = free_slot + 1U;
    (void)OwKdbCopyName(g_Associations[free_slot].Application,
                        OW_KDB_MAX_NAME, Application);
    g_Associations[free_slot].KernelId = KernelId;
    g_Associations[free_slot].Capabilities = Capabilities;
    g_Associations[free_slot].InstanceId = OW_KDB_INVALID_ID;
    g_Associations[free_slot].Flags = 0U;
    g_AssociationInUse[free_slot] = true;

    if (OutAssociationId != (uint32_t*)0) {
        *OutAssociationId = free_slot + 1U;
    }
    return OW_SUCCESS;
}

OW_STATUS OwKdbAssociationGet(uint32_t AssociationId,
                              OW_KDB_ASSOCIATION* OutAssociation) {
    if (AssociationId == OW_KDB_INVALID_ID ||
        AssociationId > OW_KDB_MAX_ASSOCIATIONS ||
        OutAssociation == (OW_KDB_ASSOCIATION*)0) {
        return OW_ERR_INVALID_PARAM;
    }
    if (!g_AssociationInUse[AssociationId - 1U]) {
        return OW_ERR_NOT_FOUND;
    }

    *OutAssociation = g_Associations[AssociationId - 1U];
    return OW_SUCCESS;
}

OW_STATUS OwKdbAssociationFind(const char* Application,
                               OW_KDB_ASSOCIATION* OutAssociation) {
    uint32_t i;

    if (Application == (const char*)0 ||
        OutAssociation == (OW_KDB_ASSOCIATION*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    for (i = 0U; i < OW_KDB_MAX_ASSOCIATIONS; ++i) {
        if (g_AssociationInUse[i] &&
            OwKdbNameEqual(g_Associations[i].Application, Application)) {
            *OutAssociation = g_Associations[i];
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

OW_STATUS OwKdbAssociationRemove(uint32_t AssociationId) {
    if (AssociationId == OW_KDB_INVALID_ID ||
        AssociationId > OW_KDB_MAX_ASSOCIATIONS) {
        return OW_ERR_INVALID_PARAM;
    }
    if (!g_AssociationInUse[AssociationId - 1U]) {
        return OW_ERR_NOT_FOUND;
    }
    if (g_Associations[AssociationId - 1U].InstanceId != OW_KDB_INVALID_ID) {
        /* The instance owns the association's resources.  Destroy or fault it
         * first; silently orphaning it would leave a running descriptor whose
         * authority record no longer exists. */
        return OW_ERR_INSUFFICIENT;
    }

    g_AssociationInUse[AssociationId - 1U] = false;
    return OW_SUCCESS;
}

bool OwKdbAssociationSetInstance(uint32_t AssociationId, uint32_t InstanceId) {
    if (AssociationId == OW_KDB_INVALID_ID ||
        AssociationId > OW_KDB_MAX_ASSOCIATIONS ||
        !g_AssociationInUse[AssociationId - 1U]) {
        return false;
    }

    if (InstanceId != OW_KDB_INVALID_ID &&
        g_Associations[AssociationId - 1U].InstanceId != OW_KDB_INVALID_ID) {
        return false;
    }

    g_Associations[AssociationId - 1U].InstanceId = InstanceId;
    return true;
}

bool OwKdbAssociationKernelInUse(uint32_t KernelId) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_ASSOCIATIONS; ++i) {
        if (g_AssociationInUse[i] &&
            g_Associations[i].KernelId == KernelId) {
            return true;
        }
    }
    return false;
}

uint32_t OwKdbAssociationCount(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KDB_MAX_ASSOCIATIONS; ++i) {
        if (g_AssociationInUse[i]) {
            ++count;
        }
    }
    return count;
}

/* ---- Public wrappers ---------------------------------------------------- */
OW_STATUS OwKdbAssociateApplication(const char* Application, uint32_t KernelId,
                                    uint32_t Capabilities,
                                    uint32_t* OutAssociationId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbAssociationCreate(Application, KernelId, Capabilities,
                                  OutAssociationId);
}

OW_STATUS OwKdbGetAssociation(uint32_t AssociationId,
                              OW_KDB_ASSOCIATION* OutAssociation) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbAssociationGet(AssociationId, OutAssociation);
}

OW_STATUS OwKdbFindAssociation(const char* Application,
                               OW_KDB_ASSOCIATION* OutAssociation) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbAssociationFind(Application, OutAssociation);
}

OW_STATUS OwKdbDisassociateApplication(uint32_t AssociationId) {
    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OwKdbAssociationRemove(AssociationId);
}
