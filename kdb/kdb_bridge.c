/* kdb_bridge.c - bounded Service Bridge and its built-in main-kernel services.
 *
 * The bridge is intentionally concrete rather than an RPC placeholder:
 *
 *   - the request is copied into KDB-owned storage before a handler runs;
 *   - the handler writes into a KDB-owned response buffer, never the caller's;
 *   - the returned length is checked against both the handler capacity and the
 *     caller's capacity before any byte is copied back;
 *   - the caller must be a live association with OW_KDB_CAP_CALL, and a call
 *     into an associated-kernel instance additionally requires that the caller
 *     owns the instance or carries OW_KDB_CAP_ADMIN.
 *
 * This is still an in-kernel call, not a syscall and not a CPL3 boundary.  It
 * is the management/data path a future execution adapter would sit behind.
 */
#include "kdb_internal.h"

typedef struct _OW_KDB_SERVICE_ENTRY {
    bool                 InUse;
    uint32_t             OwnerInstanceId;
    uint32_t             ServiceId;
    char                 Name[OW_KDB_MAX_NAME];
    uint32_t             RequiredCapabilities;
    uint32_t             MaxRequest;
    uint32_t             MaxResponse;
    OW_KDB_SERVICE_HANDLER Handler;
    void*                Context;
} OW_KDB_SERVICE_ENTRY;

static OW_KDB_SERVICE_ENTRY g_Services[OW_KDB_MAX_SERVICES];
static uint32_t              g_BridgeCalls = 0U;

static OW_KDB_SERVICE_ENTRY* service_find(uint32_t OwnerInstanceId,
                                          uint32_t ServiceId) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_SERVICES; ++i) {
        if (g_Services[i].InUse &&
            g_Services[i].OwnerInstanceId == OwnerInstanceId &&
            g_Services[i].ServiceId == ServiceId) {
            return &g_Services[i];
        }
    }
    return (OW_KDB_SERVICE_ENTRY*)0;
}

void OwKdbBridgeReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_SERVICES; ++i) {
        g_Services[i].InUse = false;
    }
    g_BridgeCalls = 0U;
}

static OW_STATUS ping_handler(uint32_t ServiceId,
                              const uint8_t* Request, uint32_t RequestLength,
                              uint8_t* Response, uint32_t ResponseCapacity,
                              uint32_t* ResponseLength, void* Context) {
    static const char pong[] = "kdb-pong";
    uint32_t i;

    (void)ServiceId;
    (void)Request;
    (void)RequestLength;
    (void)Context;

    if (ResponseCapacity < (uint32_t)(sizeof(pong) - 1U)) {
        return OW_ERR_INSUFFICIENT;
    }
    for (i = 0U; i < (uint32_t)(sizeof(pong) - 1U); ++i) {
        Response[i] = (uint8_t)pong[i];
    }
    *ResponseLength = (uint32_t)(sizeof(pong) - 1U);
    return OW_SUCCESS;
}

static OW_STATUS echo_handler(uint32_t ServiceId,
                              const uint8_t* Request, uint32_t RequestLength,
                              uint8_t* Response, uint32_t ResponseCapacity,
                              uint32_t* ResponseLength, void* Context) {
    uint32_t i;

    (void)ServiceId;
    (void)Context;

    if (RequestLength > ResponseCapacity) {
        return OW_ERR_INSUFFICIENT;
    }
    for (i = 0U; i < RequestLength; ++i) {
        Response[i] = Request[i];
    }
    *ResponseLength = RequestLength;
    return OW_SUCCESS;
}

OW_STATUS OwKdbBridgeInitializeBuiltins(void) {
    OW_STATUS status;

    status = OwKdbServiceRegister(0U, OW_KDB_SERVICE_PING, "main.ping",
                                  OW_KDB_CAP_CALL, 0U, 16U,
                                  ping_handler, (void*)0);
    if (ow_status_error(status)) {
        return status;
    }

    status = OwKdbServiceRegister(0U, OW_KDB_SERVICE_ECHO, "main.echo",
                                  OW_KDB_CAP_CALL, 64U, 64U,
                                  echo_handler, (void*)0);
    return status;
}

OW_STATUS OwKdbServiceRegister(uint32_t OwnerInstanceId, uint32_t ServiceId,
                               const char* Name,
                               uint32_t RequiredCapabilities,
                               uint32_t MaxRequest, uint32_t MaxResponse,
                               OW_KDB_SERVICE_HANDLER Handler, void* Context) {
    uint32_t i;
    uint32_t free_slot = OW_KDB_MAX_SERVICES;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (Name == (const char*)0 || Name[0] == '\0' ||
        Handler == (OW_KDB_SERVICE_HANDLER)0 || ServiceId == 0U) {
        return OW_ERR_INVALID_PARAM;
    }
    if (MaxRequest > OW_KDB_BRIDGE_MAX_REQUEST ||
        MaxResponse > OW_KDB_BRIDGE_MAX_RESPONSE) {
        return OW_ERR_INVALID_PARAM;
    }
    if (OwnerInstanceId != OW_KDB_INVALID_ID &&
        !OwKdbManagerExists(OwnerInstanceId)) {
        return OW_ERR_NOT_FOUND;
    }
    if (service_find(OwnerInstanceId, ServiceId) !=
        (OW_KDB_SERVICE_ENTRY*)0) {
        return OW_ERR_ALREADY_EXISTS;
    }

    for (i = 0U; i < OW_KDB_MAX_SERVICES; ++i) {
        if (!g_Services[i].InUse) {
            free_slot = i;
            break;
        }
    }
    if (free_slot == OW_KDB_MAX_SERVICES) {
        return OW_ERR_INSUFFICIENT;
    }

    g_Services[free_slot].OwnerInstanceId = OwnerInstanceId;
    g_Services[free_slot].ServiceId = ServiceId;
    (void)OwKdbCopyName(g_Services[free_slot].Name, OW_KDB_MAX_NAME, Name);
    g_Services[free_slot].RequiredCapabilities = RequiredCapabilities;
    g_Services[free_slot].MaxRequest = MaxRequest;
    g_Services[free_slot].MaxResponse = MaxResponse;
    g_Services[free_slot].Handler = Handler;
    g_Services[free_slot].Context = Context;
    g_Services[free_slot].InUse = true;
    return OW_SUCCESS;
}

OW_STATUS OwKdbServiceUnregister(uint32_t OwnerInstanceId,
                                 uint32_t ServiceId) {
    OW_KDB_SERVICE_ENTRY* service;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }

    service = service_find(OwnerInstanceId, ServiceId);
    if (service == (OW_KDB_SERVICE_ENTRY*)0) {
        return OW_ERR_NOT_FOUND;
    }
    service->InUse = false;
    return OW_SUCCESS;
}

void OwKdbBridgeDropOwner(uint32_t OwnerInstanceId) {
    uint32_t i;

    if (OwnerInstanceId == OW_KDB_INVALID_ID) {
        return;
    }
    for (i = 0U; i < OW_KDB_MAX_SERVICES; ++i) {
        if (g_Services[i].InUse &&
            g_Services[i].OwnerInstanceId == OwnerInstanceId) {
            g_Services[i].InUse = false;
        }
    }
}

uint32_t OwKdbBridgeServiceCount(void) {
    uint32_t i;
    uint32_t count = 0U;

    for (i = 0U; i < OW_KDB_MAX_SERVICES; ++i) {
        if (g_Services[i].InUse) {
            ++count;
        }
    }
    return count;
}

uint32_t OwKdbBridgeCallCount(void) {
    return g_BridgeCalls;
}

OW_STATUS OwKdbBridgeCall(uint32_t CallerAssociationId,
                          uint32_t TargetInstanceId, uint32_t ServiceId,
                          const void* Request, uint32_t RequestLength,
                          void* Response, uint32_t ResponseCapacity,
                          uint32_t* ResponseLength) {
    OW_KDB_ASSOCIATION association;
    OW_KDB_SERVICE_ENTRY* service;
    OW_STATUS status;
    uint8_t request_copy[OW_KDB_BRIDGE_MAX_REQUEST];
    uint8_t response_copy[OW_KDB_BRIDGE_MAX_RESPONSE];
    uint32_t local_capacity;
    uint32_t produced = 0U;
    uint32_t i;

    if (!OwKdbIsReady()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (ResponseLength == (uint32_t*)0) {
        return OW_ERR_NULL_POINTER;
    }
    *ResponseLength = 0U;

    status = OwKdbAssociationGet(CallerAssociationId, &association);
    if (ow_status_error(status)) {
        return status;
    }

    if (TargetInstanceId != OW_KDB_INVALID_ID) {
        if (!OwKdbManagerExists(TargetInstanceId)) {
            return OW_ERR_NOT_FOUND;
        }
        if (!OwKdbManagerIsRunning(TargetInstanceId)) {
            return OW_ERR_NOT_INITIALIZED;
        }
        if (association.InstanceId != TargetInstanceId &&
            (association.Capabilities & OW_KDB_CAP_ADMIN) == 0U) {
            return OW_ERR_INSUFFICIENT;
        }
    }

    service = service_find(TargetInstanceId, ServiceId);
    if (service == (OW_KDB_SERVICE_ENTRY*)0) {
        return OW_ERR_NOT_FOUND;
    }

    if ((service->RequiredCapabilities & ~association.Capabilities) != 0U) {
        return OW_ERR_INSUFFICIENT;
    }
    if (RequestLength > service->MaxRequest ||
        RequestLength > OW_KDB_BRIDGE_MAX_REQUEST) {
        return OW_ERR_INVALID_PARAM;
    }
    if (RequestLength != 0U && Request == (const void*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (ResponseCapacity != 0U && Response == (void*)0) {
        return OW_ERR_NULL_POINTER;
    }

    for (i = 0U; i < RequestLength; ++i) {
        request_copy[i] = ((const uint8_t*)Request)[i];
    }
    for (i = 0U; i < OW_KDB_BRIDGE_MAX_RESPONSE; ++i) {
        response_copy[i] = 0U;
    }

    local_capacity = ResponseCapacity;
    if (local_capacity > service->MaxResponse) {
        local_capacity = service->MaxResponse;
    }
    if (local_capacity > OW_KDB_BRIDGE_MAX_RESPONSE) {
        local_capacity = OW_KDB_BRIDGE_MAX_RESPONSE;
    }

    status = service->Handler(ServiceId, request_copy, RequestLength,
                              response_copy, local_capacity, &produced,
                              service->Context);
    if (ow_status_success(status)) {
        if (produced > local_capacity || produced > ResponseCapacity) {
            /* A handler that overruns its stated capacity does not get to
             * claim success, and nothing is copied back. */
            return OW_ERR_INSUFFICIENT;
        }
        for (i = 0U; i < produced; ++i) {
            ((uint8_t*)Response)[i] = response_copy[i];
        }
        *ResponseLength = produced;
    }

    if (TargetInstanceId != OW_KDB_INVALID_ID) {
        OwKdbManagerNoteBridgeCall(TargetInstanceId);
    }
    ++g_BridgeCalls;

    return status;
}
