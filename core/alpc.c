/* alpc.c - Advanced Local Procedure Call (ALPC) */
#include "../inc/ow_alpc.h"
#include "../inc/ow_object.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_kprintf.h"

static OW_OBJECT_TYPE g_AlpcPortType = {
    "AlpcPort", 0x1001,
    (void*)0, (void*)0, (void*)0, (void*)0
};

OW_STATUS OwAlpcInitialize(void) {
    ow_kprintf("[ALPC] Advanced Local Procedure Call subsystem initialized.\r\n");
    return OW_SUCCESS;
}

OW_ALPC_PORT* OwAlpcCreatePort(const char* Name, bool IsServer) {
    OW_ALPC_PORT* port;

    port = (OW_ALPC_PORT*)OwObjCreateObject(&g_AlpcPortType, Name, sizeof(OW_ALPC_PORT) - sizeof(OW_OBJECT_HEADER), (void*)0);
    if (!port) return (void*)0;

    port->IsServerPort = IsServer;
    port->ConnectedPort = (void*)0;
    port->QueueHead = 0;
    port->QueueTail = 0;
    port->QueueCount = 0;
    ow_memset(port->MessageQueue, 0, sizeof(port->MessageQueue));

    return port;
}

OW_STATUS OwAlpcConnect(OW_ALPC_PORT* ClientPort, OW_ALPC_PORT* ServerPort) {
    if (!ClientPort || !ServerPort) return OW_ERR_NULL_POINTER;
    ClientPort->ConnectedPort = ServerPort;
    ServerPort->ConnectedPort = ClientPort;
    return OW_SUCCESS;
}

OW_STATUS OwAlpcSend(OW_ALPC_PORT* Port, const OW_ALPC_MESSAGE* Msg) {
    OW_ALPC_PORT* target;
    if (!Port || !Msg) return OW_ERR_NULL_POINTER;

    target = Port->ConnectedPort ? Port->ConnectedPort : Port;
    if (target->QueueCount >= OW_ALPC_QUEUE_SIZE) return OW_ERR_INSUFFICIENT;

    ow_memcpy(&target->MessageQueue[target->QueueTail], Msg, sizeof(OW_ALPC_MESSAGE));
    target->QueueTail = (target->QueueTail + 1) % OW_ALPC_QUEUE_SIZE;
    target->QueueCount++;
    return OW_SUCCESS;
}

OW_STATUS OwAlpcReceive(OW_ALPC_PORT* Port, OW_ALPC_MESSAGE* Msg) {
    if (!Port || !Msg) return OW_ERR_NULL_POINTER;
    if (Port->QueueCount == 0) return OW_ERR_NOT_FOUND;

    ow_memcpy(Msg, &Port->MessageQueue[Port->QueueHead], sizeof(OW_ALPC_MESSAGE));
    Port->QueueHead = (Port->QueueHead + 1) % OW_ALPC_QUEUE_SIZE;
    Port->QueueCount--;
    return OW_SUCCESS;
}

void OwAlpcFreePort(OW_ALPC_PORT* Port) {
    if (Port) OwObjDereference(Port);
}
