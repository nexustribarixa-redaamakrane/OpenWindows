/* ow_alpc.h - Advanced Local Procedure Call (ALPC) Messaging */
#ifndef OW_ALPC_H
#define OW_ALPC_H

#include "ow_types.h"
#include "ow_object.h"

#define OW_ALPC_MAX_MSG_LEN     512U
#define OW_ALPC_QUEUE_SIZE      64U

typedef enum _OW_ALPC_MSG_TYPE {
    OW_ALPC_MSG_REQUEST,
    OW_ALPC_MSG_REPLY,
    OW_ALPC_MSG_CONNECTION_REQUEST
} OW_ALPC_MSG_TYPE;

typedef struct _OW_ALPC_MESSAGE {
    uint32_t            MessageId;
    OW_ALPC_MSG_TYPE    Type;
    uint32_t            SourceProcessId;
    uint32_t            TargetProcessId;
    uint32_t            DataLength;
    uint8_t             Data[OW_ALPC_MAX_MSG_LEN];
} OW_ALPC_MESSAGE;

typedef struct _OW_ALPC_PORT {
    OW_OBJECT_HEADER        Header;
    bool                    IsServerPort;
    struct _OW_ALPC_PORT*   ConnectedPort;
    OW_ALPC_MESSAGE         MessageQueue[OW_ALPC_QUEUE_SIZE];
    uint32_t                QueueHead;
    uint32_t                QueueTail;
    uint32_t                QueueCount;
} OW_ALPC_PORT;

OW_STATUS    OwAlpcInitialize(void);
OW_ALPC_PORT* OwAlpcCreatePort(const char* Name, bool IsServer);
OW_STATUS    OwAlpcConnect(OW_ALPC_PORT* ClientPort, OW_ALPC_PORT* ServerPort);
OW_STATUS    OwAlpcSend(OW_ALPC_PORT* Port, const OW_ALPC_MESSAGE* Msg);
OW_STATUS    OwAlpcReceive(OW_ALPC_PORT* Port, OW_ALPC_MESSAGE* Msg);
void         OwAlpcFreePort(OW_ALPC_PORT* Port);

#endif /* OW_ALPC_H */
