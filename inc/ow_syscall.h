/* ow_syscall.h - System Call Gateway (Ring 3 to Ring 0) */
#ifndef OW_SYSCALL_H
#define OW_SYSCALL_H

#include "ow_types.h"

#define OW_SYS_ALLOC            0x001U
#define OW_SYS_MAP_IO           0x002U
#define OW_SYS_VFS_CREATE       0x003U
#define OW_SYS_VFS_WRITE        0x004U
#define OW_SYS_VFS_READ         0x005U
#define OW_SYS_ALPC_CREATE      0x006U
#define OW_SYS_ALPC_SEND        0x007U
#define OW_SYS_ALPC_RECV        0x008U
#define OW_SYS_VFS_DELETE       0x009U
#define OW_SYS_OBJ_OPEN         0x00AU
#define OW_SYS_OBJ_CLOSE        0x00BU
#define OW_SYS_SAFE_POWEROFF_SCREEN 0x00CU
#define OW_SYS_PS_YIELD         0x00DU
#define OW_SYS_PS_EXIT_THREAD   0x00EU
#define OW_SYS_PS_GET_PID       0x00FU
#define OW_SYS_PS_CREATE_PROCESS 0x010U
#define OW_SYS_PS_CREATE_THREAD 0x011U
#define OW_SYS_SYNC_CREATE_EVENT       0x012U
#define OW_SYS_SYNC_SET_EVENT          0x013U
#define OW_SYS_SYNC_RESET_EVENT        0x014U
#define OW_SYS_SYNC_CREATE_SEMAPHORE   0x015U
#define OW_SYS_SYNC_RELEASE_SEMAPHORE  0x016U
#define OW_SYS_SYNC_WAIT               0x017U
#define OW_SYS_PS_SLEEP                0x018U
#define OW_SYS_SYNC_CREATE_MUTEX       0x019U
#define OW_SYS_SYNC_RELEASE_MUTEX      0x01AU
#define OW_SYS_UART_WRITE              0x01BU
#define OW_SYS_SET_AUTOREBOOT          0x01CU
#define OW_SYS_SET_KDUMP               0x01DU
#define OW_SYS_GET_AUTOREBOOT          0x01EU
#define OW_SYS_GET_KDUMP               0x01FU

OW_STATUS    OwSyscallInitialize(void);
int64_t      OwSyscallDispatch(uint32_t SyscallId, uint64_t P1, uint64_t P2, uint64_t P3);

/* User-mode wrappers */
void*        OwApiAllocateMemory(uint64_t Size);
OW_STATUS    OwApiCreateFile(const char* Path, uint32_t Attrs);
OW_STATUS    OwApiWriteFile(const char* Path, const uint8_t* Buffer, uint32_t Size);
uint32_t     OwApiReadFile(const char* Path, uint8_t* Buffer, uint32_t MaxSize);
uint64_t     OwApiAlpcCreatePort(const char* Name, bool IsServer);
OW_STATUS    OwApiAlpcSend(uint64_t PortHandle, const void* Data, uint32_t Size);
OW_STATUS    OwApiAlpcRecv(uint64_t PortHandle, void* Buffer, uint32_t MaxSize, uint32_t* OutSize);
OW_STATUS    OwApiSetSafePowerOffScreen(bool Enable);
OW_STATUS    OwApiSetAutoReboot(bool Enable);
OW_STATUS    OwApiSetKdump(bool Enable);
bool         OwApiGetAutoReboot(void);
bool         OwApiGetKdump(void);
OW_STATUS    OwApiPsYield(void);
OW_STATUS    OwApiPsExitThread(void);
uint32_t     OwApiPsGetPid(void);
uint64_t     OwApiPsCreateProcess(const char* Name, uint32_t ParentPid);
uint64_t     OwApiPsCreateThread(uint64_t ProcessHandle,
                                 uint64_t EntryFunction,
                                 uint64_t EntryArg);

/* Dispatcher object wrappers */
uint64_t     OwApiSyncCreateEvent(const char* Name, uint8_t ManualReset,
                                  uint8_t InitialState);
OW_STATUS    OwApiSyncSetEvent(uint64_t Handle);
OW_STATUS    OwApiSyncResetEvent(uint64_t Handle);
uint64_t     OwApiSyncCreateSemaphore(const char* Name, uint32_t InitialCount,
                                      uint32_t Limit);
OW_STATUS    OwApiSyncReleaseSemaphore(uint64_t Handle, uint32_t Count);
uint32_t     OwApiSyncWait(uint64_t Handle, uint64_t TimeoutTicks);
uint64_t     OwApiSyncCreateMutex(const char* Name, uint8_t InitialOwner);
OW_STATUS    OwApiSyncReleaseMutex(uint64_t Handle);
OW_STATUS    OwApiSleep(uint64_t Ticks);

#endif /* OW_SYSCALL_H */
