/* dispatcher.c - System Call Dispatcher (Ring 3 to Ring 0) */
#include "../inc/ow_acpi.h"
#include "../inc/ow_alpc.h"
#include "../inc/ow_dpc.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_sync.h"
#include "../inc/ow_syscall.h"
#include "../inc/ow_vfs.h"

static bool g_syscall_ready = false;
static OW_VAD_NODE *s_VadRoot = (void *)0;

OW_STATUS OwSyscallInitialize(void) {
  g_syscall_ready = true;
  OwHalUartWriteString("[SYSCALL] Ring 3-to-0 gateway active.\r\n");
  KeSyncSelfTest();
  OwDpcSelfTest();
  return OW_SUCCESS;
}

int64_t OwSyscallDispatch(uint32_t SyscallId, uint64_t P1, uint64_t P2,
                          uint64_t P3) {
  if (!g_syscall_ready)
    return -1;

  switch (SyscallId) {
  case OW_SYS_ALLOC: {
    uint64_t size = P1;
    static uint64_t s_VHeap = 0x10000000ULL;
    uint64_t addr = s_VHeap;
    OW_VAD_NODE *vad = OwMemCreateVad(addr, addr + size, 0x04);
    if (vad && ow_status_success(OwMemInsertVad(&s_VadRoot, vad))) {
      s_VHeap += size;
      OwMemWalkPml4(addr);
      return (int64_t)addr;
    }
    return -1;
  }
  case OW_SYS_MAP_IO:
    return (int64_t)(uintptr_t)OwHalMapMmio(P1, (uint32_t)P2);
  case OW_SYS_VFS_CREATE:
    return ow_status_success(OwVfsCreateFile((const char *)P1, (uint32_t)P2))
               ? 1
               : 0;
  case OW_SYS_VFS_WRITE:
    return ow_status_success(OwVfsWriteFile((const char *)P1,
                                            (const uint8_t *)P2, (uint32_t)P3))
               ? 1
               : 0;
  case OW_SYS_VFS_READ:
    return (int64_t)OwVfsReadFile((const char *)P1, (uint8_t *)P2,
                                  (uint32_t)P3);
  case OW_SYS_VFS_DELETE:
    return ow_status_success(OwVfsDeleteFile((const char *)P1)) ? 1 : 0;
  case OW_SYS_ALPC_CREATE:
    return (int64_t)(uintptr_t)OwAlpcCreatePort((const char *)P1, (bool)P2);
  case OW_SYS_ALPC_SEND: {
    OW_ALPC_MSG_TYPE msg_type = OW_ALPC_MSG_REQUEST;
    OW_ALPC_MESSAGE msg;
    msg.MessageId = 100;
    msg.Type = msg_type;
    msg.SourceProcessId = 4;
    msg.TargetProcessId = 0;
    msg.DataLength =
        (uint32_t)P3 < OW_ALPC_MAX_MSG_LEN ? (uint32_t)P3 : OW_ALPC_MAX_MSG_LEN;
    ow_memcpy(msg.Data, (const void *)P2, msg.DataLength);
    return ow_status_success(OwAlpcSend((OW_ALPC_PORT *)(uintptr_t)P1, &msg))
               ? 1
               : 0;
  }
  case OW_SYS_ALPC_RECV: {
    OW_ALPC_MESSAGE msg;
    if (ow_status_success(OwAlpcReceive((OW_ALPC_PORT *)(uintptr_t)P1, &msg))) {
      uint32_t read_len = msg.DataLength < P3 ? msg.DataLength : (uint32_t)P3;
      ow_memcpy((void *)P2, msg.Data, read_len);
      return 1;
    }
    return 0;
  }
  case OW_SYS_SAFE_POWEROFF_SCREEN:
    /* Userspace-only soft power-off screen switch. The kernel never
     * arms this itself; a Ring 3 request is the sole enabling path. */
    OwAcpiSetSafePowerScreen(P1 != 0);
    return 1;
  case OW_SYS_SET_AUTOREBOOT:
    OwHalSetAutoReboot(P1 != 0);
    return 1;
  case OW_SYS_SET_KDUMP:
    OwHalSetKdump(P1 != 0);
    return 1;
  case OW_SYS_GET_AUTOREBOOT:
    return OwHalGetAutoReboot() ? 1 : 0;
  case OW_SYS_GET_KDUMP:
    return OwHalGetKdump() ? 1 : 0;
  case OW_SYS_PS_YIELD:
    OwPsYield();
    return 1;
  case OW_SYS_PS_EXIT_THREAD:
    OwPsExitThread((uint64_t)P1);
    /* Never returns. */
    return 0;
  case OW_SYS_PS_GET_PID: {
    OW_THREAD_OBJECT *thr = OwPsGetCurrentThread();
    return thr ? (int64_t)thr->ProcessId : (int64_t)0;
  }
  case OW_SYS_PS_CREATE_PROCESS: {
    OW_PROCESS_OBJECT *proc = OwPsCreateProcess((const char *)P1, (uint32_t)P2);
    return proc ? (int64_t)(uintptr_t)proc : (int64_t)0;
  }
  case OW_SYS_PS_CREATE_THREAD: {
    OW_THREAD_OBJECT *thr =
        OwPsCreateThread((OW_PROCESS_OBJECT *)(uintptr_t)P1, P2, P3);
    return thr ? (int64_t)(uintptr_t)thr : (int64_t)0;
  }
  case OW_SYS_SYNC_CREATE_EVENT: {
    OW_DISPATCHER_OBJECT *ev =
        KeCreateEvent((const char *)P1, (uint8_t)P2, (uint8_t)P3);
    return ev ? (int64_t)(uintptr_t)ev : (int64_t)0;
  }
  case OW_SYS_SYNC_SET_EVENT:
    KeSetEvent((OW_DISPATCHER_OBJECT *)(uintptr_t)P1);
    return 1;
  case OW_SYS_SYNC_RESET_EVENT:
    KeResetEvent((OW_DISPATCHER_OBJECT *)(uintptr_t)P1);
    return 1;
  case OW_SYS_SYNC_CREATE_SEMAPHORE: {
    OW_DISPATCHER_OBJECT *sem =
        KeCreateSemaphore((const char *)P1, (uint32_t)P2, (uint32_t)P3);
    return sem ? (int64_t)(uintptr_t)sem : (int64_t)0;
  }
  case OW_SYS_SYNC_RELEASE_SEMAPHORE:
    KeReleaseSemaphore((OW_DISPATCHER_OBJECT *)(uintptr_t)P1, (uint32_t)P2);
    return 1;
  case OW_SYS_SYNC_WAIT:
    return (int64_t)KeWaitForSingleObject((OW_DISPATCHER_OBJECT *)(uintptr_t)P1,
                                          P2);
  case OW_SYS_SYNC_CREATE_MUTEX: {
    OW_DISPATCHER_OBJECT *mtx = KeCreateMutex((const char *)P1, (uint32_t)P2);
    return mtx ? (int64_t)(uintptr_t)mtx : (int64_t)0;
  }
  case OW_SYS_SYNC_RELEASE_MUTEX:
    return (int64_t)KeReleaseMutex((OW_DISPATCHER_OBJECT *)(uintptr_t)P1);
  case OW_SYS_UART_WRITE: {
    /* Ring-3 so far the only way to talk to the debug console. */
    const char *s = (const char *)P1;
    if (!s)
      return -1;
    OwHalUartWriteString(s);
    return 1;
  }
  case OW_SYS_PS_SLEEP:
    return (int64_t)KeSleep(P1);
  default:
    return -1;
  }
}

/* User-mode wrappers */
void *OwApiAllocateMemory(uint64_t Size) {
  return (void *)(uintptr_t)OwSyscallDispatch(OW_SYS_ALLOC, Size, 0, 0);
}

OW_STATUS OwApiCreateFile(const char *Path, uint32_t Attrs) {
  return OwSyscallDispatch(OW_SYS_VFS_CREATE, (uint64_t)(uintptr_t)Path, Attrs,
                           0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

OW_STATUS OwApiWriteFile(const char *Path, const uint8_t *Buffer,
                         uint32_t Size) {
  return OwSyscallDispatch(OW_SYS_VFS_WRITE, (uint64_t)(uintptr_t)Path,
                           (uint64_t)(uintptr_t)Buffer, Size) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

uint32_t OwApiReadFile(const char *Path, uint8_t *Buffer, uint32_t MaxSize) {
  return (uint32_t)OwSyscallDispatch(OW_SYS_VFS_READ, (uint64_t)(uintptr_t)Path,
                                     (uint64_t)(uintptr_t)Buffer, MaxSize);
}

uint64_t OwApiAlpcCreatePort(const char *Name, bool IsServer) {
  return (uint64_t)OwSyscallDispatch(
      OW_SYS_ALPC_CREATE, (uint64_t)(uintptr_t)Name, (uint64_t)IsServer, 0);
}

OW_STATUS OwApiAlpcSend(uint64_t PortHandle, const void *Data, uint32_t Size) {
  return OwSyscallDispatch(OW_SYS_ALPC_SEND, PortHandle,
                           (uint64_t)(uintptr_t)Data, Size) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

OW_STATUS OwApiAlpcRecv(uint64_t PortHandle, void *Buffer, uint32_t MaxSize,
                        uint32_t *OutSize) {
  int64_t r = OwSyscallDispatch(OW_SYS_ALPC_RECV, PortHandle,
                                (uint64_t)(uintptr_t)Buffer, MaxSize);
  if (OutSize)
    *OutSize = (uint32_t)r;
  return r == 1 ? OW_SUCCESS : OW_ERR_NOT_FOUND;
}

OW_STATUS OwApiSetSafePowerOffScreen(bool Enable) {
  return OwSyscallDispatch(OW_SYS_SAFE_POWEROFF_SCREEN, (uint64_t)Enable, 0,
                           0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

OW_STATUS OwApiSetAutoReboot(bool Enable) {
  return OwSyscallDispatch(OW_SYS_SET_AUTOREBOOT, (uint64_t)Enable, 0, 0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

OW_STATUS OwApiSetKdump(bool Enable) {
  return OwSyscallDispatch(OW_SYS_SET_KDUMP, (uint64_t)Enable, 0, 0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

bool OwApiGetAutoReboot(void) {
  return OwSyscallDispatch(OW_SYS_GET_AUTOREBOOT, 0, 0, 0) == 1;
}

bool OwApiGetKdump(void) {
  return OwSyscallDispatch(OW_SYS_GET_KDUMP, 0, 0, 0) == 1;
}

OW_STATUS OwApiPsYield(void) {
  return OwSyscallDispatch(OW_SYS_PS_YIELD, 0, 0, 0) == 1 ? OW_SUCCESS
                                                          : OW_ERR_IO;
}

OW_STATUS OwApiPsExitThread(void) {
  OwSyscallDispatch(OW_SYS_PS_EXIT_THREAD, 0, 0, 0);
  return OW_SUCCESS; /* unattainable when the thread really exits */
}

uint32_t OwApiPsGetPid(void) {
  return (uint32_t)OwSyscallDispatch(OW_SYS_PS_GET_PID, 0, 0, 0);
}

uint64_t OwApiPsCreateProcess(const char *Name, uint32_t ParentPid) {
  return (uint64_t)OwSyscallDispatch(OW_SYS_PS_CREATE_PROCESS,
                                     (uint64_t)(uintptr_t)Name, ParentPid, 0);
}

uint64_t OwApiPsCreateThread(uint64_t ProcessHandle, uint64_t EntryFunction,
                             uint64_t EntryArg) {
  return (uint64_t)OwSyscallDispatch(OW_SYS_PS_CREATE_THREAD, ProcessHandle,
                                     EntryFunction, EntryArg);
}

uint64_t OwApiSyncCreateEvent(const char *Name, uint8_t ManualReset,
                              uint8_t InitialState) {
  return (uint64_t)OwSyscallDispatch(
      OW_SYS_SYNC_CREATE_EVENT, (uint64_t)(uintptr_t)Name,
      (uint64_t)ManualReset, (uint64_t)InitialState);
}

OW_STATUS OwApiSyncSetEvent(uint64_t Handle) {
  return OwSyscallDispatch(OW_SYS_SYNC_SET_EVENT, Handle, 0, 0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

OW_STATUS OwApiSyncResetEvent(uint64_t Handle) {
  return OwSyscallDispatch(OW_SYS_SYNC_RESET_EVENT, Handle, 0, 0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

uint64_t OwApiSyncCreateSemaphore(const char *Name, uint32_t InitialCount,
                                  uint32_t Limit) {
  return (uint64_t)OwSyscallDispatch(OW_SYS_SYNC_CREATE_SEMAPHORE,
                                     (uint64_t)(uintptr_t)Name,
                                     (uint64_t)InitialCount, (uint64_t)Limit);
}

OW_STATUS OwApiSyncReleaseSemaphore(uint64_t Handle, uint32_t Count) {
  return OwSyscallDispatch(OW_SYS_SYNC_RELEASE_SEMAPHORE, Handle,
                           (uint64_t)Count, 0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

uint32_t OwApiSyncWait(uint64_t Handle, uint64_t TimeoutTicks) {
  return (uint32_t)OwSyscallDispatch(OW_SYS_SYNC_WAIT, Handle, TimeoutTicks, 0);
}

uint64_t OwApiSyncCreateMutex(const char *Name, uint8_t InitialOwner) {
  return (uint64_t)OwSyscallDispatch(OW_SYS_SYNC_CREATE_MUTEX,
                                     (uint64_t)(uintptr_t)Name,
                                     (uint64_t)InitialOwner, 0);
}

OW_STATUS OwApiSyncReleaseMutex(uint64_t Handle) {
  return OwSyscallDispatch(OW_SYS_SYNC_RELEASE_MUTEX, Handle, 0, 0) == 1
             ? OW_SUCCESS
             : OW_ERR_IO;
}

OW_STATUS OwApiSleep(uint64_t Ticks) {
  OwSyscallDispatch(OW_SYS_PS_SLEEP, Ticks, 0, 0);
  return OW_SUCCESS; /* reached only after a real sleep resumes */
}
