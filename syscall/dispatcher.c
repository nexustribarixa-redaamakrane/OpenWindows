/* dispatcher.c - System Call Dispatcher (Ring 3 to Ring 0) */
#include "../inc/ow_acpi.h"
#include "../inc/ow_alpc.h"
#include "../inc/ow_dpc.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_owx.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_sync.h"
#include "../inc/ow_syscall.h"
#include "../inc/ow_vfs.h"
#include "../storage/owdisk.h"

static bool g_syscall_ready = false;

/* Resolve the process that owns the syscall.  Every user-supplied pointer in
 * this file is validated against THIS process's VAD tree and page tables, so
 * there is no global address-space state to get wrong: the caller's own
 * VadRoot is the only thing consulted, and a process cannot name another's. */
static OW_PROCESS_OBJECT *syscall_current_process(void) {
  OW_THREAD_OBJECT *thr = OwPsGetCurrentThread();
  if (!thr)
    return (OW_PROCESS_OBJECT *)0;
  return OwPsGetProcessById(thr->ProcessId);
}

/* ====================================================================== */
/* OW_SYS_PS_SPAWN_OWX support                                            */
/* ====================================================================== */
/* Staging pools for the spawn path.  Static, as everywhere else in this kernel:
 * there is no heap to carve out of, and a syscall cannot ask the caller for
 * scratch space it might not have. */
static char s_spawn_name[OW_USERSPACE_NAME_MAX];
static char s_spawn_proc[OW_USERSPACE_NAME_MAX];
static uint8_t s_spawn_image[OW_USERSPACE_IMAGE_MAX];

/* Bounded copy of a caller-supplied NUL-terminated name.
 *
 * The bound is the point.  Every other name-taking call in this gateway walks
 * the pointer until it finds a NUL with no limit, which is tolerable for a
 * trusted caller and a fault for an untrusted one; this copy stops at the
 * buffer, so a caller that supplies an unterminated string gets a truncated
 * name that fails to resolve rather than a walk off the end of its own window.
 *
 * Returns false when the name did not fit, i.e. when it was longer than the
 * longest legal root-catalog entry, so truncation is never mistaken for a
 * valid name that merely happens to resolve. */
static bool spawn_copy_name(char *dst, size_t cap, const char *src) {
  size_t i;

  if (dst == NULL || cap == 0u)
    return false;
  if (src == NULL) {
    dst[0] = '\0';
    return false;
  }

  for (i = 0u; i + 1u < cap; ++i) {
    if (src[i] == '\0') {
      dst[i] = '\0';
      return true;
    }
    dst[i] = src[i];
  }
  dst[cap - 1u] = '\0';
  return false;
}

/* Derive the process object's name from the image file name: "owrs.owx" ->
 * "owrs".  The kernel's PS logs read "[PS] <name>: process created", so a name
 * that kept its extension would put "owrs.owx:" in every line about the
 * process.  Bounded by construction: it cannot be longer than its input. */
static void spawn_proc_name(char *dst, size_t cap, const char *image) {
  size_t i;

  for (i = 0u; i + 1u < cap && image[i] != '\0' && image[i] != '.'; ++i) {
    dst[i] = image[i];
  }
  dst[i] = '\0';
}

/* Load an OWX1 image from the primary volume and enter it as a new process
 * parented to the caller.  Shared by the boot-time hand-off in core/main.c and
 * by OW_SYS_PS_SPAWN_OWX, so the emergency userspace's owrs is loaded by exactly
 * the same path that loads owinit. */
static OW_PROCESS_OBJECT *spawn_owx_image(const char *image_name,
                                          uint32_t parent_pid) {
  uint32_t len = 0u;
  OW_PROCESS_OBJECT *proc;
  OW_STATUS st;

  if (!spawn_copy_name(s_spawn_name, sizeof(s_spawn_name), image_name))
    return (OW_PROCESS_OBJECT *)0;

  st = OwFsOwfsRead(s_spawn_name, s_spawn_image,
                    (uint32_t)sizeof(s_spawn_image), &len);
  if (!ow_status_success(st) || len == 0u) {
    ow_kprintf("[SPAWN] %s: read failed (st=0x%X, len=%u)\r\n", s_spawn_name,
               (unsigned)st, (unsigned)len);
    return (OW_PROCESS_OBJECT *)0;
  }

  /* Reject before a process slot and any frame are committed.  OwPsLoadImage
   * repeats this check, and deliberately so: the syscall must not be the only
   * place that knows a malformed image is malformed. */
  if (!OwOwxImageIsLoadable(
          (const owx_header_t *)(const void *)s_spawn_image, len)) {
    ow_kprintf("[SPAWN] %s: not a loadable OWX1 image (%u bytes)\r\n",
               s_spawn_name, (unsigned)len);
    return (OW_PROCESS_OBJECT *)0;
  }

  spawn_proc_name(s_spawn_proc, sizeof(s_spawn_proc), s_spawn_name);

  proc = OwPsCreateProcess(s_spawn_proc, parent_pid);
  if (proc == NULL)
    return (OW_PROCESS_OBJECT *)0;

  /* Provenance is named, not inferred.  This is OW_SYS_PS_SPAWN_OWX arriving
   * from CPL3, and it is recorded as a spawn rather than as a boot: a userspace
   * image arriving through the kernel's init path is exactly the confusion this
   * distinction exists to prevent. */
  if (ow_status_error(OwPsLoadImage(proc, s_spawn_image, len,
                                    (uint32_t)OW_CIS_RECORD_SPAWN))) {
    /* The process object exists but holds no image, so it can never be entered;
     * retire it rather than leaving a zombie in the table that counts against
     * OW_PS_MAX_PROCESSES. */
    OwPsTerminateProcess(proc, 0u);
    return (OW_PROCESS_OBJECT *)0;
  }

  if (OwMemAuditUserWindow(proc->Pml4Phys, proc->VadRoot) != 0u) {
    ow_kprintf("[SPAWN] %s: USER WINDOW AUDIT FAILED\r\n", s_spawn_proc);
  }

  if (ow_status_error(OwPsLaunchUserImage(proc))) {
    OwPsTerminateProcess(proc, 0u);
    return (OW_PROCESS_OBJECT *)0;
  }

  ow_kprintf("[SPAWN] %s entered at CPL3 as PID %u (parent %u)\r\n",
             s_spawn_proc, (unsigned)proc->ProcessId, (unsigned)parent_pid);
  return proc;
}

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
    /* Per-process user heap, carved out of the guarded user window.
     *
     * This used to bump a file-static cursor starting at 0x10000000 and insert
     * the result into a file-static VAD root.  Both were global, so every
     * process shared one heap cursor and one VAD tree: a second process's
     * allocation would collide with the first's, and nothing checked that the
     * address handed back was even reachable from the caller's page tables.
     * Now the cursor lives on the process, the VAD goes into the process's own
     * tree, and the pages are charged from the process's own frame run. */
    OW_PROCESS_OBJECT *proc = syscall_current_process();
    uint64_t size = P1;
    uint64_t base;
    uint64_t pages;
    uint64_t va;
    uint64_t pa;
    uint64_t end;

    if (!proc || !proc->Pml4Phys)
      return -1;
    if (size == 0u)
      return -1;

    /* Round the request out to whole pages: the mapper has no sub-page
     * granularity, and a partial page would hand out an address whose tail
     * aliases the next allocation. */
    pages = (size + (OW_PAGE_SIZE - 1u)) / OW_PAGE_SIZE;
    if (pages == 0u || pages > (OW_USER_GUARD_BASE - OW_USER_HEAP_BASE) / OW_PAGE_SIZE)
      return -1;

    /* Keep the heap strictly below the guard band.  A heap that could grow into
     * the guard would make stack-overflow detection depend on heap sizing. */
    if (proc->UserBrk < OW_USER_HEAP_BASE || proc->UserBrk >= OW_USER_GUARD_BASE)
      return -1;
    base = (proc->UserBrk + (OW_PAGE_SIZE - 1u)) & ~(uint64_t)(OW_PAGE_SIZE - 1u);
    end  = base + pages * OW_PAGE_SIZE;
    if (end > OW_USER_GUARD_BASE)
      return -1;

    /* Charge and map every page, NX by construction: user memory handed out by
     * a syscall is data until the process proves otherwise by mapping its own
     * code. */
    for (pages = 0; pages < (end - base) / OW_PAGE_SIZE; pages++) {
      va = base + pages * OW_PAGE_SIZE;
      if (ow_status_error(OwMemRunCharge(&proc->FrameRun, &pa)))
        return -1;
      if (ow_status_error(
              OwMemMapPage(proc->Pml4Phys, va, pa, OW_PAGE_USER_RW_NX))) {
        (void)OwMemRunRelease(&proc->FrameRun, pa);
        return -1;
      }
    }
    {
      OW_VAD_NODE *vad = OwMemCreateVad(base, end - 1u, OW_PAGE_USER_RW_NX);
      if (!vad || ow_status_error(OwMemInsertVad(&proc->VadRoot, vad)))
        return -1;
      vad->FirstFrame = base;
      vad->CommitCharge = (uint32_t)((end - base) / OW_PAGE_SIZE);
    }
    proc->UserBrk = end;
    return (int64_t)base;
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
  case OW_SYS_UART_READ: {
    /* Non-blocking, by contract.  OwHalUartReadChar() spins until a byte lands,
     * so calling it unconditionally would park the calling CPL3 thread inside
     * the kernel with interrupts off the scheduler's reach: a thread that could
     * not be preempted and could not yield, on a request the caller expects to
     * return immediately.  Gate on "is there one" first and report absence as
     * -1 so the caller can sleep and come back. */
    if (!OwHalUartCanRead())
      return -1;
    /* Widen before widening the sign: a 0xFF byte read from the UART is data,
     * not -1, and conflating the two would make half the byte range
     * indistinguishable from "nothing waiting". */
    return (int64_t)(unsigned char)OwHalUartReadChar();
  }
  case OW_SYS_PS_SPAWN_OWX: {
    OW_PROCESS_OBJECT *caller = syscall_current_process();
    OW_PROCESS_OBJECT *spawned;

    if (caller == NULL)
      return -1;

    /* Parentage is the caller's own PID, taken from the process the gateway
     * resolved the request against -- never from a caller-supplied value.  A
     * caller that could name its own parent could also claim PID 0, and PID 0
     * is the kernel's own identity. */
    spawned = spawn_owx_image((const char *)(uintptr_t)P1, caller->ProcessId);
    if (spawned == NULL)
      return -1;
    return (int64_t)(uint32_t)spawned->ProcessId;
  }
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

uint64_t OwApiPsSpawnOwx(const char *ImageName) {
  uint64_t r = (uint64_t)OwSyscallDispatch(OW_SYS_PS_SPAWN_OWX,
                                          (uint64_t)(uintptr_t)ImageName, 0, 0);
  /* The gateway reports failure as -1.  Callers here work in the "0 means
   * nothing happened" idiom that every other wrapper in this file uses, and a
   * raw (uint64_t)-1 handed back as a handle would be a live-looking value. */
  return (r == (uint64_t)-1) ? 0u : r;
}

int OwApiUartRead(void) {
  return (int)OwSyscallDispatch(OW_SYS_UART_READ, 0, 0, 0);
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
