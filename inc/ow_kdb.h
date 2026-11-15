/* ow_kdb.h - Kernel Dual Boot (KDB) public interface
 *
 * KDB is the kernel subsystem that admits and manages *associated kernels* for
 * KAPA (Kernel-Associated Application Architecture).  It is not a bootloader,
 * not a userspace daemon, and not a replacement for the OpenWindows kernel: it
 * runs inside the main kernel and owns the registry, compatibility policy,
 * loader front-end, instance lifecycle, application associations and the
 * Service Bridge through which a KAPA application's kernel and the main kernel
 * exchange explicit requests.
 *
 * Scope and honesty
 * -----------------
 * This build implements the management plane, the compatibility policy, OWX
 * image validation for OpenWindows-derived associated kernels, static resource
 * accounting and the bounded Service Bridge.  It does NOT execute a second
 * kernel on a separate CPU, does NOT create a hardware VM/partition for one,
 * and does NOT implement Linux or arbitrary custom-kernel boot adapters.
 *
 * "Isolation" below therefore means logical isolation and resource ownership:
 * every instance has its own stable isolation domain identifier, its own page
 * budget and its own service namespace.  It is not an MMU/CPU privilege
 * boundary for executing foreign code.  A kernel whose descriptor asks for
 * shared memory or kernel-equivalent privilege is refused rather than treated
 * as if it were isolated.
 *
 * All pools are static and sized at compile time.  No dynamic heap allocation
 * is used.  IDs are slot-derived and remain valid until the next
 * OwKdbInitialize(); the API is single-threaded kernel code and takes no locks.
 */
#ifndef OW_KDB_H
#define OW_KDB_H

#include "ow_types.h"

/* ---- Compile-time limits ------------------------------------------------ */
#define OW_KDB_MAX_KERNELS       16U
#define OW_KDB_MAX_INSTANCES     16U
#define OW_KDB_MAX_ASSOCIATIONS  32U
#define OW_KDB_MAX_SERVICES      16U
#define OW_KDB_MAX_NAME          64U

/* ABI registry.  Built-in descriptors plus manifest-composed custom ABIs share
 * this bounded table; no dynamic allocation is used. */
#define OW_KDB_MAX_ABIS           32U
#define OW_KDB_MAX_ABI_SEGMENTS   16U
#define OW_KDB_MAX_MANIFEST_FILES 8U

/* Bounded lifecycle/execution event log.  Each entry is a fact recorded by the
 * manager or an executor hook, never a speculative state. */
#define OW_KDB_MAX_HISTORY        128U

#define OW_KDB_BRIDGE_MAX_REQUEST   256U
#define OW_KDB_BRIDGE_MAX_RESPONSE  256U

/* Default page budget for an instance when the caller passes 0.  4 MiB. */
#define OW_KDB_DEFAULT_PAGE_LIMIT   1024U

#define OW_KDB_INVALID_ID        0U

/* ---- Associated-kernel taxonomy ----------------------------------------- */
typedef enum _OW_KDB_KERNEL_KIND {
    OW_KDB_KIND_NATIVE_OPENWINDOWS = 1, /* same kernel family, full image     */
    OW_KDB_KIND_STRIPPED_OPENWINDOWS,   /* reduced OpenWindows kernel         */
    OW_KDB_KIND_MODIFIED_OPENWINDOWS,   /* ABI-compatible patched kernel      */
    OW_KDB_KIND_LINUX,                  /* foreign ABI: Linux x86-64          */
    OW_KDB_KIND_CUSTOM,                 /* application-specific kernel        */
    OW_KDB_KIND_BSD,                    /* foreign ABI: BSD family            */
    OW_KDB_KIND_UNIX                    /* foreign ABI: SysV Unix             */
} OW_KDB_KERNEL_KIND;

/* ABI identifiers are descriptive, not promises about execution.  Every
 * built-in identifier has an ABI descriptor in the ABI registry; the
 * descriptor records which image format the ABI uses and whether this build
 * has an execution path for it. */
#define OW_KDB_ABI_OPENWINDOWS_NATIVE 0x4F570001U
#define OW_KDB_ABI_OPENWINDOWS_COMPAT 0x4F570002U
#define OW_KDB_ABI_LINUX_X86_64       0x4C4E5801U
#define OW_KDB_ABI_BSD_X86_64         0x42534401U
#define OW_KDB_ABI_FREEBSD_X86_64     0x42534402U
#define OW_KDB_ABI_NETBSD_X86_64      0x42534403U
#define OW_KDB_ABI_OPENBSD_X86_64     0x42534404U
#define OW_KDB_ABI_UNIX_SYSV_X86_64   0x55535801U
#define OW_KDB_ABI_CUSTOM             0x43555301U

/* Manifest-composed custom ABIs are allocated from this window.  The generic
 * custom ABI above remains the identity used by a descriptor that does not
 * name a specific manifest. */
#define OW_KDB_ABI_CUSTOM_BASE        0x43555300U
#define OW_KDB_ABI_CUSTOM_MAX         0x435553FFU

#define OW_KDB_FORMAT_OWX  1U
#define OW_KDB_FORMAT_ELF  2U
#define OW_KDB_FORMAT_RAW  3U

/* ELF e_ident[EI_OSABI] values this loader recognises. */
#define OW_KDB_ELF_OSABI_SYSV    0U
#define OW_KDB_ELF_OSABI_NETBSD  2U
#define OW_KDB_ELF_OSABI_LINUX   3U
#define OW_KDB_ELF_OSABI_FREEBSD 9U
#define OW_KDB_ELF_OSABI_OPENBSD 12U

#define OW_KDB_MEMORY_PRIVATE 1U
#define OW_KDB_MEMORY_SHARED  2U

#define OW_KDB_PRIVILEGE_UNPRIVILEGED 1U
#define OW_KDB_PRIVILEGE_KERNEL_EQUIVALENT 2U

#define OW_KDB_ARCH_X86_64 1U

/* Descriptor flags.  A declarative descriptor documents an associated kernel
 * that has no image provisioned in this volume/build.  It is listed and
 * assessed, but loading it returns OW_ERR_UNSUPPORTED.  MANIFEST_DEFINED marks
 * a descriptor whose ABI came from a composed manifest rather than a built-in
 * table entry. */
#define OW_KDB_DESC_DECLARATIVE      0x00000001U
#define OW_KDB_DESC_MANIFEST_DEFINED 0x00000002U

/* ---- ABI registry -------------------------------------------------------- */
typedef enum _OW_KDB_ABI_FAMILY {
    OW_KDB_ABI_FAMILY_OPENWINDOWS = 1,
    OW_KDB_ABI_FAMILY_LINUX,
    OW_KDB_ABI_FAMILY_BSD,
    OW_KDB_ABI_FAMILY_UNIX,
    OW_KDB_ABI_FAMILY_CUSTOM
} OW_KDB_ABI_FAMILY;

typedef enum _OW_KDB_ABI_ORIGIN {
    OW_KDB_ABI_ORIGIN_BUILTIN = 1,
    OW_KDB_ABI_ORIGIN_MANIFEST
} OW_KDB_ABI_ORIGIN;

/* One loadable segment of a manifest-composed ABI.  For a raw image these are
 * the authority for validation; for an ELF image they document the expected
 * layout and are cross-checked by the loader. */
typedef struct _OW_KDB_ABI_SEGMENT {
    char     Name[32];
    uint64_t VirtualAddress;
    uint64_t FileOffset;
    uint64_t FileSize;
    uint64_t MemorySize;
    uint32_t Flags;       /* OW_KDB_SEGMENT_* below                          */
} OW_KDB_ABI_SEGMENT;

#define OW_KDB_SEGMENT_READ    0x1U
#define OW_KDB_SEGMENT_WRITE   0x2U
#define OW_KDB_SEGMENT_EXECUTE 0x4U

/* ABI flags.  A manifest may declare that the ABI expects a shared memory
 * model or kernel-equivalent privilege; the matching descriptor must say the
 * same, and the global policy must allow it. */
#define OW_KDB_ABI_FLAG_REQUIRES_SHARED_MEMORY    0x00000001U
#define OW_KDB_ABI_FLAG_REQUIRES_KERNEL_PRIVILEGE 0x00000002U

typedef struct _OW_KDB_ABI_DESC {
    uint32_t          Id;
    char              Name[OW_KDB_MAX_NAME];
    OW_KDB_ABI_FAMILY Family;
    OW_KDB_KERNEL_KIND Kind;
    uint32_t          Format;
    uint32_t          TargetArch;
    uint32_t          ElfOsAbi;
    OW_KDB_ABI_ORIGIN Origin;
    uint32_t          Flags;
    uint64_t          LoadBase;
    uint64_t          EntryPoint;
    uint32_t          SegmentCount;
    OW_KDB_ABI_SEGMENT Segments[OW_KDB_MAX_ABI_SEGMENTS];
    /* True only when this build has an execution path that can hand the image
     * to a real executor.  Foreign ELF/raw ABIs are admitted, validated and
     * planned, but do not claim execution. */
    bool              ExecutionSupported;
} OW_KDB_ABI_DESC;

typedef struct _OW_KDB_MANIFEST_FILE {
    const char*    Name;
    const uint8_t* Data;
    uint32_t       Size;
} OW_KDB_MANIFEST_FILE;

typedef struct _OW_KDB_KERNEL_DESC {
    char                Name[OW_KDB_MAX_NAME];
    OW_KDB_KERNEL_KIND  Kind;
    uint32_t            Abi;
    uint32_t            Format;
    uint32_t            MemoryModel;
    uint32_t            PrivilegeModel;
    uint32_t            TargetArch;
    uint32_t            Flags;
    uint64_t            PreferredBase;
    const uint8_t*      Image;      /* caller-owned; must outlive registration */
    uint32_t            ImageSize;
} OW_KDB_KERNEL_DESC;

/* ---- Compatibility verdicts --------------------------------------------- */
typedef enum _OW_KDB_COMPATIBILITY {
    OW_KDB_COMPATIBLE = 0,
    OW_KDB_COMPAT_INVALID_DESCRIPTOR,
    OW_KDB_COMPAT_UNSUPPORTED_KIND,
    OW_KDB_COMPAT_ARCH_MISMATCH,
    OW_KDB_COMPAT_ABI_MISMATCH,
    OW_KDB_COMPAT_FORMAT_MISMATCH,
    OW_KDB_COMPAT_MEMORY_MODEL,
    OW_KDB_COMPAT_PRIVILEGE_MODEL
} OW_KDB_COMPATIBILITY;

typedef struct _OW_KDB_COMPAT_REPORT {
    OW_KDB_COMPATIBILITY Verdict;
    OW_STATUS            Status;   /* OW_SUCCESS or the matching OW_ERR_*    */
    const char*          Reason;   /* static string; never freed by caller   */
} OW_KDB_COMPAT_REPORT;

/* ---- Application association -------------------------------------------- */
#define OW_KDB_CAP_CALL             0x00000001U
#define OW_KDB_CAP_REGISTER_SERVICE 0x00000002U
#define OW_KDB_CAP_ADMIN            0x00000004U

typedef struct _OW_KDB_ASSOCIATION {
    uint32_t Id;
    char     Application[OW_KDB_MAX_NAME];
    uint32_t KernelId;
    uint32_t Capabilities;
    uint32_t InstanceId;   /* 0 while no instance is loaded                  */
    uint32_t Flags;
} OW_KDB_ASSOCIATION;

/* ---- Instance lifecycle -------------------------------------------------- */
typedef enum _OW_KDB_INSTANCE_STATE {
    OW_KDB_INSTANCE_READY = 1,  /* loaded/validated, resources charged       */
    OW_KDB_INSTANCE_RUNNING,    /* eligible to serve bridge calls             */
    OW_KDB_INSTANCE_STOPPED,    /* resources retained, not serving            */
    OW_KDB_INSTANCE_FAULTED     /* faulted; resources already released        */
} OW_KDB_INSTANCE_STATE;

typedef struct _OW_KDB_INSTANCE {
    uint32_t              Id;
    uint32_t              KernelId;
    uint32_t              AssociationId;
    char                  Application[OW_KDB_MAX_NAME];
    char                  Kernel[OW_KDB_MAX_NAME];
    OW_KDB_INSTANCE_STATE State;
    uint32_t              IsolationDomain;
    uint32_t              ResidentPages;
    uint32_t              PageLimit;
    uint32_t              BridgeCalls;
    OW_STATUS             LastFault;
    uint64_t              EntryPoint;
    uint64_t              MappedBase;
    uint32_t              Abi;
    uint32_t              Format;

    /* Execution bookkeeping.  ProcessId/ThreadId are PS *identifiers*, never
     * pointers: KDB resolves them through the PS accessors at event time, so a
     * terminated process cannot leave a dangling pointer behind.  They remain
     * as a historical record after the process terminates.
     *
     * ExecutionStarted becomes true only when the scheduler is about to resume
     * the bound thread on a CPU; it is never set by preparation or by a logical
     * state change. */
    uint32_t              ProcessId;
    uint32_t              ThreadId;
    uint64_t              ExitStatus;
    bool                  ExecutionStarted;
} OW_KDB_INSTANCE;

/* ---- Service Bridge ------------------------------------------------------ */
/* Service IDs are explicit.  Owner 0 is the main OpenWindows kernel; a
 * non-zero owner is the associated-kernel instance that provides the service.
 * A service ID is unique within its owner, so two instances may provide the
 * same ID without colliding. */
#define OW_KDB_SERVICE_PING 0x4B440001U
#define OW_KDB_SERVICE_ECHO 0x4B440002U
/* Bounded KAPA log: request is message bytes (not NUL-terminated), attributed
 * to the caller association/target instance by the bridge.  Response: none. */
#define OW_KDB_SERVICE_LOG 0x4B440003U
/* Monotonic runtime info: request empty.  Response: uint64_t uptime_ms
 * (little-endian), sourced from the HAL's 64-bit uptime. */
#define OW_KDB_SERVICE_RUNTIME_INFO 0x4B440004U

/* Handler contract:
 *   Request/RequestLength   KDB-owned copy of the caller's request.
 *   Response/Capacity       KDB-owned buffer; never the caller's pointer.
 *   ResponseLength          bytes written; must not exceed Capacity.
 * A handler must not retain any pointer after returning.  KDB validates the
 * returned length and copies the bytes to the caller only on OW_SUCCESS. */
typedef OW_STATUS (*OW_KDB_SERVICE_HANDLER)(
    uint32_t       ServiceId,
    const uint8_t* Request,
    uint32_t       RequestLength,
    uint8_t*       Response,
    uint32_t       ResponseCapacity,
    uint32_t*      ResponseLength,
    void*          Context);

/* ---- Initialization / introspection ------------------------------------- */
OW_STATUS    OwKdbInitialize(void);
bool         OwKdbIsReady(void);

const char*  OwKdbKernelKindName(OW_KDB_KERNEL_KIND Kind);
const char*  OwKdbCompatibilityName(OW_KDB_COMPATIBILITY Verdict);
const char*  OwKdbInstanceStateName(OW_KDB_INSTANCE_STATE State);

typedef struct _OW_KDB_STATS {
    uint32_t Kernels;
    uint32_t Associations;
    uint32_t Instances;
    uint32_t Services;
    uint32_t IsolationDomains;
    uint32_t BridgeCalls;
    uint32_t Faults;
} OW_KDB_STATS;

void         OwKdbGetStats(OW_KDB_STATS* OutStats);

/* ---- Registry ------------------------------------------------------------ */
OW_STATUS    OwKdbRegisterKernel(const OW_KDB_KERNEL_DESC* Desc,
                                 uint32_t* OutKernelId);
OW_STATUS    OwKdbUnregisterKernel(uint32_t KernelId);
OW_STATUS    OwKdbGetKernel(uint32_t KernelId, OW_KDB_KERNEL_DESC* OutDesc);
OW_STATUS    OwKdbFindKernel(const char* Name, uint32_t* OutKernelId);
OW_STATUS    OwKdbGetKernelByIndex(uint32_t Index, OW_KDB_KERNEL_DESC* OutDesc);
uint32_t     OwKdbKernelCount(void);

/* Pure policy: does this descriptor describe a kernel this build is allowed to
 * manage?  Does not touch the registry and does not inspect image contents. */
OW_STATUS    OwKdbAssessCompatibility(const OW_KDB_KERNEL_DESC* Desc,
                                      OW_KDB_COMPAT_REPORT* OutReport);

/* Loader front-end introspection.  OWX validation and page accounting are
 * real; execution is not.  Linux/BSD/Unix/custom kinds report true once their
 * ABI is known. */
bool         OwKdbLoaderSupports(OW_KDB_KERNEL_KIND Kind);
OW_STATUS    OwKdbLoaderValidate(const OW_KDB_KERNEL_DESC* Desc,
                                 uint32_t* OutResidentPages);

/* ---- ABI registry -------------------------------------------------------- */
/* Every descriptor names an ABI.  The ABI registry is the single authority for
 * the image family, format, ELF OSABI, default load base/entry, manifest
 * segments and whether this build can execute the result.  Built-ins are
 * installed by OwKdbInitialize(); custom ABIs are composed from one or more
 * manifest files with OwKdbAbiComposeCustom(). */
const char*  OwKdbAbiFamilyName(OW_KDB_ABI_FAMILY Family);
const char*  OwKdbAbiOriginName(OW_KDB_ABI_ORIGIN Origin);

OW_STATUS    OwKdbGetAbi(uint32_t AbiId, OW_KDB_ABI_DESC* OutAbi);
OW_STATUS    OwKdbGetAbiByIndex(uint32_t Index, OW_KDB_ABI_DESC* OutAbi);
OW_STATUS    OwKdbFindAbi(const char* Name, uint32_t* OutAbiId);
uint32_t     OwKdbAbiCount(void);

/* Compose (and register) a custom ABI from one or more bounded text manifests.
 * Later files override earlier ones.  Required keys: [abi] name, kind, format.
 * Optional: id (0 => allocate from OW_KDB_ABI_CUSTOM_BASE), family, arch, osabi,
 * [image] base/entry, [policy] shared_memory/kernel_privilege, and any number of
 * [segment] sections.  The caller keeps ownership of the file buffers. */
OW_STATUS    OwKdbAbiComposeCustom(const OW_KDB_MANIFEST_FILE* Files,
                                  uint32_t FileCount, uint32_t* OutAbiId);
OW_STATUS    OwKdbUnregisterAbi(uint32_t AbiId);

/* ---- ELF image inspection ------------------------------------------------ */
#define OW_KDB_ELF_CLASS_64 2U
#define OW_KDB_ELF_DATA_LSB 1U
#define OW_KDB_ELF_TYPE_EXEC 2U
#define OW_KDB_ELF_TYPE_DYN  3U

typedef struct _OW_KDB_ELF_INFO {
    bool     Valid;
    uint8_t  Class;
    uint8_t  Data;
    uint8_t  OsAbi;
    uint16_t Type;
    uint16_t Machine;
    bool     EntryInExecutable;
    uint64_t Entry;
    uint64_t PreferredBase;
    uint64_t Limit;
    uint32_t SegmentCount;
    uint32_t LoadSegments;
    uint32_t ResidentPages;
} OW_KDB_ELF_INFO;

/* Parse/validate an ELF64 x86-64 image.  ExpectedOsAbi == 0xFF disables the
 * OSABI check; otherwise the header must carry exactly that value. */
OW_STATUS    OwKdbElfInspect(const uint8_t* Image, uint32_t ImageSize,
                             OW_KDB_ELF_INFO* OutInfo);
OW_STATUS    OwKdbElfValidate(const uint8_t* Image, uint32_t ImageSize,
                              uint32_t ExpectedOsAbi,
                              uint32_t* OutResidentPages);

/* ---- Compatibility policy ------------------------------------------------ */
/* The default policy refuses shared memory and kernel-equivalent privilege.
 * An operator may deliberately widen it; every assessment then reports the
 * active policy rather than silently assuming isolation. */
#define OW_KDB_POLICY_ALLOW_SHARED_MEMORY    0x00000001U
#define OW_KDB_POLICY_ALLOW_KERNEL_PRIVILEGE 0x00000002U

void         OwKdbSetPolicy(uint32_t PolicyFlags);
uint32_t     OwKdbGetPolicy(void);

/* ---- Lifecycle history --------------------------------------------------- */
typedef enum _OW_KDB_INSTANCE_EVENT {
    OW_KDB_EVENT_LOADED = 1,
    OW_KDB_EVENT_STARTED,
    OW_KDB_EVENT_RUNNING,
    OW_KDB_EVENT_STOPPED,
    OW_KDB_EVENT_FAULTED,
    OW_KDB_EVENT_EXECUTED,
    OW_KDB_EVENT_DESTROYED
} OW_KDB_INSTANCE_EVENT;

typedef struct _OW_KDB_HISTORY_EVENT {
    OW_KDB_INSTANCE_EVENT Event;
    OW_STATUS             Status;
    uint32_t              InstanceId;
    uint32_t              ProcessId;
    uint32_t              ThreadId;
    uint64_t              EntryPoint;
} OW_KDB_HISTORY_EVENT;

const char*  OwKdbInstanceEventName(OW_KDB_INSTANCE_EVENT Event);
uint32_t     OwKdbHistoryCount(void);
OW_STATUS    OwKdbGetHistoryEvent(uint32_t Index, OW_KDB_HISTORY_EVENT* OutEvent);
OW_STATUS    OwKdbGetHistoryEventForInstance(uint32_t InstanceId, uint32_t Index,
                                            OW_KDB_HISTORY_EVENT* OutEvent);
uint32_t     OwKdbHistoryCountForInstance(uint32_t InstanceId);
void         OwKdbClearHistory(void);

/* ---- Service enumeration ------------------------------------------------- */
typedef struct _OW_KDB_SERVICE_INFO {
    uint32_t OwnerInstanceId;
    uint32_t ServiceId;
    char     Name[OW_KDB_MAX_NAME];
    uint32_t RequiredCapabilities;
    uint32_t MaxRequest;
    uint32_t MaxResponse;
    uint32_t CallCount;
} OW_KDB_SERVICE_INFO;

OW_STATUS    OwKdbGetServiceByIndex(uint32_t Index,
                                    OW_KDB_SERVICE_INFO* OutService);
uint32_t     OwKdbServiceCount(void);

/* ---- Associations -------------------------------------------------------- */
OW_STATUS    OwKdbAssociateApplication(const char* Application, uint32_t KernelId,
                                       uint32_t Capabilities,
                                       uint32_t* OutAssociationId);
OW_STATUS    OwKdbGetAssociation(uint32_t AssociationId,
                                 OW_KDB_ASSOCIATION* OutAssociation);
OW_STATUS    OwKdbFindAssociation(const char* Application,
                                  OW_KDB_ASSOCIATION* OutAssociation);
OW_STATUS    OwKdbDisassociateApplication(uint32_t AssociationId);
uint32_t     OwKdbAssociationCount(void);

/* ---- Instances ----------------------------------------------------------- */
/* Validates compatibility and the image, charges ResidentPages against
 * PageLimit (0 => OW_KDB_DEFAULT_PAGE_LIMIT), and creates the instance in
 * OW_KDB_INSTANCE_READY.  One association owns at most one instance. */
OW_STATUS    OwKdbLoadInstance(uint32_t AssociationId, uint32_t PageLimit,
                               uint32_t* OutInstanceId);
OW_STATUS    OwKdbStartInstance(uint32_t InstanceId);
OW_STATUS    OwKdbStopInstance(uint32_t InstanceId);
/* Fault cleanup: releases the page charge, clears the association link and
 * unregisters every service owned by the instance.  The descriptor remains
 * queryable as FAULTED until OwKdbDestroyInstance(). */
OW_STATUS    OwKdbFaultInstance(uint32_t InstanceId, OW_STATUS FaultStatus);
OW_STATUS    OwKdbDestroyInstance(uint32_t InstanceId);
OW_STATUS    OwKdbGetInstance(uint32_t InstanceId, OW_KDB_INSTANCE* OutInstance);
OW_STATUS    OwKdbGetInstanceByIndex(uint32_t Index,
                                     OW_KDB_INSTANCE* OutInstance);
uint32_t     OwKdbInstanceCount(void);

/* ---- Service Bridge ------------------------------------------------------ */
OW_STATUS    OwKdbServiceRegister(uint32_t OwnerInstanceId, uint32_t ServiceId,
                                  const char* Name,
                                  uint32_t RequiredCapabilities,
                                  uint32_t MaxRequest, uint32_t MaxResponse,
                                  OW_KDB_SERVICE_HANDLER Handler, void* Context);
OW_STATUS    OwKdbServiceUnregister(uint32_t OwnerInstanceId,
                                    uint32_t ServiceId);

/* Call a service.
 *
 * TargetInstanceId == 0 addresses a main-kernel service.  Otherwise the target
 * instance must exist and be RUNNING, the caller association must own that
 * instance (or carry OW_KDB_CAP_ADMIN), and the service must belong to the
 * target.  The caller's request is copied into a KDB buffer before the handler
 * sees it, and a successful response is length-checked before it is copied
 * back, so a handler never receives or writes caller-owned memory. */
OW_STATUS    OwKdbBridgeCall(uint32_t CallerAssociationId,
                             uint32_t TargetInstanceId, uint32_t ServiceId,
                             const void* Request, uint32_t RequestLength,
                             void* Response, uint32_t ResponseCapacity,
                             uint32_t* ResponseLength);

/* Attribution for the bridge call currently inside a handler.  The pointer is
 * only valid for the duration of that handler on the single-threaded kernel
 * execution context; it lets a built-in service attribute a request without
 * receiving caller-controlled identifiers. */
typedef struct _OW_KDB_CALL_ATTR {
    uint32_t CallerAssociationId;
    uint32_t TargetInstanceId;
} OW_KDB_CALL_ATTR;

const OW_KDB_CALL_ATTR* OwKdbBridgeGetCallAttr(void);

/* ---- Execution model (launch plan + executor seam) ----------------------- */
/* KDB's management half materializes, for one live instance, every fact an
 * executor would need: the still-valid image (re-validated at call time, since
 * the registry holds a caller-owned pointer), its page charge, entry point,
 * mapped base, isolation domain and service namespace, plus an explicit
 * blocker.
 *
 * State distinctions (never conflated):
 *   Admissible      - image/policy/charge checks pass for the current image.
 *   ManagementReady - KDB has prepared the launch metadata for handoff.
 *   Executing       - a real executor backend accepted the launch and initiated
 *                     execution (not implemented in this build; no backend is
 *                     registered by default).
 *
 * ExecutionAvailable reflects whether a backend is registered.  No backend is
 * registered by default, so it is false in this build until a real, verified
 * backend is installed via OwKdbRegisterExecutor().
 */
typedef enum _OW_KDB_EXEC_BLOCKER {
    OW_KDB_BLOCKER_NONE = 0,
    OW_KDB_BLOCKER_INSTANCE_NOT_FOUND,
    OW_KDB_BLOCKER_INSTANCE_FAULTED,
    OW_KDB_BLOCKER_IMAGE_INVALID,
    OW_KDB_BLOCKER_PAGE_BUDGET_EXCEEDED,
    OW_KDB_BLOCKER_NO_ISOLATION_DOMAIN,
    OW_KDB_BLOCKER_NO_ENTRY_POINT,
    OW_KDB_BLOCKER_EXECUTOR_UNAVAILABLE,  /* no backend registered             */
    OW_KDB_BLOCKER_ABI_UNSUPPORTED,       /* ABI validated, no execution path  */
    OW_KDB_BLOCKER_BACKEND_REJECTED       /* backend refused the validated plan */
} OW_KDB_EXEC_BLOCKER;

typedef struct _OW_KDB_LAUNCH_PLAN {
    uint32_t            InstanceId;
    uint32_t            KernelId;
    uint32_t            AssociationId;
    uint32_t            Abi;
    uint32_t            Format;
    uint32_t            ImageSize;
    uint32_t            ResidentPages;
    uint32_t            PageLimit;
    uint64_t            EntryPoint;
    uint64_t            MappedBase;
    uint32_t            IsolationDomain;
    OW_KDB_INSTANCE_STATE State;
    bool                ManagementReady;      /* admissible, charged, live     */
    bool                ExecutionAvailable;   /* backend registered?           */
    OW_KDB_EXEC_BLOCKER Blocker;              /* OW_KDB_BLOCKER_NONE if ready  */
    const char*         BlockerReason;        /* static string                 */
} OW_KDB_LAUNCH_PLAN;

/* Backend contract: receives a KDB-validated, freshly built launch plan.  The
 * backend must not retain the pointer after returning.  Returning OW_SUCCESS
 * means the backend accepted the plan and initiated/owns execution; KDB does
 * not change the instance to a fake executing state on its own.  Any error
 * causes OwKdbExecuteInstance() to fault the instance and release resources. */
typedef OW_STATUS (*OW_KDB_EXECUTOR_BACKEND)(
    const OW_KDB_LAUNCH_PLAN* Plan,
    void*                     Context);

/* Build the launch plan for an instance.  Fills OutPlan for every live
 * instance -- even when execution is unavailable -- and returns OW_SUCCESS.
 * Returns OW_ERR_NOT_FOUND / OW_ERR_INVALID_PARAM for unknown or null inputs. */
OW_STATUS    OwKdbBuildLaunchPlan(uint32_t InstanceId,
                                  OW_KDB_LAUNCH_PLAN* OutPlan);

/* True only when an executor backend is registered.  No backend is registered
 * by default in this build. */
bool         OwKdbExecutionAvailable(void);

/* Register/unregister the executor backend (single slot).  Passing a null
 * backend unregisters.  Registration does not imply MMU/CPU execution; it only
 * makes the handoff seam reachable. */
OW_STATUS    OwKdbRegisterExecutor(OW_KDB_EXECUTOR_BACKEND Backend,
                                   void* Context);
void         OwKdbUnregisterExecutor(void);

/* Rebuild and validate the launch plan internally, then hand it to the
 * registered backend.  Never trusts a caller-owned plan.  Returns
 * OW_ERR_UNSUPPORTED when no backend is registered (instance state unchanged),
 * propagates plan/instance lookup errors, or faults the instance and returns
 * the backend/validation error on a failed handoff. */
OW_STATUS    OwKdbExecuteInstance(uint32_t InstanceId);

/* ---- Executor binding view ----------------------------------------------- */
/* A binding is the executor's own record that InstanceId is owned by a concrete
 * PS process/thread.  It is exposed read-only so the syscall gateway and the
 * scheduler attribution hooks can derive authority from the thread that is
 * actually running instead of trusting a caller-supplied identifier. */
typedef struct _OW_KDB_BINDING {
    bool     InUse;
    uint32_t InstanceId;
    uint32_t AssociationId;
    uint32_t KernelId;
    uint32_t ProcessId;
    uint32_t ThreadId;
    uint64_t EntryPoint;
    uint64_t MappedBase;
    uint32_t IsolationDomain;
} OW_KDB_BINDING;

OW_STATUS    OwKdbGetBinding(uint32_t InstanceId, OW_KDB_BINDING* OutBinding);
OW_STATUS    OwKdbFindBindingByThread(uint32_t ThreadId, uint32_t ProcessId,
                                      OW_KDB_BINDING* OutBinding);
uint32_t     OwKdbBindingCount(void);

/* ---- PS scheduler/exception integration hooks ---------------------------- */
/* These are the only places where PS events become KDB execution facts.  They
 * are called by ps/ps.c and core/pgfault.c.  A thread without a live binding
 * always takes the no-op path, so normal kernel/shell threads are untouched. */
bool         OwKdbNotifyThreadDispatch(uint32_t ThreadId, uint32_t ProcessId);
bool         OwKdbNotifyThreadExit(uint32_t ThreadId, uint32_t ProcessId,
                                   uint64_t ExitStatus);
bool         OwKdbNotifyThreadFault(uint32_t ThreadId, uint32_t ProcessId,
                                    OW_STATUS FaultStatus);

/* ---- Sweep reference integration ---------------------------------------- */
/* Sweep is the primary reference associated kernel: a stripped OpenWindows
 * kernel belonging to a KAPA application.  No Sweep implementation exists in
 * this repository, so KDB registers a documented reference descriptor during
 * initialization and provides this fixture seam.  With no image the descriptor
 * is DECLARATIVE and cannot be loaded.  OwKdbAttachSweepImage() attaches a real
 * OWX image (typically the test fixture) so the same registry/loader/lifecycle
 * path can be exercised end to end. */
#define OW_KDB_SWEEP_NAME "sweep"
OW_STATUS    OwKdbRegisterSweep(const uint8_t* Image, uint32_t ImageSize,
                                uint32_t* OutKernelId);
OW_STATUS    OwKdbAttachSweepImage(const uint8_t* Image, uint32_t ImageSize);

#endif /* OW_KDB_H */
