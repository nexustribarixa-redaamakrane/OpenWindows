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
    OW_KDB_KIND_LINUX,                  /* foreign ABI: no adapter in build   */
    OW_KDB_KIND_CUSTOM                  /* application-specific kernel        */
} OW_KDB_KERNEL_KIND;

/* ABI identifiers are descriptive, not promises.  Only the OpenWindows
 * identifiers have a loader backend in this build. */
#define OW_KDB_ABI_OPENWINDOWS_NATIVE 0x4F570001U
#define OW_KDB_ABI_OPENWINDOWS_COMPAT 0x4F570002U
#define OW_KDB_ABI_LINUX_X86_64       0x4C4E5801U
#define OW_KDB_ABI_CUSTOM             0x43555301U

#define OW_KDB_FORMAT_OWX  1U
#define OW_KDB_FORMAT_ELF  2U
#define OW_KDB_FORMAT_RAW  3U

#define OW_KDB_MEMORY_PRIVATE 1U
#define OW_KDB_MEMORY_SHARED  2U

#define OW_KDB_PRIVILEGE_UNPRIVILEGED 1U
#define OW_KDB_PRIVILEGE_KERNEL_EQUIVALENT 2U

#define OW_KDB_ARCH_X86_64 1U

/* Descriptor flags.  A declarative descriptor documents an associated kernel
 * that has no image provisioned in this volume/build.  It is listed and
 * assessed, but loading it returns OW_ERR_UNSUPPORTED. */
#define OW_KDB_DESC_DECLARATIVE 0x00000001U

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
} OW_KDB_INSTANCE;

/* ---- Service Bridge ------------------------------------------------------ */
/* Service IDs are explicit.  Owner 0 is the main OpenWindows kernel; a
 * non-zero owner is the associated-kernel instance that provides the service.
 * A service ID is unique within its owner, so two instances may provide the
 * same ID without colliding. */
#define OW_KDB_SERVICE_PING 0x4B440001U
#define OW_KDB_SERVICE_ECHO 0x4B440002U

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
 * real; execution is not.  Linux/custom kinds report false. */
bool         OwKdbLoaderSupports(OW_KDB_KERNEL_KIND Kind);
OW_STATUS    OwKdbLoaderValidate(const OW_KDB_KERNEL_DESC* Desc,
                                 uint32_t* OutResidentPages);

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
    OW_KDB_BLOCKER_BACKEND_REJECTED       /* backend refused the validated plan */
} OW_KDB_EXEC_BLOCKER;

typedef struct _OW_KDB_LAUNCH_PLAN {
    uint32_t            InstanceId;
    uint32_t            KernelId;
    uint32_t            AssociationId;
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
