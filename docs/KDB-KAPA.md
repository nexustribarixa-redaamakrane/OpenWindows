# Kernel Dual Boot (KDB) and Kernel-Associated Application Architecture (KAPA)

## Architecture

- **KDB** is a kernel subsystem of the main OpenWindows kernel.  It is not a
  bootloader, not a userspace daemon and not a second-kernel execution host.  It
  lives under `kdb/` and is initialized as phase 4d in `core/main.c`, after the
  process subsystem and before the VFS phase.
- **KAPA** (Kernel-Associated Application Architecture) is the application-facing
  architecture: one application owns one associated kernel and one live instance.
  `kapa/kapa_core.c` provides a bounded facade over KDB so an application is a
  single durable object (name, association, kernel, instance, observable state)
  rather than a caller re-deriving state from three separate tables.
- An associated kernel is **admitted, validated and managed** by KDB.  This build
  executes native OpenWindows OWX images through the PS scheduler on non-host
  builds; foreign Linux/BSD/Unix/custom images are validated, planned and tracked
  but have no execution path yet.

KDB owns the registry, the ABI table, the compatibility policy, the loader
front-end, application associations, the instance lifecycle, the executor
bindings, the bounded history log, the Service Bridge and the Sweep reference
integration.  KAPA owns the application view over that machinery.

## Scope and honest limitations

What this build implements:

- a static, compile-time-sized registry of associated-kernel descriptors;
- a static ABI registry with nine built-in ABIs (OpenWindows, Linux, BSD,
  FreeBSD, NetBSD, OpenBSD, SysV Unix and generic custom) plus custom ABIs
  composed from one or more manifest files;
- ABI-aware compatibility policy with distinct verdicts per axis (architecture,
  ABI/family/kind, format, memory model, privilege model);
- image front-ends for three formats:
  - **OWX** — the existing OpenWindows structural checks and whole-image CRC32c
    verdicts from `ps/owx_loader.c`, plus resident-page accounting;
  - **ELF** — a bounded ELF64 little-endian x86-64 parser/validator;
  - **RAW** — a flat image whose load base, entry point and segments are
    supplied by a composed ABI manifest;
- multi-file manifest composition, where later files override earlier ones and
  unknown keys/values are refused;
- application associations between KAPA applications and kernel descriptors;
- instance lifecycle (`READY -> RUNNING -> STOPPED -> RUNNING`, faults terminal)
  with page budget, logical isolation domain and fault cleanup;
- a PS-backed executor for native OWX images: process/thread creation, CIS-gated
  image load, dormant launch, binding installation, scheduler wake, dispatch /
  exit / fault attribution;
- bounded read-only executor bindings (`OW_KDB_BINDING`) so authority can be
  derived from the thread that is actually running;
- a bounded lifecycle/execution history ring;
- explicit policy widening for shared memory and kernel-equivalent privilege;
- a bounded in-kernel Service Bridge with four built-in main-kernel services and
  per-service call accounting;
- a CPL3 syscall gateway (`OW_SYS_KDB_BRIDGE`) whose authorization comes from
  the calling thread's live KDB binding, never from a caller-supplied
  association;
- the Sweep reference associated kernel, registered declaratively while no
  Sweep implementation exists in this repository.

What this build does **not** implement, and therefore does not claim:

- execution of Linux, BSD, Unix or custom associated kernels (they are
  admitted/validated/planned, but the launch plan reports
  `OW_KDB_BLOCKER_ABI_UNSUPPORTED`);
- foreign-OS syscall emulation or boot adapters;
- hypervisor/VM/partition support;
- MMU/CPU privilege isolation between the main kernel and foreign code, or a
  second kernel running on a separate CPU.

`ExecutionSupported` is true only for the native/compat OWX ABIs.  A foreign ABI
is a first-class managed object with a real loader and real resource accounting;
it is not silently treated as OpenWindows.

## ABI registry

The ABI registry (`kdb/kdb_abi.c`) is the single authority for family, kind,
image format, ELF OSABI, default load base/entry, manifest segments and whether
the build has an execution path.  It is bounded by `OW_KDB_MAX_ABIS` (32) and
uses no dynamic allocation.

Built-ins installed by `OwKdbInitialize()`:

| ID | Name | Family | Kind | Format | OSABI | Executes |
|---|---|---|---|---|---|---|
| `0x4F570001` | `openwindows.native` | OpenWindows | native | OWX | SYSV | yes |
| `0x4F570002` | `openwindows.compat` | OpenWindows | modified | OWX | SYSV | yes |
| `0x4C4E5801` | `linux.x86_64` | Linux | Linux | ELF | Linux | no |
| `0x42534401` | `bsd.x86_64` | BSD | BSD | ELF | SYSV (any BSD flavour) | no |
| `0x42534402` | `freebsd.x86_64` | BSD | BSD | ELF | FreeBSD | no |
| `0x42534403` | `netbsd.x86_64` | BSD | BSD | ELF | NetBSD | no |
| `0x42534404` | `openbsd.x86_64` | BSD | BSD | ELF | OpenBSD | no |
| `0x55535801` | `unix.sysv.x86_64` | Unix | Unix | ELF | SYSV | no |
| `0x43555301` | `custom` | Custom | Custom | RAW | SYSV | no |

Manifest-composed custom ABIs are allocated from `OW_KDB_ABI_CUSTOM_BASE`
(`0x43555300`); allocation starts at `0x43555302`.  The generic
`OW_KDB_ABI_CUSTOM` (`0x43555301`) remains the identity for a descriptor that
does not name a specific manifest.

Public queries: `OwKdbGetAbi`, `OwKdbGetAbiByIndex`, `OwKdbFindAbi`,
`OwKdbAbiCount`, `OwKdbAbiFamilyName`, `OwKdbAbiOriginName`.

## Image formats and validation

### OWX

OWX is the native format.  Validation reuses the main loader's structural and
CRC32c checks (`OwOwxImageIsLoadable`, `OwOwxImageIsUsable`), requires a
non-zero entry point, and charges the image size in 4 KiB pages.  The descriptor
must carry an OpenWindows ABI.

### ELF

`kdb/kdb_elf.c` parses only ELF64, little-endian, `EM_X86_64`,
`ET_EXEC`/`ET_DYN` images.  It validates the program-header table bounds, every
`PT_LOAD` segment (`p_filesz <= p_memsz`, file range inside the image, no
arithmetic overflow), requires all loads and the entry point to be inside
`OW_USER_WINDOW_BASE..OW_USER_WINDOW_END`, and requires the entry to fall inside
an executable `PT_LOAD` segment.

- `ET_EXEC` keeps its declared virtual addresses.
- `ET_DYN` is relocated to `OW_USER_IMAGE_BASE`.
- If a composed ABI documents an expected base or entry, the image must match
  it; a mismatch is `OW_ERR_CORRUPT` rather than a guess.

The OSABI check is ABI-aware: Linux accepts `SYSV` or `Linux`; a generic BSD ABI
accepts `SYSV`, `NetBSD`, `FreeBSD` or `OpenBSD`; a specific BSD ABI requires
exactly its OSABI; Unix requires `SYSV`.  `OwKdbElfInspect` reports the parsed
facts; `OwKdbElfValidate` adds the OSABI check and resident-page count.

### RAW

A flat image has no self-describing header, so the composed ABI is the authority:

- `[image] base` and `entry` are required and must be inside the user window;
- `entry >= base`;
- each `[segment]` must have non-zero `memsz`, `filesz <= memsz`, and its whole
  virtual range inside the user window;
- the entry point must fall inside an executable segment.

Resident pages are the image size in pages plus any documented segment span that
extends beyond the flat image.

## Custom ABIs from one or more manifests

`OwKdbAbiComposeCustom()` (and the KAPA-level `OwKapaComposeAbi()`) accepts up
to `OW_KDB_MAX_MANIFEST_FILES` (8) bounded text files.  Files are applied in
order, so a later file overrides earlier values.  The caller keeps ownership of
the buffers.

Manifest grammar:

- `#` starts a comment; blank lines and lines beginning with `;` are ignored;
- sections: `[abi]`, `[image]`, `[policy]`, `[segment]`;
- `key = value`, case-insensitive keys and symbolic values;
- numbers accept decimal or `0x` hexadecimal;
- unknown sections, keys or values are refused (`OW_ERR_INVALID_PARAM`);
- a line longer than the internal bound is refused.

Recognized keys:

| Section | Keys | Notes |
|---|---|---|
| `[abi]` | `name` (required), `id`, `family`, `kind`, `format`, `osabi`/`elf_osabi`, `arch`/`target_arch` | `family` and `kind` must agree |
| `[image]` | `base`/`load_base`, `entry`/`entry_point` | required for RAW |
| `[policy]` | `shared_memory`/`shared`, `kernel_privilege`/`privileged` | boolean |
| `[segment]` | `name`, `vaddr`/`virtual_address`, `offset`/`file_offset`, `filesz`/`file_size`, `memsz`/`memory_size`, `flags` | `flags` is `r`, `w`, `x`, a combination, or `0` |

Defaults when omitted: family `custom`; kind derived from family; format `OWX`
for OpenWindows, `ELF` for Linux/BSD/Unix and `RAW` for custom; OSABI `Linux`
for Linux, `FreeBSD` for BSD and `SYSV` otherwise.  Only x86-64 is admitted.

Example — a raw custom ABI split across two files:

```ini
# base.manifest
[abi]
name = example.raw
family = custom
kind = custom
format = raw
[image]
base = 0x04000000
entry = 0x04000000
[segment]
name = code
vaddr = 0x04000000
offset = 0
filesz = 0x40
memsz = 0x1000
flags = rx
```

```ini
# local.overlay
[abi]
name = example.raw.local
[policy]
shared_memory = true
```

Composition registers the result immediately and returns its ABI id.
`OwKdbUnregisterAbi()` removes a manifest-composed ABI; built-ins are refused
(`OW_ERR_INSUFFICIENT`).

## Compatibility matrix

`OwKdbAssessCompatibility()` is pure policy: it does not touch the registry and
does not inspect image contents.

| Axis | Verdict | Meaning |
|---|---|---|
| Descriptor | `OW_KDB_COMPAT_INVALID_DESCRIPTOR` | Malformed name, ABI or image metadata |
| Architecture | `OW_KDB_COMPAT_ARCH_MISMATCH` | Only x86-64 targets are admitted |
| Kind | `OW_KDB_COMPAT_UNSUPPORTED_KIND` | Unknown kind |
| ABI | `OW_KDB_COMPAT_ABI_MISMATCH` | The descriptor's kind and ABI family/kind do not agree, or the ABI is unknown |
| Format | `OW_KDB_COMPAT_FORMAT_MISMATCH` | Descriptor format differs from the ABI's format |
| Memory model | `OW_KDB_COMPAT_MEMORY_MODEL` | ABI requires shared memory but descriptor is private, or shared memory is not allowed by policy |
| Privilege | `OW_KDB_COMPAT_PRIVILEGE_MODEL` | ABI requires kernel privilege but descriptor is unprivileged, or policy refuses it |

A valid Linux/BSD/Unix/custom descriptor returns `OW_SUCCESS` /
`OW_KDB_COMPATIBLE`.  Execution support is reported separately by the ABI
descriptor and the launch plan, so "right ABI, no execution path" is never
confused with "wrong ABI".

## Policy

The default policy is closed: shared memory and kernel-equivalent privilege are
refused.  An operator may widen it explicitly:

- `OW_KDB_POLICY_ALLOW_SHARED_MEMORY` — admit `OW_KDB_MEMORY_SHARED`;
- `OW_KDB_POLICY_ALLOW_KERNEL_PRIVILEGE` — admit
  `OW_KDB_PRIVILEGE_KERNEL_EQUIVALENT`.

`OwKdbSetPolicy()` / `OwKdbGetPolicy()` expose the active flags.  An ABI's own
requirements (`OW_KDB_ABI_FLAG_REQUIRES_SHARED_MEMORY`,
`OW_KDB_ABI_FLAG_REQUIRES_KERNEL_PRIVILEGE`) must also match the descriptor;
the descriptor cannot silently lower an ABI's requirement.

## Isolation semantics

KDB's isolation is logical and resource ownership based, not an MMU or CPU
privilege boundary across an execution that does not happen for foreign code:

- every instance receives a stable isolation-domain identifier;
- every instance receives a page budget (`OW_KDB_DEFAULT_PAGE_LIMIT` = 1024
  pages by default; an explicit per-association limit overrides it);
- every instance receives its own service namespace (service IDs are unique
  within an owner, so two instances may own the same ID without colliding);
- a native instance that is really executed receives its own PS process, guarded
  user window and primary thread.

## Public API

### KDB (`inc/ow_kdb.h`)

- initialization: `OwKdbInitialize`, `OwKdbIsReady`, `OwKdbGetStats`;
- registry: `OwKdbRegisterKernel`, `OwKdbUnregisterKernel`, `OwKdbGetKernel`,
  `OwKdbFindKernel`, `OwKdbGetKernelByIndex`, `OwKdbKernelCount`,
  `OwKdbAssessCompatibility`;
- ABI registry: `OwKdbGetAbi`, `OwKdbGetAbiByIndex`, `OwKdbFindAbi`,
  `OwKdbAbiCount`, `OwKdbAbiComposeCustom`, `OwKdbUnregisterAbi`;
- ELF: `OwKdbElfInspect`, `OwKdbElfValidate`;
- loader: `OwKdbLoaderSupports`, `OwKdbLoaderValidate`;
- policy: `OwKdbSetPolicy`, `OwKdbGetPolicy`;
- associations: `OwKdbAssociateApplication`, `OwKdbGetAssociation`,
  `OwKdbFindAssociation`, `OwKdbDisassociateApplication`,
  `OwKdbAssociationCount`;
- instances: `OwKdbLoadInstance`, `OwKdbStartInstance`, `OwKdbStopInstance`,
  `OwKdbFaultInstance`, `OwKdbDestroyInstance`, `OwKdbGetInstance`,
  `OwKdbGetInstanceByIndex`, `OwKdbInstanceCount`;
- history: `OwKdbHistoryCount`, `OwKdbGetHistoryEvent`,
  `OwKdbGetHistoryEventForInstance`, `OwKdbHistoryCountForInstance`,
  `OwKdbClearHistory`, `OwKdbInstanceEventName`;
- execution: `OwKdbBuildLaunchPlan`, `OwKdbExecutionAvailable`,
  `OwKdbRegisterExecutor`, `OwKdbUnregisterExecutor`, `OwKdbExecuteInstance`;
- bindings: `OwKdbGetBinding`, `OwKdbFindBindingByThread`, `OwKdbBindingCount`;
- scheduler/exception hooks: `OwKdbNotifyThreadDispatch`,
  `OwKdbNotifyThreadExit`, `OwKdbNotifyThreadFault`;
- Service Bridge: `OwKdbServiceRegister`, `OwKdbServiceUnregister`,
  `OwKdbBridgeCall`, `OwKdbBridgeGetCallAttr`, `OwKdbGetServiceByIndex`,
  `OwKdbServiceCount`;
- Sweep: `OwKdbRegisterSweep`, `OwKdbAttachSweepImage`.

Internal cross-module interfaces live in `kdb/kdb_internal.h`; the implementation
is split one translation unit per module (`kdb_core.c`, `kdb_registry.c`,
`kdb_loader.c`, `kdb_manager.c`, `kdb_assoc.c`, `kdb_bridge.c`, `kdb_sweep.c`,
`kdb_exec.c`, `kdb_exec_ps.c`, `kdb_abi.c`, `kdb_elf.c`, `kdb_manifest.c`,
`kdb_history.c`).

### KAPA (`inc/ow_kapa.h`)

`OwKapaInitialize`, `OwKapaIsReady`, `OwKapaStateName`,
`OwKapaRegisterApplication`, `OwKapaUnregisterApplication`,
`OwKapaGetApplication`, `OwKapaFindApplication`,
`OwKapaGetApplicationByIndex`, `OwKapaApplicationCount`, `OwKapaComposeAbi`,
`OwKapaLoad`, `OwKapaExecute`, `OwKapaStop`, `OwKapaFault`, `OwKapaDestroy`,
`OwKapaBridgeCall`, `OwKapaGetStats`.

## Instance lifecycle and history

```
READY -> RUNNING -> STOPPED -> RUNNING
  |         |          |
  +---------+----------+-------> FAULTED -> destroyed
```

- Loading an association validates compatibility and the image, runs the loader
  front-end, charges resident pages against the page limit and creates the
  instance in `READY`.
- `OW_KDB_DEFAULT_PAGE_LIMIT` is used when the caller passes a zero limit; a
  smaller budget than the delivered image is refused with `OW_ERR_INSUFFICIENT`.
- `OwKdbStartInstance()` is the logical start; for a real execution the PS
  backend moves the instance to `RUNNING` only from the scheduler dispatch hook.
- Stopping an instance abandons any live PS binding before the instance becomes
  `STOPPED`.
- Fault cleanup releases the page charge, clears the association link, unregisters
  every service owned by the instance and abandons the PS binding.  The
  descriptor remains queryable as `FAULTED` until `OwKdbDestroyInstance()`.
- One association owns at most one instance.

Every material transition is recorded in a bounded ring (`OW_KDB_MAX_HISTORY` =
128): `LOADED`, `STARTED`, `RUNNING`, `STOPPED`, `FAULTED`, `EXECUTED`,
`DESTROYED`, with status, instance id, process/thread ids and entry point.
Entries are facts recorded by the manager or an executor hook, never speculative
state.  Per-instance queries filter the ring without copying it.

## Execution model

### Launch plan and blockers

`OwKdbBuildLaunchPlan()` materializes, for one live instance, everything an
executor would need: the still-valid image (re-validated at call time, since the
registry holds a caller-owned pointer), its page charge, ABI/format, entry point,
mapped base, isolation domain and state, plus `ManagementReady` and an explicit
`OW_KDB_EXEC_BLOCKER`.

State distinctions are never conflated:

- **Admissible** — image/policy/charge checks pass for the current image.
- **ManagementReady** — KDB has prepared the launch metadata for handoff.
- **Executing** — a real executor accepted the launch and initiated execution.

Blockers: `NONE`, `INSTANCE_NOT_FOUND`, `INSTANCE_FAULTED`, `IMAGE_INVALID`,
`PAGE_BUDGET_EXCEEDED`, `NO_ISOLATION_DOMAIN`, `NO_ENTRY_POINT`,
`EXECUTOR_UNAVAILABLE`, `ABI_UNSUPPORTED`, `BACKEND_REJECTED`.

A foreign ABI produces a management-ready plan with
`OW_KDB_BLOCKER_ABI_UNSUPPORTED`.  `OwKdbExecuteInstance()` returns
`OW_ERR_UNSUPPORTED` and leaves a valid instance unchanged; it does not fault it
merely because execution is unavailable.

### PS-backed executor (native OWX)

On non-host builds `OwKdbExecPsInitialize()` registers the PS backend.  For an
accepted native OWX plan it:

1. creates a PS process owned by the kernel identity;
2. loads the image with `OwPsLoadImage(..., OW_CIS_RECORD_SPAWN)` so the
   Copyleft Integrity Safeguard verdict gates the load;
3. launches the entry thread **dormant and unpublished** via
   `OwPsLaunchUserImageEx(..., false)`;
4. installs the instance binding (process/thread ids, entry, base, domain);
5. records the execution fact in the history;
6. wakes the thread with `OwPsWakeThread()` only after the binding exists.

The instance becomes `RUNNING` from `OwKdbNotifyThreadDispatch()` when the
scheduler is about to resume the thread.  A normal exit takes
`OwKdbNotifyThreadExit()` to `STOPPED`; a terminal ring-3 fault takes
`OwKdbNotifyThreadFault()` (from `core/pgfault.c`) to `FAULTED` before
`OwPsExitThread()`.  Threads without a binding always take the no-op path, so
normal kernel and shell threads are untouched.

`OwKdbExecPsAbandonInstance()` is the single teardown path used by stop, fault,
destroy and exit.  It clears the binding, retires a still-ready thread from the
scheduler and terminates the process.

On `OW_HOST_HAL` builds the PS backend is deliberately not registered, so
`OwKdbExecutionAvailable()` is false and host tests exercise the
executor-unavailable and foreign-ABI-blocker paths without pretending a real
CPL3 launch happened.

### Bindings and attribution

A binding is the executor's own record that an instance is owned by a concrete
PS process/thread.  Bindings are read-only through `OwKdbGetBinding()` and
`OwKdbFindBindingByThread()`; they store identifiers, never PS object pointers.
The syscall gateway and the scheduler hooks derive authority from the thread that
is actually running instead of trusting a caller-supplied id.

## Service Bridge

- Service IDs are explicit and unique within their owner.  Owner `0` is the main
  OpenWindows kernel; a non-zero owner is an associated-kernel instance.
- Built-in main-kernel services:
  - `main.ping` (`0x4B440001`) — response `kdb-pong` (8 bytes);
  - `main.echo` (`0x4B440002`) — echoes the request;
  - `main.log` (`0x4B440003`) — bounded attributed log, no response;
  - `main.runtime_info` (`0x4B440004`) — 8-byte little-endian uptime in ms.
- A handler is invoked through KDB-owned copies: the request is copied into a
  KDB buffer before the handler runs, the handler writes into a KDB-owned
  response buffer, and a successful response is length-checked and copied back
  to the caller.  Handlers must not retain any pointer after returning.
- Capability checks enforce the required bits per service; a caller that is not
  the owning association needs `OW_KDB_CAP_ADMIN`.
- Calls into a non-zero instance require a `RUNNING` target owned by the caller
  or admin.
- `OwKdbGetServiceByIndex()` / `OwKdbServiceCount()` expose the service table
  with owner, required capabilities, request/response bounds and per-service
  call count.
- `OwKdbBridgeGetCallAttr()` gives a handler the caller association and target
  instance for the call currently inside it, so built-ins can attribute a
  request without receiving caller-controlled identifiers.

## Syscall gateway (`OW_SYS_KDB_BRIDGE`, `0x022`)

CPL3 code reaches the bridge through one syscall:

- `P1` is a user VA of `OW_SYS_KDB_BRIDGE_CALL`; `P2`/`P3` must be zero.
- The struct carries magic (`'KDB C'`), version `1`, `ServiceId`,
  `TargetInstanceId`, request/response VAs and lengths, and a zero `Reserved`.
- Authorization is derived from `OwKdbFindBindingByThread()` for the calling
  thread.  A thread with no binding is refused, so an ordinary userspace process
  cannot reach the associated-kernel bridge.
- `TargetInstanceId` must be `0` (main kernel) or the binding's own instance.
- The request struct, request payload and response buffer are each validated
  against the caller's own user range and the guarded user window before any byte
  is copied.  Lengths are bounded by `OW_KDB_BRIDGE_MAX_REQUEST` /
  `OW_KDB_BRIDGE_MAX_RESPONSE`.
- On success the updated struct (including `ResponseLength`) is copied back; any
  refusal returns `-1` without calling the bridge.

## KAPA facade

KAPA is a thin, bounded application registry over KDB.  It deliberately does not
add a second state machine: application state is refreshed from the live KDB
instance every time it is observed, so KAPA cannot report `RUNNING` for an
instance KDB says is `READY`, or keep an instance link after a fault released it.

- `OwKapaRegisterApplication()` registers the application and creates its KDB
  association in one step; the kernel must already exist and pass compatibility.
- `OwKapaLoad()` loads the association into a `READY` instance and refuses a
  second live instance for the same application.
- `OwKapaExecute()` calls `OwKdbExecuteInstance()`.  It never calls
  `OwKdbStartInstance()` on its own and never fabricates execution; with no
  backend the application stays `LOADED`.
- `OwKapaStop()` abandons the live PS binding through the KDB stop path before
  marking the application `STOPPED`.
- `OwKapaFault()` faults the instance and releases resources.
- `OwKapaDestroy()` destroys the instance but keeps the application associated,
  ready to load again.
- `OwKapaUnregisterApplication()` destroys any live instance, releases the
  association and frees the slot.
- `OwKapaBridgeCall()` forwards to `OwKdbBridgeCall()` using the application's
  association as the caller identity.
- `OwKapaComposeAbi()` is the KAPA-level entry point to manifest composition.

All storage is static (`OW_KAPA_MAX_APPLICATIONS` = 32); the API is
single-threaded kernel code and takes no locks.

## Sweep reference integration

Sweep is the primary reference associated kernel of the architecture.  No Sweep
implementation exists in this repository, so KDB registers a declarative Sweep
descriptor (`OW_KDB_SWEEP_NAME`, stripped OpenWindows kind, compatibility ABI,
private memory, unprivileged) during `OwKdbInitialize()`.  Until an image is
attached with `OwKdbAttachSweepImage()`, the descriptor is `DECLARATIVE` and
cannot be loaded; loading returns `OW_ERR_UNSUPPORTED`.

`OwKdbAttachSweepImage()` accepts a real OWX image (the host test uses the
validated `owinit.owx` fixture) so the registry, loader, lifecycle and bridge
paths are exercised end to end.  A native OWX descriptor is the only kind the
PS backend will execute.

## Implementation status

- Implemented (freestanding build verified): initialization, registry round trips
  and duplicate rejection, the nine-ABI registry and manifest composition,
  ABI-aware compatibility verdicts, OWX/ELF/RAW validation and page accounting,
  policy widening, association management, instance lifecycle and page budget,
  isolation-domain assignment, fault cleanup, the bounded history ring, Service
  Bridge ownership/bounds/capability rules and four built-ins, service
  enumeration and call accounting, launch-plan materialization, the
  executor-backend seam, PS-backed native OWX execution on non-host builds,
  bindings, scheduler/exception attribution, the CPL3 syscall gateway and the
  KAPA facade.
- Not implemented, and therefore not claimed: foreign Linux/BSD/Unix/custom
  execution, foreign-OS syscall emulation, VM/partition/MMU isolation for
  foreign code, and a second kernel on a separate CPU.
- KDB boot failure is tolerated by `core/main.c`: it logs
  `OW_W_KDB_UNAVAILABLE` and the boot continues without KAPA associations.

## Verification (honest status)

- Freestanding PE build: `make -j 4` produces `openwinkrnl.owx` successfully.
  The KDB/KAPA objects and SuperUnicode objects/generated font header
  (`tools/embed_suf.py` → `build-generated/generated/ow_terminal_font.h`) are
  wired into both the Makefile and CMake.
- Hosttest: `make hosttest` — **`=== RESULT: 1608 passed, 0 failed ===`**.
  The KDB suite prints `--- Kernel Dual Boot / KAPA verified`, and the extension
  suite prints `--- KDB extensions verified`.  Kernel Integrity passes with the
  correctly provisioned full image.
- ASan: `make hosttest-asan` cannot link in this w64devkit toolchain because
  `libasan`/`libubsan` are absent (`ld: cannot find -lasan`, `cannot find
  -lubsan`).  This is an environment limitation, not a code failure; the normal
  host suite is green.

### Hosttest boot-failure diagnosis (resolved)

- **Symptom:** an earlier run logged `[PS] owinit: address space allocation
  FAILED`, then provisioned a truncated `openwinkrnl.owx`, hit Sentinel
  `SHA-256 checksum mismatch` and entered `SYSTEM HALTED`.
- **Root cause:** silent truncation in `tools/hosttest/host_boot.c`.  The image
  buffer was too small and `host_read_file()` stopped at capacity.
- **Not the cause:** `[PS] owinit: address space allocation FAILED` is expected
  under `OW_HOST_HAL` (`OwMemCreateAddressSpace()` returns 0 by design).
- **Fix:** the image buffer was enlarged and `host_read_file()` now probe-reads
  after filling capacity and fails instead of returning a truncated count.

## Diagnostics

- `OW_C_KDB_READY` (`0x0011AC14`) — KDB phase reached its ready state.
- `OW_W_KDB_UNAVAILABLE` (`0x0011A806`) — KDB initialization failed; the boot
  continues without KAPA associations.

## Tests (source coverage)

`tools/hosttest/host_boot.c` contains:

- `test_kdb()` — initialization, Sweep declarative state, registry duplicates and
  invalid descriptors, the compatibility matrix, OWX loader support/validation
  and corruption handling, associations, instance lifecycle and page budget,
  fault cleanup, Service Bridge built-ins and rules, cross-instance
  authorization, Sweep fixture attach/load, launch-plan/executor-seam checks and
  executor binding/attribution scaffolding.
- `test_kdb_extensions()` — the ABI registry (nine built-ins, queries, names),
  ELF `ET_EXEC`/`ET_DYN` and malformed images, multi-file manifest composition
  and override, raw custom load/plan/history/policy, binding absence, KAPA
  register/load/execute-unsupported/stop/fault/destroy/unregister, bridge
  PING/ECHO/LOG/RUNTIME_INFO enumeration and call counts, and syscall-gateway
  refusal without a caller.

Run with `make hosttest` (or `cmake --build <build> --target hosttest && ctest -R
hosttest`).  Latest verified run: **1608 passed, 0 failed**.
