# Kernel Dual Boot (KDB) and Kernel-Associated Application Architecture (KAPA)

## Architecture

- KDB is a kernel subsystem of the main OpenWindows kernel, not a bootloader, not a
  userspace daemon, and not a second-kernel execution host.  It lives under `kdb/` and
  is integrated into the boot sequence as a new phase in `core/main.c` (phase 4d, after
  the process subsystem and before the VFS phase).
- KAPA (Kernel-Associated Application Architecture) is the overall architecture that
  describes an application owning one associated kernel.  KDB is the kernel-side
  management plane that the KAPA application is expressed through: it owns the
  registry, the compatibility policy, the loader front-end, the application
  associations, the instance lifecycle, the Service Bridge and the Sweep reference
  integration.
- An associated kernel is *admitted*, not *executed* by KDB.  This build does not run a
  second kernel on spare CPUs, does not create a VM partition or a flat kernel media for
  one, and does not implement boot adapters for Linux or arbitrary custom kernels.  The
  loader front-end recognizes those kinds and reports them as unsupported rather than
  silently treating them as OpenWindows-derived.

## Scope and honest limitations

What this build implements:

- static, compile-time-sized registry of associated-kernel descriptors;
- compatibility policy with distinct verdicts per axis (architecture, ABI, format,
  memory model, privilege model, kind);
- OWX image validation front-end using the same structural checks and whole-image CRC32c
  verdicts the main loader uses (`ps/owx_loader.c`), plus resident-page accounting;
- application associations between KAPA applications and kernel descriptors;
- instance lifecycle (READY -> RUNNING -> STOPPED -> RUNNING, faults terminal) with
  page budget, logical isolation domain and fault cleanup;
- bounded in-kernel Service Bridge (explicit service IDs, KDB-owned request and response
  copies, capability checks, caller/instance validation, length checks, ownership rules);
- the Sweep reference associated kernel, registered declaratively while no Sweep
  implementation exists in this repository.

What this build does not implement, and therefore does not claim:

- execution of an associated kernel as real second-kernel execution;
- hypervisor/VM/partition support;
- Linux or custom-kernel execution adapters;
- MMU/CPU privilege isolation between the main kernel and associated kernel code.

## Isolation semantics

KDB's "isolation" is deliberately logical and resource ownership based, not an MMU or CPU
privilege boundary across an execution that does not happen in this build:

- every instance receives a stable isolation-domain identifier;
- every instance receives a page budget (`OW_KDB_DEFAULT_PAGE_LIMIT` = 1024 pages by
  default, the explicit per-association limit overrides it);
- every instance receives its own service namespace (service IDs are unique within an
  owner, so two instances may own the same ID without colliding).

A descriptor that asks for shared memory or kernel-equivalent privilege is refused by the
compatibility policy instead of being loaded under an isolation assumption KDB cannot keep.

## Public API (`inc/ow_kdb.h`)

- `OwKdbInitialize()` / `OwKdbIsReady()` / `OwKdbGetStats()` — boot phase entry point and
  aggregate accounting;
- registry: `OwKdbRegisterKernel`, `OwKdbUnregisterKernel`, `OwKdbGetKernel`,
  `OwKdbFindKernel`, `OwKdbGetKernelByIndex`, `OwKdbKernelCount`, `OwKdbAssessCompatibility`;
- loader: `OwKdbLoaderSupports`, `OwKdbLoaderValidate`;
- associations: `OwKdbAssociateApplication`, `OwKdbGetAssociation`,
  `OwKdbFindAssociation`, `OwKdbDisassociateApplication`;
- instances: `OwKdbLoadInstance`, `OwKdbStartInstance`, `OwKdbStopInstance`,
  `OwKdbFaultInstance`, `OwKdbDestroyInstance`, `OwKdbGetInstance`, `OwKdbGetInstanceByIndex`;
- execution model: `OwKdbBuildLaunchPlan`, `OwKdbExecutionAvailable`,
  `OwKdbRegisterExecutor`, `OwKdbUnregisterExecutor`, `OwKdbExecuteInstance`;
- Service Bridge: `OwKdbServiceRegister`, `OwKdbServiceUnregister`, `OwKdbBridgeCall`;
- Sweep: `OwKdbRegisterSweep`, `OwKdbAttachSweepImage`.

Internal cross-module interfaces live in `kdb/kdb_internal.h`; the implementation is split
into one translation unit per module (`kdb/kdb_core.c`, `kdb_registry.c`, `kdb_loader.c`,
`kdb_manager.c`, `kdb_assoc.c`, `kdb_bridge.c`, `kdb_sweep.c`) so no module is a single
monolithic file.

## Compatibility matrix

| Axis | Verdict | Meaning |
|---|---|---|
| Kind | `OW_KDB_COMPAT_UNSUPPORTED_KIND` | OpenWindows-derived kinds have backends in this build; Linux / custom report unsupported |
| Architecture | `OW_KDB_COMPAT_ARCH_MISMATCH` | Only x86-64 targets are admitted |
| ABI | `OW_KDB_COMPAT_ABI_MISMATCH` | OpenWindows-derived kinds require their documented ABI; Linux / custom require their documented ABI |
| Format | `OW_KDB_COMPAT_FORMAT_MISMATCH` | OpenWindows requires OWX, Linux requires ELF, custom requires raw |
| Memory model | `OW_KDB_COMPAT_MEMORY_MODEL` | Only private memory is admitted; shared memory is refused |
| Privilege | `OW_KDB_COMPAT_PRIVILEGE_MODEL` | Only unprivileged kernels are admitted |
| Descriptor | `OW_KDB_COMPAT_INVALID_DESCRIPTOR` | Malformed names or image metadata |

A compatible descriptor for a Linux or custom kernel is returned as `OW_KDB_COMPAT_UNSUPPORTED_KIND`
with the reason "this build has no loader adapter for that kernel kind", which distinguishes
"wrong ABI" from "right ABI, not implemented yet".

## Instance lifecycle
```
READY -> RUNNING -> STOPPED -> RUNNING
  |         |          |
  +---------+----------+-------> FAULTED -> destroyed
```

- Loading an association validates the kernel, runs the loader front-end, charges the
  resident pages against the page limit and creates the instance in `READY`.
- `OW_KDB_DEFAULT_PAGE_LIMIT` is used when the caller passes a zero limit; a smaller budget
  than the delivered image is refused with `OW_ERR_INSUFFICIENT`.
- Fault cleanup releases the page charge, clears the association link and unregisters every
  service owned by the instance. The descriptor remains queryable as `FAULTED` until
  `OwKdbDestroyInstance()`.
- One association owns at most one instance.

## Execution model (launch plan + executor seam)

`OwKdbBuildLaunchPlan()` is the management half of associated-kernel execution. For one
live instance it materializes everything an executor would be handed: the still-valid image
(re-validated at call time, since the registry holds a caller-owned pointer), its page
charge, entry point, mapped base and isolation domain, plus a `ManagementReady` verdict and
an explicit `Blocker`.

State distinctions (never conflated):
- **Admissible**: image/policy/charge checks pass for the current image.
- **ManagementReady**: KDB has prepared the launch metadata for handoff.
- **Executing**: a real executor backend accepted the launch and initiated execution (not
  implemented in this build; no backend is registered by default).

`OwKdbExecutionAvailable()` is true only when an executor backend is registered; no backend
is registered by default. A ready instance with no backend reports
`OW_KDB_BLOCKER_EXECUTOR_UNAVAILABLE`.

`OwKdbExecuteInstance()` rebuilds the authoritative launch plan internally (it never trusts
a caller-owned plan), validates invariants, and hands the validated plan to the registered
backend (`OW_KDB_EXECUTOR_BACKEND`). No backend => `OW_ERR_UNSUPPORTED` with instance state
unchanged. Backend failure => the instance is faulted (resources released via the manager's
fault path) and the error is returned. Backend success means the backend accepted the plan;
KDB does not fabricate a fake hardware-executing state.

Actual second-kernel CPU/VM/MMU execution, Linux/custom adapters, and address-space
handoff remain future work. The first intended execution target is the OpenWindows-derived
Sweep kernel image.

## Service Bridge

- Service IDs are explicit and unique within their owner; owner `0` is the main
  OpenWindows kernel, a non-zero owner is the associated-kernel instance.
- A handler is invoked through KDB-owned copies: the request is copied into a KDB buffer
  before the handler runs, the handler writes into a KDB-owned response buffer, and a
  successful response is length-checked and copied back to the caller.
- Handlers must not retain any pointer after returning.
- Capability checks enforce the required capability bits per service; a caller that is not
  the owning association needs `OW_KDB_CAP_ADMIN`.
- Calls into a non-zero instance require a `RUNNING` target owned by the caller or admin.

## Sweep reference integration

Sweep is the primary reference associated kernel of the architecture. No Sweep
implementation exists in this repository, so KDB registers a declarative Sweep descriptor
(`OW_KDB_SWEEP_NAME`, stripped OpenWindows kind, compatibility ABI, private memory,
unprivileged) during `OwKdbInitialize()`. Until an image is attached with
`OwKdbAttachSweepImage()`, the descriptor is `DECLARATIVE` and cannot be loaded; loading
returns `OW_ERR_UNSUPPORTED`.

`OwKdbAttachSweepImage()` accepts a real OWX image (the host test uses the validated
`owinit.owx` fixture) so the registry, loader, lifecycle and bridge paths are exercised end
to end.

## Implementation status

- Implemented (freestanding build verified): initialization, registry round trips and
  duplicate rejection, compatibility verdicts, OWX load validation (structure + CRC32c)
  and page accounting, association management, instance lifecycle, page budget,
  isolation-domain assignment, fault cleanup, Service Bridge ownership/bounds/capability
  rules, built-in `main.ping` / `main.echo` services, Sweep attach path, launch-plan
  materialization, and the executor backend registration/handoff seam (no backend
  registered by default).
- Not implemented, and therefore not claimed: actual second-kernel execution on
  separate CPU/context, VM/partition/MMU isolation for foreign code, and
  Linux/custom-kernel boot adapters.
- KDB boot failure is tolerated by `core/main.c`: it logs
  `OW_W_KDB_UNAVAILABLE` and the boot continues without KAPA associations.

## Verification (honest status)

- Freestanding PE build: `make -j 4` produces `openwinkrnl.owx` successfully (verified).
  `kdb_exec.c`/KDB objects and SuperUnicode objects/generated font header
  (`tools/embed_suf.py` → `build-generated/generated/ow_terminal_font.h`, included via
  `-I./build-generated/generated`, `lib/ow_superunicode.o`) are wired in Makefile/CMake.
- Hosttest: `make hosttest` — **`=== RESULT: 1418 passed, 0 failed ===`**
  (`build-hosttest-kdb-exec.log`, completed). Kernel Integrity passed with the correctly
  provisioned full image (`provisioned openwinkrnl.owx on host OWFS (ino 5, size 1642496)`,
  `<<[FINISHED] Kernel Integrity>> x1`). `--- Kernel Dual Boot / KAPA verified` printed.
- ASan: `make hosttest-asan` attempted; this w64devkit toolchain lacks `-lasan`/`-lubsan`
  (`ld` cannot find libraries, `build-hosttest-asan.log`), so sanitizer execution could not
  be completed in this environment. Main hosttest is green.
- Prior baseline (before latest launch-plan/executor-seam source edits): `1351 passed, 0 failed`
  (earlier run; did not cover the newest KDB assertions).

### Hosttest boot-failure diagnosis (resolved)
- **Symptom:** `build-hosttest.log` (exit 1, no summary) logged `[PS] owinit: address space
  allocation FAILED` (after `[FINISHED] owinit`), then provisioned a 1,048,576-byte
  `openwinkrnl.owx`, hit Sentinel `SHA-256 checksum mismatch` (`expected 4aab...`,
  computed from truncated data) and entered `SYSTEM HALTED` / `[HAL] BROADCASTING
  IPI_FREEZE_SMP` loop; process was terminated.
- **Confirmed root cause:** silent truncation in `tools/hosttest/host_boot.c`.
  `kernel_image` was `static uint8_t[1024U*1024U]` and `host_read_file()` stopped at
  `capacity`, returning the truncated byte count. The real `openwinkrnl.owx` is
  1,642,496 bytes (grew with KDB, full SUAS/SUTS/SUTR/SUTF/SUST/SUF refs, executor seam).
  The harness provisioned the correct `openwinkrnl.chk` but a truncated image, so Sentinel
  **correctly** detected mismatch and invoked the fatal integrity path.
- **Not the cause:** `[PS] owinit: address space allocation FAILED` is expected under
  `OW_HOST_HAL` (`OwMemCreateAddressSpace()` returns 0 by design in `core/memory.c`;
  `OwPsCreateProcess` logs and continues). Not caused by KDB phase 4d (static init
  before VFS/storage/owinit handoff). No evidence of PS/KDB memory corruption.
- **Fix:** `tools/hosttest/host_boot.c` — `kernel_image` buffer increased to 4 MiB;
  `host_read_file()` probe-reads after filling capacity and returns `-1` if more data
  exists (prevents silent truncation). No integrity/PS checks weakened.
- **Test correction (my added assertion):** out-of-range instance launch-plan lookup
  expects `OW_ERR_INVALID_PARAM` (`OwKdbGetInstance` contract), while the plan still
  reports an explicit `OW_KDB_BLOCKER_INSTANCE_NOT_FOUND` blocker.

### New KDB assertions executed (confirmed in completed hosttest)
In `test_kdb()`/KDB suite, executed and passing: launch-plan construction for live
READY/RUNNING instances with expected metadata, null/out-of-range handling, executor
unavailable (`OwKdbExecutionAvailable()` false, `OW_KDB_BLOCKER_EXECUTOR_UNAVAILABLE`),
faulted-instance plan inspectability, and Sweep service-ID bridge/authorization
integration scaffolding (owner/instance/capability enforcement). Dedicated executor-seam
assertions now install **test-only** backends and verify: registration makes execution
available; `OwKdbExecuteInstance` invokes an accepting backend exactly once with the
validated instance id; a null backend restores the unavailable default; execution without
a backend returns `OW_ERR_UNSUPPORTED` without faulting or releasing pages; an unknown
instance is rejected before the backend is reached; a rejecting backend propagates its
error and faults the instance (page charge released, fault status recorded); unregistration
restores the no-executor default. These backends do not execute a second kernel.

- Sweep (separate project): engine slice `24 passed, 0 failed`; service handlers
  `18 passed, 0 failed`; text `30 passed, 0 failed`; browser `39 passed, 0 failed`;
  HTML `30 passed, 0 failed`; CSS/cascade/layout/paint `174 passed, 0 failed`
  (**315 total, 0 failed** via `make sweep-tests`). See
  `C:\Users\KARIMABENDA\Documents\Sweep\SWEEP.md`.

## Diagnostics

- `OW_C_KDB_READY` (`0x0011AC14`) — KDB phase reached its ready state.
- `OW_W_KDB_UNAVAILABLE` (`0x0011A806`) — KDB initialization failed; the boot continues
  without KAPA associations.

## Tests (source coverage)

`tools/hosttest/host_boot.c` contains the `test_kdb()` suite: initialization, Sweep
declarative state, registry duplicates and invalid descriptors, the full compatibility
matrix, loader support/validation and corruption handling, associations, instance lifecycle
and page budget, fault cleanup, Service Bridge built-ins and rules, cross-instance
authorization, Sweep fixture attach/load path, launch-plan/executor-seam checks, and
Sweep service-ID bridge/authorization integration scaffolding.

Run with `make hosttest` (or `cmake --build <build> --target hosttest && ctest -R hosttest`).
Latest verified run: **1418 passed, 0 failed** (`build-hosttest-kdb-exec.log`).
