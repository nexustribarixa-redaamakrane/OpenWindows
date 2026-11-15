# OWKSan Suite - OpenWindows Kernel Sanitization Framework

The OWKSan Suite is OpenWindows' own kernel sanitization and runtime-diagnostics
framework.  It is a custom suite written against the OpenWindows architecture:
the PML4/VAD memory manager, the fixed-pool kernel heap, the paging layer, the
interrupt/syscall environment, the BANhammer crash path and the kernel console.

It is deliberately **not** a wrapper around a hosted compiler toolchain.  Host-side
`ASan`/`UBSan` runs (the `hosttest-asan` target) and the OWKSan Suite's own
kernel-side instrumentation are complementary: the first proves the host harness
and its bounds checks against a real sanitizer runtime, the second is the
in-kernel framework the production kernel would consult.

## Suite components

| Component | Responsibility | Phase |
|---|---|---|
| OWKAsan | Address-access validation (shadow/redzone/invalid-address) | 3+ |
| OWKUbSan | Undefined-behavior detection (shifts, overflow, alignment, enum, division) | 4+ |
| OWKMSan | Memory initialization tracking | 3+ |
| OWKTSan | Data-race detection | 5+ |
| OWKLSan | Lock-state and synchronization diagnostics | 5+ |
| OWStackSan | Stack integrity and stack-boundary validation | 4+ |
| OWKHeapSan | Kernel heap integrity and allocation validation | 2+ |
| OWKPageSan | Physical/virtual page-management validation | 2+ |
| OWKBoundsSan | Buffer, array and memory-region bounds validation | 2+ |
| OWKIntSan | Integer overflow and invalid arithmetic detection | 4+ |
| OWKInitSan | Initialization-order and initialization-state validation | 4+ |
| OWKLockSan | Kernel lock correctness and misuse detection | 5+ |

## Phase 1 - Foundation: implemented

Phase 1 delivered the **OWKSan core framework**.  Files changed:

- `inc/owksan.h` - public framework API.
- `sanitizer/owksan_core.c` - framework implementation.
- `core/main.c`, `inc/ow_diag.h` - boot wiring and diagnostic codes.

Implemented behaviour:

- **Suite lifecycle**: `OwKSanInitialize`, `OwKSanShutdown`, `OwKSanReady`.
- **Module registry**: bounded table (`OW_KSAN_MODULE_MAX = 16`, name capacity
  `OW_KSAN_MODULE_NAME_MAX = 32`), modules kept sorted by ascending
  `InitOrder`, register/get/unregister/enable/disable/configure, module and
  enabled-module counts.  Duplicate names are refused, a full table is refused
  with `OW_ERR_INSUFFICIENT`, missing modules with `OW_ERR_NOT_FOUND`.
- **Runtime configuration**: master switch (`OwKSanSetMasterEnabled`,
  `OwKSanMasterEnabled`) plus per-module enable/disable/configure.
  **The suite starts inert** (master off) and only initialises modules that are
  registered and enabled; enabling a module marks it for (re-)initialisation.
- **Diagnostic reporting**: `OwKSanReport(Severity, Module, Format, ...)` emits a
  single bounded console line through the kernel formatter, maintains report and
  fatal counters, and returns the severity.  Formatting goes through
  `ow_vsnprintf`; all report storage is static and bounded.
- **Panic integration**: `OwKSanSetPanicHook`, `OwKSanPanic(Module, Detail, Status)`
  invoke an installable hook (default: kernel-console sink).  Modules escalate a
  `OW_KSAN_SEVERITY_FATAL` finding by calling `OwKSanPanic`.
- **Error classification**: `OwKSanSeverityToStatus` maps severities onto the
  existing `OW_STATUS` error families.
- **Introspection**: `OwKSanSeverityName`, `OwKSanModuleName`, counter accessors.

Phase 1 deliberately contains **no check implementations**: the registered
modules of later phases provide the actual diagnostics.  This keeps the rule "do
not mark a sanitizer as implemented merely because a placeholder exists" intact.

## Phase 2 onwards - planned

- Phase 2: `OWKHeapSan`, `OWKPageSan`, `OWKBoundsSan` plus focused tests.
- Phase 3: `OWKAsan`, `OWKMSan` with metadata tracking.
- Phase 4: `OWKUbSan`, `OWKIntSan`, `OWKInitSan`, `OWStackSan`.
- Phase 5: `OWKTSan`, `OWKLSan`, `OWKLockSan`.
- Phase 6: integration of all modules, regression tests, enabled/disabled
  configurations, documentation updates.

## Quality constraints honoured by the Phase-1 core

- Freestanding: no hosted runtime, no dynamic allocation in the framework.
- Static, bounded storage only; no locks (single-threaded kernel context).
- Diagnostics safe during early boot (report before init is inert; init failure is
  advisory and does not halt).
- Disabled modules are lightweight (master/module switch is checked before any
  reporting work).
- Explicit configuration (master off by default).
- Failures are not swallowed: unknown module names classify as `ERROR`, an
  initialisation failure is returned to the boot phase, uninitialised reports are
  inert rather than dropped silently.
- No unsupported conditions are reported as detected: the framework reports what
  registered modules ask it to report, and no module registers itself in Phase 1.

## Integration status

- Build wiring: `Makefile` (`SANITIZER_OBJS`, `ALL_OBJS`, pattern rule,
  `HOSTTEST_SRC`) and `CMakeLists.txt` (`KERNEL_COMMON_SOURCES`).
- Boot wiring: `core/main.c` runs the suite core during boot phase 4f and records
  diagnostic milestone `OW_C_OWKSAN_READY` (`0x0011AC15`).  The host boot harness
  (`tools/hosttest/host_boot.c`) mirrors this phase directly (the harness does
  not execute `_start`, so it replicates the boot sequence).
- Host tests: `test_owksan_core()` in `tools/hosttest/host_boot.c` exercises the
  framework core end to end against the live harness state: boot-ready status,
  inert default (master off, empty module table), register/get/enable/configure,
  module init lifecycle, report severity/counter accounting, waived reports
  (master-disabled and disabled-module), the FATAL diagnostic path through the
  panic sink, shutdown-unregister-reinitialize lifecycle.  The full suite now
  reports 1643 passed, 0 failed, and the sanitized build (clang + ASan/UBSan)
  reports the same.
