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
| OWKHeapSan | Kernel heap integrity and allocation validation | 2 (done) |
| OWKPageSan | Physical/virtual page-management validation | 2 (done) |
| OWKBoundsSan | Buffer, array and memory-region bounds validation | 2 (done) |
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

## Phase 2 - Memory diagnostics: implemented

Phase 2 delivers the three memory-diagnostics modules, each backed by real
checks against the live OpenWindows allocator/frame arena.  Files changed:

- `inc/owkheapsan.h`, `sanitizer/owkheapsan.c` - OWKHeapSan
- `inc/owkpagesan.h`, `sanitizer/owkpagesan.c` - OWKPageSan
- `inc/owkbounds.h`, `sanitizer/owkbounds.c` - OWKBoundsSan
- `inc/owksan.h`, `sanitizer/owksan_core.c` - new `OwKSanIsEnabled` hot-path query
- `lib/kalloc.h`, `lib/kalloc.c` - shared arena layout constants, read-only
  arena walker (`OwKAllocWalk`), arena-containment query (`OwKAllocContains`),
  and the `OwKHeapSanNoteAlloc`/`OwKHeapSanNoteFree` hooks wired into
  `kalloc_raw` and `kfree`
- `core/memory.c`, `inc/ow_memory.h` - read-only frame-arena audit exports
  (`OwMemArenaBase`, `OwMemNonRamWindowCount`, `OwMemNonRamWindow`)
- `core/main.c`, `tools/hosttest/host_boot.c` - the three modules are
  registered before the suite initialises in boot phase 4f (and its host-harness
  mirror), so they are enabled at boot but inert while the master switch is off
- `tools/hosttest/host_boot.c` - new `test_owkheapsan`, `test_owkpagesan`,
  `test_owkbounds` suites

### OWKHeapSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- header-chain inconsistency in the `lib/kalloc.c` bump arena: walk length not
  matching the committed byte counter, zero-sized headers, non-owning walk,
- payload misalignment (every kalloc payload is 8-byte aligned),
- `kfree()` of a pointer outside the arena,
- `kfree()` of an already-freed allocation (double free of a tracked block),
- `kfree()` of an allocation never tracked while the bounded registry was
  guaranteed to hold it.

Does NOT detect, and deliberately does not claim:
- use-after-free: `lib/kalloc.c` is a bump allocator that never reuses memory,
  so a UAF is indistinguishable from a live allocation without allocator changes,
- payload-content corruption or out-of-arena scribbling,
- bounds of the 8 MiB arena itself (callers are still responsible),
- anything before the suite arms its master switch or when the module is
  disabled (diagnostics are waived, not dropped),
- detection is limited to a bounded registry (256 entries) and a freed-pointer
  set; once those overflow, untracked frees are counted, never reported.

### OWKPageSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- frame ranges that are unaligned, wrap the address space, fall outside the
  kernel frame arena, or overlap the non-RAM holes the allocator skips,
- raw leaf page-table entries that violate LA48 structure: reserved bits
  [62:52], reserved bits [10:9], a 4K leaf with the `PS` bit set, a huge-page
  frame base unaligned to its page size,
- frame-allocator invariant violations visible via public state: used pages
  exceeding the pool, committed charge exceeding the commit ceiling, arena base
  misalignment.

Does NOT detect, and deliberately does not claim:
- CPU walk faults or page-table aliasing bugs (no CR3 walk is performed),
- correctness of address-space sharing between processes,
- whether the allocator skipped the right non-RAM windows (only that handed-out
  frames never overlap them),
- virtual-translation correctness on hosts without page tables (the host HAL
  has none; translate-dependent checks are not exercised).

### OWKBoundsSan - what it detects and what it does not

Detects:
- an index past the declared element count,
- an access span that does not fit a declared base+size,
- `base+size` or `access+size` wraparound,
- a `memcpy`-style copy whose length exceeds the destination capacity (and
  leaves the destination untouched).

Does NOT detect: compiler-generated bounds violations, mis-stated capacities,
or anything about the contents copied.

## Phase 3 onwards - planned

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
- No unsupported conditions are reported as detected: the suite reports only
  what a registered module asks it to report, and boot-phase registration is
  followed by the inert default (master off), so the kernel pays no diagnostic
  cost unless explicitly armed.

## Integration status

- Build wiring: `Makefile` (`SANITIZER_OBJS`, `ALL_OBJS`, pattern rule,
  `HOSTTEST_SRC`) and `CMakeLists.txt` (`KERNEL_COMMON_SOURCES`).
- Boot wiring: `core/main.c` runs the suite core during boot phase 4f and records
  diagnostic milestone `OW_C_OWKSAN_READY` (`0x0011AC15`); the three Phase-2
  modules are registered before the suite initialises (a failed registration is
  advisory and does not halt the machine).  The host boot harness
  (`tools/hosttest/host_boot.c`) mirrors both calls directly (the harness does
  not execute `_start`, so it replicates the boot sequence).
- Host tests: `test_owksan_core()`, `test_owkheapsan()`, `test_owkpagesan()` and
  `test_owkbounds()` in `tools/hosttest/host_boot.c` exercise the framework and
  the three Phase-2 modules end to end: boot-ready state, inert default, module
  registration/init, report/counter accounting, waived reports, the FATAL panic
  path, a deliberate arena-header corruption that the arena audit catches, PTE
  LA48 structural violations, frame-range refusal cases, bounds/copy negative
  paths.  The full suite now reports 1690 passed, 0 failed, and the sanitized
  build (clang + ASan/UBSan) reports the same.
