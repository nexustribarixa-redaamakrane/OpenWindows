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
| OWKAsan | Address-access validation - implemented (Phase 3) | 3 (done) |
| OWKUbSan | Undefined-behavior detection (shifts, overflow, alignment, enum, division) | 4+ |
| OWKMSan | Memory initialization tracking - implemented (Phase 3) | 3 (done) |
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
- `lib/kalloc.h`, `lib/kalloc.c` - **allocator rewrite**: free-list allocation
  with block magic tags, trailing redzone canaries (0xA5), poison-on-free
  (0xDD), a bounded 32-block quarantine before reuse, shared arena layout
  constants (`KALLOC_ALIGN`, `KALLOC_HEADER_SIZE`, `KALLOC_REDZONE`), read-only
  arena walker (`OwKAllocWalk`), arena-containment query (`OwKAllocContains`),
  the `OwKHeapSanNoteFree` verdict hook (OK / FOREIGN / DOUBLE) wired into
  `kfree`, and the frame-arena registration consumed by OWKPageSan
- `core/memory.c`, `inc/ow_memory.h` - frame-arena registry
  (`OwMemFrameArenaRegister`/`OwMemFrameArenaGet`/`OwMemFrameArenaCount`); the
  16 MiB static pool registers itself in `OwMemInitialize`
- `core/main.c`, `tools/hosttest/host_boot.c` - the modules are registered
  before the suite initialises in boot phase 4f (and its host-harness
  mirror), so they are enabled at boot but inert while the master switch is off
- `tools/hosttest/host_boot.c` - new `test_owkheapsan`, `test_owkpagesan`,
  `test_owkbounds` suites

### OWKHeapSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- header-chain inconsistency in the `lib/kalloc.c` arena: walk length not
  matching the committed byte counter, zero-sized headers, non-owning walk,
- payload misalignment (every kalloc payload is 8-byte aligned),
- header magic corruption (a block whose tag is neither LIVE nor FREE),
- redzone canary corruption (a trailing write past the payload),
- `kfree()` of a pointer outside the arena,
- `kfree()` of an already-freed block (double free; the block goes to the
  bounded quarantine and its tag is FREE, so the second free is detected
  unambiguously - there is no unbounded registry and no overflow blind spot).

Does NOT detect, and deliberately does not claim:
- payload-content corruption that leaves the header and redzone intact,
- arbitrary out-of-bounds writes that land inside a live block (no shadow, no
  per-access checking at arbitrary call sites),
- use-after-free reads/writes that never call the allocator or the checked
  access APIs (see OWKAsan for the checked-API surface),
- memory leaks (every block is live until kfree; reachability is untracked).

### OWKPageSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- frame ranges that are unaligned, wrap the address space, fall outside every
  registered arena, or overlap the non-RAM holes the allocator skips,
- raw leaf page-table entries that violate LA48 structure: reserved bits
  [62:52], reserved bits [10:9], a 4K leaf with the `PS` bit set, a huge-page
  frame base unaligned to its page size,
- frame-allocator invariant violations visible via registered-arena state:
  committed bytes exceeding the arena extent, arena base misalignment,
  committed charge exceeding the commit ceiling.

Does NOT detect, and deliberately does not claim:
- CPU walk faults or page-table aliasing bugs (no CR3 walk is performed),
- correctness of address-space sharing between processes,
- defects of an arena that never registered itself (the audit is registry-driven;
  an arena with no owner is invisible to it),
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

## Phase 3 - Memory access instrumentation: implemented

Phase 3 delivers OWKMSan and OWKAsan, plus the allocator instrumentation that
makes them meaningful.  Files changed:

- `inc/owkmsan.h`, `sanitizer/owkmsan.c` - OWKMSan (shadow tracking)
- `inc/owkasan.h`, `sanitizer/owkasan.c` - OWKAsan (access validation)
- `lib/kalloc.h`, `lib/kalloc.c` - block magic tags, trailing redzone canaries,
  poison-on-free, bounded 32-block quarantine (FIFO promotion to the free list),
  read-only arena walker and quarantine/block-find exports
- `core/main.c`, `tools/hosttest/host_boot.c` - both modules registered before
  the suite initialises in phase 4f (and the host-harness mirror)
- `tools/hosttest/host_boot.c` - new `test_owkmsan` and `test_owkasan` suites

### OWKMSan - what it detects and what it does not

One shadow byte per 8 arena bytes; bit i marks payload byte (8g+i) as
uninitialized.  The shadow covers the kalloc arena only; non-heap memory is
outside the tracking domain.

Detects (validated with host-side negative tests):
- reads of uninitialized bytes of a kalloc'd block (at the time the check is
  performed, i.e. at checked call sites),
- reads of a freed block (freed memory is marked uninitialized again),
- krealloc copies propagate initialization exactly (the growth half of a
  re-allocated block reads uninitialized until it is explicitly marked),
- zero-initialized allocations (kcalloc) read clean.

Does NOT detect, and deliberately does not claim:
- reads of uninitialized stack, statics, MMIO or non-heap globals,
- out-of-bounds reads at arbitrary call sites (no compiler instrumentation
  exists in this kernel; tracking is allocation- and check-driven only),
- correctness of writes that "initialize" memory, or the moment of the write
  (write tracking is intentionally not a finding class; the API contract is
  that callers mark initialization with `OwKMSanMarkInit`/`kcalloc`),
- non-heap frees,
- anything before the master switch is armed or when the module is disabled
  (shadow operations are skipped; checks report OW_SUCCESS as "not tracked").

### OWKAsan - what it detects and what it does not

ASan-style, allocator-integrated validation over the kalloc arena: block magic
tags, redzone canaries, poison-on-free, bounded quarantine.

Detects (validated with host-side negative tests):
- use-after-free access through the checked access APIs (`OwKAsanCheckRead` /
  `OwKAsanCheckWrite`): the block's tag is FREE, and the access is reported,
- heap accesses that cross a block boundary into the redzone or a neighbouring
  block (at checked call sites),
- trailing buffer overflows that corrupt the redzone canary (audit-time),
- writes into freed memory: a stale write overwrites the 0xDD poison; the
  quarantine integrity sweep at audit time detects any deviation from poison,
  including a single byte,
- freed blocks whose redzone was corrupted after free (audit-time).

Does NOT detect, and deliberately does not claim:
- arbitrary out-of-bounds loads/stores outside the checked APIs (no compiler
  instrumentation exists in this kernel),
- use-after-free through raw pointers that never call the checked APIs,
- stack/global buffer overflows,
- it is NOT ASan-compatible: no shadow, no global instrumentation, no
  interposition of loads/stores; allocation-time bookkeeping plus API-boundary
  validation only,
- quarantine is bounded (32 blocks, FIFO); once full, the oldest freed block
  becomes reusable and stale-pointer writes to it are no longer observable.

## Phase 4 onwards - planned

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
- No unsupported conditions are reported as detected: the suite reports only
  what a registered module asks it to report, and boot-phase registration is
  followed by the inert default (master off), so the kernel pays no diagnostic
  cost unless explicitly armed.

## Integration status

- Build wiring: `Makefile` (`SANITIZER_OBJS`, `ALL_OBJS`, pattern rule,
  `HOSTTEST_SRC`) and `CMakeLists.txt` (`KERNEL_COMMON_SOURCES`).
- Boot wiring: `core/main.c` runs the suite core during boot phase 4f and records
  diagnostic milestone `OW_C_OWKSAN_READY` (`0x0011AC15`); the Phase-2 and
  Phase-3 modules are registered before the suite initialises (a failed
  registration is advisory and does not halt the machine).  The host boot
  harness (`tools/hosttest/host_boot.c`) mirrors all calls directly (the
  harness does not execute `_start`, so it replicates the boot sequence).
- Host tests: `test_owksan_core()`, `test_owkheapsan()`, `test_owkpagesan()`,
  `test_owkbounds()`, `test_owkmsan()` and `test_owkasan()` in
  `tools/hosttest/host_boot.c` exercise the framework and all registered
  modules end to end: boot-ready state, inert default, module
  registration/init, report/counter accounting, waived reports, the FATAL panic
  path, frame-arena registration and invariant audit, a deliberate
  arena-header and redzone-canary corruption that the audit catches, PTE
  LA48 structural violations, frame-range refusal cases, bounds/copy negative
  paths, shadow-tracked initialization checks, use-after-free access checks,
  and quarantine poison verification.  The full suite now reports
  1728 passed, 0 failed, and the sanitized build (clang + ASan/UBSan) reports
  the same.
