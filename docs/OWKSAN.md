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
| OWKUbSan | Undefined-behavior detection - implemented (Phase 4) | 4 (done) |
| OWKMSan | Memory initialization tracking - implemented (Phase 3) | 3 (done) |
| OWKTSan | Data-race detection - implemented (Phase 5) | 5 (done) |
| OWKLSan | Lock-state and synchronization diagnostics - implemented (Phase 5) | 5 (done) |
| OWStackSan | Stack integrity (compiler canary + validation) - implemented (Phase 4) | 4 (done) |
| OWKHeapSan | Kernel heap integrity and allocation validation | 2 (done) |
| OWKPageSan | Physical/virtual page-management validation | 2 (done) |
| OWKBoundsSan | Buffer, array and memory-region bounds validation | 2 (done) |
| OWKIntSan | Integer overflow and invalid arithmetic detection - implemented (Phase 4) | 4 (done) |
| OWKInitSan | Initialization-order and initialization-state validation - implemented (Phase 4) | 4 (done) |
| OWKLockSan | Kernel lock correctness and misuse detection - implemented (Phase 5) | 5 (done) |

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

One shadow byte per 8 tracked bytes; bit i marks tracked byte (8g+i) as
uninitialized.  Two regions are tracked: the 8 MiB kalloc arena and the 16 MiB
physical frame arena (fresh frames are marked uninitialized at handout and
cleared at the zeroing sites in `core/memory.c`).  Non-arena memory is outside
the tracking domain.

Detects (validated with host-side negative tests):
- reads of uninitialized bytes of a kalloc'd block (at the time the check is
  performed, i.e. at checked call sites),
- reads of a freed block (freed memory is marked uninitialized again),
- krealloc copies propagate initialization exactly (the growth half of a
  re-allocated block reads uninitialized until it is explicitly marked),
- zero-initialized allocations (kcalloc) read clean,
- reads of frame memory that was never written after allocation.

Does NOT detect, and deliberately does not claim:
- reads of uninitialized stack, statics, MMIO or non-arena memory,
- out-of-bounds reads at arbitrary call sites (API-driven; see the note on
  compiler instrumentation below),
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
- stack/global buffer overflows in unprotected functions and non-stack-global
  arrays (stack arrays in instrumented functions are canary-protected),
- it is NOT ASan-compatible: no shadow, no global instrumentation, no
  interposition of loads/stores; allocation-time bookkeeping plus API-boundary
  validation only,
- quarantine depth is runtime-tunable (`OwKAsanSetQuarantineLimit`/`OwKAsanQuarantineLimit`):
  0 disables it (freed blocks reuse immediately), default 32 blocks, hard
  bound 64 in the static table; once full, the oldest freed block becomes
  reusable and stale-pointer writes to it are no longer observable.

## Phase 4 - Runtime validation: implemented

Phase 4 delivers the four runtime-validation modules.  Files changed:

- `inc/owkubsan.h`, `sanitizer/owkubsan.c` - OWKUbSan
- `inc/owkintsan.h`, `sanitizer/owkintsan.c` - OWKIntSan
- `inc/owkinitsan.h`, `sanitizer/owkinitsan.c` - OWKInitSan
- `inc/owkstacksan.h`, `sanitizer/owkstacksan.c` - OWStackSan (compiler canary
  + explicit checks)
- `core/main.c` - every boot phase in `boot_begin` / `boot_diag_done` /
  `boot_diag_failed` / `boot_skip_phase` is tracked by OWKInitSan (begin order
  auto-increments); the four modules are registered before the suite
  initialises in phase 4f (a failed registration is a warning, not a halt)
- `tools/hosttest/host_boot.c` - new `test_owkubsan`, `test_owkintsan`,
  `test_owkinitsan`, `test_owkstacksan` suites
- `Makefile`, `CMakeLists.txt` - `-fstack-protector-strong` for the kernel and
  the host harness (was `-fno-stack-protector`); the host-side ASan build keeps
  its own stack instrumentation
- `lib/kalloc.h`, `lib/kalloc.c` - quarantine depth is runtime-tunable
  (`OwKAllocQuarantineLimit`/`SetLimit`), `OwKAllocArenaBase`/`OwMemArenaBase`
  exports for OWKMSan's second shadow region

### OWKUbSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- invalid shifts: shift count >= bit width, or a zero/over-64 width,
- signed add/subtract/multiply overflow (via compiler intrinsics, no library
  calls),
- division by zero and `INT64_MIN / -1` wraparound (both `/` and `%`),
- misaligned pointer access (address not a multiple of a power-of-two
  alignment; non-power-of-two alignment is refused outright),
- enum value outside its declared range,
- null pointer where a non-null pointer is required.

Does NOT detect, and deliberately does not claim:
- invalid enum casts across types, strict aliasing, unsequenced side effects,
  lifetime violations, signed/unsigned comparison UB,
- anything in code the suite has not been asked to check; these are checked
  call sites only, and this is NOT UBSan-compatible,
- the moment a compiler-introduced misalignment occurs in a caller that never
  asked.

### OWKIntSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- unsigned add/subtract/multiply overflow,
- allocation-size calculation overflow (`Count * Size`),
- pointer offset overflow (`Base + Offset`),
- scaled index overflow (`Base + Index * Scale`, both steps),
- region span wraparound (`Base + Size`).

Does NOT detect: signed arithmetic (use OWKUbSan), floating-point arithmetic,
compiler-inserted arithmetic checks, or overflows in code the suite was not
asked to check.

### OWKInitSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- duplicate initialization (begin of an already-tracked phase),
- re-entrant initialization (phase begun while RUNNING),
- initialization-order violations (a phase begun with an Order lower than the
  highest Order seen so far),
- end of a phase that was never begun, end of a phase that was not running,
  end of an already-DONE phase,
- skipped phases (recorded as SKIPPED, terminal, and accepted as-is),
- boot-phase tracking: every `boot_begin`/`boot_diag_done`/
  `boot_diag_failed`/`boot_skip_phase` call in `core/main.c::_start` is
  tracked, so the whole boot sequence appears in the tracker.

Does NOT detect, and deliberately does not claim:
- access-to-uninitialized-subsystem enforcement inside subsystem code: no
  in-tree caller consumes the query API yet (`OwKInitSanIsInitialized`,
  `OwKInitSanRequireInitialized`, `OwKInitSanPhaseFailed`); wiring one into
  the shared call paths breaks the host harness (which never runs `_start` and
  therefore tracks no phases), and wiring one into `_start` is redundant with
  the runlevel-consistency gates already at the userspace boundary; the API
  and its tests exist, wiring consumer call sites is a separate change,
- data-level initialization tracking (this tracks subsystem state, not whether
  a particular variable was written),
- dependency graphs beyond the ordering rule above.

### OWStackSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- stack corruption caught by the compiler's own stack canary: the kernel and
  the host harness are built with `-fstack-protector-strong`, so functions
  whose frames carry arrays are instrumented by GCC itself; a mismatch calls
  `__stack_chk_fail()`, which reports FATAL and halts through the BANhammer
  crash path.  This is genuine compiler instrumentation, not a checked call
  site.
- corruption of the guard symbol in memory (the OWStackSan audit compares the
  guard against the value this module wrote),
- declared stack regions that overlap the kernel heap arena, misaligned
  stack bases, zero-sized or wrapping stack spans.

Does NOT detect, and deliberately does not claim:
- stack-buffer overflows in functions the compiler did not protect (leaf
  functions without arrays/local addresses),
- return-address overwrites that bypass the epilogue canary check,
- stack leaks of uninitialized locals,
- stack-smashing in the assembly paths (ISR stubs are not themselves
  instrumented),
- anything about the validity of a stack region the caller never declares.

## Phase 5 - Concurrency diagnostics: implemented

Phase 5 delivers the three concurrency modules.  The kernel is single-CPU,
ring-0 only, with NT-like dispatcher objects as its synchronization primitive;
the architecture is what the modules check against.  Files changed:

- `inc/owklocksan.h`, `sanitizer/owklocksan.c` - OWKLockSan
- `inc/owklsan.h`, `sanitizer/owklsan.c` - OWKLSan
- `inc/owktsan.h`, `sanitizer/owktsan.c` - OWKTSan (shadow happens-before)
- `sync/ow_sync.c` - instrumentation hooks (create/acquire/release/wait/wake/
  exit), each gated on the suite switches
- `core/main.c`, `tools/hosttest/host_boot.c` - the three modules are
  registered before the suite initialises in boot phase 4f (and its host-
  harness mirror)
- `tools/hosttest/host_boot.c` - new `test_owklocksan`, `test_owklsan`,
  `test_owktsan` suites

### OWKLockSan - what it detects and what it does not

Detects (validated with host-side negative tests):
- release of a mutex the caller does not own (the kernel previously returned
  0 silently),
- recursive acquisition beyond the depth ceiling (16),
- semaphore release that would exceed its limit (the kernel previously
  clamped silently),
- circular-wait (potential deadlock) detection over the mutex wait-for graph:
  when a thread is about to block, the chain of (wanted object -> owner ->
  that owner's wanted object) is walked; if it returns to the requesting
  thread the cycle is reported,
- mutex abandoned when a thread exits without releasing it (KeOnThreadExit
  leaves the object half-done),
- a wait waking on an abandoned mutex.

Does NOT detect, and deliberately does not claim:
- lock-order inversions that never close a live cycle,
- deadlocks that do not pass through dispatcher objects (cli/sti sections are
  not waits),
- ISR-vs-thread races (the uniprocessor model cannot attribute an interrupt
  to a distinct thread),
- detection for code the suite was not asked to check.

The lock-tracking table is a static, bounded 64-record store; ownership is
tracked per dispatcher object, and the wait-for graph is bounded by
OW_KLCKSAN_MAX_LOCKS.

### OWKLSan - what it detects and what it does not

OWKLockSan answers "is this lock operation legal?"; OWKLSan answers "is the
kernel's lock state sane right now?"  It installs no instrumentation of its
own - it audits OWKLockSan's tracked table.  Detects:
- held-lock census: tracked records, owned records, deepest recursion depth,
  abandoned count,
- locks held at a quiescent point (e.g. just before entering userspace),
- locks held longer than a tick budget (backdating supported by the test
  hook),
- abandoned mutexes.

Does NOT detect: lock order inversions, cli/sti critical sections, priority
inversion, or anything about why a lock is held.

### OWKTSan - what it detects and what it does not

Shadow-based happens-before detection over the 8 MiB kalloc arena: a global
synchronization epoch (bumped at dispatcher signal/release operations and
explicit sync points) plus one 4-byte shadow entry per 8 bytes of heap
(epoch, accessing tid, write flag).  Two accesses to the same group by
different threads in the same epoch, with at least one write, report a race.

Detects (validated with host-side negative tests):
- unsynchronized cross-thread accesses to the same heap group,
- races across independently scheduled accesses that never cross a
  synchronization epoch boundary,
- (detector is report-side only; same-epoch conflicting pairs report once per
  access).

Does NOT detect, and deliberately does not claim:
- plain loads/stores that bypass the tracked APIs (no compiler instrumentation
  exists in this kernel; detection covers the tracked call sites only),
- accesses outside the kalloc arena,
- ISR-vs-thread conflicts attributable to distinct threads,
- epoch wraparound (the epoch wraps at 65536; reports are per-epoch),
- this is NOT TSan and provides no completeness guarantee.

## Phase 6 - Integration and verification: implemented

Phase 6 integrated the suite end to end and hardened it:
- All 12 modules are registered at boot phase 4f (kernel and host-harness
  mirrors); the suite is armed by default only while a test wants it armed.
- Regression tests for the defects found during development: middle-insert
  module registration (the phase-5 gate's root cause), the Tid-0 sentinel
  class (the System thread is tid 0), and lock-order inversion detection
  (new in this phase).
- Enabled/disabled configurations tested: suite-level disarm waives reports
  without counter drift; per-module disable/re-enable tested.
- Diagnostic reporting verified: the installable panic hook receives
  Module/Detail/Status intact, the built-in sink path works, FATAL counters
  and the severity name/status mappings are stable.
- A latent toolchain issue was fixed: the emergency PE/OWX rules now always
  use gcc, so `make hosttest-asan CC=clang` no longer fails at the image
  build step (the PE packer flow is gcc-oriented and lld-link rejects `-e`).
- QEMU boot validation passes (34 checks) with the full instrumented suite
  in the real `_start` path.

## Per-module overhead and dependencies

For each module: memory overhead (static), the hot-path cost when armed and
when disarmed, and dependencies.

| Module | Static storage | Disarmed cost | Armed cost | Depends on |
|---|---|---|---|---|
| OWKAsan | ~8 KB tables + quarantine | one predictable branch | lookup + visit per alloc/free/access | OWKSan core, lib/kalloc.c hooks |
| OWKHeapSan | 64-record table (~2 KB) | one predictable branch | arena walk on audit (O(nblocks)) | lib/kalloc.c walker |
| OWKPageSan | none (reads allocator state) | one predictable branch | per-entry PTE decode; arena audit | registered arenas |
| OWKBoundsSan | none (stateless) | one predictable branch | span arithmetic per checked call | OWKSan core |
| OWKMSan | 3 MiB shadow | one predictable branch | shadow lookup per checked access | lib/kalloc.c, frame-arena hooks |
| OWKTSan | 4 MiB shadow | one predictable branch | shadow update per tracked access (2M groups) | OWKSan core, heap arena |
| OWKUbSan | none (stateless) | one predictable branch | builtin-overflow per checked op | OWKSan core |
| OWKIntSan | none (stateless) | one predictable branch | builtin-overflow per checked op | OWKSan core |
| OWKInitSan | 48-slot table (~2 KB) | one predictable branch | per-phase track (boot sequence only) | OWKSan core |
| OWKLockSan | 64-record table (~4 KB) + 512 B edge matrix | one predictable branch | lookup + graph walk at block time | OWKSan core, sync layer |
| OWKLSan | none extra (reads LockSan table) | one predictable branch | audit-time walk (O(nblocks)) | OWKLockSan read-only table |
| OWStackSan | guard symbol only | one predictable branch | audit-time compare; per-frame canary check | compiler stack protector + OWKSan core |

All modules: freestanding, no locks (single-threaded uniprocessor scope),
report through the OWKSan core only; nothing reports when its module or the
master switch is disabled.

## Suite status

All twelve components are implemented and tested: framework (Phase 1),
memory diagnostics (Phase 2), memory access instrumentation (Phase 3),
runtime validation (Phase 4), concurrency diagnostics (Phase 5), and
integration/verification (Phase 6). The suite boots inert (master off),
registers every module at phase 4f, and passes the host harness with
the full negative-test corpus included. Honest limits remain documented
per module; the suite does not claim compiler-instrumented memory
instrumentation for arbitrary loads and stores.

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
- Compiler instrumentation exists for stacks only: `-fstack-protector-strong`
  with a kernel-provided `__stack_chk_guard`/`__stack_chk_fail` (the OWStackSan
  layer of protection).  Loads/stores are not intercepted; OWKAsan/OWKMSan
  remain API-driven.

## Integration status

- Build wiring: `Makefile` (`SANITIZER_OBJS`, `ALL_OBJS`, pattern rule,
  `HOSTTEST_SRC`) and `CMakeLists.txt` (`KERNEL_COMMON_SOURCES`).  Both build
  systems were built and run with this tree: `make`, `make hosttest`,
  `make hosttest-asan`, `make qemu` (the QEMU dev-boot targets now self-build
  with `CIS_DEV_TRUST=1`), and `cmake --build build-cmake4` with
  `build-cmake4/hosttest.exe` run against the full suite.
- Compiler instrumentation: `-fstack-protector-strong` in the freestanding
  kernel (`Makefile` `CFLAGS`, `CMakeLists.txt` `openwinkrnl_pe`) and the host
  harness (`HOSTTEST_FLAGS`).  The host-side ASan build keeps only ASan/UBSan.
  Every C object in the image references `__stack_chk_guard`/`__stack_chk_fail`
  (verified with `objdump -r`).
- Boot wiring: `core/main.c` runs the suite core during boot phase 4f and
  records diagnostic milestone `OW_C_OWKSAN_READY` (`0x0011AC15`); all
  Phase-2 through Phase-5 modules (heap, page, bounds, MSan, ASan, UbSan,
  IntSan, InitSan, StackSan, LockSan, LSan, TSan) are registered before the
  suite initialises; a failed registration is advisory and does not halt the
  machine.  The host boot harness mirrors all registration calls directly
  (the harness does not execute `_start`, so it replicates the boot sequence).
  `boot_begin`/`boot_diag_done`/`boot_diag_failed`/`boot_skip_phase` are all
  tracked by OWKInitSan; the dispatcher paths in `sync/ow_sync.c` are
  instrumented by OWKLockSan and OWKTSan.
- Host tests: `test_owksan_core()`, `test_owkheapsan()`, `test_owkpagesan()`,
  `test_owkbounds()`, `test_owkmsan()`, `test_owkasan()`, `test_owkubsan()`,
  `test_owkintsan()`, `test_owkinitsan()`, `test_owkstacksan()`,
  `test_owklocksan()`, `test_owklsan()` and `test_owktsan()` in
  `tools/hosttest/host_boot.c` exercise the framework and all registered
  modules end to end: boot-ready state, inert default, module
  registration/init, report/counter accounting, waived reports, the FATAL panic
  path, frame-arena registration and invariant audit, a deliberate
  arena-header and redzone-canary corruption that the audit catches, PTE
  LA48 structural violations, frame-range refusal cases, bounds/copy negative
  paths, shadow-tracked initialization checks (heap and frame arena),
  use-after-free access checks, quarantine poison verification, UbSan/IntSan
  arithmetic and range checks, InitSan duplicate/order/re-entrant detection,
  the stack-guard audit and region checks, dispatcher-object lock checks
  (non-owner release, recursion depth, semaphore over-release, circular-wait
  detection, lock-order inversion detection), the lock census/long-hold/quiescent
  audits, and the TSan shadow-epoch race detector.  Phase-6 suites add:
  `test_owksan_regressions` (middle-insert module ordering incl. the
  Tid-0/acquire-order trap), `test_owksan_suite_toggles` (armed/disarmed suite
  and per-module disable/re-enable), `test_owksan_reporting` (custom panic hook
  capture, FATAL counter accounting, severity-name and severity-to-status
  mappings).  The full suite reports 1860 passed, 0 failed; the sanitized
  build (clang + ASan/UBSan) reports the same; the CMake build of the same
  harness passes with 1861, 0 failed; QEMU boot validation passes (34 checks).
