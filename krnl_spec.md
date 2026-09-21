# OpenWindows Kernel Specification

This document describes the implementation currently present in this directory.
It is intentionally a source inventory, not a roadmap for components that have
not been created yet.

## Build Products and Entry Points

The CMake and Make builds produce the following artifacts:

* `openwinkrnl.pe`: freestanding x86-64 kernel executable.
* `openwinkrnl.owx`: OWX1-packed kernel image.
* `openwinkrnl.chk`: generated kernel checksum information.
* `hosttest.exe`: host boot and integration-test harness.

The boot sources in `boot/` include assembly and C entry paths for the test
images. `tools/` contains the OWX packer, boot-image scripts, and VM launch
scripts. The supported development environment is currently QEMU and the
host harness; the scripts also contain VirtualBox paths.

The build imports shared sources from the sibling `superunicode`, `vip`, and
`OpenWindows-Storage` directories. Those dependencies provide UTF-8/string
support, UniVIP support, and OWFS/USFS storage code used by this tree.

## BANcode Registry, Kernel Traps, and Active Defense

`BANCODE.md`, `inc/bancode/`, `bancode/`, and `diag/` define the diagnostic
framework used by the kernel. The codepoint ranges are:

| Class | Range | Meaning |
| --- | --- | --- |
| B+ BANcode | `0x0011A000`-`0x0011A7FF` | Fatal kernel or integrity condition |
| W+ WARNcode | `0x0011A800`-`0x0011ABFF` | Non-fatal warning |
| C+ COMcode | `0x0011AC00`-`0x0011ADFF` | Initialization or transition milestone |
| S+ SOFTcode | `0x0011AE00`-`0x0011AEFF` | Recoverable fault or mitigation |

The kernel-specific constants currently defined in `inc/ow_diag.h` are:

* **C+ milestones:** HAL initialized, PML4 built, object manager ready,
	primary/secure VFS mounted, network online, Sentinel online, syscall gateway
	ready, boot complete, runlevel table ready, runlevel transition complete,
	ACPI tables ready, rc shutdown run, ACPI power-off, process subsystem ready,
	scheduler running, owinit process created, and owinit image loaded.
* **W+ warnings:** PnP resource conflict, unsigned driver, skipped runlevel
	feature, ACPI not found, and ignored rc directive.
* **S+ soft faults:** stack alignment fault, undefined instruction, and blocked
	driver hook.
* **B+ fatal codes:** page fault fatal, Sentinel integrity failure, tier
	extension violation, ALPC triple fault, VFS corruption, and missing owinit.

The generated registry table in `bancode/bancode.c` currently assigns the
named entry `BANCODE_OWINIT_MISSING` (`0x0011A005`). The other kernel-specific
codes above are defined and emitted through the diagnostic API, while the
registry ranges reserve space for future generated entries. Unknown codes are
reported as `UNKNOWN` by the registry lookup functions.

### Kernel Security Trap Dispatch

`bancode/bancode_trap.c` implements the Kernel Security Trap damage-control
layer with a fixed static table of 15 handlers and no allocation. Trap
codepoints are `0x7FFFFFF0` through `0x7FFFFFFE`; each slot governs a cluster
of 128 B+ BANcodes. B+ codes in the unmapped final cluster
(`0x0011A780`-`0x0011A7FF`) do not dispatch to a trap slot.

The trap API supports registering, replacing, querying, unregistering, and
clearing slot handlers. It also records the most recent dispatch, including
whether it fired, the slot, trap codepoint, and originating BANcode. Only B+
codes route through this mechanism. In system mode they invoke the installed
kernel handler. In app mode they bypass kernel trap dispatch and invoke the
registered application crash handler instead.

`diag/bancode_krnl.c` initializes system mode, clears the trap table, and
registers the kernel BanHammer handler in all 15 slots. `OwDiagBanHammer`
formats the fatal diagnostic, invokes BANcode trap dispatch, prints the
component and reason, records the state-dump path as `openwinkrnl.chk`, sends
the SMP halt IPI hook, and enters the halt loop if control returns.

### Sentinel and Image Trust

`sentinel/damagecntrl.c` implements the active-defense entry points for
undefined-instruction and stack-segment faults. It logs the fault context and
emits the corresponding S+ mitigation message. It also reads
`openwinkrnl.chk`, extracts the expected SHA-256 value, streams
`openwinkrnl.owx` from OWFS, and compares the computed digest. A missing,
malformed, or mismatched checksum is escalated as
`B_SENTINEL_INTEGRITY_FAIL` through BanHammer.

`sentinel/fltrmgr.c` implements the current driver/image trust check. It
validates the filename extension associated with each tier:

* Tier 1 core drivers: `.owc`
* Tier 2 system libraries: `.owd`
* Tier 3 user executables: `.owx`

This is extension-based validation at present. It is not a cryptographic
signature, certificate, or secure-boot implementation.

## OWX Image and Trust Hierarchy

The repository implements the OWX1 image format and packaging path. The kernel
image is produced as `openwinkrnl.pe`, packed as `openwinkrnl.owx`, and paired
with `openwinkrnl.chk` by `tools/owx_pack.py`. `ps/owx_loader.c` validates OWX1
headers, checks section bounds, copies supported code/data sections into its
fixed execution arena, zero-fills BSS, and resolves the entry point. The
required `owinit` source is
`OpenWindows-Essentials/Software/owinit/owinit.c`; the build packages its
compiled executable through `tools/owx_pack.py` before provisioning it.

The loader currently supports the MVP section types needed by this tree. It
does not yet implement relocations, imports, exports, TLS, per-process CR3
isolation, or a general dynamic module loader. Empty or payload-free images are
rejected rather than accepted as valid `owinit` executables.

## Runlevel Profiles

`core/runlevel.c` and `inc/ow_runlevel.h` implement a thirteen-profile table
covering levels `-6` through `6`. Each profile contains a name, description,
feature bitmask, flags, log verbosity, watchdog value, heap budget, and handle
ceiling.

* `-6` through `-1` are progressively richer recovery and maintenance levels.
* `0` is the terminal `HALT` profile and runs shutdown/power-off handling.
* `1` through `5` progressively arm the kernel, storage, user-mode hand-off,
  network, VIP, and optional AI feature bits.
* `6` is the `REBOOT` recycle profile.

The runlevel API supports lookup, active-feature queries, table/feature
printing, and live transitions. A transition tears down the network router
when the destination profile no longer arms networking, records a diagnostic
milestone, and handles the halt/reboot profiles through the existing rc and
ACPI paths. Feature names such as `AI` are configured runlevel capabilities;
this directory does not contain a separate AI module implementation.

## Kernel Subsystems

### `core/`

Contains kernel startup, the object namespace, the memory manager, ALPC, and
runlevel management.

* `core/main.c` initializes the kernel services in boot order.
* `core/object.c` provides a small object directory and global handle table.
* `core/memory.c` provides a fixed 16 MiB page allocator and VAD metadata with
	an AVL-style tree. It also reports PML4 indices; it is not a complete virtual
	memory or physical page manager.
* `core/alpc.c` provides fixed-size local message-port communication.
* `core/runlevel.c` provides the configured runlevel table and transitions.

### `hal/` and `inc/ow_hal.h`

The hardware layer supports the current VM-oriented target: UART, VGA text
output, keyboard input, port I/O, a RAM-backed disk device, MMIO mapping,
interrupt descriptor setup, PIT/PIC scheduling support, and selected ACPI
power operations. `hal/interrupts.S` contains x86-64 exception entry stubs;
`hal/idt.c` installs the exception gates.

This tree does not contain a general PCI, USB, NVMe, AHCI, VirtIO, graphics,
audio, or physical-hardware driver framework.

### `ps/`, `sync/`, and `dpc/`

`ps/` contains static process and thread tables, kernel stacks, a round-robin
scheduler, context switching, timer hooks, and a small Ring 3 demonstration.
`sync/` contains dispatcher objects for events, semaphores, mutexes, timers,
waits, and sleep. `dpc/` contains a single-CPU FIFO deferred procedure-call
queue.

These implementations are currently single-CPU and statically bounded. They
are not an SMP scheduler or a Linux-compatible process, signal, or futex model.

### `syscall/` and the OWX user-mode hand-off

`syscall/dispatcher.c` implements the current syscall switch for memory
allocation, MMIO, VFS operations, ALPC, power controls, process/thread
creation, synchronization, UART output, and sleep/yield/exit operations.
The real Ring 3 hand-off is the Essentials `owinit.owx` process created during
the boot phase described above. The kernel reads that OWX image from OWFS,
loads it through `ps/owx_loader.c`, creates PID 1 and its primary thread, and
then starts scheduling. There is no separate user-mode demo or alternate
launcher that can satisfy, replace, or bypass `owinit`.

The current interface is an internal prototype. It does not yet provide a
stable userspace ABI, per-process handles, general executable loading, or full
syscall argument validation.

### `vfs/`, `storage/`, and `inc/ow_vfs.h`

The VFS facade mounts primary OWFS and secure USFS volumes through the HAL
block-device interface. It supports formatting/mounting, root-level file
creation, one-block file reads and writes, deletion, checksums, bitmap block
allocation, and a secure-volume purge operation.

The filesystem implementation is a small custom prototype. It does not yet
provide a complete pathname resolver, nested directories, file descriptors,
journaling, caching, or standard filesystem compatibility.

### `net/` and `vip/`

`net/router.c` implements a 44-bit sparse radix/hex-trie route table with
longest-prefix lookup. `net/vip.c` and the imported UniVIP source provide the
current VIP/FVIP integration points.

There are no Ethernet or NIC drivers, sockets, TCP/UDP, ARP, IPv4/IPv6 stack,
firewall, or network namespace implementation in this directory.

### `bancode/`, `diag/`, `rc/`, and `sentinel/`

These directories contain BANcode definitions and validation, diagnostic
logging, recovery-controller logic, checksum/crash support, damage-control
handling, and filter-manager code. `openwinkrnl.chk` is generated during OWX
packaging and is used by the existing integrity path.

The code provides diagnostics and failure handling for the current kernel; it
does not implement a general security policy engine, verified-boot system, or
SMP-wide crash dump facility.

### `shell/`, `kapi/`, `lib/`, and `sucs/`

* `shell/` contains the kernel console command handling.
* `kapi/` contains the current kernel-facing API implementation.
* `lib/` contains allocation, memory, strings, formatted output, checksums,
	hashing, and hardware-translation helpers.
* `sucs/` contains the local SUCS mode/UTF support objects used by the build.

## Current Diagnostics and Testing

`BANCODE.md` documents the BANcode, WARNcode, COMcode, and SOFTcode registry.
The host integration test is registered with CTest as `hosttest` and exercises
the common kernel initialization path without touching real hardware.

The normal verification commands are:

```text
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

Passing the host test confirms the current host-visible initialization path and
does not establish production hardware compatibility or security readiness.