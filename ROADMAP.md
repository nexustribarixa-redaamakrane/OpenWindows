# OpenWindows Kernel Roadmap

This roadmap compares the current OpenWindows kernel with the broader Linux
kernel feature set. It describes the repository as it exists now and separates
implemented prototype functionality from future work.

## Current Baseline

The current build is functional for the supported VM and host-test paths.

| Area | Current OpenWindows implementation | Remaining gap compared with Linux |
| --- | --- | --- |
| Build and runtime | CMake and Make builds link successfully. OWX1 packaging produces `openwinkrnl.owx` and `openwinkrnl.chk`. | Broader CI, release packaging, reproducible builds, and long-running stability testing. |
| Boot and validation | x86-64 boot paths for QEMU and VirtualBox; host integration harness; ACPI power control; serial/VGA diagnostics. | Wider firmware, hardware, and bootloader compatibility. |
| `owinit` user mode | The real Essentials `owinit` executable is packaged from `OpenWindows-Essentials/Software/owinit/owinit.c`, loaded as PID 1, and scheduled as the primary user-mode orchestrator. | A complete userspace environment, process isolation, stable ABI, and additional production applications. |
| Other user applications | `usermode/` contains standalone Ring 3 applications such as the hello-world launcher. These are separate from `owinit` and are not used to satisfy the boot gate. | A general application loader, packaging model, libraries, permissions, and lifecycle management. |
| Physical memory | Fixed 16 MiB page allocator, VAD metadata, AVL-style VAD tree, and PML4 index reporting. | Buddy allocator, reclaim, demand paging, swapping, NUMA, page cache, COW, and complete page-table management. |
| Processes and threads | Static process/thread tables, kernel stacks, context switching, round-robin scheduling, PIT-driven ticks, and user-thread creation. | Robust lifecycle management, signals, credentials, namespaces, futexes, cgroups, CPU affinity, SMP scheduling, and load balancing. |
| User/kernel boundary | Ring 3 syscall gate and dispatcher for memory, VFS, ALPC, process/thread, synchronization, UART, power, and sleep operations. | Complete syscall ABI, pointer validation, per-process handles, isolation, auditing, and compatibility guarantees. |
| Synchronization and DPC | Events, semaphores, mutexes, timers, waits, sleep, and a single-CPU FIFO DPC queue. | SMP-safe primitives, richer wait queues, priority handling, scalable timers, and workqueue/softirq infrastructure. |
| Filesystem and VFS | OWFS/USFS mounting, formatting, checksums, root catalog operations, file reads/writes, deletion, block allocation, and secure-volume purge. | Full pathname resolution, nested directories, file descriptors, symlinks, permissions, journaling, caching, mount namespaces, and standard filesystems. |
| Storage | RAM-backed/custom block-device abstraction with OWFS and USFS support. | PCI discovery, DMA, VirtIO, AHCI, NVMe, SCSI, USB storage, interrupt-driven queues, and power management. |
| Networking | 44-bit sparse radix/hex-trie route table and UniVIP/FVIP integration points. | Ethernet/NIC drivers, ARP, IPv4/IPv6, TCP/UDP, sockets, firewalling, routing protocols, and network namespaces. |
| Hardware support | UART, VGA text, keyboard, port I/O, MMIO mapping, IDT, exception stubs, PIC/PIT, and selected ACPI operations. | PCI/PCIe, USB, APIC/IOAPIC, broader timer support, graphics, audio, hotplug, and physical-hardware coverage. |
| SMP | Halt-IPI hook and single-CPU synchronization/scheduling model. | CPU discovery/startup, per-CPU state, SMP scheduler, scalable locks, IPI infrastructure, and multicore validation. |
| Diagnostics and defense | BANcode registry, 15-slot kernel trap dispatch, BanHammer fatal path, Sentinel exception hooks, SHA-256 image verification, and tier-extension checks. | Full crash-dump writer, signed modules, secure boot, policy enforcement, fuzzing, and security auditing. |
| Kernel interfaces | Object namespace, global bounded handle table, ALPC message ports, runlevels, shell, and kernel API. | Per-process handles, mature object lifetime/refcounting, access control, auditing, and stable public interfaces. |

The Linux comparison areas are represented primarily by its `arch/`, `drivers/`,
`fs/`, `mm/`, `net/`, `kernel/`, `ipc/`, and `security/` trees.

## Implemented Architecture

### Boot and `owinit`

The boot sequence requires `owinit.owx` when the selected runlevel arms the
`OWINIT` feature. The kernel:

1. Checks the OWFS volume for `owinit.owx`.
2. Raises `B_OWINIT_MISSING` if the image is absent.
3. Reads and validates the real Essentials OWX1 image.
4. Creates the `owinit` process as PID 1.
5. Loads its sections and entry point through `ps/owx_loader.c`.
6. Creates its primary thread and starts scheduling.

The standalone applications in `usermode/` are additional Ring 3 programs.
They do not discover, provision, replace, or bypass `owinit`.

### Diagnostics and trust

The implemented diagnostic framework includes:

- BANcode, WARNcode, COMcode, and SOFTcode ranges.
- Fixed 15-slot Kernel Security Trap dispatch.
- System-mode BanHammer handling and app-mode crash-handler support.
- Sentinel SHA-256 verification of the kernel image.
- `.owc`, `.owd`, and `.owx` extension-tier validation.
- Dynamic BanHammer messages for telemetry and recovery status.

The current KDump setting is reported truthfully, but a complete persistent
kernel dump writer remains future work.

### Runlevels

`core/runlevel.c` implements profiles from `-6` through `6`:

- `-6` through `-1`: recovery and maintenance profiles.
- `0`: HALT and shutdown.
- `1` through `5`: progressively richer runtime profiles.
- `6`: REBOOT and system recycle.

Profiles contain feature masks, logging, watchdog, heap, and handle settings.
Live transitions can tear down the network router and route halt/reboot through
the existing rc and ACPI paths.

## Priority Roadmap

### Phase 1: Foundation hardening

**Estimated effort: 2-4 months**

- Replace the fixed physical-memory bump allocator with a page-frame allocator.
- Implement real page-table creation, mapping, unmapping, and protection checks.
- Add allocator/page-table tests, guard pages, and fault-injection coverage.
- Add reproducible build and boot tests to CI.

### Phase 2: Process and user-mode isolation

**Estimated effort: 3-5 months**

- Give each process an isolated address space and CR3.
- Add syscall pointer probing and argument validation.
- Define per-process handle tables and ownership rules.
- Formalize the OWX userspace ABI and executable lifecycle.
- Keep `owinit` as the required PID 1 orchestrator while adding other apps as
	independently loaded processes.

### Phase 3: VFS and storage

**Estimated effort: 3-6 months**

- Implement nested directories and complete pathname resolution.
- Add file descriptors, permissions, links, caching, and journaling.
- Introduce block queues and DMA-safe I/O.
- Add one virtual storage driver, preferably VirtIO, as the first stable target.

### Phase 4: Networking

**Estimated effort: 3-6 months**

- Add an Ethernet device abstraction and one supported virtual NIC.
- Implement ARP, IPv4, UDP, TCP, and sockets incrementally.
- Add packet ownership, timeouts, routing integration, and basic firewalling.

### Phase 5: SMP and hardware expansion

**Estimated effort: 6-15 months**

- Discover and start additional CPUs.
- Add per-CPU state, IPI delivery, SMP-safe locks, and scheduler balancing.
- Add PCI/PCIe discovery and VirtIO, AHCI, or NVMe support.
- Expand timer, USB, graphics, audio, and hotplug support as needed.

### Phase 6: Security and reliability

**Estimated effort: 4-8 months**

- Add users, groups, capabilities, ACLs, and process isolation policies.
- Replace extension-only trust with signed image/module verification.
- Implement a real persistent crash-dump path.
- Add fuzzing, race testing, fault injection, watchdogs, and security review.

### Cross-cutting testing and documentation

**Estimated effort: 3-6 months, overlapping the phases above**

- Maintain host, QEMU, VDI, and VirtualBox boot coverage.
- Add tests for every syscall, filesystem operation, trap route, and runlevel.
- Test corrupted OWX images, missing `owinit`, failed checksums, and recovery
	paths.
- Document stable interfaces and supported VM configurations.

## Time Outlook

For a small, usable OpenWindows OS rather than Linux parity, the estimated
effort is approximately **18-36 person-months** with one experienced systems
developer. Parallel development can reduce calendar time, but increases the
coordination and integration burden.

Approaching general-purpose Linux-class breadth would require roughly
**60-120+ person-years**. The main cost is not copying individual APIs; it is
hardware compatibility, concurrency correctness, security auditing, filesystem
behavior, driver maintenance, and long-running validation.

## Current Validation

The repository currently validates these paths:

```text
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
make qemu
make vdi-test
```

The QEMU test image provisions the real Essentials `owinit` image and validates
interactive boot, runlevel transitions, shutdown, ACPI power-off, and the safe
power-off screen. The production VDI intentionally omits `owinit` and validates
the expected `B_OWINIT_MISSING` BanHammer halt. VirtualBox can use the same
production VDI after running `tools/vbox_setup.ps1` to attach the current disk.

