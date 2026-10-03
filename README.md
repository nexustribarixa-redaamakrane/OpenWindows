# OpenWindows Kernel

OpenWindows is an experimental freestanding x86-64 kernel and operating-system prototype focused on VM and host-test development. It is not a Linux-compatible kernel, not a general-purpose desktop OS, and not yet production-hardened hardware software.

## Current status

The tree is now much more than a basic boot stub. The current build includes:

- x86-64 boot, IDT and interrupt handling, UART/VGA console output, keyboard input, PIT/PIC support, and selected ACPI power paths
- OWX1 packaging and checksum generation for kernel and userspace images
- real `owinit.owx` provisioning from `OpenWindows-Essentials` and fallback emergency images (`owinitv.owx`, `owrs.owx`)
- static process and thread tables with single-CPU round-robin scheduling
- Ring 3 to Ring 0 syscall dispatch using the supported `int 0x80` ABI
- OWFS and USFS storage support through a small VFS facade and disk abstraction
- ALPC, events, semaphores, mutexes, timers, wait/sleep primitives, and a single-CPU DPC queue
- runlevel management from `-6` through `6`, including shutdown/reboot transitions
- BANcode diagnostics, kernel trap dispatch, Sentinel fault handling, and BanHammer fatal path
- a CIS (Copyleft Integrity Safeguard) verification pipeline for signed OWX images and protected boot trust decisions
- QEMU, VDI, VirtualBox, and host-harness validation paths

`owinit` remains the required user-mode orchestrator for the normal boot path. Applications under `usermode/` are additional Ring 3 programs and do not replace or bypass `owinit`.

For the implementation roadmap and broader feature comparison against Linux, see [ROADMAP.md](ROADMAP.md). For the source-level inventory, see [krnl_spec.md](krnl_spec.md). For the live formalized diagnostics and trust model, see [BANCODE.md](BANCODE.md) and [docs/CIS.md](docs/CIS.md).

## Highlights of the current implementation

### Kernel and runtime subsystems

- `core/`: kernel startup, object namespace, memory state, ALPC, and runlevel logic
- `hal/`: hardware abstraction for interrupts, UART/VGA, keyboard, memory-mapped I/O, ACPI, and timer hooks
- `ps/`: process/thread tables, context switching, scheduler, and OWX loading
- `syscall/`: the current user/kernel ABI dispatcher and validation gates
- `sync/` and `dpc/`: synchronization primitives and deferred procedure calls
- `shell/`, `rc/`, and `usermode/`: boot shell, rc.d policy, and standalone user-mode binaries

### Filesystem, storage, and networking

- `vfs/` and `storage/`: VFS facade, disk abstraction, block-device logic, and storage volume management
- `net/`: router and network path management for the current VM-oriented environment
- `vip/`: UniVIP/FVIP integration points used by the repo's networking and routing stack
- `OpenWindows-Storage` dependencies provide OWFS and USFS support, as well as checksum and security helpers

### Diagnostics and security

- `bancode/` and `diag/`: BANcode, WARNcode, COMcode, and SOFTcode handling
- `sentinel/`: active defense for undefined-instruction and stack faults, plus trust validation
- `cis/`: image verification, metadata policy, and fail-closed boot behavior
- `emergency/`: recovery images used when the primary userspace orchestrator is unavailable

OpenWindows currently treats the kernel as the mandatory authority for policy, image verification, and transmission of fatal conditions. Recovery paths exist, but they are deliberately constrained and not a replacement for a general secure-boot or production OS model.

## Repository layout

| Path | Purpose |
| --- | --- |
| `core/` | Kernel startup, memory, objects, ALPC, and runlevels |
| `hal/` | Hardware translation layer, interrupts, ACPI, keyboard, and VGA/UART support |
| `ps/` | Processes, threads, scheduler, OWX loading, and user-mode handoff |
| `syscall/` | Ring 3 to Ring 0 syscall dispatcher |
| `sync/`, `dpc/` | Synchronization objects and deferred work queues |
| `vfs/`, `storage/` | VFS facade, OWFS/USFS integration, and disk abstraction |
| `net/`, `vip/` | Routing and UniVIP/FVIP integration |
| `bancode/`, `diag/`, `sentinel/`, `cis/` | Diagnostics, traps, integrity, trust, and defense |
| `boot/` | Boot entry points and generated `owinit` image header |
| `emergency/` | Recovery userspace images for missing or broken primary orchestrator |
| `tools/` | OWX packers, embed helpers, VM scripts, host tooling, and diagnostics |
| `docs/` | Design and behavior notes including the syscall ABI and CIS policy |
| `usermode/` | Standalone Ring 3 applications |
| `build/` | Local CMake build directory; generated and ignored |

## Dependencies and external inputs

The build expects these sibling directories under the same parent folder as this repository:

```text
OpenWindows/
OpenWindows-Essentials/
OpenWindows-Storage/
superunicode/
vip/
```

Key external inputs include:

- `OpenWindows-Essentials/Artifacts/Software/owinit.owx`
- `OpenWindows-Storage/common/`
- `OpenWindows-Storage/owfs/`
- `OpenWindows-Storage/usfs/`
- `superunicode/sutf/`
- `vip/`

The Essentials `owinit.owx` artifact is packaged into an OWX1 image and embedded for host and seeded VM tests. Production disk images intentionally do not seed `owinit`; this exercises the missing-orchestrator fatal path instead of silently booting.

## Requirements

- Windows PowerShell
- CMake 3.20 or newer
- Python 3
- A C99-capable GCC toolchain configured for freestanding builds
- QEMU for QEMU and VDI validation
- VirtualBox for VirtualBox validation
- NASM for the floppy/disk Make targets

## Build with CMake

Configure the build directory:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
```

Optional development trust mode for signed test images:

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCIS_DEV_TRUST=ON
```

Build the kernel, host harness, OWX package, checksum, and embedded `owinit` image:

```powershell
cmake --build build --parallel 2
```

Run the host integration test:

```powershell
ctest --test-dir build --output-on-failure
```

Generated artifacts include:

- `build/hosttest.exe`
- `build/openwinkrnl.pe`
- `build/openwinkrnl.owx`
- `build/openwinkrnl.chk`
- `build/generated/owinit_image.h`

## Build and validate with Make

The Makefile provides the primary VM-oriented workflows:

```powershell
make
make hosttest
make qemu
make vdi
make vdi-test
```

Development trust mode is also supported there:

```powershell
make CIS_DEV_TRUST=1 hosttest
```

`make qemu` builds a seeded test image and validates interactive shell boot, runlevel transitions, shutdown, ACPI power-off, and the safe power-off screen.

`make vdi` builds the production VDI without a seeded `owinit`. `make vdi-test` boots that image under QEMU and validates the expected `B_OWINIT_MISSING` fatal path.

The floppy/VirtualBox image workflow remains available:

```powershell
make vbox-image
make vbox
```

## VirtualBox

For the production VDI, regenerate the image first:

```powershell
make vdi
pwsh -ExecutionPolicy Bypass -File .\tools\vbox_setup.ps1 -Vdi "$env:TEMP\openwinkrnl_vbox\openwinkrnl.vdi"
```

The setup script attaches the current VDI to the `OpenWindows` VM and repairs stale VirtualBox medium registrations. The VM is configured for a 512 MiB single-CPU VM with serial logging.

## QEMU directly

The maintained validator is:

```powershell
make qemu
```

For a production VDI:

```powershell
make vdi-test
```

The QEMU scripts use serial output and do not require a graphical display.

## Diagnostics and security model

The kernel uses four diagnostic classes:

- `B+` BANcodes: fatal conditions routed to BanHammer
- `W+` WARNcodes: non-fatal warnings
- `C+` COMcodes: startup and transition milestones
- `S+` SOFTcodes: recoverable faults and mitigations

The diagnostic framework records initialization and shutdown milestones, surfaces warnings, and escalates fatal trust or integrity problems through the BanHammer crash path. This is documented in [BANCODE.md](BANCODE.md).

The current trust model includes:

- `CIS_DEV_TRUST` as an explicit, opt-in development-only configuration
- fail-closed handling when the trust store is empty or verification fails
- explicit separation between integrity, authenticity, and compliance checks
- signed OWX validation before the kernel publishes an executable mapping or process

See [docs/CIS.md](docs/CIS.md) for the full CIS behavior and policy model.

## Syscall ABI notes

The supported syscall ABI is `int 0x80` with `RAX` as the syscall number and arguments passed in `RCX`, `RDX`, and `R8`. The ABI is documented in [docs/SYSCALL_ABI.md](docs/SYSCALL_ABI.md). In particular:

- the supported ABI is the kernel-owned `int 0x80` path
- `owrp` and other alternate calling conventions are not supported by this kernel
- `owinit` is the required PID 1 orchestrator, while standalone apps are additional programs

## Documentation

The repository includes these primary design and specification documents:

- [BANCODE.md](BANCODE.md): BANcode registry and diagnostic catalog
- [ROADMAP.md](ROADMAP.md): current feature baseline and future work plan
- [krnl_spec.md](krnl_spec.md): source inventory and current implementation specification
- [docs/CIS.md](docs/CIS.md): code-signing and trust enforcement architecture
- [docs/SYSCALL_ABI.md](docs/SYSCALL_ABI.md): supported kernel interface and ABI constraints

## License and release status

OpenWindows-owned source in this repository is licensed under the GNU General Public License, version 3 or any later version. See [LICENSE](LICENSE).

Some build inputs and sibling components are separate works with their own licenses. In particular, SuperUnicode and OpenWindows-Storage are dual-licensed under MIT or Apache-2.0, at the recipient's option. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) before redistributing a build that includes external or generated components.

This is a developer preview. It is not production-ready, security-hardened, Linux-compatible, or validated across general physical hardware.
