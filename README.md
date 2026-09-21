# OpenWindows Kernel

OpenWindows is an experimental freestanding x86-64 kernel and operating-system prototype. It is currently focused on QEMU, VirtualBox, and host-harness development rather than production hardware or Linux compatibility.

## Status

The repository currently provides:

- x86-64 boot, IDT exception entry, UART, VGA text, keyboard, PIT/PIC, and selected ACPI support
- OWX1 kernel packaging with checksum generation
- Real `owinit.owx` integration from `OpenWindows-Essentials`
- Static process/thread tables and a single-CPU round-robin scheduler
- Ring 3 syscall dispatch and standalone user-mode applications
- OWFS/USFS storage paths and a small VFS facade
- ALPC, synchronization objects, DPCs, runlevels, BANcode traps, Sentinel checks, and BanHammer diagnostics
- QEMU, VDI, VirtualBox, and host integration validation

`owinit` is the required user-mode orchestrator. Applications under `usermode/` are separate programs and do not replace or bypass `owinit`.

See [ROADMAP.md](ROADMAP.md) for the current implementation comparison and planned work. See [krnl_spec.md](krnl_spec.md) for the source-based kernel specification.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `core/` | Kernel startup, memory, objects, ALPC, and runlevels |
| `hal/` | Hardware translation layer, interrupts, ACPI, keyboard, and VGA/UART support |
| `ps/` | Processes, threads, scheduler, and OWX loading |
| `syscall/` | Ring 3 to Ring 0 syscall dispatcher |
| `usermode/` | Standalone Ring 3 applications |
| `vfs/`, `storage/` | VFS facade, OWFS/USFS integration, and disk abstraction |
| `net/`, `vip/` | Routing and UniVIP/FVIP integration |
| `bancode/`, `diag/`, `sentinel/` | Diagnostics, kernel traps, integrity, and defense |
| `boot/` | Boot entry points and generated Essentials `owinit` image header |
| `tools/` | Image packers, embedding helpers, VM scripts, and host tooling |
| `build/` | Local CMake build directory; generated and ignored |

## Dependencies

The build expects these sibling directories under `Documents`:

```text
OpenWindows/
OpenWindows-Essentials/
OpenWindows-Storage/
superunicode/
vip/
```

The important external inputs are:

- `OpenWindows-Essentials/Artifacts/Software/owinit.owx`
- `OpenWindows-Storage/common/`
- `OpenWindows-Storage/owfs/`
- `OpenWindows-Storage/usfs/`
- `superunicode/sutf/`
- `vip/`

The Essentials `owinit.owx` artifact is packaged into an OWX1 image and embedded for host and seeded VM tests. Production disk images intentionally do not seed `owinit`; they exercise the missing-orchestrator BanHammer path.

## Requirements

- Windows PowerShell
- CMake 3.20 or newer
- Python 3
- A C99-capable GCC toolchain configured for freestanding builds
- QEMU for QEMU and VDI validation
- VirtualBox for VirtualBox validation
- NASM for the floppy/disk Make targets

## Build with CMake

Configure the existing build directory if needed:

```powershell
cmake -S . -B build -G "MinGW Makefiles"
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
- `boot/owinit_image.h`

## Build and Validate with Make

The Makefile provides VM-oriented workflows:

```powershell
make
make hosttest
make qemu
make vdi
make vdi-test
```

`make qemu` builds a seeded test image and validates interactive shell boot, runlevel transitions, shutdown, ACPI power-off, and the safe power-off screen.

`make vdi` builds the production VDI without seeded `owinit`. `make vdi-test` boots that image under QEMU and validates the expected `B_OWINIT_MISSING` fatal path.

The floppy image workflow is available with:

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

## QEMU Directly

The maintained validator is:

```powershell
make qemu
```

For a production VDI:

```powershell
make vdi-test
```

The QEMU scripts use serial output and do not require a graphical display.

## Diagnostics

The kernel uses four diagnostic classes:

- `B+` BANcodes: fatal conditions routed to BanHammer
- `W+` WARNcodes: non-fatal warnings
- `C+` COMcodes: initialization and transition milestones
- `S+` SOFTcodes: recoverable faults and mitigations

The crash path supports dynamic messages for Autoreboot and KDump settings. KDump status is reported honestly; a complete persistent dump writer is still future work.

## License and Release Status

OpenWindows-owned source in this repository is licensed under the GNU General
Public License, version 3 or any later version. See [LICENSE](LICENSE).

Some build inputs and sibling components are separate works with their own
licenses. In particular, SuperUnicode and OpenWindows-Storage are dual-licensed
under MIT or Apache-2.0, at the recipient's option. See
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) before redistributing a build
that includes external or generated components.

This is a developer preview. It is not production-ready, security-hardened, Linux-compatible, or validated across general physical hardware.
