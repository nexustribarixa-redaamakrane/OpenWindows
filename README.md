# OpenWindows kernel

OpenWindows is an experimental freestanding x86-64 kernel prototype. The
primary implementation is C99 plus x86 assembly; it builds a PE kernel image
and packages it in the project-specific OWX format. It is not a Linux
compatibility layer or a production-ready general-purpose operating system.

## What is implemented

The kernel tree contains startup and object/memory code (`core/`), interrupt
and device-facing code (`hal/`), process/thread and OWX loading code (`ps/`),
an `int 0x80` syscall dispatcher (`syscall/`), synchronization and deferred
procedure calls (`sync/`, `dpc/`), shell/runlevel code (`shell/`, `rc/`), a
VFS facade (`vfs/`), routing (`net/`), and diagnostics/CIS code (`bancode/`,
`diag/`, `sentinel/`, `cis/`). The Makefile and CMake build both integrate
neighboring SuperUnicode, VIP, and OpenWindows-Storage sources.

| Area | Status in this checkout |
| --- | --- |
| x86-64 kernel image and OWX packing | Implemented build path |
| Host boot harness and QEMU workflows | Implemented test paths |
| Process, scheduler, syscall, synchronization, and storage interfaces | Prototype; project-specific and VM-oriented |
| Physical hardware support and security hardening | Not established |

The supported syscall entry is `int 0x80`; see `docs/SYSCALL_ABI.md` for the
register contract. CIS verification is part of the image-loading path. The
default build trusts no signing key. `CIS_DEV_TRUST` enables a public,
checked-in development key for test images only; it does not provide a
production trust anchor.

## Repository dependencies

The build expects these sibling checkouts, because the build files refer to
them using `..` paths:

```text
OpenWindows-Essentials/
OpenWindows-Storage/
superunicode/
vip/
```

The normal boot and test path also packages
`OpenWindows-Essentials/Artifacts/Software/owinit.owx`. The Makefile includes
the sibling C sources directly; the CMake file exposes
`OWINIT_SOURCE` if the image is elsewhere.

## Build with CMake

Requirements: CMake 3.20+, Python 3, a GCC-compatible C/ASM toolchain, and the
sibling repositories above. QEMU is needed for the VM checks; NASM and
VirtualBox/qemu-img are needed for the relevant image workflows.

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
```

The CMake build produces `openwinkrnl.pe`, `openwinkrnl.owx`, a checksum file,
the host harness, and a generated `owinit_image.h` in the build tree. For a
bootable development image signed with the test key, configure explicitly:

```powershell
cmake -S . -B build-dev -G "MinGW Makefiles" -DCIS_DEV_TRUST=ON
cmake --build build-dev --parallel 2
ctest --test-dir build-dev --output-on-failure
```

Never ship images signed with the repository's public development key.

## Make workflows

The root `Makefile` provides additional VM targets:

```powershell
make hosttest
make hosttest-asan
make CIS_DEV_TRUST=1 qemu
make vdi
make vdi-test
```

`hosttest` runs the host boot harness; `hosttest-asan` runs its ASan/UBSan
build. `qemu` is the seeded interactive test image. `vdi` builds the
production-style VirtualBox disk without a seeded `owinit`; `vdi-test` checks
the expected missing-orchestrator failure. `make help` is not defined by this
Makefile; inspect the target names near the end of `Makefile` for the remaining
`vbox`, `emergency`, and audit workflows.

The code and build scripts are the authority for current behavior. VM tests
do not constitute hardware certification or a security audit.
