# OpenWindows Tirimid Testing-Report — Findings Response

Response to `open_windows_testing_report.pdf` (14 pages, 13 topics) and the tester
artifacts under `artifacts/tirimid/`.

## Method

* **Reproduce first.** The report's own boot command was replayed against the
  unmodified tree and the full transcript captured:
  `qemu-system-x86_64 -m 512M -smp 1 -kernel openwinkrnl_qemu.bin
  -no-reboot -no-shutdown` → `%TEMP%\ow_probe_baseline.txt`.
* **Then fix, then re-test on the same command.** Final interactive transcript:
  `%TEMP%\ow_probe_final.txt`; runlevel-6 transcript: `%TEMP%\ow_probe_rl6.txt`.
* **Regression gates** (both must stay green):
  * `make hosttest CIS_DEV_TRUST=1` — **974 passed, 0 failed**
    (961 before this pass; +13 new assertions).
  * `make qemu CIS_DEV_TRUST=1` — **QEMU BOOT VALIDATION PASSED (28 checks)**
    (18 before; +10 new auto-init checks).
  * `make qemu-emergency CIS_DEV_TRUST=1` — 8 checks passed.
* **Base commit.** The pass started at `db3fee3`. One unrelated commit landed
  during the pass, `b0ff4a4` ("Set explicit entry point for PE image"), which
  edits only the PE link line in `Makefile`/`CMakeLists.txt`; it touches none of
  the files changed here.
* **Legend.** 🟩 works · 🟨 partial · 🟥 broken. Every verdict distinguishes
  *observed* behaviour from *by-design* behaviour.

## Verdict summary

| # | Report topic | Tester | HEAD (observed) | After this pass | Kind |
|---|--------------|--------|-----------------|-----------------|------|
| 1 | Booting | 🟩 | 🟩 | 🟩 | works |
| 2 | Terminal navigation (scrollback) | 🟨 | 🟨 | 🟨 | by-design (serial console) |
| 3 | Shell navigation (`pwd/cd/ls/dir`) | 🟨 | 🟥 | 🟩 | **fixed** |
| 4 | Help listing | 🟨 | 🟨 | 🟨 | consequence of #2 |
| 5 | Runlevel read/write (level 6) | 🟨 | 🟩 | 🟩 | by-design (REBOOT profile) |
| 6 | VFS ↔ physical FS | 🟨 | 🟥 | 🟩 | **fixed** |
| 7 | `fs` command usability | 🟨 | 🟨 | 🟩 | **fixed** (now cross-testable) |
| 8 | Memory allocation (`alloc`) | 🟥 | 🟥 | 🟩 | **fixed** |
| 9 | Manual traps | 🟨 | 🟨 | 🟨 | by-design + clarified |
| 10 | Power off | 🟩 | 🟩 | 🟩 | works |
| 11 | SUCS mode | 🟥 | 🟥 | 🟩 | **fixed** (+ documented limit) |
| 12 | System status | 🟥 | 🟥 | 🟩 | **fixed** |
| 13 | Running programs from disk | 🟨 | 🟨 | 🟨 | tooling gap, not a defect |

---

## Fixes, with root cause and evidence

### 3. Shell navigation commands — 🟥 → 🟩

**Observed at HEAD** (`ow_probe_baseline.txt`): `pwd`, `cwd`, `ls`, `dir`, `cd`
all answered `Unknown command. Type 'help'.`

**Root cause.** The shell simply had no such commands. The OWFS catalog is a
tree (`owfs_inode_t.parent_inode`, nested catalogs via `owfs_catalog_mkdir`), but
nothing exposed it — so the only way to see the filesystem was the flat `fs …`
family.

**Fix** (`shell/shell.c`). Added `pwd`/`cwd`, `cd <dir|..|/|path>`, `ls`/`dir`,
backed by new OWFS helpers in `storage/owdisk.{c,h}`:
`OwFsOwfsRootInode`, `OwFsOwfsLookupIn`, `OwFsOwfsGetParent`, `OwFsOwfsListIn`.
`cd` resolves `.`, `..` (via `parent_inode`), absolute and relative paths and
maintains a persistent CWD shown by `pwd` and in `status`.

**Evidence:**
```
ow-krnl> pwd
/
ow-krnl> ls
  [DIR ] System (ino 1)
  [FILE] bootvid.owd (ino 2)
  [FILE] interop.txt (ino 3)
[FS] /: 3 entries
ow-krnl> cd System
[FS] cd: /System
ow-krnl> cd ..
[FS] cd: /
```
Regression: `make qemu` asserts `[FS] cd: /System` and `[FS] /System: 0 entries`.

### 6 & 7. VFS vs the physical filesystem — 🟥 → 🟩

**Observed at HEAD.** `write ProbeFile hello world` reported success, but
`fs read ProbeFile` answered `[FS] read 'ProbeFile': FAILED (code 0x7)` — the two
commands wrote to **two independent on-disk stacks**. The report put it well:
"files can be created using the `fs` command … the relationship between the
physical filesystem and VFS is unclear."

**Root cause.** `vfs/vfs.c` implemented its *own* `OwFs*` catalog format on the
primary disk, while the `fs` command (and boot) used the OWFS/USFS stack in
`storage/owdisk.c`. Both wrote "the disk"; neither could see the other's files.
The VFS facade was therefore a second, divergent filesystem.

**Fix.** Rewired the whole `OwVfs*` facade in `vfs/vfs.c` to **delegate** to the
one real stack: `OwVfsMountPrimary → OwFsOwfsMount`, `OwVfsMountSecure →
OwFsUsfsMount`, and create/write/read/delete to `OwFsOwfsCreate/Write/Read/Delete`
with new OWFS primitives (`OwFsOwfsDelete`, etc.). `OwVfsIsPrimary/SecureMounted`
now also confirm the OWFS/USFS device is mounted, and `status` names the backing
filesystem. `OwFsChecksumCalc` is kept (it is an exported contract used by the
crash-dump path).

**Evidence — one file, two views:**
```
ow-krnl> write interop.txt via-vfs-facade
[OK] Written to 'interop.txt'.
ow-krnl> read interop.txt
[OK] Read 14 bytes:
---
via-vfs-facade
---
ow-krnl> fs read interop.txt
[FS] read 'interop.txt' (14 bytes):
---
via-vfs-facade
---
```
This also makes finding #7 fully testable: `fs` output can now be produced and
read back through `write`/`read`, and vice-versa. Regression: `make qemu` asserts
`[OK] Written to 'interop.txt'.` and `[FS] read 'interop.txt' (14 bytes):`.

> **Documented limit:** persistence across reboot is impossible in this image
> because the "disk" is a RAM disk (`hal/htl.c`, 8 MiB primary). That is a
> property of the live environment, not of the filesystem code — a real block
> device would persist.

### 8. `alloc` — 🟥 → 🟩

**Observed at HEAD.** Every size failed with a bare `[FAIL] Allocation rejected.`
— no size, no reason.

**Root cause.** The shell (Ring 0, no process) called
`OwSyscallDispatch(OW_SYS_ALLOC, …)`. That syscall allocates a private page
*inside a CPL3 process address space* and is rejected for a caller with no
process — so `alloc` could never succeed.

**Fix** (`shell/shell.c`). The shell now takes frames directly from the kernel
arena via `OwMemAllocatePages`, and reports the size, page count, address and the
resulting pool usage. Oversized requests are refused with the real free/total
figures instead of a generic message.

**Evidence:**
```
ow-krnl> alloc 4096
[OK] Allocated 1 page(s) (4096 bytes) at 0x1EC000; pool 143/4096 pages used
ow-krnl> alloc 65536
[OK] Allocated 16 page(s) (65536 bytes) at 0x1ED000; pool 159/4096 pages used
ow-krnl> alloc 33554432
[FAIL] alloc 33554432 bytes (8192 page(s)): kernel pool exhausted (3955 of 4096 4-KiB pages free)
```
Regression: `make qemu` asserts `[OK] Allocated 1 page(s) (4096 bytes)` and
`[FAIL] alloc 33554432 bytes`.

### 11. SUCS mode — 🟥 → 🟩 (with a documented limit)

**Observed at HEAD.** `sucs ext` → `[SUCS] request: staged, reboot required`, and
that was the end of it: `active` never changed, `changes=0` forever. Because the
live image uses a RAM disk and is booted with `-no-reboot`, the boot-time commit
path (`OwSucsCommitBoot`) is never reached again — so **EXTENDED was untestable**,
exactly as the report says.

**Fix.**
1. `shell/shell.c` + `lib/sucs.c` (`OwSucsCommitNow`): added **`sucs commit`**,
   which applies the staged mode immediately (`sucs_commit_mode_on_boot`), no
   reboot. Staging semantics are preserved.
2. Fixed the request path so the decision is made against the **kernel's
   committed** mode rather than the library's private, never-advanced copy —
   without this, after committing EXTENDED it was impossible to stage a switch
   back to BASE.
3. Documented SUCS meaning in the `help` text.

**Evidence:**
```
ow-krnl> sucs ext
[SUCS] request: staged, reboot required
ow-krnl> sucs commit
[SUCS] committed: active=EXTENDED pending=EXTENDED reboot=0 changes=1
ow-krnl> sucs
[SUCS] active=EXTENDED pending=EXTENDED reboot=0 changes=1
ow-krnl> sucs ext
[SUCS] request: already active
```
Regression: `make qemu` asserts `[SUCS] committed: active=EXTENDED`; `hosttest`
now drives BASE→EXTENDED→BASE and asserts both commits and the refusal to commit
when nothing is staged.

### 12. System status — 🟥 → 🟩

**Observed at HEAD:** `Memory Pages: 140 / 4096 used`. The report's arithmetic is
correct: 4096 × 4 KiB = 16 MiB, which looks impossible on a 512 MiB VM.

**Root cause.** `4096` is the size of a **fixed 16 MiB static frame arena**
(`g_PhysicalRam`), not a claim about installed RAM. Nothing ever read the
firmware memory map, so the kernel could not tell the difference — and neither
could the reader.

**Fix.**
* `core/memory.c` + `inc/ow_memory.h`: `OwMemSetBootInfo(magic, mbi)` parses the
  multiboot info block handed over in `%rcx/%rdx`; `OwMemFirmwareBytes/Pages`
  report firmware RAM. `boot/qemu_entry.c` forwards `(magic, mbi)` before
  `_start()`.
* `status` now prints the two figures separately and names the VFS backends.

**Evidence:**
```
--- SYSTEM STATUS ---
Memory (kernel pool): 141 / 4096 pages used (16 MiB 4-KiB arena)
Memory (firmware):    511 MiB reported by the bootloader (131040 4-KiB pages, not managed)
VFS Primary:   MOUNTED (OWFS)
VFS Secure:    MOUNTED (USFS)
CWD:           /
```
Regression: `hosttest` parses a synthetic multiboot block (256 MiB, 65536 pages)
and asserts the "no map" / "wrong magic" paths; `make qemu` asserts
`Memory (firmware):` and `4-KiB pages, not managed)`.

> **Documented limit:** the managed pool is still a 16 MiB arena. Enlarging it to
> use all firmware RAM is a memory-manager change, not a reporting bug; it is
> deliberately **not** done here. `status` now states the limit plainly instead of
> implying it is the machine's RAM.

---

## Not defects / by design (documented, no code change)

### 2. Terminal navigation (scrollback) — 🟨, environmental

Up/PageUp/Shift+PageUp/Ctrl+PageUp "did nothing". The kernel writes a **linear
byte stream to a UART**; it has no framebuffer and no line history to scroll. The
tester's command line uses `-serial mon:stdio`, under which QEMU owns the
terminal in raw mode and provides no scrollback of its own. Scrolling past output
is a *terminal* function, not a kernel one. Workarounds that exist today: use a
terminal emulator with scrollback, or capture the serial stream to a file
(`-serial file:…`), which is what the Tirimid artifacts themselves do
(`artifacts/tirimid/transcripts/`). No kernel change can make a remote serial
console scroll, so this is recorded as by-design rather than "fixed".

### 4. Help listing — 🟨, consequence of #2

`help` correctly lists every command (now including `pwd`/`cd`/`ls`/`dir` and
`sucs commit`). It is long, and the same scrollback limit applies. With the
navigation commands added, the filesystem itself is now inspectable rather than
just described.

### 5. Runlevel 6 — 🟩, by design

The report reads "cannot be set above 5; when set to 6 it causes the system to
power off". Runlevel 6 is the **REBOOT** profile. The kernel performs exactly that
and says so (`ow_probe_rl6.txt`):
```
ow-krnl> runlevel set 6
[SHUTDOWN] Runlevel 6 (REBOOT) - restart
... rc.d shutdown sequence …
[SHUTDOWN] Starting restart...
[ACPI] software reset
```
Then QEMU exits because the tester's command line includes **`-no-reboot`** (QEMU
honours the reset request by exiting instead of rebooting). Runlevels `-6..5`
transition normally. No defect.

### 9. Manually triggering trap interrupts — 🟨, by design + clarified

The reviewer's expectation ("a page fault should be demand-paged, not crash the
kernel") is already how the kernel behaves: CPL3 faults are resolved by demand
paging (`[PF] RESOLVED err=… cr2=… rip=…`). The `trap pf` **command** is a
diagnostic that deliberately injects a fatal vector to exercise the crash screen,
the SMP IPI halt and the halt record. The confusion was that its output did not
say so. `execute_trap` now prints an explicit banner first:
```
[TRAP] diagnostic only - injecting Vector 14 on purpose to show the fatal-fault path
[TRAP] CPU Hardware Exception Vector 14 (Page Fault): Unmapped page translation fault (#PF)
```
The fatal crash path is intentionally unchanged.

### 13. Running programs from disk — 🟨, tooling gap

The kernel does execute images from disk: boot seeds and runs `owinit.owx` (and
the emergency images `owinitv.owx`/`owrs.owx`) as CPL3 processes at the profiles
that require them — the transcript shows `[PF] RESOLVED` for the user window and
`Hello from Ring 3!`. What is missing is a **sample user program** plus a shell
command to launch an arbitrary `.owx` from the catalog. That is new tooling, not
a kernel defect; noted here rather than claimed as fixed.

### 1 & 10. Booting / power-off — 🟩, confirmed

Boot succeeds on the given command line, and power-off (`shutdown`/`exit`,
runlevel halt, ACPI S5, and the safe power-off screen) works. Unchanged.

---

## Files changed

| File | Change |
|------|--------|
| `shell/shell.c` | `pwd`/`cwd`, `cd`, `ls`/`dir`; `alloc` via frame allocator; `status` arena+firmware+VFS; `sucs commit`; `write` tolerates existing file; `execute_trap` clarification; auto-init regression script |
| `vfs/vfs.c` | `OwVfs*` facade delegates to OWFS/USFS (one on-disk truth) |
| `storage/owdisk.c` / `.h` | OWFS lookup/list/parent/delete primitives for the shell + VFS |
| `core/memory.c` / `inc/ow_memory.h` | firmware-RAM reporting API; multiboot `mem_upper` parse |
| `boot/qemu_entry.c` | forward `(magic, mbi)` to the memory manager |
| `lib/sucs.c` / `inc/ow_ecosys.h` | `OwSucsCommitNow`; request keys off committed mode |
| `tools/hosttest/host_boot.c` | +13 assertions (firmware parse, SUCS live commit/reversibility) |
| `tools/qemu_run.ps1` | +10 asserted auto-init markers |

## Honest limitations carried forward

1. **16 MiB managed arena** — `status` now labels it; not enlarged (memory-manager work, out of scope).
2. **No reboot persistence** — the live image's device is a RAM disk.
3. **SUCS boot-time commit** is unreachable in a live boot by construction; `sucs commit` exposes EXTENDED without pretending that the boot path ran.
4. **Scrollback** is the terminal's job; not solvable from the guest.
5. **No sample user program** shipped for the scheduler/process test.
6. `make hosttest-asan` cannot link on this host (the w64devkit toolchain ships no `libasan`/`libubsan`); the non-ASan host and QEMU suites cover the changes. This is a toolchain limitation, not a change in behaviour.
