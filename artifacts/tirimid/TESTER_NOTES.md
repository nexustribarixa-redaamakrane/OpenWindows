# Tester notes — OpenWindows Tirimid test package

Read this before you treat anything in this directory as a result.

---

## 1. What this package is

A **developer test package**: three bootable images plus transcripts and VGA
screenshots, produced on one Windows host with QEMU 11.1.0. It exists to let
someone else reproduce what we booted and see the same screens.

It is **not** a release, not production-signed, and not a claim that OpenWindows
is feature-complete. Several components are deliberately stubbed (§3).

---

## 2. Trust model

Every image here was built with `make CIS_DEV_TRUST=1`, which:

- compiles with `-DCIS_DEV_TRUST`, accepting the **public development key**
  (`tools/cis_block.py`) at the CIS gate, and
- signs the image with that dev key.

The dev seed is public. A `CIS_DEV_TRUST=1` image is the difference between
"boots" and "halts at init" on this codebase, so the flag was used to get a
bootable test artefact — **not** to weaken any check. No integrity rule, NX
enforcement, audit path or policy class was disabled or relaxed to make this
package boot.

**Do not ship these images.** A production image must be built and signed
without `CIS_DEV_TRUST`.

---

## 3. What is real and what is stubbed

`make CIS_DEV_TRUST=1 owx-entries` reports 13 targets, 0 failures — but the
audit's own definition of "ok" for twelve of them is *"entry is
`owx_entry_stub`"*:

| Entry point | State |
|---|---|
| `owinit.owx` → `owinit_main` | **Real** — `48 83 EC 28 E8…`, actually loads and runs, exits at CPL3 with code `0x4017000` |
| `bancat`, `banhammer_cli`, `kconfctl`, `kextctl`, `owedit`, `owkill`, `owsh`, `owwm`, `sfontview`, `startwm`, `vipmount`, `win` | **Stub** — entry is `xor eax,eax; ret` (`31 C0 C3`) |

Consequences a tester must keep in mind:

- Invoking one of the twelve stub programs **succeeds vacuously**. It returns
  0 and does nothing. A passing `run <app>` result is *not* evidence that the
  program works.
- The OWX binaries live in
  `..\OpenWindows-Essentials\Artifacts\Software`; only `owinit.owx`'s entry
  point was audited as functional.
- Converting the twelve stubs into real programs needs a richer syscall surface
  than today's gateway exposes (essentially `UART_WRITE`, `PS_SLEEP`,
  `PS_EXIT_THREAD`). That work was explicitly deferred.

---

## 4. Known defects

### 4.1 `alloc 4096` fails — **fixed 2026-10-15**

The shell is Ring 0, but it used to call `OwSyscallDispatch(OW_SYS_ALLOC, …)`,
which needs a CPL3 process and so was rejected for every size. It now allocates
kernel frames directly via `OwMemAllocatePages`:

```
ow-krnl> alloc 4096
[OK] Allocated 1 page(s) (4096 bytes) at 0x186000; pool 282/4096 pages used
ow-krnl> alloc 18446744073709551615
[FAIL] alloc 18446744073709551615 bytes: request is too large to size
```

See `screenshots/07-alloc.txt`. A near-`UINT64_MAX` size is now refused up front
(previously `size + 4095` wrapped, the page count became zero, and the allocator
reported a misleading "frame allocator refused"). Both behaviours are asserted
by the `make qemu` gate.

**Follow-up defect — fixed 2026-10-16.** An independent final audit found a
second, deeper bug behind the same command: the decimal/hex parser
`ow_strtoull()` (`lib/kstring.c`) silently **wrapped** on values greater than
`UINT64_MAX`, so the size never reached the guard above:

```
ow-krnl> alloc 18446744073709551617
[OK] Allocated 1 page(s) (1 bytes) at 0x186000; pool 283/4096 pages used
```

The wrapped value (`1`) passed every check and allocated a spurious 4-KiB page
while reporting a nonsense size. `ow_strtoull()` now **saturates at `UINT64_MAX`**
(standard `strtoull` semantics), so the existing "too large to size" guard sees
the true value and rejects it. Regression: 6 assertions added to
`tools/hosttest/host_boot.c`.

### 4.2 Kernel timestamps are not wall-clock

`hal/htl.c:484` `OwHalDelayMs()` programs PIT channel 2 with divisor 1193
(1193 ticks per millisecond) but then accumulates **raw ticks** into `elapsed`
and compares that to a millisecond count:

```c
elapsed += (uint16_t)(start - now);   /* ticks */
start = now;
}                                     /* while (elapsed < ms) */
g_kernel_uptime_ms += elapsed;
```

Two effects:

1. The delay returns after `ms` **ticks** instead of `ms` **milliseconds** —
   about **1193× too fast**.
2. `g_kernel_uptime_ms` still records the full requested `ms`, i.e. time that
   never actually elapsed.

Measured: the guest prints `[BOOT] kernel boot complete in 79674 ms`, while
host wall clock from QEMU serial connect to the `ow-krnl>` prompt is
**2.3 seconds**. The 79.674 s is the sum of requested delays; those delays cost
roughly 79.674 / 1193 ≈ 67 ms of real time. Treat every `[  64.842]`-style
timestamp as **relative, not seconds**.

The same image on VirtualBox 7.2.16 reports a much larger value
(`kernel boot complete in 539332 ms` in the current capture) for identical
source and identical delay arguments. That is the clearest single piece of
evidence that the value tracks host PIT-emulation behaviour rather than elapsed
time.

Scope of the bug — callers of `OwHalDelayMs` only:

| Caller | Effect |
|---|---|
| `rc/rc.c:209` — `sleep N` in an rc/init script | `sleep 1` returns in ~0.8 ms; the init script runs faster than authored |
| `hal/acpi.c` — 1100 ms total across the ACPI S5 sequence | Firmware settle delays are ~0.9 ms real; shutdown still worked but is tight |
| `core/main.c` `boot_pace()` — per-step `OwHalDelayMs(60)` boot-log pacing | ~0.05 ms real per step |

**Not** affected (verified): the scheduler tick (PIT channel 0, 100 Hz),
`PS_SLEEP` and all sync/timer waits (`ow_sync.c:340` uses
`OwPsGetTickCount() + WaitTimeout`), disk I/O, and page-table/audit code.

**Not fixed in this package** — correcting it would add ~80 s of real boot time
(the delays are now near-free) and would require re-tuning every validation
timeout in `tools/qemu_run.ps1` and `tools/tirimid_capture.ps1`.

### 4.3 Disk and floppy images did not boot before a memory fix (fixed, committed)

The static physical-RAM pool `g_PhysicalRam[16MB]` is linked immediately after
the kernel. In the `boot/vbox.ld` build (link base `0x10000`) the pool spans
**`0x6B000`–`0x106B000`**, which straddles the ISA reserved window
`0xA0000`–`0xFFFFF` (VGA aperture and BIOS ROM). Reads from that window return
`0xFF`, writes are dropped.

Observed symptom: `OwMemCreateAddressSpace` copied `0x00051023` from the boot
page directory and read back `0xFFFFFFFFFFFFFFFF` → non-canonical
`boot_pdpt = 0x000FFFFFFFFFF000` → `#GP` at `RIP 0x13EAF`, before the shell.
The same dropped stores produced earlier `[AUDIT] NX mismatch … pte=1` reports.
The QEMU `-kernel` build (`0x100000` link base, pool at `0x15C000`) never
overlapped, which is why it always passed while floppy/disk crashed.

Fixed in `core/memory.c` by skipping `0x00000–0x0FFFF` and `0xA0000–0xFFFFF`
when bump-allocating. Both the qemu and the disk/floppy paths are exercised
after the fix. This change is now **committed** in `a1961d5` — it is no longer a
local modification required to make the package boot.

### 4.4 CIS enforcement — the kernel provenance gate **is** wired (corrected 2026-10-15)

> Corrected during the 2026-10-15 refresh. The 2026-10-08 snapshot stated that
> the kernel provenance/license verifier had zero callers. That was true of the
> tree the snapshot was cut from, but it is **obsolete**. The superseding
> write-up is `artifacts/tirimid-provenance-addendum-2026-10-09/ADDENDUM.md`.

CIS applies its license/provenance policy on the **live kernel boot path** as
well as through the userspace OWX loader.

**Working**

- Userspace `.owx` policy + license enforcement, wired through the OWX loader:
  `OwCisVerifyImage()` is called from `ps/owx_loader.c:399`.
- The host-side CIS policy engine: `make CIS_DEV_TRUST=1 hosttest` reports
  **980 passed, 0 failed**, including `kernel_mit_refused produces
  REJECT_POLICY`.
- Kernel **checksum** verification at boot: `core/main.c:751` calls
  `OwSentinelVerifyKernelChecksum()` (SHA-256 against `openwinkrnl.chk`). This
  is an integrity check, **not** a license check.
- Development-key signing of the test images (`CIS_DEV_TRUST=1`).

**Live kernel path (wired).**

- `core/main.c:767` calls `OwSentinelVerifyKernelProvenanceFromVolume()`, which
  reads `openwinkrnl.owx` from the volume and applies the `CORE_KERNEL` /
  `GPL-3.0-or-later` policy via `OwSentinelVerifyKernelProvenance()`
  (`sentinel/damagecntrl.c:132`).
- The recovery hand-off calls `OwSentinelVerifyRecoveryKernel()`
  (`core/main.c:382`, `sentinel/damagecntrl.c:219`).
- The kernel **checksum** verifier still runs first (`core/main.c:751`,
  `OwSentinelVerifyKernelChecksum()`).

**Development-policy caveat — what these images actually show.** The bootable
images do **not** carry a packed kernel CIS release block: they are
`objcopy -O binary` of the linked PE, and only `openwinkrnl.owx` passes through
`tools/owx_pack.py` with `--policy-class CORE_KERNEL --cis-licence
GPL-3.0-or-later`. Under `CIS_DEV_TRUST=1` the kernel gate therefore reports:

```
[CIS] kernel image provenance: openwinkrnl.owx optional (development policy)
[SENTINEL] kernel provenance NOT verified: openwinkrnl.owx absent from the volume
           (development policy tolerates absence; enforcement skipped)
```

The gate **runs**; it finds no kernel `.owx` and (under dev policy only)
tolerates the absence. A production build without `CIS_DEV_TRUST` does not
tolerate it. The 2026-10-08 audit result — a `CORE_KERNEL` / `Apache-2.0`
dev-signed kernel image booted to `ow-krnl>` — no longer holds on the current
tree: that image is refused by the gate before PID 1 is created (see the
addendum).

**Live userspace enforcement — empirically verified.** Regenerating
`boot/owinit_image.h` so the embedded `owinit.owx` declares
`LICENSE = Proprietary` (dev-signed, subsystem `BOOT`) makes the boot refuse it:

```
[CIS] owinit refused: policy refused
[OWX] owinit refused by CIS: POLICY-REFUSED (status 0x11AF07)
[OWINIT] state PRIMARY but no init was entered - unrecoverable boot failure - panic...
[FATAL] SYSTEM HALTED
```

This proves a non-permissive userspace image is actively rejected by CIS.

**Known issue.** The halt reason reported in that case is `OWINIT_MISSING`
(`U+0011A005`), even though the image *was present* and was refused by policy.
`OWINIT_MISSING` is misleading here; the actual cause is `POLICY-REFUSED`.

**Build-system caveat.** `$(CIS_STAMP)` is a `.PHONY` target (`Makefile:399`), so
`make` regenerates `boot/owinit_image.h` on every build (rule at
`Makefile:425-431`). Preserving an experimental header therefore required
building with `make -o boot/owinit_image.h …`. This behavior was left unchanged. (The tester
images *were* rebuilt for the 2026-10-15 refresh, but no experimental header is
involved there.)

---

## 5. Not validated

- **Visual review of the PNGs.** Nobody looked at them in an image viewer.
  Mitigation: every screenshot ships with a `.txt` decoded from the raw
  `0xB8000` dump, and each `.txt` was programmatically checked against the
  state it is captioned as. For the boot-console redesign the PNGs were also
  confirmed to be 720×400 text-mode renders with a small palette, and the
  VirtualBox PNG was additionally checked row-band by row-band for text in
  rows 0–10 (wordmark) and 11–24 (log); pixel content is otherwise not
  independently verified (the `.txt` is the content of record).

Everything else this section previously listed as un-run has now been run for
the 2026-10-15 refresh:

- **`make CIS_DEV_TRUST=1 qemu-emergency`** — PASS, **8 checks**.
- **`make CIS_DEV_TRUST=1 vdi`.** Built and validated. Note it links
  `$(VBOX_DISK_KERNEL)` *without* `$(TEST_SEED_OBJS)`, so it is a different,
  **program-free production** image with no `owinit` payload; it correctly halts
  at the `U+11A005` owinit gate (8-check validation). It is a git-ignored local
  artefact and is deliberately not distributed inside this seeded package — the
  packaged disk image is still built from the seeded floppy kernel.

`make CIS_DEV_TRUST=1 hosttest` **was** also run: **980 passed, 0 failed**. It
drives the CIS policy engine on the host and is the evidence that the engine
refuses a non-GPL kernel *when the verifier is invoked* — even though, as §4.4
records, the live boot path does not currently invoke it.

VirtualBox 7.2.16 **was** available and the packaged `.vdi` **was** booted and
validated (`transcripts/05_virtualbox_boot.txt`, `screenshots/09-vbox-boot.png`).
Note for automation: `VBoxManage` is not on `PATH` on this host — it lives at
`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`, so `Get-Command VBoxManage`
fails and scripts must be given the full path.

---

## 6. Screenshot caveats

- `01-boot` and `01b-bootcomplete` are captured with a monitor `stop` issued
  inside the same write as `screendump`, because the guest reaches a shell
  prompt in ~2–3 s and the 14-line log area scrolls the boot log away. An
  earlier attempt without the freeze produced three identical frames; the
  current frames are all distinct and content-checked.
- All ten captures were **regenerated for the 2026-10-16 boot-console
  redesign**: the previous frames showed the four-line `O P E N W I N D O W S`
  banner and the `BOOT [ … ] NN%` HUD, both of which the redesign removed. Each
  new `.txt` was decoded from its own `.vgabin` and shows the 11-line wordmark
  in rows 0–10 with the kernel log in rows 11–24.
- `09-vbox-boot.png` is a VirtualBox `screenshotpng` capture of the same disk
  image, provided as independent evidence that the QEMU screen is not a
  QEMU-specific artefact. It was taken from a byte-identical temporary copy of
  the packaged `.vdi` (so the packaged `.vdi` is not modified by booting it),
  and reproduces the same serial transcript (`ow-krnl>`, `violations=0`,
  `[CIS] owinit: TRUSTED`, no halt). A VirtualBox screenshot is not a raw
  `0xB8000` dump, so its pixel content is checked structurally only (a 720×400
  render whose text sits in rows 0–10 and 11–24); the serial transcript is the
  content of record.
- The VGA console is an 80×25 mirror of the serial log (rows 0–10 pinned
  wordmark, 11–24 log, no HUD row). It is a text buffer, not a compositor —
  there is no graphical window system on screen.
- `07-alloc` now shows a **success** (`alloc 4096` → `[OK] Allocated 1 page(s) (4096 bytes) …`).
  It showed a failure in the previous package; that defect is fixed.

---

## 7. Recommendation

Safe to use for: booting, inspecting the serial log, checking the shell (now
including `pwd` / `cd` / `ls [dir]` / `sucs commit` and a working `alloc`), the
init/runlevel sequence, the filesystem verbs, and the shutdown path.

Do **not** use for: correctness claims about the twelve stub `.owx` programs,
or any timing-sensitive test.

Suggested follow-up order:

1. Fix `OwHalDelayMs` (divide accumulated ticks by 1193) and re-tune the
   validation timeouts.
2. Convert the twelve `.owx` stubs to real programs — first inventory
   `OpenWindows-Essentials` per file and decide the syscall surface needed.
