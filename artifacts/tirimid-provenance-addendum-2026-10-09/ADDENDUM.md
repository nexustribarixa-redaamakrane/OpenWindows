# Tirimid Package - CIS Kernel-Provenance Addendum

Date: 2026-10-09
Applies to: `artifacts/tirimid/` (frozen snapshot produced 2026-10-08)
Status: informational correction. The snapshot itself is NOT modified.

## 1. Why this addendum exists

The Tirimid tester snapshot in `artifacts/tirimid/` was packaged on 2026-10-08,
before the CIS kernel-provenance gate was wired into the kernel boot path. Its
`TESTER_NOTES.md` (section 4.4) and `PROVENANCE.txt` describe the kernel
license/provenance verifier as having **zero callers** and state that live kernel
enforcement during boot is **NOT WIRED**. Those statements were accurate for the
source tree the snapshot was taken from. They are obsolete for the current
source tree.

This addendum records the current state. The historical snapshot - including its
own `TESTER_NOTES.md`, `PROVENANCE.txt`, `MANIFEST.sha256`, transcripts,
screenshots and packaged images - has not been rewritten. No claim is made that
the snapshot contains this correction. The snapshot's manifest and hashes remain
those of 2026-10-08.

## 2. Current boot-path wiring

- The kernel boot path calls `OwSentinelVerifyKernelProvenanceFromVolume()`
  during **Phase 5c.2**, before PID 1 is created and before any userspace
  hand-off: `core/main.c:685`. The checksum (integrity) check runs first, at
  `core/main.c:669`, and the provenance call is reached only if the checksum
  passes (`core/main.c:684`). Both run under
  `OwRunlevelRequires(OW_RUNLVL_F_INTEGRITY)` (`core/main.c:666`).
- `OwSentinelVerifyKernelProvenanceFromVolume()` is defined at
  `sentinel/damagecntrl.c:176`. It reads `openwinkrnl.owx` from the volume,
  validates the OWX header, and calls `OwSentinelVerifyKernelProvenance()` at
  `sentinel/damagecntrl.c:216`.
- `OwSentinelVerifyKernelProvenance()` is defined at
  `sentinel/damagecntrl.c:132`. It invokes `OwCisVerifyImage()` with the
  CORE_KERNEL provenance record and halts (`OwDiagBanHammer`) on any non-TRUSTED
  verdict.
- The recovery/emergency hand-off calls `OwSentinelVerifyRecoveryKernel()`
  (defined at `sentinel/damagecntrl.c:219`) at `core/main.c:311`; that path also
  applies CIS policy and refuses a non-TRUSTED recovery image. The hand-off
  itself (`boot_launch_init`, `core/main.c:289`) is gated behind the Phase 5c.2
  integrity/provenance phase and the fail-closed guard at `core/main.c:713-722`.

Statements in the frozen snapshot that are now obsolete:

- `TESTER_NOTES.md` section 4.4 heading: "CIS license enforcement is
  userspace-only at boot (kernel path not wired)".
- `TESTER_NOTES.md`: "`OwSentinelVerifyKernelProvenance()` ... currently has
  **zero callers**" and "Its sibling `OwSentinelVerifyRecoveryKernel()` ...
  likewise has no caller".
- `PROVENANCE.txt` (follow-up investigation): "Live kernel license/provenance
  enforcement during boot: NOT WIRED (`OwSentinelVerifyKernelProvenance` has zero
  callers; the boot path calls only `OwSentinelVerifyKernelChecksum`)."

Both verifiers have live callers on the boot and recovery hand-offs. The
snapshot's recorded empirical result - that a CORE_KERNEL / Apache-2.0
dev-signed kernel image boots - does not hold on the current tree: that image is
now refused by the gate before PID 1 is created.

## 3. Corrected test counts

The snapshot cites "771 passed, 0 failed" for `make CIS_DEV_TRUST=1 hosttest`
(`PROVENANCE.txt`, and `TESTER_NOTES.md` section 4.4 and section 5). Current
counts:

- `make CIS_DEV_TRUST=1 qemu-provenance`: control 13/13, denied 16/16 (PASSED).
- `make hosttest`: 775 passed, 0 failed.
- `make CIS_DEV_TRUST=1 hosttest`: 773 passed, 0 failed.

The difference between 775 and 773 is the small set of checks that exist only in
a non-dev build; both are green.

## 4. Scope and caveats

These results are evidence for the tested configurations only. They are not a
production-readiness certification, nor a complete security review of CIS.

Not covered here and still requiring separate coverage:

- The offline recovery (7-stage) flow.
- The VirtualBox/VDI boot path.

## 5. Build-tracking correction (CIS_DEV_TRUST)

This audit found a build-system hazard that predates the snapshot: switching
`CIS_DEV_TRUST` did not invalidate cached kernel and seed object files. Only the
generated image headers were stamp-tracked, so a plain `make` after a
`CIS_DEV_TRUST=1` build relinked the kernel from development-trust objects and
packed a production `openwinkrnl.owx` that still pinned the **development** key
(verified: the development anchor's key id appears in the packed production
image). The reverse also produced stale results: a leftover non-dev `cis_core.o`
silently broke the dev-trust provenance regression until `make clean`.

The `Makefile` now depends on the value-stamped `CIS_STAMP` from `$(ALL_OBJS)`
and `$(SEED_OBJS)`, and the stamp is driven by `FORCE` (no longer `.PHONY`) so
its timestamp changes only when the setting does. Effects: flipping the flag
rebuilds the affected objects; an unchanged flag causes no rebuild; a dev build
followed by a plain `make all` (no clean) now yields a production image with **no**
development anchor.

## 6. Verification of this addendum

The accompanying `MANIFEST.sha256` lists the SHA-256 of every file in this
addendum directory (excluding the manifest itself): lowercase hexadecimal
hashes, forward-slash relative paths, case-insensitive path ordering consistent
with the original package convention, and a final newline.
