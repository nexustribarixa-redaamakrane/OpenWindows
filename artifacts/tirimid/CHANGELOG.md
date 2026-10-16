# Tirimid test package — change log

All dates are 2026. Every file in this package is covered by
`MANIFEST.sha256`; regenerate the manifest after any change.

---

## 2026-10-16 — independent final audit (commit `0bf3108`)

The 2026-10-15 fixes below were committed by the operator as `0bf3108`
("Refactor shell commands and improve VFS handling"); the tree was clean at the
start of this audit. One further genuine defect was found and fixed, and the
package was rebuilt from the fixed source.

### Fix in this audit

- `lib/kstring.c` `ow_strtoull()` silently wrapped on overflow. A decimal or hex
  literal greater than `UINT64_MAX` (for example `alloc 18446744073709551617`)
  wrapped to a small value, so the size guard in the `alloc` handler never saw
  it: the shell allocated one spurious 4-KiB page and printed
  `[OK] Allocated 1 page(s) (1 bytes)`. It now saturates at `UINT64_MAX`
  (standard `strtoull` semantics), and the existing "too large to size" guard
  rejects the request. Regression: 6 assertions added to
  `tools/hosttest/host_boot.c` (hosttest 974 → 980 passed).

### Images (rebuilt from the fixed source)

| Image | Note |
|---|---|
| `images/openwinkrnl_tirimid_qemu.bin` | 272,064 bytes (unchanged size) |
| `images/openwinkrnl_tirimid_floppy.flp` | rebuilt from `stage1.S` + seeded kernel |
| `images/openwinkrnl_tirimid_disk.img` | rebuilt from `stage1disk.S` + seeded kernel, 4 MB |
| `images/openwinkrnl_tirimid_disk.vdi` | same disk converted with `qemu-img` |

The unseeded production image `vbox/openwinkrnl.vdi` (git-ignored, not part of
this package) was rebuilt too and re-passed the 8-check `U+11A005` owinit gate.

### Captures

- `screenshots/01b-bootcomplete` (`.png`/`.txt`/`.vgabin`) was **recaptured**:
  the previously committed copy showed the shell banner/help, not the
  boot-complete log its caption claims. The other eight captures were
  re-generated from a fresh boot and compared bit-for-bit against the committed
  copies; all were identical, so the committed ones were kept.
- The boot-only transcripts (`02`/`03`/`05`) reproduce byte-for-byte apart from
  the SeaBIOS/iPXE pre-boot lines and `[ N.NNN]` timestamps, so the committed
  copies were retained.
- A fresh VirtualBox 7.2.16 boot of the rebuilt **seeded** VDI (a temp copy, so
  the packaged `.vdi` is untouched) reproduced the same serial transcript
  (`ow-krnl>`, `violations=0`, `[CIS] owinit: TRUSTED`, `user-hello`, no halt).
  `screenshots/09-vbox-boot.png` is retained unchanged: the guest screen is
  identical in the re-generated QEMU captures, and a VirtualBox PNG is not a raw
  `0xB8000` dump, so (as before) only its serial transcript is content-checked,
  not the PNG pixels.

### Validation for this audit

| Check | Result |
|---|---|
| `make CIS_DEV_TRUST=1 qemu` | PASS — 31 checks |
| `make CIS_DEV_TRUST=1 qemu-emergency` | PASS — 8 checks |
| `make CIS_DEV_TRUST=1 hosttest` | PASS — 980 passed, 0 failed |
| `make CIS_DEV_TRUST=1 owx-entries` | PASS — 13 targets, 0 failures |
| `make CIS_DEV_TRUST=1 vdi` (production, unseeded) | PASS — 8-check `U+11A005` owinit gate |
| VirtualBox 7.2.16 VDI boot | PASS |

`make hosttest-asan` still cannot build on this host (no ASAN runtime in
w64devkit); unchanged.

---

## 2026-10-15 — refresh for the testing-report fixes

Rebuilt every image and every capture against commit `a1961d5` plus the
uncommitted testing-report fixes.

### Images (all four rebuilt)

| Image | Note |
|---|---|
| `images/openwinkrnl_tirimid_qemu.bin` | 272,064 bytes (was 263,840) |
| `images/openwinkrnl_tirimid_floppy.flp` | rebuilt from `stage1.S` + seeded kernel |
| `images/openwinkrnl_tirimid_disk.img` | rebuilt from `stage1disk.S` + seeded kernel, 4 MB |
| `images/openwinkrnl_tirimid_disk.vdi` | same disk converted with `qemu-img` |

### Behaviour fixes exercised by this package

- `alloc <size>` works. The shell is Ring 0; it used to call the CPL3-only
  `OW_SYS_ALLOC` syscall and was rejected for every size. It now allocates kernel
  frames directly. A near-`UINT64_MAX` size is also refused up front instead of
  wrapping the page count to zero and reporting a bogus "frame allocator
  refused".
- `pwd` / `cd` / `ls [dir]` are present. `ls <dir>` honours its argument and
  reports a missing directory instead of silently listing the current one.
- `sucs commit` applies the staged SUCS mode with no reboot.
- `status` reports the managed kernel arena and the firmware RAM separately
  (it used to print a fixed "4096 pages").
- The VFS facade and the OWFS path are now one on-disk truth: a file written
  with `write` is visible to `fs read` / `fs list` (they used to be two
  divergent stacks).

### Build-enabling fixes now committed

The ISA-reserved-window skip in `core/memory.c` and the `.bss` zeroing in
`boot/stage1.S` / `boot/stage1disk.S` — previously local modifications required
for the disk/floppy images to boot at all — are committed in `a1961d5`.

### Validation for this refresh

| Check | Result |
|---|---|
| `make CIS_DEV_TRUST=1 qemu` | PASS — 31 checks (was 18) |
| `make CIS_DEV_TRUST=1 qemu-emergency` | PASS — 8 checks |
| `make CIS_DEV_TRUST=1 hosttest` | PASS — 974 passed, 0 failed (was 771) |
| `make CIS_DEV_TRUST=1 owx-entries` | PASS — 13 targets, 0 failures |
| `make CIS_DEV_TRUST=1 vdi` (production, unseeded) | PASS — 8-check `U+11A005` owinit gate |
| VirtualBox 7.2.16 VDI boot | PASS |

`make hosttest-asan` cannot build on this host (no ASAN runtime in w64devkit);
that is pre-existing and unchanged.

### Regenerated captures

All `screenshots/*` (`.png` + decoded `.txt` + raw `.vgabin`), all
`transcripts/*`, and the VirtualBox screenshot/transcript
(`VBoxManage controlvm screenshotpng`).

### Known limitation (unchanged)

The floppy, disk and VDI boots report
`Memory (firmware): unknown (no bootloader memory map)`. That is correct: only
the QEMU `-kernel` path enters through the multiboot protocol that supplies
`mem_upper`; `stage1.S` / `stage1disk.S` jump straight to the kernel.

---

## 2026-10-08 — original package (commit `06984b4`)

Initial package: four bootable images, five transcripts, ten screenshots.
`alloc` failed on every image; `pwd` / `cd` / `ls` / `sucs commit` did not exist.
