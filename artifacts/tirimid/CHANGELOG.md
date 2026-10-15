# Tirimid test package — change log

All dates are 2026. Every file in this package is covered by
`MANIFEST.sha256`; regenerate the manifest after any change.

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
