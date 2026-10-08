# OpenWindows — Tirimid developer / test package

Bootable test images, boot transcripts and VGA screenshots of OpenWindows,
built and exercised on a Windows host with QEMU 11.1.0.

This is a **developer test package**, not a production release: every image here
is signed with the public development key (`CIS_DEV_TRUST=1`). Read
[`TESTER_NOTES.md`](TESTER_NOTES.md) before drawing conclusions from anything in
this directory.

---

## 1. Contents

| Path | What it is |
|---|---|
| `images/openwinkrnl_tirimid_qemu.bin` | Flat kernel image, 257 KB, loaded with QEMU `-kernel` (no boot sector) |
| `images/openwinkrnl_tirimid_floppy.flp` | 1.44 MB boot floppy (`stage1.S` + kernel), QEMU `-fda -boot a` |
| `images/openwinkrnl_tirimid_disk.img` | 4 MB raw IDE disk (`stage1disk.S` LBA loader + kernel), QEMU `-drive -boot c` |
| `images/openwinkrnl_tirimid_disk.vdi` | Same 4 MB disk converted to VirtualBox VDI format — **not validated, see notes** |
| `transcripts/` | Full serial-console transcripts of the boot / capture sessions |
| `screenshots/*.png` | 9 VGA screenshots (PPM → PNG), 720×400 stdvga text mode |
| `screenshots/*.txt` | The same screens decoded from the raw 80×25 text buffer (`0xB8000`) |
| `screenshots/*.vgabin` | Raw 4000-byte VGA text dumps — the source the `.txt` files are decoded from |
| `MANIFEST.sha256` | SHA-256 of every file above |
| `PROVENANCE.txt` | Source commit, dirty-file list and build commands |

SHA-256 of every file is in `MANIFEST.sha256`; verify with:

```
certutil -hashfile MANIFEST.sha256 SHA256      # or
Get-FileHash <file> -Algorithm SHA256
```

---

## 2. Booting the images

Host command used throughout (QEMU 11.1.0):

```
"C:\Program Files\qemu\qemu-system-x86_64.exe"
```

### 2.1 Kernel image only (fastest, recommended first run)

```
& "C:\Program Files\qemu\qemu-system-x86_64.exe" `
    -m 512M -smp 1 -kernel openwinkrnl_tirimid_qemu.bin `
    -serial mon:stdio -no-reboot -no-shutdown
```

### 2.2 Boot floppy

```
& "C:\Program Files\qemu\qemu-system-x86_64.exe" `
    -m 512M -smp 1 -fda openwinkrnl_tirimid_floppy.flp -boot a `
    -serial mon:stdio -no-reboot -no-shutdown
```

### 2.3 Boot disk (raw IDE)

```
& "C:\Program Files\qemu\qemu-system-x86_64.exe" `
    -m 512M -smp 1 -drive file=openwinkrnl_tirimid_disk.img,format=raw,if=ide,index=0,media=disk `
    -boot c -serial mon:stdio -no-reboot -no-shutdown
```

`-serial mon:stdio` multiplexes the serial console and the QEMU monitor onto
this terminal while a window still shows the VGA screen. Press **Ctrl-A C** to
switch to the QEMU monitor and **Ctrl-a x** to quit QEMU.

Expected: the `O P E N W I N D O W S` boot-monitor banner, an auto-init script
that prints the phase list, then the `ow-krnl>` shell prompt. Boot to prompt is
roughly **2–3 seconds** wall clock (the on-screen/log timestamps are not
wall-clock — see `TESTER_NOTES.md` §4.2).

### 2.4 Headless / scripted (no window)

Replace `-serial mon:stdio` with a TCP serial chardev, which is what
`tools/tirimid_capture.ps1` does:

```
-chardev socket,id=com0,port=13031,host=127.0.0.1,server=on,wait=on,ipv4=on `
-serial chardev:com0 `
-monitor tcp:127.0.0.1:13032,server=on,wait=off
```

Connect the serial client **first** (`wait=on` blocks QEMU initialisation).

### 2.5 VirtualBox — **validated**

VirtualBox 7.2.16 was used to boot `openwinkrnl_tirimid_disk.vdi`. `VBoxManage`
is **not on `PATH`** on this host; use the full path
`C:\Program Files\Oracle\VirtualBox\VBoxManage.exe`.

```
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name OpenWindows-Tirimid --ostype Other --register
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm OpenWindows-Tirimid `
    --memory 512 --cpus 1 --ioapic on --acpi on --boot1 disk `
    --uart1 0x3F8 4 --uartmode1 file "C:\path\to\owx_serial.log"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl OpenWindows-Tirimid --name SATA --add sata --controller IntelAhci
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach OpenWindows-Tirimid `
    --storagectl SATA --port 0 --device 0 --type hdd --medium openwinkrnl_tirimid_disk.vdi
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm OpenWindows-Tirimid --type headless
```

Result (`transcripts/05_virtualbox_boot.txt`): full auto-init, `violations=0`,
`[CIS] owinit: TRUSTED`, `user-hello` PID 2, `[FS] list root: OK`, `ow-krnl>`
prompt, no fatal/halt markers. Screenshot:
`screenshots/09-vbox-boot.png` (720×400, taken with
`VBoxManage controlvm <vm> screenshotpng <file>`).

Note the ACPI firmware is reported as `OEM 'VBOX  '` — the ACPI path is
exercised against real VirtualBox tables, not QEMU's.

---

## 3. Reproducing the screenshots

```
pwsh -ExecutionPolicy Bypass -File tools\tirimid_capture.ps1 `
    -Image artifacts\tirimid\images\openwinkrnl_tirimid_disk.img -Media disk `
    -OutDir <outdir>
python tools\ppm2png.py --dir <outdir>
python tools\vgatext.py <outdir>\<name>.vgabin -o <outdir>\<name>.txt
```

`tirimid_capture.ps1` boots one QEMU instance, drives the shell over serial and
issues `stop` → `screendump` → `pmemsave 0xb8000 4000` → `cont` as a single
monitor write, so each capture freezes the framebuffer at the instant it starts
(the boot log scrolls off the 19-line log area in about two seconds).

Windows paths are sent to the monitor with **forward slashes**: the QEMU monitor
treats a backslash as a string escape.

### Screenshot index

| File | Guest state captured |
|---|---|
| `01-boot` | Boot-monitor banner, HUD `BOOT [......] 0%` — before the kernel log starts |
| `01b-bootcomplete` | End of the boot log (`kernel boot complete`, scheduler start, `user-hello: process created (PID 2)`), HUD `100%` |
| `02-shell` | Auto-init script finished, `ow-krnl>` prompt |
| `03-help` | Output of `help` |
| `04-runlevel` | Output of `runlevel features` |
| `05-fs` | Output of `fs list` |
| `06-sucs` | Output of `sucs` |
| `07-alloc` | Output of `alloc 4096` — **known failure**, see notes |
| `08-poweroff` | `You can safely power off your device now.` after `safeoff on` + `exit` |
| `09-vbox-boot` | Same disk image booted under **VirtualBox** 7.2.16 (`controlvm screenshotpng`) |

The `.txt` next to each PNG is decoded from the raw `0xB8000` dump, so the text
can be checked independently of the PNG render.

---

## 4. Provenance

Source commit: see `PROVENANCE.txt` (generated with this package).

Three files differ from the committed tree and are required for the disk/floppy
images to boot at all:

| File | Change |
|---|---|
| `core/memory.c` | Skip the ISA reserved window (`0x00000–0x0FFFF`, `0xA0000–0xFFFFF`) when bump-allocating from the physical-RAM pool |
| `boot/stage1.S` | Zero `.bss` from the multiboot header's `_end_of_file` / `_end_of_bss` fields |
| `boot/stage1disk.S` | Same `.bss` zeroing for the disk loader |

Build commands:

```
make CIS_DEV_TRUST=1 qemu          # flat image -> openwinkrnl_tirimid_qemu.bin
make CIS_DEV_TRUST=1 vbox-image    # 1.44 MB floppy -> openwinkrnl_tirimid_floppy.flp
make CIS_DEV_TRUST=1 owx-entries   # OWX entry audit (13 targets, 0 failures)
```

The packaged **disk** image is built from the *seeded* floppy kernel, not from
`make vdi`:

```
nasm -f bin boot\stage1disk.S -o stage1disk.bin
python tools\mkboot.py stage1disk.bin <openwinkrnl_vbox.bin> openwinkrnl_tirimid_disk.img 4194304
qemu-img convert -f raw -O vdi openwinkrnl_tirimid_disk.img openwinkrnl_tirimid_disk.vdi
```

This matters: the Makefile's own `vdi` target links `$(VBOX_DISK_KERNEL)`
without `$(TEST_SEED_OBJS)`, so `make CIS_DEV_TRUST=1 vdi` produces a
**different, unseeded** disk image with no `owinit` payload. That image was not
built or validated here.

---

## 5. Validation performed

| Check | Result |
|---|---|
| `make CIS_DEV_TRUST=1 qemu` | PASS — 18 checks, including ACPI S5 shutdown and the safe-power-off screen |
| `make CIS_DEV_TRUST=1 owx-entries` | PASS — 13 targets, 0 failures |
| Floppy boot (`-fda -boot a`) | PASS — `ow-krnl>` prompt, `violations=0`, `user-hello` PID 2 |
| Disk boot (`-drive -boot c`) | PASS — `ow-krnl>` prompt, `violations=0`, `user-hello` PID 2 |
| **VirtualBox 7.2.16 VDI boot** | **PASS** — `ow-krnl>` prompt, `violations=0`, `[CIS] owinit: TRUSTED`, ACPI `OEM 'VBOX  '` |
| Screenshot content (all 10) | PASS — each `.txt` matches the state it is captioned as |

Re-run the reference validation yourself with `make CIS_DEV_TRUST=1 qemu`.
