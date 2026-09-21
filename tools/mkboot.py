#!/usr/bin/env python3
"""mkboot.py - pack stage1 boot sector + flat kernel into a bootable image.

Usage:
    python tools/mkboot.py <stage1.bin> <kernel.bin> <output.img> [size_bytes]

Patches the boot sector's `nsec` word (total sectors, incl. boot sector)
using the magic marker 'NSNS' placed by the assembler, then writes the
boot sector, the kernel sectors, and zero padding. Default size is a
1.44MB floppy; pass a larger size_bytes (e.g. 4194304) to produce a raw
hard-disk image that can be converted to VDI with qemu-img.
"""
import io
import math
import re
import struct
import sys

FLOPPY_BYTES = 1474560          # 1.44MB floppy
FLOPPY_SECTORS = FLOPPY_BYTES // 512
SIGNATURE_OFFSET = 0x1FE
BOOT_SIGNATURE = b"\x55\xAA"

MAGIC = b"NSNS"


def build(stage1: bytes, kernel: bytes, size_bytes: int = FLOPPY_BYTES) -> bytes:
    boot = bytearray(stage1)
    if len(boot) < 512:
        boot += b"\x00" * (512 - len(boot))
    if len(boot) != 512:
        raise SystemExit("stage1.bin must fit in one 512-byte sector")

    magic = boot.find(MAGIC)
    if magic < 0 or magic + 6 > len(boot):
        raise SystemExit("stage1.bin missing the NSNS nsec magic marker")
    nsec = 1 + math.ceil(len(kernel) / 512)
    total_sectors = size_bytes // 512
    if nsec > total_sectors:
        raise SystemExit(f"kernel too large: {nsec} sectors > {total_sectors}")
    boot[magic + 4:magic + 6] = struct.pack("<H", nsec)

    if boot[SIGNATURE_OFFSET:SIGNATURE_OFFSET + 2] != BOOT_SIGNATURE:
        raise SystemExit("stage1.bin missing 0x55AA boot signature")

    padding = size_bytes - len(boot) - len(kernel)
    if padding < 0:
        raise SystemExit("output size smaller than boot sector + kernel")
    img = io.BytesIO()
    img.write(boot)
    img.write(kernel)
    img.write(b"\x00" * padding)
    return img.getvalue()


def main(argv):
    if len(argv) not in (4, 5):
        print(__doc__)
        return 2
    if len(argv) == 5:
        _, stage1_path, kernel_path, out_path, size_path = argv
        size_bytes = int(size_path)
    else:
        _, stage1_path, kernel_path, out_path = argv
        size_bytes = FLOPPY_BYTES
    with open(stage1_path, "rb") as f:
        stage1 = f.read()
    with open(kernel_path, "rb") as f:
        kernel = f.read()
    out = build(stage1, kernel, size_bytes)
    with open(out_path, "wb") as f:
        f.write(out)
    print(f"{out_path}: {len(out)} bytes, {len(out)//512} sectors, "
          f"kernel {len(kernel)} bytes ({math.ceil(len(kernel)/512)} sectors)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))