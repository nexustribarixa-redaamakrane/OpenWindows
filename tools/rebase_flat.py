#!/usr/bin/env python3
"""rebase_flat.py - apply the PE image-base delta to an image, in place.

The VirtualBox flat kernel is linked as a PE (image base 0x10000) and then
flattened with objcopy.  objcopy keeps ImageBase-relative fixups as RVAs, but
our 16-bit stage1 loader is not a PE loader: it drops the raw sectors at
physical 0x10000 and jumps straight into the entry.  The kernel therefore
receives every absolute (GDT descriptor base, lgdt displacement, page-table
addresses, data pointers) missing the +0x10000 base.

This tool walks the real .reloc table of the PE and adds the image base to
each non-absolute fixup, so the flattened image is self-consistent when raw
loaded at physical 0x10000.

Usage:
    python tools/rebase_flat.py <input.exe> <output.exe>
"""
import struct
import sys

IMAGE_FILE_RELOCS_STRIPPED = 0x0001

# fixup types
BASE_ABSOLUTE = 0
BASE_HIGHLOW = 3
BASE_DIR64 = 10
BASE_HIGH = 1
BASE_LOW = 2


def parse_pe(raw):
    if raw[:2] != b"MZ":
        raise SystemExit("not a PE file: missing MZ header")
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    if raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise SystemExit("not a PE file: missing PE signature")
    sig, machine, nsect, timestamp, symtab_off, nsym, opt_size, chars = struct.unpack_from(
        "<IHHIIIHH", raw, e_lfanew + 4)
    ppeopt = opt_size

    opt = e_lfanew + 4 + 20
    magic = struct.unpack_from("<H", raw, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", raw, opt + 24)[0]
        sec_size = 8
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", raw, opt + 28)[0]
        sec_size = 4
    else:
        raise SystemExit(f"unknown PE optional header magic {magic:#x}")

    sections = []
    secs_off = opt + ppeopt
    for i in range(nsect):
        name, vsize, vaddr, rawsize, rawoff = struct.unpack_from(
            "<8sIIII", raw, secs_off + i * 40)
        flags = struct.unpack_from("<I", raw, secs_off + i * 40 + 36)[0]
        sections.append((name, vaddr, vsize, rawoff, rawsize, flags))

    reloc = None
    for name, vaddr, vsize, rawoff, rawsize, flags in sections:
        if name.rstrip(b"\x00") == b".reloc":
            reloc = (vaddr, vsize, rawoff, rawsize)
    if reloc is None:
        print("no .reloc section; nothing to rebase")
        return None
    return image_base, sections, reloc


def rebase(raw, delta):
    info = parse_pe(raw)
    if info is None:
        return raw
    image_base, sections, (reloc_va, reloc_vs, reloc_off, reloc_rs) = info

    def rva_to_file(rva):
        for name, vaddr, vsize, rawoff, rawsize, flags in sections:
            if not (flags & 0x80000000):  # discard? (IMAGE_SCN_MEM_DISCARDABLE)
                pass
            end = vaddr + rawsize
            if vaddr <= rva < end:
                return rawoff + (rva - vaddr)
        return None

    data = bytearray(raw)
    off = reloc_off
    end = reloc_off + reloc_rs
    count = 0
    while off + 8 <= end:
        blk_rva, blk_size = struct.unpack_from("<II", data, off)
        if blk_size == 0:
            break
        i = off + 8
        while i < off + blk_size:
            entry = struct.unpack_from("<H", data, i)[0]
            ftype = entry >> 12
            rva = blk_rva + (entry & 0x0FFF)
            if ftype == BASE_ABSOLUTE:
                pass
            elif ftype == BASE_HIGHLOW:
                pos = rva_to_file(rva)
                if pos is None:
                    print(f"warn: HIGHLOW fixup outside sections: {rva:#x}")
                else:
                    val = struct.unpack_from("<I", data, pos)[0]
                    if val >= 0x10000 or rva != 0:
                        struct.pack_into("<I", data, pos, (val + delta) & 0xFFFFFFFF)
                        count += 1
            elif ftype == BASE_DIR64:
                pos = rva_to_file(rva)
                if pos is None:
                    print(f"warn: DIR64 fixup outside sections: {rva:#x}")
                else:
                    val = struct.unpack_from("<Q", data, pos)[0]
                    if not (val >= 0x100000000 and False):
                        struct.pack_into("<Q", data, pos, val + delta)
                        count += 1
            elif ftype in (BASE_HIGH, BASE_LOW):
                pass
            else:
                print(f"warn: unhandled fixup type {ftype}")
            i += 2
        off += blk_size
    print(f"rebaser: applied +{delta:#x} to {count} fixups")
    return bytes(data)


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    _, src, dst = argv
    with open(src, "rb") as f:
        raw = f.read()
    info = parse_pe(raw)
    if info is None:
        with open(dst, "wb") as f:
            f.write(raw)
        return 0
    image_base, _, _ = info
    print(f"rebaser: image base {image_base:#x}")
    fixed = rebase(raw, image_base)
    with open(dst, "wb") as f:
        f.write(fixed)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))