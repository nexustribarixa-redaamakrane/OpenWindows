#!/usr/bin/env python3
# owx_pack.py - Wrap a freestanding kernel PE/COFF image into an OpenWindows .owx container.
# Produces OWX1 binaries per the authoritative owx_format.h schema (Extensions/owx_format.h).
#
# Usage:
#   python tools/owx_pack.py <kernel.pe> <out.owx> [--subsystem 0x01] [--flags 0x09]
#
# Input is a PE32+ image (gcc -nostdlib freestanding link). Content-bearing sections
# (.text/.data/.rdata/...) are emitted as .code/.data OWX sections; .bss becomes a
# zero-fill section with no file payload (the loader zeros it). All CRC32c checksums
# are computed and written into the header.

import sys
import os
import struct
import hashlib

OWX_MAGIC             = 0x3158574F   # "OWX1" as little-endian u32 (on-disk bytes spell OWX1)
OWX_HEADER_SIZE       = 256
OWX_FORMAT_VERSION    = 0x0001

OWX_SUBSYSTEM_NATIVE  = 0x01
OWX_SECTION_CODE      = 0x01
OWX_SECTION_RDATA     = 0x02
OWX_SECTION_DATA      = 0x03
OWX_SECTION_BSS       = 0x04
OWX_FLAG_PRIVILEGED   = 0x00000001
OWX_FLAG_SUPERUNICODE = 0x00000008

SECTION_ENTRY_SIZE    = 40   # owx_section_entry_t: I I Q Q Q I I
ALIGN                 = 4096

IMAGE_SCN_CNT_CODE    = 0x00000020
IMAGE_SCN_CNT_INITIALIZED = 0x00000040
IMAGE_SCN_CNT_UNINIT   = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_EXECUTE  = 0x20000000
IMAGE_SCN_MEM_READ     = 0x40000000
IMAGE_SCN_MEM_WRITE    = 0x80000000

# ---------------------------------------------------------------------------
# CRC32c (Castagnoli)
# ---------------------------------------------------------------------------
CRC32C_POLY = 0x82F63B78
_crc_table = None


def _build_crc_table():
    global _crc_table
    table = []
    for i in range(256):
        crc = i
        for _ in range(8):
            crc = (crc >> 1) ^ (CRC32C_POLY if (crc & 1) else 0)
        table.append(crc & 0xFFFFFFFF)
    _crc_table = table


def crc32c(data, seed=0xFFFFFFFF):
    if _crc_table is None:
        _build_crc_table()
    crc = seed
    for b in data:
        crc = _crc_table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def compute_fletcher64(data):
    sum1 = 0
    sum2 = 0
    i = 0
    length = len(data)
    while length >= 4:
        word = data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)
        sum1 = (sum1 + word) % 0xFFFFFFFF
        sum2 = (sum2 + sum1) % 0xFFFFFFFF
        i += 4
        length -= 4
    if length > 0:
        word = 0
        for k in range(length):
            word |= data[i + k] << (8 * k)
        sum1 = (sum1 + word) % 0xFFFFFFFF
        sum2 = (sum2 + sum1) % 0xFFFFFFFF
    return ((sum2 << 32) | sum1) & 0xFFFFFFFFFFFFFFFF


class Section:
    def __init__(self, name, vaddr, raw_ptr, raw_size, vsize, flags):
        self.name = name
        self.vaddr = vaddr
        self.raw_ptr = raw_ptr
        self.raw_size = raw_size
        self.vsize = vsize
        self.flags = flags


def parse_pe(data):
    """Parse PE32+; return (image_base, entry_rva, [Section...], import_count)."""
    if data[:2] != b'MZ':
        return None
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b'PE\x00\x00':
        return None
    coff = pe_off + 4
    num_sections = struct.unpack_from('<H', data, coff + 2)[0]
    size_of_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    opt_magic = struct.unpack_from('<H', data, opt)[0]
    if opt_magic != 0x20B:  # PE32+
        return None
    image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    entry_rva = struct.unpack_from('<I', data, opt + 16)[0]
    sec_tbl = coff + 20 + size_of_opt

    sections = []
    for i in range(num_sections):
        off = sec_tbl + i * 40
        name = data[off:off + 8].rstrip(b'\x00').decode('ascii', 'replace')
        vsize = struct.unpack_from('<I', data, off + 8)[0]
        vaddr = struct.unpack_from('<I', data, off + 12)[0]
        raw_size = struct.unpack_from('<I', data, off + 16)[0]
        raw_ptr = struct.unpack_from('<I', data, off + 20)[0]
        flags = struct.unpack_from('<I', data, off + 36)[0]
        sections.append(Section(name, vaddr, raw_ptr, raw_size, vsize, flags))

    # Data directory 1 is the import table.  Its presence and the number of
    # descriptors both matter: an image that imports anything cannot be packed
    # honestly into OWX1, which has nowhere to record a symbol name.
    num_dd = struct.unpack_from('<I', data, opt + 108)[0]
    import_count = 0
    if num_dd > 1:
        imp_rva, imp_size = struct.unpack_from('<II', data, opt + 112 + 8)
        if imp_rva and imp_size:
            import_count = _count_import_descriptors(data, imp_rva, sections)
    return image_base, entry_rva, sections, import_count


def _rva_to_offset(rva, sections):
    for sec in sections:
        span = max(sec.vsize, sec.raw_size)
        if sec.vaddr <= rva < sec.vaddr + span:
            return sec.raw_ptr + (rva - sec.vaddr)
    return None


def _count_import_descriptors(data, imp_rva, sections):
    """Count import descriptors (each 20 bytes) up to the null terminator."""
    off = _rva_to_offset(imp_rva, sections)
    if off is None:
        return 0
    count = 0
    while off + 20 <= len(data):
        ilt, ts, fc, name_rva, iat = struct.unpack_from('<IIIII', data, off)
        if ilt == 0 and name_rva == 0 and iat == 0:
            break
        count += 1
        off += 20
    return count


def section_owx_type(sec):
    if sec.flags & IMAGE_SCN_CNT_CODE:
        return OWX_SECTION_CODE
    if sec.flags & IMAGE_SCN_CNT_UNINIT:
        return OWX_SECTION_BSS
    if sec.flags & IMAGE_SCN_MEM_WRITE:
        return OWX_SECTION_DATA
    return OWX_SECTION_RDATA


def protection_flags(sec):
    f = 0
    if sec.flags & IMAGE_SCN_MEM_READ:
        f |= 0x00000020
    if sec.flags & IMAGE_SCN_MEM_WRITE:
        f |= 0x00000010
    if sec.flags & IMAGE_SCN_MEM_EXECUTE:
        f |= 0x40000000
    return f


def build_header(base, entry_off, image_size, subsystem, flags, sec_count,
                 import_count=0):
    hdr = bytearray(OWX_HEADER_SIZE)

    def h8(off, v):
        hdr[off] = v & 0xFF

    def h32(off, v):
        struct.pack_into('<I', hdr, off, v & 0xFFFFFFFF)

    def h64(off, v):
        struct.pack_into('<Q', hdr, off, v & 0xFFFFFFFFFFFFFFFF)

    h32(0x00, OWX_MAGIC)
    h32(0x04, (OWX_HEADER_SIZE << 16) | OWX_FORMAT_VERSION)
    h32(0x08, image_size)
    h32(0x0C, 0)              # header_checksum placeholder
    h64(0x10, base + entry_off)
    h64(0x18, base)
    h64(0x20, 0x100000)       # stack_reserve
    h64(0x28, 0x10000)        # stack_commit
    h64(0x30, 0x400000)       # heap_reserve (fixed pool)
    h64(0x38, 0x10000)        # heap_commit
    h32(0x40, sec_count)
    h32(0x44, import_count)    # reported truthfully; OWX1 has no import table
    h32(0x48, 0)              # string_table_size
    h8(0x4C, subsystem)
    h8(0x4D, 3)               # target_arch = x86-64
    h8(0x4E, 0)               # target_subarch
    h8(0x4F, 12)              # alignment_log2 (4 KiB)
    h32(0x50, flags)
    h32(0x54, 0)              # tls_index
    h64(0x58, 0)              # timestamp
    h32(0x60, OWX_HEADER_SIZE)  # section_table_offset
    h32(0x64, 0)
    h32(0x68, 0)
    h32(0x6C, 0)
    h32(0x70, 0)
    h32(0x74, 0)
    h32(0x78, 0)
    h32(0x7C, 0)
    h32(0x80, 0)              # sentinel_bancode
    h32(0x84, 0)              # sentinel_trap_slot
    h64(0x88, 0)              # sentinel_recovery_ep
    h32(0x90, 0)              # image_checksum placeholder
    # 0x94..0xFF remain zero (padding[27])

    return bytes(hdr)


def main():
    args = sys.argv[1:]
    if len(args) < 2:
        print('usage: owx_pack.py <kernel.pe> <out.owx> '
              '[--subsystem 0x01] [--flags 0x09] [--sign-dev]')
        sys.exit(2)

    in_path, out_path = args[0], args[1]
    subsystem = OWX_SUBSYSTEM_NATIVE
    flags = OWX_FLAG_PRIVILEGED | OWX_FLAG_SUPERUNICODE
    sign_dev = False
    cis_licence = 'MIT'
    cis_copyright = '(c) OpenWindows'
    cis_policy_class = None
    cis_source_digest = None

    i = 2
    while i < len(args):
        if args[i] == '--subsystem' and i + 1 < len(args):
            subsystem = int(args[i + 1], 0)
        elif args[i] == '--flags' and i + 1 < len(args):
            flags = int(args[i + 1], 0)
        elif args[i] == '--sign-dev':
            # Append a CICB signed with the development image key from
            # tools/cis_block.py.  The seed is public and fixed; what makes this
            # safe is that a build only accepts this key when it was configured
            # with CIS_DEV_TRUST, so a default build refuses the result.
            sign_dev = True
            i += 1
            continue
        elif args[i] == '--cis-licence' and i + 1 < len(args):
            cis_licence = args[i + 1]
        elif args[i] == '--cis-copyright' and i + 1 < len(args):
            cis_copyright = args[i + 1]
        elif args[i] == '--policy-class' and i + 1 < len(args):
            cis_policy_class = args[i + 1]
            if cis_policy_class == 'CORE_KERNEL' and cis_licence == 'MIT':
                cis_licence = 'GPL-3.0-or-later'
        elif args[i] == '--source-digest' and i + 1 < len(args):
            val = args[i + 1]
            if os.path.isfile(val):
                with open(val, 'r', encoding='utf-8') as sf:
                    cis_source_digest = sf.read().strip()
            else:
                cis_source_digest = val
        elif args[i] == '--manifest' and i + 1 < len(args):
            with open(args[i + 1], 'rb') as mf:
                cis_source_digest = hashlib.sha256(mf.read()).hexdigest()
        i += 2

    with open(in_path, 'rb') as f:
        pe = f.read()

    info = parse_pe(pe)
    if info is None:
        print(f'error: {in_path} is not a PE32+ image')
        sys.exit(1)
    image_base, entry_rva, sections, import_count = info

    # An image that imports symbols cannot be represented in OWX1: the 256-byte
    # header has no import entry structure, the section table has no import
    # type, and there is no relocation pass.  Its IAT slots hold RVAs into its
    # own hint/name table, which a uniform load bias cannot turn back into
    # callable addresses.
    #
    # Refusing here is deliberate.  The previous behaviour wrote import_count=0
    # regardless and packed .idata as plain RDATA, which produced an image that
    # claimed to be self-contained, loaded without complaint, and then faulted
    # at CPL3 the first time it called an imported function.  A build-time error
    # names the actual problem; a CPL3 page fault does not.
    if import_count:
        print(f'error: {in_path} imports {import_count} symbol descriptor(s); '
              'OWX1 cannot represent imports.')
        print('       Resolve them at link time (static binding) or implement the '
              '.owd dynamic linker')
        print('       (OpenWindows-Essentials/Extensions/owd_format.h: symbol table, '
              'relocations, dependencies).')
        sys.exit(1)

    # OWX content sections come from PE sections that carry file bytes or are BSS.
    content_parts = []      # (file_bytes) in file order
    owx_sections = []       # (type, flags, file_offset, virtual_addr, size, checksum)

    dedup = set()
    for sec in sections:
        if sec.name in dedup:
            continue
        dedup.add(sec.name)
        if sec.name.startswith('.debug'):
            continue

        is_uninit = bool(sec.flags & IMAGE_SCN_CNT_UNINIT)
        discardable = bool(sec.flags & IMAGE_SCN_MEM_DISCARDABLE)
        if is_uninit:
            owx_sections.append((section_owx_type(sec), protection_flags(sec),
                                 0, image_base + sec.vaddr, sec.vsize, 0))
        elif sec.raw_size > 0 and not discardable:
            payload = pe[sec.raw_ptr:sec.raw_ptr + sec.raw_size]
            owx_sections.append((section_owx_type(sec), protection_flags(sec),
                                 0, image_base + sec.vaddr, len(payload), 0))
            content_parts.append(payload)

    # Layout: header + section table, then contiguous payload (all content).
    n = len(owx_sections)
    table_off = OWX_HEADER_SIZE
    table_size = n * SECTION_ENTRY_SIZE
    payload_off = table_off + table_size
    payload_aligned = (payload_off + ALIGN - 1) & ~(ALIGN - 1)

    blob = bytearray(payload_aligned)
    cursor = payload_aligned
    content_idx = 0
    for idx in range(n):
        st, sflags, _, svaddr, ssize, _ = owx_sections[idx]
        if st == OWX_SECTION_BSS:
            owx_sections[idx] = (st, sflags, payload_aligned, svaddr, ssize, 0)
            continue
        pay = content_parts[content_idx]
        content_idx += 1
        blob += pay
        sfile = cursor
        cursor += len(pay)
        owx_sections[idx] = (st, sflags, sfile, svaddr, len(pay), crc32c(pay))

    file_end = (cursor + ALIGN - 1) & ~(ALIGN - 1)
    if len(blob) < file_end:
        blob.extend(b'\x00' * (file_end - len(blob)))
    blob = blob[:file_end]
    image_size = file_end

    # Build section table
    table = bytearray()
    for st, sflags, sfile, svaddr, ssize, scrc in owx_sections:
        table += struct.pack('<IIQQQII', st, sflags, sfile, svaddr, ssize, scrc, 0)
    blob[table_off:table_off + table_size] = bytes(table)

    header = build_header(image_base, entry_rva, image_size, subsystem, flags, n,
                          import_count)
    blob[0:OWX_HEADER_SIZE] = header

    image_checksum = crc32c(bytes(blob[0x10:]))           # image_checksum field is 0 here
    struct.pack_into('<I', blob, 0x90, image_checksum)
    header_checksum = crc32c(bytes(blob[0x10:0x100]))     # as stored (incl. image_checksum)
    struct.pack_into('<I', blob, 0x0C, header_checksum)

    # ---- CIS block ---------------------------------------------------------
    #
    # Appended *after* the OWX image is final and after both CRC32c fields are
    # computed.  The header's image_size stays at the OWX image length, which is
    # exactly the range the CIS digest covers and exactly the range the loader
    # maps; the block occupies [image_size, file_size).  Those are two different
    # lengths on purpose and conflating them is the bug this comment exists to
    # prevent -- see inc/ow_cis_format.h on ImageSize vs FileSize.
    #
    # The CRC32c fields must not cover the block: they are the OWX structural
    # checksums and the loader validates them over the image, and a trailer
    # folded into image_checksum would make the OWX checksum depend on the
    # signature over the OWX.
    cis_block_bytes = b''
    if sign_dev:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import cis_block

        cis_block_bytes = cis_block.build_signed_block(
            cis_block.DEV_IMAGE_SEED, bytes(blob), cis_licence, cis_copyright,
            declared_image_size=image_size, policy_class=cis_policy_class,
            source_digest=cis_source_digest)

    artifact = bytes(blob) + cis_block_bytes

    with open(out_path, 'wb') as f:
        f.write(artifact)

    # Generate openwinkrnl.chk plaintext checksum file containing SHA-256 hex
    #
    # Over the whole artifact as written, block included.  A .chk names a file on
    # disk, and the file on disk is image||block; hashing only the image would
    # leave two different OWX files with one checksum, which is the ambiguity the
    # chk-to-one-image rule below was written to remove.
    file_bytes = artifact
    file_len = len(file_bytes)
    file_crc = crc32c(file_bytes)
    sha256_hex = hashlib.sha256(file_bytes).hexdigest()

    chk_text = f"{sha256_hex}\n"
    chk_path = os.path.splitext(out_path)[0] + '.chk'
    with open(chk_path, 'w', encoding='utf-8') as f:
        f.write(chk_text)

    # The checksum must always describe the image packed immediately above it,
    # and it is written next to that image (chk_path).  Nothing else belongs
    # here.
    #
    # A previous version additionally overwrote a hardcoded 'openwinkrnl.chk'
    # in the working directory with the hash of whatever image it had just
    # packed.  For the kernel that was a redundant no-op copy, but for every
    # other target it was destructive: packing owinit (which embed_owx.py
    # does for boot/owinit_image.h) replaced the kernel's checksum file with
    # owinit's hash.  The sentinel then compared openwinkrnl.owx against a
    # checksum describing a different binary, decided the kernel was corrupted,
    # raised BanHammer, and froze the cores -- a build-ordering accident that
    # presented as a kernel integrity failure.  One checksum per image, named
    # after that image, is the whole contract.

    print('OWX packaged:')
    print(f'  input   : {in_path}')
    print(f'  output  : {out_path} ({len(artifact)} bytes)')
    print(f'  chk     : {chk_path} ({len(chk_text)} bytes)')
    print(f'  base    : 0x{image_base:X}  entry : 0x{image_base + entry_rva:X} '
          f'(rva 0x{entry_rva:X})')
    print(f'  subsys  : 0x{subsystem:X}  flags : 0x{flags:X}')
    print(f'  image   : {image_size} bytes (OWX image_size; the loader maps and '
          f'CIS authenticates exactly this much)')
    if cis_block_bytes:
        print(f'  cis     : {len(cis_block_bytes)} bytes signed block, '
              f'key id {cis_block.dev_key_id().hex()} (dev image key)')
    else:
        print('  cis     : none (this image will be refused by a CIS-gated '
              'loader)')
    print(f'  sections:')
    for st, sflags, sfile, svaddr, ssize, scrc in owx_sections:
        print(f'    type=0x{st:X} flags=0x{sflags:08X} off=0x{sfile:X} '
              f'vaddr=0x{svaddr:X} size=0x{ssize:X} crc=0x{scrc:08X}')
    hdr_crc = struct.unpack_from('<I', blob, 0x0C)[0]
    img_crc = struct.unpack_from('<I', blob, 0x90)[0]
    print(f'  hdr_crc : 0x{hdr_crc:08X}  img_crc : 0x{img_crc:08X}  (validated)')
    print(f'  file_crc: 0x{file_crc:08X}  sha256  : {sha256_hex[:16]}... (checksum verified)')


if __name__ == '__main__':
    main()