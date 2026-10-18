#!/usr/bin/env python3
"""Audit the linked entry point of every OWX target the kernel can boot.

Two populations, two different questions, because they are built two different
ways:

  Essentials (13 targets, built by OpenWindows-Essentials/CMakeLists.txt)
      Every one of the thirteen now enters its own real function: owinit.owx
      enters owinit_main (pinned below), and the other twelve enter their
      *_main directly.  There is no longer a stubbed population here --
      ow_owx_props() requires an entry symbol and fails configuration if one is
      omitted, so no target can silently fall back to owx_entry_stub.  This
      compares the instruction bytes actually sitting at each PE's entry point
      anyway, because the artifacts in Artifacts/Software/ are what the kernel
      embeds and they are audited as shipped, not as built.

          owinit.owx        entry RVA 0x1000, owinit_main's prologue, import-free
          every other       a real entry, import-free, not the stub
          Essentials target

  Real-entry targets (all thirteen Essentials targets here; owinitv.owx and
  owrs.owx built by this repository's Makefile from emergency/)
      These are compiled so their prologues are the compiler's business and
      pinning five bytes of one would make the audit fail on a toolchain bump
      rather than on a real regression.  What has to hold for them is the four
      properties that would each break the launch outright:

          import-free       the loader binds nothing and REJECTS an image with
                            imports, so an import here is an unloadable program
                            discovered only at the moment it is launched
          not the stub      owx_entry_stub is `xor eax,%eax; ret`.  Entered as
                            PID 1 that is a one-instruction init that exits
                            immediately; spawned as a shell it is a shell that
                            never prints a prompt.  Both present as "the program
                            did nothing".
          executable entry  the entry RVA must sit in a section marked
                            IMAGE_SCN_MEM_EXECUTE (PE) or OWX_SECTION_CODE
                            (packed OWX1).  An entry that is file-backed but
                            lives in .data is a fault, not a program.
          the expected      entry RVA must equal section VA + value of the
          function          target's named *_main symbol, read from the COFF
                            symbol table.  A nonzero entry RVA proves only that
                            some bytes are there, not that the right function
                            is: a typo'd -e at link time leaves ld picking some
                            other start, and this is what notices.  The eight
                            targets are pinned by name in
                            EXPECTED_ENTRY_SYMBOLS -- never derived from the
                            image under audit.  Packed OWX1 images carry no
                            COFF table (the packer consumes the PE), so the
                            symbol rule applies to PE images only; owinit keeps
                            its own pinned-RVA rules below.

Run with --self-test to exercise the rule engine against synthetic images that
mimic the regressions it exists to catch (owinit silently reverted to the stub,
entry moved off owinit_main, a real-entry target left on the stub or grown an
import, an emergency image that grew an import, an emergency image left on the
stub, an entry selecting the wrong function, a missing or ambiguous expected
symbol, a symbol bound to a nonexistent section, an entry in a non-executable
section, a symbol whose value lies past its section, an auxiliary-record
overrun, an unresolvable string-table name, a packed image entered in a
non-code section, and a truncated PE driven through the real audit entry
path).  Each malformed case also asserts the REASON it was rejected, so a
check cannot stop firing and pass silently while another one happens to trip.
The self-test needs no artifacts and no mutation, so it is safe to run on
every build; it is the reason a signature that stopped matching cannot pass
quietly.
"""

import os
import struct
import sys

# owx_entry_stub: `xor eax,%eax ; ret`
STUB_SIG = bytes((0x31, 0xC0, 0xC3))
# owinit_main: `sub $0x28,%rsp` then a direct `call` to kconf64_init.
OWINIT_SIG = bytes((0x48, 0x83, 0xEC, 0x28, 0xE8))
OWINIT_ENTRY_RVA = 0x1000
OWINIT_BASENAME = "owinit.owx"

# The targets that enter their own real entry point and are built statically
# (import-free).  ow_owx_props() requires an entry_symbol for every .owx, so
# these are all of them bar owinit (which has its own pinned rules below).
# Checked by the properties that matter rather than by pinned bytes, because
# their prologue is the compiler's: see the module docstring.
REAL_ENTRY_TARGETS = ("owsh.owx", "kconfctl.owx", "banhammer_cli.owx",
                      "bancat.owx", "kextctl.owx", "owedit.owx", "owkill.owx",
                      "owwm.owx", "sfontview.owx", "startwm.owx",
                      "vipmount.owx", "win.owx")

# The entry function each of the eight formerly-stubbed targets must enter,
# by name and hardcoded: the expected symbol is the standard the image is held
# to, so it can never be inferred from the image itself (a wrong image would
# then pick its own answer).  Section VA + value must equal the PE entry RVA.
# The four protected PE targets (owsh/kconfctl/banhammer_cli/bancat) and the
# packed emergency pair are outside this mapping by scope; owinit has its own
# pinned rules in check_owinit().
EXPECTED_ENTRY_SYMBOLS = {
    "kextctl.owx":   "kextctl_main",
    "owedit.owx":    "owedit_main",
    "owkill.owx":    "owkill_main",
    "owwm.owx":      "owwm_main",
    "sfontview.owx": "sfontview_main",
    "startwm.owx":   "startwm_main",
    "vipmount.owx":  "vipmount_main",
    "win.owx":       "win_main",
}

# The emergency pair, built by this repository.  Checked by the rules in
# check_real_entry() rather than by a byte signature: see the module docstring.
EMERGENCY_TARGETS = ("owinitv.owx", "owrs.owx")

ALL_TARGETS = ((OWINIT_BASENAME,) + REAL_ENTRY_TARGETS + EMERGENCY_TARGETS)


class PeError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def parse_pe(data):
    """Return {entry_rva, image_base, sig, import_descriptors, entry_exec,
    symbols, sections} for a PE image.

    entry_exec  whether the section holding the entry RVA carries
                IMAGE_SCN_MEM_EXECUTE (0x20000000).
    symbols     {name: [(section_number, value), ...]} from the COFF symbol
                table -- a list per name so duplicate definitions stay visible
                as ambiguity -- or None when the image carries no symtab.
    sections    [(virtual_address, virtual_size, characteristics), ...] so the
                rule engine can resolve a symbol's section-relative value.
    """
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise PeError("not a PE image (no MZ)")
    pe = _u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise PeError("no PE signature")

    nsec = _u16(data, pe + 6)
    opt_size = _u16(data, pe + 20)
    opt = pe + 24
    magic = _u16(data, opt)
    plus = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        raise PeError("unrecognised optional header magic 0x%X" % magic)

    entry_rva = _u32(data, opt + 0x10)
    base = _u64(data, opt + 0x18) if plus else _u32(data, opt + 0x1C)
    dd = opt + (0x70 if plus else 0x60)
    imp_rva = _u32(data, dd + 8)
    imp_size = _u32(data, dd + 12)

    sec_off = opt + opt_size
    if sec_off + nsec * 40 > len(data):
        raise PeError("section table runs past end of file")
    secs = []
    for i in range(nsec):
        b = sec_off + i * 40
        vs = _u32(data, b + 8)
        va = _u32(data, b + 12)
        rs = _u32(data, b + 16)
        rp = _u32(data, b + 20)
        ch = _u32(data, b + 36)
        secs.append((va, max(vs, rs), rp, rs, ch))

    def to_file(rva):
        for va, span, rp, rs, ch in secs:
            if va <= rva < va + span:
                delta = rva - va
                if delta >= rs:
                    raise PeError("rva 0x%X is not file-backed" % rva)
                return rp + delta
        raise PeError("rva 0x%X lies in no section" % rva)

    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    entry_exec = any(va <= entry_rva < va + span and ch & IMAGE_SCN_MEM_EXECUTE
                     for va, span, rp, rs, ch in secs)

    off = to_file(entry_rva)
    if off + len(OWINIT_SIG) > len(data):
        raise PeError("entry bytes run past end of file")
    sig = data[off:off + len(OWINIT_SIG)]

    # Count non-null import descriptors the way the loader would.
    imports = 0
    if imp_rva and imp_size:
        io = to_file(imp_rva)
        while io + 20 <= len(data):
            desc = data[io:io + 20]
            if desc == b"\0" * 20:
                break
            imports += 1
            io += 20

    return {
        "entry_rva": entry_rva,
        "image_base": base,
        "sig": sig,
        "import_descriptors": imports,
        "entry_exec": entry_exec,
        "symbols": _parse_coff_symbols(data, pe),
        "sections": [(va, span, ch) for va, span, rp, rs, ch in secs],
    }


def _parse_coff_symbols(data, pe):
    """COFF symbol table -> {name: [(section_number, value), ...]}.

    File header fields: PointerToSymbolTable at pe+12, NumberOfSymbols at
    pe+16.  Each entry is 18 bytes; names longer than 8 bytes live in the
    string table that follows (first 4 bytes = its size), addressed as a zero
    dword plus a byte offset.  Auxiliary records are skipped via their count.
    Returns None when the image has no symbol table, and raises PeError when a
    declared table lies outside the file or its auxiliary records overrun the
    declared length (a corrupt table is an unreadable image, not an absent
    one).
    """
    sym_ptr = _u32(data, pe + 12)
    sym_count = _u32(data, pe + 16)
    if not sym_ptr or not sym_count:
        return None
    table_end = sym_ptr + sym_count * 18
    if table_end > len(data):
        raise PeError("COFF symbol table runs past end of file")

    strtab = table_end
    strtab_end = len(data)
    if strtab + 4 <= len(data):
        strtab_size = _u32(data, strtab)
        if strtab + strtab_size <= len(data) and strtab_size >= 4:
            strtab_end = strtab + strtab_size

    def long_name(soff):
        if soff < 4 or strtab + soff >= strtab_end:
            return None
        end = data.find(b"\0", strtab + soff, strtab_end)
        if end < 0:
            return None
        return data[strtab + soff:end].decode("ascii", "replace")

    symbols = {}
    i = 0
    while i < sym_count:
        off = sym_ptr + i * 18
        if off + 18 > table_end:
            raise PeError("COFF symbol record runs past end of table")
        raw = data[off:off + 8]
        if raw[:4] == b"\0\0\0\0":
            name = long_name(_u32(raw, 4))
        else:
            name = raw.split(b"\0", 1)[0].decode("ascii", "replace")
        value = _u32(data, off + 8)
        secnum = struct.unpack_from("<h", data, off + 12)[0]
        naux = data[off + 17]
        if name:
            symbols.setdefault(name, []).append((secnum, value))
        i += 1 + naux
        # NumberOfSymbols counts aux records too, so a walk that steps past it
        # means the aux counts and the declared length disagree.  The table's
        # layout is then unknowable: reading what remains would attribute the
        # entry to an image parsed from the wrong offsets, so reject.
        if i > sym_count:
            raise PeError("COFF auxiliary records overrun the symbol table")
    return symbols


def parse_owx(data):
    """Return the same shape parse_pe() does, for a packed OWX1 image.

    The emergency pair is audited in its PACKED form on purpose.  The packer
    deletes the PE it consumed, so auditing the PE would mean keeping a
    build intermediate around purely to be inspected -- and an audit of an
    intermediate is an audit of something the shipped artifact was derived from,
    not of the artifact.  OWX1 carries everything the checks need: entry_point,
    import_count, and a section table that maps the entry's virtual address back
    to file bytes.
    """
    if len(data) < 0x100 or data[0:4] != b"OWX1":
        raise PeError("not an OWX1 image")

    image_size = _u32(data, 0x08)
    entry_point = _u64(data, 0x10)
    image_base = _u64(data, 0x18)
    section_count = _u32(data, 0x40)
    import_count = _u32(data, 0x44)
    table_off = _u32(data, 0x60)

    if image_size > len(data):
        raise PeError("declared image_size 0x%X exceeds the %d byte file"
                      % (image_size, len(data)))
    if table_off + section_count * 32 > len(data):
        raise PeError("section table runs past end of file")

    entry_rva = entry_point - image_base
    if entry_rva < 0:
        raise PeError("entry point 0x%X is below the image base 0x%X"
                      % (entry_point, image_base))

    for i in range(section_count):
        b = table_off + i * 32
        s_va = _u64(data, b + 0x10)
        s_size = _u64(data, b + 0x18)
        s_off = _u64(data, b + 0x08)
        # BSS carries no file bytes: its "size" is a virtual extent and its
        # file_offset is a placeholder, so a range test against it is meaningless
        # (the loader makes the same exemption, and for the same reason).
        s_type = _u32(data, b)
        if s_type == 0x04:  # OWX_SECTION_BSS
            continue
        # Compared in the virtual-address domain: a section's virtual_addr is a
        # full VA (image_base + RVA) while entry_rva has already had the base
        # subtracted, so testing one against the other silently matches nothing.
        if s_va <= entry_point < s_va + s_size:
            delta = entry_point - s_va
            if s_off + delta + len(OWINIT_SIG) > len(data):
                raise PeError("entry bytes run past end of file")
            return {
                "entry_rva": entry_rva,
                "image_base": image_base,
                "sig": data[s_off + delta: s_off + delta + len(OWINIT_SIG)],
                "import_descriptors": import_count,
                # OWX_SECTION_CODE (0x01) is the packed image's equivalent of
                # IMAGE_SCN_MEM_EXECUTE; RDATA/DATA are the non-executable ones.
                "entry_exec": s_type == 0x01,
                # The packer consumes the PE it encoded, so a packed artifact
                # carries no COFF table by construction -- not "not yet read".
                "symbols": None,
                "sections": [],
            }
    raise PeError("entry va 0x%X lies in no file-backed section" % entry_point)


def read_image(path):
    """Parse either form.  OWX1 first: it is a magic check, and a PE can never
    match it, so the order costs nothing and keeps the packed artifacts on the
    same code path as the Essentials PEs."""
    with open(path, "rb") as fh:
        data = fh.read()
    if data[0:4] == b"OWX1":
        return parse_owx(data)
    return parse_pe(data)


def check(name, info):
    """Return a list of failure strings for one target (empty == pass)."""
    if name == OWINIT_BASENAME:
        return check_owinit(name, info)
    return check_real_entry(name, info)


def check_owinit(name, info):
    """owinit has one extra rule beyond the real-entry pair: it must enter at
    its pinned RVA on owinit_main's prologue, because it is the kernel's first
    CPL3 process and a silent move of its entry is a boot regression the
    import/stub checks alone would not see."""
    bad = []
    sig = info["sig"]
    hexsig = " ".join("%02X" % b for b in sig)

    if info["entry_rva"] != OWINIT_ENTRY_RVA:
        bad.append("entry RVA 0x%X, expected 0x%X (owinit_main)"
                   % (info["entry_rva"], OWINIT_ENTRY_RVA))
    if sig.startswith(STUB_SIG):
        bad.append("entry is owx_entry_stub (31 C0 C3) -- owinit was "
                   "reverted off owinit_main")
    elif not sig.startswith(OWINIT_SIG):
        bad.append("entry %s is not owinit_main's prologue "
                   "(48 83 EC 28 E8)" % hexsig)
    if info["import_descriptors"] != 0:
        bad.append("%d import descriptor(s); owinit must be statically "
                   "self-contained" % info["import_descriptors"])
    return bad


def check_real_entry(name, info):
    """The four properties without which a repointed program is a no-op or a
    fault: import-free, not the stub, entered in an executable section, and --
    for the eight targets pinned in EXPECTED_ENTRY_SYMBOLS -- actually the
    expected *_main function rather than merely *some* nonzero bytes.

    Deliberately not a prologue signature.  These targets are compiled so their
    first instructions are the toolchain's choice; pinning bytes would turn
    every compiler update into a failure that looks like a code defect.  What
    is worth asserting is what the loader and the launch policy actually depend
    on.
    """
    bad = []
    sig = info["sig"]

    if info["import_descriptors"] != 0:
        bad.append("%d import descriptor(s); the OWX1 loader binds nothing and "
                   "would REFUSE this image at the moment it is launched"
                   % info["import_descriptors"])
    if sig.startswith(STUB_SIG):
        bad.append("entry is owx_entry_stub (31 C0 C3) -- %s would return "
                   "immediately instead of running its real entry" % name)
    if info["entry_rva"] == 0:
        bad.append("entry RVA is 0; the loader rejects a zero entry point")
    if not info.get("entry_exec"):
        bad.append("entry RVA 0x%X is file-backed but sits in a "
                   "non-executable section -- entering it is a fault, not a "
                   "program" % info["entry_rva"])

    expected = EXPECTED_ENTRY_SYMBOLS.get(name)
    if expected is not None:
        bad.extend(check_expected_symbol(expected, info))
    return bad


def check_expected_symbol(expected, info):
    """Resolve EXPECTED_ENTRY_SYMBOLS[name] in the COFF table and require
    section VA + value == entry RVA.

    The symbol is a standard held against the image, never read out of it as
    the answer, so a wrong image cannot pick its own pass condition.  Each way
    the relationship can be unusable -- absent table, absent name, a name
    defined twice, a section number that names nothing (0 = undefined, <0 =
    absolute/debug, > section count), a value past its section, and finally a
    correct symbol sitting at a different RVA than the entry -- gets its own
    message so a self-test fixture can assert the reason it was rejected.
    """
    symbols = info.get("symbols")
    if not symbols or expected not in symbols:
        return ["expected symbol %s not found in the COFF symbol table -- the "
                "entry cannot be attributed to a known function" % expected]

    defs = symbols[expected]
    if len(defs) > 1:
        return ["expected symbol %s is ambiguous: %d definitions in the "
                "symbol table" % (expected, len(defs))]

    secnum, value = defs[0]
    nsec = len(info.get("sections") or ())
    if secnum < 1 or secnum > nsec:
        return ["expected symbol %s has invalid section number %d (no such "
                "section); its address is unresolvable"
                % (expected, secnum)]

    sec_va, sec_span, sec_ch = info["sections"][secnum - 1]
    if value >= sec_span:
        return ["expected symbol %s value 0x%X lies outside its section "
                "(span 0x%X)" % (expected, value, sec_span)]

    sym_rva = sec_va + value
    if sym_rva != info["entry_rva"]:
        return ["entry RVA 0x%X does not match %s at 0x%X -- the image enters "
                "some other function" % (info["entry_rva"], expected, sym_rva)]
    return []


def _build_coff_symbols(items, text_va):
    """(name, rva[, section]) tuples -> COFF symbol table + string table.

    Values are section-relative (rva - section VA); section defaults to 1
    (.text), which is how build_pe lays the image out.  Names <= 8 bytes sit
    inline, longer ones are a zero dword plus an offset into the string table
    that follows the records (its first dword is the table size, including
    itself).
    """
    records = b""
    strings = b""
    for item in items:
        name = item[0]
        rva = item[1]
        secnum = item[2] if len(item) > 2 else 1
        raw = name.encode("ascii")
        if len(raw) <= 8:
            nameb = raw.ljust(8, b"\0")
        else:
            nameb = struct.pack("<II", 0, 4 + len(strings))
            strings += raw + b"\0"
        # name(8) value(4) section(2, signed) type(2) sclass(1) naux(1) = 18
        records += nameb + struct.pack("<IhHBB", rva - text_va, secnum,
                                       0x20, 0x02, 0)
    return records + struct.pack("<I", 4 + len(strings)) + strings


def build_pe(entry_rva, entry_bytes, imports=0, base=0x140000000, sym=None,
             exec_sec=True):
    """Minimal PE32+ with one CODE section, used only by --self-test.

    The section is grown to cover both the entry and the import directory so
    that every case exercises the rule engine rather than tripping the parser's
    range checks first -- a rejection is only evidence if the checker actually
    got to look at the bytes.

    sym       optional [(name, rva), (name, rva, section), ...] emitted as a
              genuine COFF symbol table with PointerToSymbolTable and
              NumberOfSymbols patched into the file header, so the expected-
              symbol rule is exercised against real table bytes.  The
              three-tuple form puts a symbol in a chosen section, which is how
              the invalid-section fixture is built.
    exec_sec  False packs the section WITHOUT IMAGE_SCN_MEM_EXECUTE (a data
              section), for the non-executable-entry fixture; the entry is
              still file-backed so the rule engine, not the parser, rejects it.
    """
    rva_alignment = 0x1000
    file_alignment = 0x200
    text_va = rva_alignment
    imp_rva = text_va + 0x1000

    need = entry_rva + len(entry_bytes) + 16
    if imports:
        need = max(need, imp_rva + 20 * (imports + 1))
    raw_size = (need - text_va + 15) & ~15

    # CNT_CODE|MEM_EXECUTE|MEM_READ, or CNT_INITIALIZED_DATA|MEM_READ when the
    # fixture must prove the audit notices a non-executable entry section.
    chars = 0x60000020 if exec_sec else 0x40000040
    sec_name = b".text\x00\x00\x00" if exec_sec else b".data\x00\x00\x00"
    section = struct.pack(
        "<8sIIIIIIHHI",
        sec_name, raw_size, text_va, raw_size, file_alignment,
        0, 0, 0, 0, chars)
    section += b"\0" * (40 - len(section))

    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0x00, 0x20B)
    struct.pack_into("<I", opt, 0x10, entry_rva)
    struct.pack_into("<Q", opt, 0x18, base)
    struct.pack_into("<I", opt, 0x20, rva_alignment)
    struct.pack_into("<I", opt, 0x24, file_alignment)
    struct.pack_into("<H", opt, 0x6C, 16)
    if imports:
        struct.pack_into("<II", opt, 0x78, imp_rva, imports * 20)
    struct.pack_into("<H", opt, 0x5C, 0x0002)  # subsystem: GUI

    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, len(opt), 0x0022)
    body = b"PE\0\0" + coff + bytes(opt) + section
    stub = bytearray(0x80)
    stub[0:2] = b"MZ"
    struct.pack_into("<I", stub, 0x3C, 0x80)

    head = bytes(stub) + body
    head += b"\0" * ((-len(head)) % file_alignment)

    raw = bytearray(b"\x90" * raw_size)
    at = entry_rva - text_va
    raw[at:at + len(entry_bytes)] = entry_bytes
    if imports:
        at = imp_rva - text_va
        for i in range(imports):
            raw[at + i * 20:at + i * 20 + 20] = b"k" + b"\0" * 19

    out = bytearray(head + bytes(raw))
    if sym:
        # The COFF file header sits right after the PE signature at the
        # e_lfanew offset packed above (0x80): PointerToSymbolTable at +12,
        # NumberOfSymbols at +16.  One record per entry; no aux records.
        sym_off = len(out)
        out += _build_coff_symbols(sym, text_va)
        struct.pack_into("<I", out, 0x80 + 12, sym_off)
        struct.pack_into("<I", out, 0x80 + 16, len(sym))
    return bytes(out)


def self_test():
    """Every synthetic regression below MUST be rejected FOR ITS STATED
    REASON, or the checker is broken: a case that fails only because some other
    rule tripped would let the rule under test stop firing unnoticed."""
    # Real, non-stub, import-free prologue bytes, used wherever a fixture must
    # survive every rule except the one it exists to provoke.
    real = bytes((0x55, 0x48, 0x89, 0xE5, 0x90)) + b"\x00" * 4

    def corrupt_strtab():
        """A correct image whose one long symbol name can no longer be
        resolved: the record's string-table offset is pushed outside the
        table, so the expected symbol becomes unattributable.  Nothing else
        in the image differs from the matching good fixture."""
        blob = bytearray(build_pe(0x1450, real, sym=[("sfontview_main", 0x1450)]))
        sym_ptr = struct.unpack_from("<I", blob, 0x80 + 12)[0]
        # Long-name records store zero dword + offset into the string table.
        struct.pack_into("<I", blob, sym_ptr + 4, 0xFFFF)
        return bytes(blob)

    def aux_overrun():
        """A one-record table whose record claims three aux records: the walk
        would step past NumberOfSymbols, which is a malformed layout rather
        than a short one."""
        blob = bytearray(build_pe(0x1000, real, sym=[("kextctl_main", 0x1000)]))
        sym_ptr = struct.unpack_from("<I", blob, 0x80 + 12)[0]
        blob[sym_ptr + 17] = 3  # NumberOfAuxSymbols of record 0
        return bytes(blob)

    def build_owx_in(section_type):
        """Minimal packed OWX1 image whose entry sits in a section of the
        given type: 0x100-byte header with a one-entry section table at 0x70,
        entry bytes at file offset 0x100, entry at base + 0x1000."""
        base = 0x180000000
        hdr = bytearray(0x100)
        hdr[0:4] = b"OWX1"
        struct.pack_into("<I", hdr, 0x08, 0x100 + len(real))  # image_size
        struct.pack_into("<Q", hdr, 0x10, base + 0x1000)      # entry_point
        struct.pack_into("<Q", hdr, 0x18, base)               # image_base
        struct.pack_into("<I", hdr, 0x40, 1)                  # section_count
        struct.pack_into("<I", hdr, 0x44, 0)                  # import_count
        struct.pack_into("<I", hdr, 0x60, 0x70)               # table_off
        b = 0x70
        struct.pack_into("<I", hdr, b + 0x00, section_type)
        struct.pack_into("<Q", hdr, b + 0x08, 0x100)          # raw offset
        struct.pack_into("<Q", hdr, b + 0x10, base + 0x1000)  # virtual address
        struct.pack_into("<Q", hdr, b + 0x18, 0x20)           # size
        return bytes(hdr) + real

    cases = [
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, STUB_SIG),
         "owinit reverted to the stub", "owx_entry_stub"),
        ("owinit.owx", build_pe(0x1AC0, STUB_SIG), "owinit entry at stub RVA",
         "owx_entry_stub"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, bytes((0x31, 0xC0, 0x90))),
         "owinit entry one byte off the stub", "owinit_main's prologue"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, STUB_SIG + b"\x90"),
         "owinit entry with a trailing opcode", "owx_entry_stub"),
        ("owinit.owx", build_pe(0x2000, OWINIT_SIG + b"\x00" * 4),
         "owinit entry moved off 0x1000", "expected 0x1000"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, b"\x55\x48\x89\xE5\x90"),
         "owinit entry is an unrelated prologue", "owinit_main's prologue"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, OWINIT_SIG + b"\x00" * 4, 1),
         "owinit carrying an import descriptor", "import descriptor"),
        # win is now a real-entry target, so its regressions are the same two
        # as every other repointed image: left on the stub, or carrying an
        # import.  (An earlier case asserted that a bare `jmp` at win's entry
        # was rejected; that was the stub rule, which no longer applies here,
        # and accepting it now would be correct rather than a catch.)
        ("win.owx", build_pe(0x1000, STUB_SIG + b"\x90" * 5),
         "win left on owx_entry_stub -- launches then returns at once",
         "owx_entry_stub"),
        ("win.owx", build_pe(0x1000, bytes((0x55, 0x48, 0x89, 0xE5, 0x90)), 1),
         "win carrying import descriptors -- unloadable when launched",
         "import descriptor"),
        # owsh is now a real-entry target: the two ways it silently stops
        # working, plus an import that would make it unloadable.
        ("owsh.owx", build_pe(0x1450, STUB_SIG + b"\x90" * 5),
         "owsh left on owx_entry_stub -- launches then returns at once",
         "owx_entry_stub"),
        ("owsh.owx", build_pe(0x1450, bytes((0x55, 0x48, 0x89, 0xE5, 0x90)), 1),
         "owsh carrying import descriptors -- unloadable when launched",
         "import descriptor"),
        # kconfctl is a real-entry target too: same two silent no-op modes and
        # the import that would make it unloadable.
        ("kconfctl.owx", build_pe(0x1000, STUB_SIG + b"\x90" * 5),
         "kconfctl left on owx_entry_stub -- launches then returns at once",
         "owx_entry_stub"),
        ("kconfctl.owx", build_pe(0x1000, bytes((0x56, 0x48, 0x83, 0xEC, 0x20)), 1),
         "kconfctl carrying import descriptors -- unloadable when launched",
         "import descriptor"),
        # banhammer_cli is a real-entry target as well: the same two silent
        # no-op modes and the import that would make it unloadable.
        ("banhammer_cli.owx", build_pe(0x11A0, STUB_SIG + b"\x90" * 5),
         "banhammer_cli left on owx_entry_stub -- launches then returns at once",
         "owx_entry_stub"),
        ("banhammer_cli.owx", build_pe(0x11A0, bytes((0x53, 0x48, 0x89, 0xCB, 0x90)), 1),
         "banhammer_cli carrying import descriptors -- unloadable when launched",
         "import descriptor"),
        # bancat is a real-entry target as well: the same two silent no-op modes
        # and the import that would make it unloadable.
        ("bancat.owx", build_pe(0x1450, STUB_SIG + b"\x90" * 5),
         "bancat left on owx_entry_stub -- launches then returns at once",
         "owx_entry_stub"),
        ("bancat.owx", build_pe(0x1450, bytes((0x41, 0x57, 0x41, 0x56, 0x41)), 1),
         "bancat carrying import descriptors -- unloadable when launched",
         "import descriptor"),
        # The emergency pair: the two ways it silently stops working.
        ("owinitv.owx", build_pe(0x1000, STUB_SIG + b"\x90" * 4),
         "owinitv left on owx_entry_stub -- PID 1 that returns immediately",
         "owx_entry_stub"),
        ("owrs.owx", build_pe(0x1450, STUB_SIG + b"\x90" * 4),
         "owrs left on owx_entry_stub -- a shell that never prompts",
         "owx_entry_stub"),
        ("owinitv.owx", build_pe(0x1000, bytes((0x55, 0x48, 0x89, 0xE5, 0x90)),
                                 imports=2),
         "owinitv carrying import descriptors -- unloadable when needed",
         "import descriptor"),
        ("owrs.owx", build_pe(0x1000, bytes((0x55, 0x48, 0x89, 0xE5, 0x90)),
                              imports=1),
         "owrs carrying an import descriptor", "import descriptor"),
        # --- expected-symbol rule ---------------------------------------
        # Each of these is real, non-stub, import-free, executable code -- but
        # not the function its target is named for.  A nonzero entry RVA alone
        # would satisfy every one of those facts and still be the wrong program.
        ("win.owx", build_pe(0x1450,
                             bytes((0x41, 0x57, 0x41, 0x56, 0x41)) + b"\x00" * 4,
                             sym=[("win_main", 0x1000),
                                  ("startwm_main", 0x1450)]),
         "entry enters startwm_main while win_main sits at 0x1000",
         "does not match win_main"),
        ("kextctl.owx", build_pe(0x1000, real, sym=[("kext_helper", 0x1000)]),
         "kextctl_main absent from the symbol table",
         "kextctl_main not found"),
        ("owedit.owx", build_pe(0x1450, real, sym=[("owedit_main", 0x1000)]),
         "entry RVA disagrees with owedit_main's address",
         "does not match owedit_main"),
        ("vipmount.owx", build_pe(0x1000, real,
                                  sym=[("vipmount_main", 0x1000, 99)]),
         "vipmount_main bound to section 99, which does not exist",
         "invalid section number 99"),
        ("owkill.owx", build_pe(0x1000, real,
                                sym=[("owkill_main", 0x1000),
                                     ("owkill_main", 0x1010)]),
         "owkill_main defined twice -- ambiguous which address is the entry",
         "is ambiguous"),
        # --- executable-section rule ------------------------------------
        ("startwm.owx", build_pe(0x1000, real, sym=[("startwm_main", 0x1000)],
                                 exec_sec=False),
         "entry file-backed in a non-executable data section",
         "non-executable section"),
        # --- symbol-value bounds ----------------------------------------
        ("kextctl.owx", build_pe(0x1000, real, sym=[("kextctl_main", 0x4000)]),
         "expected symbol's value lies past the end of its own section",
         "lies outside its section"),
        # --- string-table resolution ------------------------------------
        ("sfontview.owx", corrupt_strtab(),
         "long expected name's string-table offset points outside the table",
         "sfontview_main not found"),
        # --- packed OWX1 non-code entry ---------------------------------
        ("owinitv.owx", build_owx_in(0x02),
         "packed image entered in an RDATA (non-code) section",
         "non-executable section"),
    ]
    good = [
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, OWINIT_SIG + b"\xF7\x04\x00\x00")),
        # Any non-stub, import-free prologue is acceptable for a real-entry
        # target that is not symbol-pinned; only the import count and the stub
        # bytes are asserted.  The eight pinned targets below each carry a
        # matching COFF symbol so the expected-symbol rule is proven to ACCEPT
        # a correct image, not merely to reject broken ones.
        ("owsh.owx", build_pe(0x1450, bytes((0x55, 0x48, 0x89, 0xE5, 0x90))
                              + b"\x00" * 4)),
        ("kconfctl.owx", build_pe(0x1000, bytes((0x56, 0x48, 0x83, 0xEC, 0x20))
                                  + b"\x00" * 4)),
        ("banhammer_cli.owx", build_pe(0x11A0, bytes((0x53, 0x48, 0x89, 0xCB, 0x90))
                                       + b"\x00" * 4)),
        ("bancat.owx", build_pe(0x1450, bytes((0x41, 0x57, 0x41, 0x56, 0x41))
                                + b"\x00" * 4)),
        # The eight targets that used to be stubbed now pass the same rules;
        # each gets a good case so a future checker edit that starts rejecting
        # them fails here first.
        ("owedit.owx", build_pe(0x1450, real, sym=[("owedit_main", 0x1450)])),
        ("owkill.owx", build_pe(0x1450, real, sym=[("owkill_main", 0x1450)])),
        ("owwm.owx", build_pe(0x1450, real, sym=[("owwm_main", 0x1450)])),
        ("startwm.owx", build_pe(0x1450, real, sym=[("startwm_main", 0x1450)])),
        ("win.owx", build_pe(0x1000, bytes((0xE9, 0, 0, 0, 0))
                            + b"\x00" * 4, sym=[("win_main", 0x1000)])),
        ("vipmount.owx", build_pe(0x1450, real, sym=[("vipmount_main", 0x1450)])),
        ("sfontview.owx", build_pe(0x1450, real, sym=[("sfontview_main", 0x1450)])),
        ("kextctl.owx", build_pe(0x1450, real, sym=[("kextctl_main", 0x1450)])),
        ("owinitv.owx", build_pe(0x10E0, bytes((0x55, 0x48, 0x89, 0xE5, 0x90))
                                 + b"\x00" * 4)),
        ("owrs.owx", build_pe(0x1220, bytes((0x48, 0x83, 0xEC, 0x28, 0xE8))
                              + b"\x00" * 4)),
        # Packed OWX1 positive control: the same layout as the non-code
        # rejection above but typed OWX_SECTION_CODE, proving that fixture's
        # rejection comes from the section type and nothing else.
        ("owinitv.owx", build_owx_in(0x01)),
    ]

    failures = 0
    print("=== check_owx_entries self-test ===")

    def verdict(name, why, bad, expect):
        # Rejecting is not enough: reject FOR THE INTENDED REASON, or a rule
        # that silently stopped firing would pass while another happened to trip.
        nonlocal failures
        if not bad:
            print("[FAIL] %-12s ACCEPTED but should be rejected -- %s"
                  % (name, why))
            failures += 1
            return
        hit = next((m for m in bad if expect in m), None)
        if hit is None:
            print("[FAIL] %-12s rejected for the wrong reason (wanted %r): %s"
                  % (name, expect, "; ".join(bad)))
            failures += 1
        else:
            print("[ok]   %-12s rejected: %s" % (name, hit))

    # A zero entry RVA cannot be built by build_pe (it places the section above
    # RVA 0x1000), so it is fed to the rule engine directly.  Every rule
    # check_real_entry() enforces needs a negative case, or it is a comment.
    synthetic = [
        ("owinitv.owx",
         {"entry_rva": 0, "image_base": 0x140000000,
          "sig": bytes((0x55, 0x48, 0x89, 0xE5, 0x90)), "import_descriptors": 0,
          "entry_exec": True, "symbols": None, "sections": []},
         "owinitv with a zero entry RVA", "entry RVA is 0"),
        ("owsh.owx",
         {"entry_rva": 0, "image_base": 0x140000000,
          "sig": bytes((0x55, 0x48, 0x89, 0xE5, 0x90)), "import_descriptors": 0,
          "entry_exec": True, "symbols": None, "sections": []},
         "owsh with a zero entry RVA", "entry RVA is 0"),
    ]

    for name, info, why, expect in synthetic:
        verdict(name, why, check(name, info), expect)

    for name, blob, why, expect in cases:
        try:
            # Same magic dispatch read_image() applies, so packed OWX1
            # fixtures exercise the production parse path.
            info = parse_owx(blob) if blob[:4] == b"OWX1" else parse_pe(blob)
            bad = check(name, info)
        except PeError as exc:
            print("[FAIL] %-12s rejected by parser (%s) -- %s" % (name, exc, why))
            failures += 1
            continue
        verdict(name, why, bad, expect)

    # A corrupt COFF table is rejected by the PARSER with PeError -- an
    # unreadable image, distinct from a readable-but-bad one -- so these
    # fixtures must raise, and raise with the stated message.  Silently parsing
    # is a failure; so is raising anything other than PeError, which would
    # escape main()'s handler (that case surfaces as a crashed self-test).
    malformed = [
        ("kextctl.owx", aux_overrun(),
         "aux-record count extends past the declared symbol count",
         "overrun the symbol table"),
    ]
    for name, blob, why, expect in malformed:
        raised = None
        try:
            parse_pe(blob)
        except PeError as exc:
            raised = exc
        if raised is None:
            print("[FAIL] %-12s corrupt table parsed cleanly -- %s" % (name, why))
            failures += 1
        elif expect not in str(raised):
            print("[FAIL] %-12s parser rejected for the wrong reason "
                  "(wanted %r): %s" % (name, expect, raised))
            failures += 1
        else:
            print("[ok]   %-12s parser rejected: %s" % (name, raised))

    for name, blob in good:
        try:
            info = parse_owx(blob) if blob[:4] == b"OWX1" else parse_pe(blob)
            bad = check(name, info)
        except PeError as exc:
            print("[FAIL] %-12s good case failed to parse (%s)" % (name, exc))
            failures += 1
            continue
        if bad:
            print("[FAIL] %-12s good case rejected: %s" % (name, bad[0]))
            failures += 1
        else:
            print("[ok]   %-12s accepted" % name)

    # End-to-end truncated-PE check through the REAL audit entry path: a PE
    # cut inside its optional header raises struct.error out of the unpackers,
    # and main() must turn that into an ordinary "[FAIL] unreadable" line and
    # a nonzero exit -- never an uncaught traceback.  The fixture lives in the
    # system temp directory and is removed afterwards; no repository file is
    # touched.
    import contextlib
    import io as _io
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp(prefix="owx-trunc-")
    try:
        with open(os.path.join(tmp, "kextctl.owx"), "wb") as fh:
            # 160 bytes cuts at RVA 0xA8 -- inside the optional header, before
            # any PeError guard can fire, which is the case under test.
            fh.write(build_pe(0x1000, real)[:160])
        out = _io.StringIO()
        rc, raised = None, None
        try:
            with contextlib.redirect_stdout(out):
                rc = main(["check_owx_entries.py", tmp])
        except Exception as exc:  # the failure mode this fixture exists to prevent
            raised = exc
        text = out.getvalue()
        if raised is not None:
            print("[FAIL] truncated PE made the audit entry path raise %s: %s"
                  % (type(raised).__name__, raised))
            failures += 1
        elif rc == 0 or "[FAIL] kextctl.owx" not in text or "unreadable" not in text:
            print("[FAIL] truncated PE not reported as unreadable "
                  "(rc=%s): %r" % (rc, text.splitlines()[-2:]))
            failures += 1
        else:
            print("[ok]   %-12s rejected: %s" % ("kextctl.owx",
                  next(l.strip() for l in text.splitlines()
                       if "[FAIL] kextctl.owx" in l)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("--- self-test: %d check(s), %d failure(s)"
          % (len(synthetic) + len(cases) + len(malformed) + len(good) + 1,
             failures))  # + 1: the truncated-PE entry-path check above
    return 1 if failures else 0


def main(argv):
    if len(argv) > 1 and argv[1] == "--self-test":
        return self_test()

    # With an explicit root, audit whatever population that root holds.  The
    # Makefile calls this twice -- once with the Essentials Artifacts directory
    # for the thirteen targets there, once with emergency/ for the two built
    # here -- and each root is audited against the rules for the targets it is
    # supposed to contain, so a missing or unexpected file is itself a failure
    # rather than a silently shorter list.
    root = argv[1] if len(argv) > 1 else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        os.pardir, "OpenWindows-Essentials", "Artifacts", "Software")

    is_emergency = os.path.basename(os.path.normpath(root)) == "emergency"
    if is_emergency:
        targets = list(EMERGENCY_TARGETS)
    else:
        targets = [OWINIT_BASENAME] + list(REAL_ENTRY_TARGETS)
    print("=== OWX entry audit (%s) ===" % root)

    failures = 0
    checked = 0
    for name in targets:
        path = os.path.join(root, name)
        try:
            info = read_image(path)
        # struct.error joins the tuple because a PE truncated inside its
        # headers raises out of the unpackers before any PeError guard can
        # run.  That is a malformed artifact -- an audit failure, not a crash
        # -- so it gets the same "[FAIL] unreadable" line.  Nothing broader is
        # caught here: a genuine programming error must still surface as a
        # traceback rather than masquerade as a bad image.
        except (IOError, OSError, PeError, struct.error) as exc:
            print("[FAIL] %-18s unreadable: %s" % (name, exc))
            failures += 1
            continue

        bad = check(name, info)
        checked += 1
        if name == OWINIT_BASENAME:
            role = "owinit_main"
        else:
            role = "real entry"
        detail = ("rva 0x%04X %s, %d import(s)"
                  % (info["entry_rva"],
                     " ".join("%02X" % b for b in info["sig"]),
                     info["import_descriptors"]))
        if bad:
            print("[FAIL] %-18s %s -- %s" % (name, role, "; ".join(bad)))
            failures += 1
        else:
            print("[ok]   %-18s %-15s %s" % (name, role, detail))

    print("--- %d target(s) checked, %d failure(s)" % (checked, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
