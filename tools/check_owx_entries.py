#!/usr/bin/env python3
"""Audit the linked entry point of every OWX target the kernel can boot.

Two populations, two different questions, because they are built two different
ways:

  Essentials (13 targets, built by OpenWindows-Essentials/CMakeLists.txt)
      owinit.owx is the one target that enters its real function directly; the
      other twelve still enter owx_entry_stub.  Both are "an .owx entry that
      returns", so a boot test that only proves "some entry ran at CPL3" cannot
      tell them apart.  This compares the instruction bytes actually sitting at
      each PE's entry point.

          owinit.owx        entry RVA 0x1000, owinit_main's prologue, import-free
          everything else   owx_entry_stub's `xor eax,%eax; ret`

  Emergency pair (2 targets, built by this repository's Makefile from emergency/)
      owinitv.owx and owrs.owx are compiled -O2 here, so their prologues are the
      compiler's business and pinning five bytes of one would make the audit fail
      on a toolchain bump rather than on a real regression.  What has to hold for
      them is the two properties that would each break the rescue path outright:

          import-free       the loader binds nothing and REJECTS an image with
                            imports, so an import here is an unloadable rescue
                            shell discovered only at the moment of need
          not the stub      owx_entry_stub is `xor eax,%eax; ret`.  Entered as
                            PID 1 that is a one-instruction emergency init that
                            exits immediately; spawned as a shell it is a shell
                            that never prints a prompt.  Both present as "the
                            emergency path did nothing".

Run with --self-test to exercise the rule engine against synthetic images that
mimic the regressions it exists to catch (owinit silently reverted to the stub,
entry moved off owinit_main, a non-owinit target repointed at the real code, an
emergency image that grew an import, an emergency image left on the stub).  The
self-test needs no artifacts and no mutation, so it is safe to run on every
build; it is the reason a signature that stopped matching cannot pass quietly.
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

# The twelve targets that must keep using owx_entry_stub. ow_owx_props() defaults
# its optional entry_symbol argument to the stub, so every call site that omits
# the argument lands here; only owinit.owx passes owinit_main.
STUB_TARGETS = (
    "bancat.owx", "banhammer_cli.owx", "kconfctl.owx", "kextctl.owx",
    "owedit.owx", "owkill.owx", "owsh.owx", "owwm.owx", "sfontview.owx",
    "startwm.owx", "vipmount.owx", "win.owx",
)

# The emergency pair, built by this repository.  Checked by the rules in
# check_emergency() rather than by a byte signature: see the module docstring.
EMERGENCY_TARGETS = ("owinitv.owx", "owrs.owx")

ALL_TARGETS = (OWINIT_BASENAME,) + STUB_TARGETS + EMERGENCY_TARGETS


class PeError(Exception):
    pass


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def parse_pe(data):
    """Return {entry_rva, image_base, sig, import_descriptors} for a PE image."""
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
    secs = []
    for i in range(nsec):
        b = sec_off + i * 40
        vs = _u32(data, b + 8)
        va = _u32(data, b + 12)
        rs = _u32(data, b + 16)
        rp = _u32(data, b + 20)
        secs.append((va, max(vs, rs), rp, rs))

    def to_file(rva):
        for va, span, rp, rs in secs:
            if va <= rva < va + span:
                delta = rva - va
                if delta >= rs:
                    raise PeError("rva 0x%X is not file-backed" % rva)
                return rp + delta
        raise PeError("rva 0x%X lies in no section" % rva)

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
    }


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
    if name in EMERGENCY_TARGETS:
        return check_emergency(name, info)
    return check_essentials(name, info)


def check_essentials(name, info):
    bad = []
    sig = info["sig"]
    hexsig = " ".join("%02X" % b for b in sig)

    if name == OWINIT_BASENAME:
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
    else:
        if not sig.startswith(STUB_SIG):
            bad.append("entry %s is not owx_entry_stub (31 C0 C3); this "
                       "target must keep using the stub" % hexsig)

    return bad


def check_emergency(name, info):
    """The two properties without which the rescue path is a no-op.

    Deliberately not a prologue signature.  These two targets are compiled -O2 by
    this repository's Makefile, so their first instructions are the toolchain's
    choice; pinning bytes would turn every compiler update into a failure that
    looks like a code defect.  What is worth asserting is what the loader and the
    boot policy actually depend on.
    """
    bad = []
    sig = info["sig"]
    hexsig = " ".join("%02X" % b for b in sig)

    if info["import_descriptors"] != 0:
        bad.append("%d import descriptor(s); the OWX1 loader binds nothing and "
                   "would REFUSE this image at the moment it is needed"
                   % info["import_descriptors"])
    if sig.startswith(STUB_SIG):
        bad.append("entry is owx_entry_stub (31 C0 C3) -- %s would return "
                   "immediately, which is a rescue path that does nothing"
                   % name)
    if info["entry_rva"] == 0:
        bad.append("entry RVA is 0; the loader rejects a zero entry point")
    return bad


def build_pe(entry_rva, entry_bytes, imports=0, base=0x140000000):
    """Minimal PE32+ with one CODE section, used only by --self-test.

    The section is grown to cover both the entry and the import directory so
    that every case exercises the rule engine rather than tripping the parser's
    range checks first -- a rejection is only evidence if the checker actually
    got to look at the bytes.
    """
    rva_alignment = 0x1000
    file_alignment = 0x200
    text_va = rva_alignment
    imp_rva = text_va + 0x1000

    need = entry_rva + len(entry_bytes) + 16
    if imports:
        need = max(need, imp_rva + 20 * (imports + 1))
    raw_size = (need - text_va + 15) & ~15

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00", raw_size, text_va, raw_size, file_alignment,
        0, 0, 0, 0, 0x60000020)
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

    return head + bytes(raw)


def self_test():
    """Every synthetic regression below MUST be rejected, or the checker is broken."""
    cases = [
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, STUB_SIG),
         "owinit reverted to the stub"),
        ("owinit.owx", build_pe(0x1AC0, STUB_SIG), "owinit entry at stub RVA"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, bytes((0x31, 0xC0, 0x90))),
         "owinit entry one byte off the stub"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, STUB_SIG + b"\x90"),
         "owinit entry with a trailing opcode"),
        ("owinit.owx", build_pe(0x2000, OWINIT_SIG + b"\x00" * 4),
         "owinit entry moved off 0x1000"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, b"\x55\x48\x89\xE5\x90"),
         "owinit entry is an unrelated prologue"),
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, OWINIT_SIG + b"\x00" * 4, 1),
         "owinit carrying an import descriptor"),
        ("owsh.owx", build_pe(0x1450, OWINIT_SIG + b"\x00" * 4),
         "owsh repointed at the real entry"),
        ("win.owx", build_pe(0x1000, bytes((0xE9, 0, 0, 0, 0))),
         "win entry is a bare jmp"),
        # The emergency pair: the two ways it silently stops working.
        ("owinitv.owx", build_pe(0x1000, STUB_SIG + b"\x90" * 4),
         "owinitv left on owx_entry_stub -- PID 1 that returns immediately"),
        ("owrs.owx", build_pe(0x1450, STUB_SIG + b"\x90" * 4),
         "owrs left on owx_entry_stub -- a shell that never prompts"),
        ("owinitv.owx", build_pe(0x1000, bytes((0x55, 0x48, 0x89, 0xE5, 0x90)),
                                 imports=2),
         "owinitv carrying import descriptors -- unloadable when needed"),
        ("owrs.owx", build_pe(0x1000, bytes((0x55, 0x48, 0x89, 0xE5, 0x90)),
                             imports=1),
         "owrs carrying an import descriptor"),
    ]
    good = [
        ("owinit.owx", build_pe(OWINIT_ENTRY_RVA, OWINIT_SIG + b"\xF7\x04\x00\x00")),
        ("owsh.owx", build_pe(0x1450, STUB_SIG + b"\x90" * 5)),
        # Any non-stub prologue is acceptable for the emergency pair; only the
        # import count and the stub bytes are asserted.
        ("owinitv.owx", build_pe(0x10E0, bytes((0x55, 0x48, 0x89, 0xE5, 0x90))
                                 + b"\x00" * 4)),
        ("owrs.owx", build_pe(0x1220, bytes((0x48, 0x83, 0xEC, 0x28, 0xE8))
                              + b"\x00" * 4)),
    ]

    failures = 0
    print("=== check_owx_entries self-test ===")

    # A zero entry RVA cannot be built by build_pe (it places the section above
    # RVA 0x1000), so it is fed to the rule engine directly.  Every rule
    # check_emergency() enforces needs a negative case, or it is a comment.
    synthetic = [
        ("owinitv.owx",
         {"entry_rva": 0, "image_base": 0x140000000,
          "sig": bytes((0x55, 0x48, 0x89, 0xE5, 0x90)), "import_descriptors": 0},
         "owinitv with a zero entry RVA"),
    ]

    for name, info, why in synthetic:
        bad = check(name, info)
        if bad:
            print("[ok]   %-12s rejected: %s" % (name, bad[0]))
        else:
            print("[FAIL] %-12s ACCEPTED but should be rejected -- %s" % (name, why))
            failures += 1

    for name, blob, why in cases:
        try:
            bad = check(name, parse_pe(blob))
        except PeError as exc:
            print("[FAIL] %-12s rejected by parser (%s) -- %s" % (name, exc, why))
            failures += 1
            continue
        if bad:
            print("[ok]   %-12s rejected: %s" % (name, bad[0]))
        else:
            print("[FAIL] %-12s ACCEPTED but should be rejected -- %s" % (name, why))
            failures += 1

    for name, blob in good:
        try:
            bad = check(name, parse_pe(blob))
        except PeError as exc:
            print("[FAIL] %-12s good case failed to parse (%s)" % (name, exc))
            failures += 1
            continue
        if bad:
            print("[FAIL] %-12s good case rejected: %s" % (name, bad[0]))
            failures += 1
        else:
            print("[ok]   %-12s accepted" % name)

    print("--- self-test: %d check(s), %d failure(s)"
          % (len(synthetic) + len(cases) + len(good), failures))
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
        targets = [OWINIT_BASENAME] + list(STUB_TARGETS)
    print("=== OWX entry audit (%s) ===" % root)

    failures = 0
    checked = 0
    for name in targets:
        path = os.path.join(root, name)
        try:
            info = read_image(path)
        except (IOError, OSError, PeError) as exc:
            print("[FAIL] %-18s unreadable: %s" % (name, exc))
            failures += 1
            continue

        bad = check(name, info)
        checked += 1
        if name in EMERGENCY_TARGETS:
            role = "real entry"
        elif name == OWINIT_BASENAME:
            role = "owinit_main"
        else:
            role = "owx_entry_stub"
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
