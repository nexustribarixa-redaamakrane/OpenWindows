#!/usr/bin/env python3
"""Generate signed CIS fixtures for the host test.

Emits tools/hosttest/cis_fixtures.h: a set of OWX images, each with a CIS block
appended, covering the accept path and one fixture per rejection verdict.

The signer is tools/cis_sign.py, which shares no code with lib/ow_ed25519.c.  A
signature accepted by the kernel and produced here is therefore evidence that
both implementations are right, rather than evidence that both are wrong in the
same way -- which is the reason the crypto was written twice in the first place.

Usage:
  python tools/gen_cis_fixtures.py > tools/hosttest/cis_fixtures.h

The keys below are TEST keys, derived from fixed seeds written down here.  They
are not release keys, they sign nothing that ships, and cis_keys.h stays empty:
nothing here is a secret and nothing here is trusted by a production build.  They
are in the repository precisely because the alternative -- a test that needs a
key nobody can see -- is a test nobody can rerun.
"""

import hashlib
import struct
import sys

import cis_sign
import cis_block

# ---------------------------------------------------------------------------
# Block format.
#
# The block itself lives in tools/cis_block.py, shared with tools/owx_pack.py so
# the signed-image tooling and the fixture corpus cannot drift apart.  Re-exported
# here under their original names because the fixture bodies below read better
# against short constants.
# ---------------------------------------------------------------------------

CIS_MAGIC = cis_block.CIS_MAGIC
CIS_HEADER_SIZE = cis_block.CIS_HEADER_SIZE
CIS_VERSION = cis_block.CIS_VERSION
CIS_SIGNATURE_SIZE = cis_block.CIS_SIGNATURE_SIZE
MANIFEST_PREFIX = cis_block.MANIFEST_PREFIX

TAG_LICENSE = cis_block.TAG_LICENSE
TAG_DIGEST_ALGO = cis_block.TAG_DIGEST_ALGO
TAG_KEY_ID = cis_block.TAG_KEY_ID
TAG_CONTENT_DIGEST = cis_block.TAG_CONTENT_DIGEST
TAG_COPYRIGHT = cis_block.TAG_COPYRIGHT
TAG_BUILD_ID = cis_block.TAG_BUILD_ID

DIGEST_ALGO_SHA256 = cis_block.DIGEST_ALGO_SHA256

OWX_MAGIC = 0x3158574F  # "OWX1"
OWX_HEADER_SIZE = 256
OWX_FORMAT_VERSION = 1
OWX_SECTION_ENTRY_SIZE = 40  # packed owx_section_entry_t
OWX_SECTION_CODE = 0x01
OWX_SUBSYSTEM_BOOT = 0x04
OWX_SUBSYSTEM_RECOVERY = 0x05
OWX_TARGET_ARCH_X64 = 3

OWX_OFF_HEADER_CHECKSUM = 0x0C
OWX_OFF_IMAGE_CHECKSUM = 0x90


def crc32c(data, crc=0xFFFFFFFF):
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 & -(crc & 1) & 0xFFFFFFFF)
    return crc


def image_checksum(image):
    """The packer's image_checksum: CRC32c from 0x10 with the field treated as
    absent, because the field lies inside its own hash window."""
    crc = crc32c(image[0x10:OWX_OFF_IMAGE_CHECKSUM])
    crc = crc32c(b"\0\0\0\0", crc)
    crc = crc32c(image[OWX_OFF_IMAGE_CHECKSUM + 4:], crc)
    return ~crc & 0xFFFFFFFF


def header_checksum(header):
    """CRC32c over the header with the header_checksum field itself excluded."""
    crc = crc32c(header[0:OWX_OFF_HEADER_CHECKSUM])
    crc = crc32c(b"\0\0\0\0", crc)
    crc = crc32c(header[OWX_OFF_HEADER_CHECKSUM + 4:], crc)
    return ~crc & 0xFFFFFFFF


def build_owx(subsystem, code_len=256, seed=b"cis-fixture"):
    """A structurally valid OWX1 image: one CODE section, no imports, a real
    CRC32c.  Not bootable code -- the point is that it satisfies every check
    OwOwxImageIsLoadable makes, so a fixture that reaches the loader is refused
    by CIS rather than by the header parser first."""
    section_offset = OWX_HEADER_SIZE
    payload_offset = section_offset + OWX_SECTION_ENTRY_SIZE
    image_size = payload_offset + code_len
    image = bytearray(image_size)

    # Deterministic filler, so a diff between two fixtures shows the change
    # rather than noise.
    stream = hashlib.sha256(seed).digest()
    while len(stream) < code_len:
        stream += hashlib.sha256(stream).digest()
    image[payload_offset:image_size] = stream[:code_len]

    virtual_base = 0x0000000140000000

    # Every field written at its own offset rather than through one packed
    # struct, because inc/ow_owx.h numbers each one and a single
    # pack_into() with thirty-odd arguments is a format string with no name
    # attached to any of its positions.
    def put(offset, fmt, *values):
        struct.pack_into(fmt, image, offset, *values)

    put(0x00, "<I", OWX_MAGIC)
    put(0x04, "<H", OWX_FORMAT_VERSION)
    put(0x06, "<H", OWX_HEADER_SIZE)
    put(0x08, "<I", image_size)
    put(0x0C, "<I", 0)  # header_checksum, patched below
    put(0x10, "<Q", virtual_base + 0x1000)  # entry_point
    put(0x18, "<Q", virtual_base)  # preferred_base
    put(0x20, "<Q", 0x00100000)  # stack_reserve
    put(0x28, "<Q", 0x00010000)  # stack_commit
    put(0x30, "<Q", 0x00100000)  # heap_reserve
    put(0x38, "<Q", 0x00010000)  # heap_commit
    put(0x40, "<I", 1)  # section_count
    put(0x44, "<I", 0)  # import_count: the loader refuses declared imports
    put(0x48, "<I", 0)  # string_table_size
    put(0x4C, "<B", subsystem)
    put(0x4D, "<B", OWX_TARGET_ARCH_X64)
    put(0x4E, "<B", 0)  # target_subarch
    put(0x4F, "<B", 12)  # alignment_log2
    put(0x50, "<I", 0)  # flags
    put(0x54, "<I", 0)  # tls_index
    put(0x58, "<Q", 0)  # timestamp
    put(0x60, "<I", section_offset)
    # 0x64 import_table_offset, 0x68 string_table_offset,
    # 0x6C reloc_table_offset, 0x70 resource_offset, 0x74 resource_size,
    # 0x78 debug_offset, 0x7C debug_size, 0x80 sentinel_bancode,
    # 0x84 sentinel_trap_slot: all zero, and the buffer already is.
    put(0x88, "<Q", 0)  # sentinel_recovery_ep
    put(0x90, "<I", 0)  # image_checksum, patched below
    # 0x94 padding[27]: zero, as the packer leaves it.

    put(section_offset, "<I", OWX_SECTION_CODE)
    put(section_offset + 4, "<I", 0)  # flags
    put(section_offset + 8, "<Q", payload_offset)  # file_offset
    put(section_offset + 16, "<Q", virtual_base)  # virtual_addr
    put(section_offset + 24, "<Q", code_len)  # size
    put(section_offset + 32, "<I",
        crc32c(bytes(image[payload_offset:image_size])))
    put(section_offset + 36, "<I", 0)  # reserved

    put(OWX_OFF_IMAGE_CHECKSUM, "<I", image_checksum(bytes(image)))
    put(OWX_OFF_HEADER_CHECKSUM, "<I",
        header_checksum(bytes(image[:OWX_HEADER_SIZE])))
    return bytes(image)


# ---------------------------------------------------------------------------
# Keys.  Fixed seeds, documented, and not secrets.
# ---------------------------------------------------------------------------

TEST_KEYS = {
    # name: (seed, flags)
    "release": (b"cis-test-release-seed-0000000001", 0x00000001),
    "recovery": (b"cis-test-recovery-seed-000000002", 0x00000002),
    "untrusted": (b"cis-test-untrusted-seed-00000003", 0x00000001),
}


def key_id_for(public_key):
    return cis_block.key_id_for(public_key)


def tlv(tag, value):
    return cis_block.tlv(tag, value)


def build_manifest(license_expr, digest, key_id, copyright, build_id=None):
    return cis_block.build_manifest(license_expr, digest, key_id, copyright,
                                    build_id)


def build_block(manifest, signature):
    return cis_block.build_block(manifest, signature)


def sign_block(seed, image, license_expr, copyright, build_id=None,
               key_id=None, corrupt_signature=False, corrupt_after_signing=None,
               extra_trailing=b"", declared_image_size=None, file_image=None):
    return cis_block.sign_block(
        seed, image, license_expr, copyright, build_id, key_id,
        corrupt_signature, corrupt_after_signing, extra_trailing,
        declared_image_size, file_image)


def mutate_copyright_in_block(block):
    return cis_block.mutate_copyright_in_block(block)


def corrupt_block_magic(block):
    """Flip the low bit of the block's magic, at the block's first byte.

    The file's byte 0 is the OWX header's magic, not the block's: the block starts
    at image_size.  Corrupting the wrong one would produce an image the header
    parser refuses, which tests OwOwxValidateHeader rather than CIS.
    """
    out = bytearray(block)
    out[0] ^= 0x01
    return bytes(out)


def fixtures():
    """Every fixture, as (name, description, expected verdict, file bytes,
    image_size, subsystem, key_name).

    `key_name` is the key the harness pins, which is not always the key that
    signed the block: unknown_key is signed by a key nobody pins, and pinning the
    signer would turn it into a trusted fixture.
    """
    out = []

    seeds = {name: entry[0] for name, entry in TEST_KEYS.items()}
    image = build_owx(OWX_SUBSYSTEM_BOOT)

    # --- accepted ---
    out.append((
        "good_boot",
        "MIT, signed by the release key, boot subsystem",
        "OW_CIS_VERDICT_TRUSTED",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   build_id="test-1"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    recovery = build_owx(OWX_SUBSYSTEM_RECOVERY, seed=b"cis-fixture-recovery")
    out.append((
        "good_recovery",
        "MIT, signed by the recovery key, recovery subsystem",
        "OW_CIS_VERDICT_TRUSTED",
        sign_block(seeds["recovery"], recovery, "MIT", "(c) OpenWindows"),
        len(recovery),
        OWX_SUBSYSTEM_RECOVERY,
        "recovery",
    ))

    out.append((
        "good_with_build_id",
        "the optional build-id tag present",
        "OW_CIS_VERDICT_TRUSTED",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   build_id="build-2026.10.1"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    # --- refusals, one per verdict ---
    out.append((
        "unsigned",
        "no block at all: the image is exactly as long as it says",
        "OW_CIS_VERDICT_REJECT_UNSIGNED",
        image,
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    # A byte of section content changed after signing.  The block is signed over
    # the pristine image while the file carries the altered one, which is exactly
    # what a post-signing edit looks like to the verifier: the signature is
    # genuinely valid over the block, and the block genuinely names a digest that
    # no longer matches the mapped bytes.
    tampered = bytearray(image)
    tampered[OWX_HEADER_SIZE + 4] ^= 0x01
    out.append((
        "digest_mismatch",
        "one byte of image content changed after signing",
        "OW_CIS_VERDICT_REJECT_DIGEST_MISMATCH",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   file_image=bytes(tampered)),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "bad_signature",
        "the manifest changed after signing: canonical, but not covered",
        "OW_CIS_VERDICT_REJECT_BAD_SIGNATURE",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   corrupt_after_signing=mutate_copyright_in_block),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "corrupt_signature",
        "the signature's R byte flipped",
        "OW_CIS_VERDICT_REJECT_BAD_SIGNATURE",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   corrupt_signature=True),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    # Signed by a key that exists but is deliberately not the one the harness
    # pins.  The key is a real Ed25519 key with a real signature: this fixture
    # fails on trust, not on cryptography, which is the distinction that matters
    # and the reason the harness pins "release" for every row rather than the key
    # named in the fixture.
    out.append((
        "unknown_key",
        "signed by a key the trust store never pins",
        "OW_CIS_VERDICT_REJECT_UNKNOWN_KEY",
        sign_block(seeds["untrusted"], image, "MIT", "(c) OpenWindows"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "unpermitted_licence",
        "a real licence this build does not accept",
        "OW_CIS_VERDICT_REJECT_POLICY",
        sign_block(seeds["release"], image, "GPL-3.0-only", "(c) OpenWindows"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "licence_prefix_only",
        "MIT-0 must not match the accepted entry MIT",
        "OW_CIS_VERDICT_REJECT_POLICY",
        sign_block(seeds["release"], image, "MIT-0", "(c) OpenWindows"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    # Two licence-length cases, both properly signed and both well formed, so
    # the only thing the verifier can object to is the licence itself.
    #
    # oversized_licence is what a hostile or confused signer produces: a licence
    # string far longer than any entry in the accepted table.  The block parses
    # cleanly -- the parser's ceiling is the 64 KiB manifest bound -- so the
    # refusal comes from policy, not format.
    #
    # empty_licence is the same shape at the other end.  A zero-length TLV value
    # is structurally legal and the parser accepts it.
    #
    # Both are POLICY-REFUSED whether or not cis_license_permitted's explicit
    # length checks exist, because the comparison already fails closed: an
    # oversized string matches no short literal, and a zero-length one matches
    # nothing because the comparison returns false at the first byte.  So these
    # two fixtures cannot detect the removal of those checks, and are not
    # claiming to.  What they do establish is the verdict an operator sees for a
    # well-formed signed block with an unusable licence, and that it is recorded.
    out.append((
        "oversized_licence",
        "a signed licence longer than the policy table will consider",
        "OW_CIS_VERDICT_REJECT_POLICY",
        sign_block(seeds["release"], image, "MIT AND " + "x" * 200,
                   "(c) OpenWindows"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "empty_licence",
        "a signed block whose licence tag is zero-length",
        "OW_CIS_VERDICT_REJECT_POLICY",
        sign_block(seeds["release"], image, "", "(c) OpenWindows"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "recovery_key_on_boot_image",
        "a recovery key signing a boot image",
        "OW_CIS_VERDICT_REJECT_POLICY",
        sign_block(seeds["recovery"], image, "MIT", "(c) OpenWindows"),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "recovery",
    ))

    # The block's own magic, at the block's first byte -- not the image's.  Flipping
    # byte 0 of the file would corrupt the OWX header instead, and the loader's
    # header check would refuse the image before CIS ever saw it, which is a
    # different test entirely.
    out.append((
        "malformed_block",
        "the block's magic altered",
        "OW_CIS_VERDICT_REJECT_MALFORMED",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   corrupt_after_signing=corrupt_block_magic),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    out.append((
        "trailing_bytes",
        "signed, then arbitrary bytes appended past the block",
        "OW_CIS_VERDICT_TRUSTED",
        sign_block(seeds["release"], image, "MIT", "(c) OpenWindows",
                   extra_trailing=b"\xde\xad\xbe\xef" * 9),
        len(image),
        OWX_SUBSYSTEM_BOOT,
        "release",
    ))

    return out


def c_bytes(data, per_line=16):
    lines = []
    for at in range(0, len(data), per_line):
        chunk = data[at:at + per_line]
        lines.append("    " + " ".join("0x%02X," % b for b in chunk))
    return "\n".join(lines)


def main():
    out = []
    w = out.append
    w("/* cis_fixtures.h - GENERATED by tools/gen_cis_fixtures.py.  Do not edit.")
    w(" *")
    w(" * Signed OWX images with CIS blocks appended, covering the accept path and")
    w(" * one fixture per rejection verdict.  The signatures were produced by")
    w(" * tools/cis_sign.py, which shares no code with lib/ow_ed25519.c, so a")
    w(" * fixture the kernel accepts is evidence that both are correct rather than")
    w(" * evidence that both are wrong the same way.")
    w(" *")
    w(" * The keys are test keys derived from the fixed seeds in that tool.  They")
    w(" * sign nothing that ships, cis_keys.h stays empty, and none of this is a")
    w(" * secret: a test that needs a key nobody can see is a test nobody can")
    w(" * rerun. */")
    w("#ifndef OW_CIS_FIXTURES_H")
    w("#define OW_CIS_FIXTURES_H")
    w("")
    w('#include "../../inc/ow_cis.h"')
    w("#include <stdint.h>")
    w("")

    # Keys.
    w("typedef struct {")
    w("    const char* Name;")
    w("    uint8_t     Seed[32];")
    w("    uint8_t     PublicKey[OW_CIS_PUBLIC_KEY_SIZE];")
    w("    uint8_t     KeyId[OW_CIS_KEY_ID_SIZE];")
    w("    uint32_t    Flags;")
    w("} ow_cis_fixture_key_t;")
    w("")
    w("#define OW_CIS_FIXTURE_KEY_COUNT %du" % len(TEST_KEYS))
    w("")
    w("static const ow_cis_fixture_key_t ow_cis_fixture_keys"
      "[OW_CIS_FIXTURE_KEY_COUNT] = {")
    for name, (seed, flags) in TEST_KEYS.items():
        pub = cis_sign.public_key_from_seed(seed)
        w("    {")
        w('        "%s",' % name)
        w("        { " + ", ".join("0x%02X" % b for b in seed) + " },")
        w("        { " + ", ".join("0x%02X" % b for b in pub) + " },")
        w("        { " + ", ".join("0x%02X" % b
                                for b in key_id_for(pub)) + " },")
        w("        0x%08Xu," % flags)
        w("    },")
    w("};")
    w("")

    fx = fixtures()
    w("typedef struct {")
    w("    const char* Name;")
    w("    const char* Note;")
    w("    /* The verdict this fixture must produce.  Emitted as the enum value")
    w("     * rather than a name so that renaming a verdict in inc/ow_cis.h breaks")
    w("     * this header at compile time instead of turning a stale name into a")
    w("     * silently-vacuous string comparison. */")
    w("    OW_CIS_VERDICT Want;")
    w("    const uint8_t* File;")
    w("    uint32_t FileSize;   /* everything the loader is handed */")
    w("    uint32_t ImageSize;  /* the signed, mapped range */")
    w("    uint32_t Subsystem;")
    w("    const char* KeyName;")
    w("} ow_cis_fixture_t;")
    w("")
    w("#define OW_CIS_FIXTURE_COUNT %du" % len(fx))
    w("")

    for name, note, want, data, image_size, subsystem, key_name in fx:
        w("static const uint8_t ow_cis_fixture_%s[] = {" % name)
        w(c_bytes(data))
        w("};")
        w("")

    w("static const ow_cis_fixture_t ow_cis_fixtures[OW_CIS_FIXTURE_COUNT] = {")
    for name, note, want, data, image_size, subsystem, key_name in fx:
        w("    {")
        w('        "%s",' % name)
        w('        "%s",' % note.replace('"', '\\"'))
        w("        %s," % want)
        w("        ow_cis_fixture_%s," % name)
        w("        (uint32_t)sizeof(ow_cis_fixture_%s)," % name)
        w("        %du," % image_size)
        w("        0x%02Xu," % subsystem)
        w('        "%s"' % key_name)
        w("    },")
    w("};")
    w("")
    w("#endif /* OW_CIS_FIXTURES_H */")

    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()