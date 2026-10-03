#!/usr/bin/env python3
"""The canonical CICB block: one implementation, two callers.

tools/gen_cis_fixtures.py builds signed OWX images for the host test corpus, and
tools/owx_pack.py signs the images the kernel actually boots.  Both must emit a
byte-identical block for the same inputs, because the parser in cis/cis_format.c
is strict -- a field that is wrong in one and right in the other shows up as a
malformed-block rejection for no visible reason.  So the block lives here once and
both import it.

This module is signing *format* only: it builds and signs blocks.  It is not
opinionated about which keys exist.  The only seed named in it is the dev image
key, which is public by construction (see DEV_IMAGE_SEED) and exists so that an
opt-in development build can boot an image it signed itself.

The signing primitive is cis_sign.py, which shares no code with lib/ow_ed25519.c.
"""

import hashlib
import struct

import cis_sign

# ---------------------------------------------------------------------------
# Block format.  Kept as explicit bytes rather than struct.pack of a C struct:
# the same reasoning as the kernel side, where the signed sequence must not be a
# function of the toolchain's padding choices.
# ---------------------------------------------------------------------------

CIS_MAGIC = 0x42434943  # "CICB"
CIS_HEADER_SIZE = 48
CIS_VERSION = 1
CIS_SIGNATURE_SIZE = 64
MANIFEST_PREFIX = b"OWX-CIS-MANIFEST-v1"

TAG_LICENSE = 0x0001
TAG_DIGEST_ALGO = 0x0002
TAG_KEY_ID = 0x0003
TAG_CONTENT_DIGEST = 0x0004
TAG_COPYRIGHT = 0x0005
TAG_BUILD_ID = 0x0006

DIGEST_ALGO_SHA256 = 1

# ---------------------------------------------------------------------------
# The development image key.
# ---------------------------------------------------------------------------

# A fixed seed, written down here on purpose.  It is not a secret and must never
# become one: it signs development images only, and the public half is the only
# half any build sees.  The alternative -- a dev key in a private location -- would
# mean a build nobody can reproduce and a trust anchor nobody can inspect.
#
# This seed exists solely behind the CIS_DEV_TRUST opt-in.  A build without that
# opt-in does not compile this key into cis_keys.h and does not sign anything, so
# it cannot be used to produce an image that such a build would accept.
#
# Exactly 32 bytes, because that is what cis_sign.py takes: an Ed25519 seed is a
# hash input, not a passphrase, so there is no stretching and no reason to be
# clever about its length.
DEV_IMAGE_SEED = b"cis-dev-image-seed-0000000000010"


def key_id_for(public_key):
    """A key id is a label, not a secret: the first 16 bytes of the SHA-256 of
    the public key.  Derived rather than assigned so it cannot drift from the
    key it names, and so a fixture that pins a new key gets a new id for free."""
    return hashlib.sha256(b"cis-key-id" + public_key).digest()[:16]


def dev_public_key():
    return cis_sign.public_key_from_seed(DEV_IMAGE_SEED)


def dev_key_id():
    return key_id_for(dev_public_key())


def tlv(tag, value):
    if not isinstance(value, bytes):
        value = bytes(value)
    return struct.pack("<HH", tag, len(value)) + value


def build_manifest(license_expr, digest, key_id, copyright, build_id=None):
    """Tags strictly ascending, which is the canonical order the parser requires.
    Build-id (6) sorts after copyright (5), so it is simply appended when
    present."""
    out = bytearray(MANIFEST_PREFIX)
    out += b"\0" * (32 - len(MANIFEST_PREFIX))
    out += tlv(TAG_LICENSE, license_expr.encode())
    out += tlv(TAG_DIGEST_ALGO, struct.pack("<I", DIGEST_ALGO_SHA256))
    out += tlv(TAG_KEY_ID, key_id)
    out += tlv(TAG_CONTENT_DIGEST, digest)
    out += tlv(TAG_COPYRIGHT, copyright.encode())
    if build_id:
        out += tlv(TAG_BUILD_ID, build_id.encode())
    return bytes(out)


def build_block(manifest, signature):
    assert len(signature) == CIS_SIGNATURE_SIZE
    block_size = CIS_HEADER_SIZE + len(manifest) + CIS_SIGNATURE_SIZE
    header = struct.pack(
        "<IHHIIII",
        CIS_MAGIC,
        CIS_VERSION,
        CIS_HEADER_SIZE,
        block_size,
        len(manifest),
        0,  # reserved0
        0,  # flags
    )
    # reserved0, flags, reserved1[16], reserved2[8] -- all zero, both here and
    # required by the parser, so the two sides agree on a canonical block.
    header += b"\0" * (CIS_HEADER_SIZE - len(header))
    assert len(header) == CIS_HEADER_SIZE, len(header)
    return header + manifest + signature


def build_signed_block(seed, image, license_expr, copyright, build_id=None,
                       key_id=None, corrupt_signature=False,
                       corrupt_after_signing=None, declared_image_size=None):
    """Return just the signed block -- no image in front of it.

    `image` is the OWX image whose bytes the digest covers, which is also the
    range [0, image_size) the loader maps.  `declared_image_size` says how much of
    it to hash and defaults to all of it.

    sign_block() is the same thing with the image prepended, for callers building
    a whole file.  The packer wants this one: it has already written the image
    and appending image+block would duplicate it.
    """
    pub = cis_sign.public_key_from_seed(seed)
    key_id = key_id or key_id_for(pub)
    size = declared_image_size if declared_image_size is not None else len(image)
    digest = hashlib.sha256(image[:size]).digest()
    manifest = build_manifest(license_expr, digest, key_id, copyright, build_id)

    # The signature must cover the final header, so the block is built once,
    # signed, and then embedded: signing a header that is then changed would
    # produce a block whose signature never covers its own sizes.
    prefix = build_block(manifest, b"\0" * CIS_SIGNATURE_SIZE)[: -CIS_SIGNATURE_SIZE]
    signature = cis_sign.sign(seed, prefix)
    if corrupt_signature:
        signature = bytes([signature[0] ^ 0x01]) + signature[1:]

    block = build_block(manifest, signature)
    if corrupt_after_signing:
        # Applied to the finished block, after the signature exists.  Mutating
        # before signing would produce a block whose signature was computed over
        # the altered bytes -- i.e. a valid signature, which is a different
        # fixture and a much less interesting one.
        block = corrupt_after_signing(block)
    return block


def sign_block(seed, image, license_expr, copyright, build_id=None,
               key_id=None, corrupt_signature=False, corrupt_after_signing=None,
               extra_trailing=b"", declared_image_size=None, file_image=None):
    """Build image||block, signed, and return the whole file.

    `image` is the bytes the digest covers and the bytes the manifest is built
    from.  `file_image` is what actually goes in front of the block, and defaults
    to `image`.  The two differ only for the digest-mismatch fixture, which is
    precisely the point there: the block names one image's digest while the file
    carries another, which is what a tampered file looks like to a verifier.

    `declared_image_size` is what goes in the OWX header.  It defaults to len(image),
    which is the whole OWX image and the correct value when the block is appended
    to an image whose header was not written to know about it.

    The signature covers the block's own bytes up to the signature, which is what
    the kernel verifies.
    """
    block = build_signed_block(seed, image, license_expr, copyright, build_id,
                                key_id, corrupt_signature, corrupt_after_signing,
                                declared_image_size)
    head = image if file_image is None else file_image
    return head + block + extra_trailing


def mutate_copyright_in_block(block):
    """Flip one byte inside the copyright text, after signing.

    The block stays well formed and canonical -- every length still agrees, every
    tag still ascends, the text is still UTF-8 -- so the only thing wrong with it
    is that the signature no longer covers it.  That is what separates
    BAD_SIGNATURE from MALFORMED, and a fixture that only ever produced the latter
    would leave the signature check untested.

    A copyright byte is chosen over a length or a tag because those would be
    rejected by the parser, which would test the parser again.
    """
    at = block.index(b"(c) OpenWindows")
    out = bytearray(block)
    out[at] = ord("(") ^ 0x01
    return bytes(out)