/* ow_cis_format.h - the CIS block: on-disk layout, canonical form, parser
 *
 * A CIS block is a trailer appended to a packed OWX image.  It carries the
 * signer's declaration about the image -- its licence expression, its digest,
 * which key signed it -- plus the signature over that declaration.  The kernel
 * verifies; it never writes, and nothing in this header or its implementation
 * can produce a signature.
 *
 * ---- Where the block lives -----------------------------------------------
 *
 * An OWX file is a header, a section table, and section content, and its length
 * is recorded in owx_header_t::image_size.  The packer sets image_size to the
 * file length, so the bytes from image_size onward are outside every structure
 * the loader walks.  The CIS block is exactly those bytes:
 *
 *     [0, image_size)      the image proper.  Mapped, executed, and digested.
 *     [image_size, file)   the CIS block.  Parsed, verified, never mapped.
 *
 * Two consequences are deliberate.  Appending the block needs no change to
 * owx_header_t, so an image signed by this subsystem still parses under a
 * loader that has never heard of CIS.  And because nothing in the image proper
 * moves, the digest covers the mapped bytes and nothing else -- which is the
 * only way "these exact bytes were signed" can be checked rather than
 * asserted.
 *
 * Trailing bytes past the block are permitted and ignored.  They are already
 * ignored by the loader, and rejecting them would make the format refuse files
 * it can otherwise read for no security gain.
 *
 * ---- Layout --------------------------------------------------------------
 *
 * All fields are little-endian and fixed width.  There is no C struct on disk
 * here and none may be introduced: a struct makes the signed byte sequence a
 * function of the compiler's padding decisions, so a different toolchain would
 * sign different bytes for the same declaration.  Everything below is read and
 * written byte by byte.
 *
 *     off  size  field
 *     ---  ----  -----------------------------------------------------------
 *     0x00     4  magic            "CICB"
 *     0x04     2  block_version    1
 *     0x06     2  header_size      48
 *     0x08     4  block_size       total size of the block, signature included
 *     0x0C     4  manifest_size    signed manifest length, excludes the header
 *     0x10     4  reserved0        must be zero
 *     0x14     4  flags            must be zero; no flag is defined yet
 *     0x18    16  reserved1        must be zero
 *     0x28     8  reserved2        must be zero
 *     0x30     -  header ends at 48
 *
 * The reserved bytes are split in two rather than one block of 24 so that the
 * first 16 bytes of reserved space stay available to a future header that needs
 * a fixed-width field aligned to 16.  Neither is used, and both are checked, so
 * the split costs nothing until something needs it.
 *
 * then, immediately after the header:
 *
 *     manifest[manifest_size]
 *     signature[64]
 *
 * and block_size == header_size + manifest_size + 64, exactly.  The signature
 * therefore always sits at the very end of the block and the two sizes cannot
 * disagree: there is one layout, not a set of offsets to cross-check.
 *
 * ---- What the signature covers -------------------------------------------
 *
 * The signed message is block[0, block_size - 64): the header, the header_size
 * field that bounds the manifest, and the manifest itself.  The trailing 64
 * bytes are the signature and are excluded, because a signature cannot contain
 * itself.
 *
 * Reading the signed range as "everything but the last 64 bytes" rather than
 * assembling it field by field is the point.  A verifier that copies header
 * fields into a scratch buffer has to keep that copy in agreement with the
 * block; one that hands the block's own bytes to the verifier cannot drift.
 * The only thing excluded is the signature, by construction.
 *
 * The image bytes are bound too, but transitively and on purpose: the manifest
 * carries OW_CIS_TAG_CONTENT_DIGEST, the SHA-256 of [0, image_size), so a valid
 * signature over a manifest that names a different digest does not make those
 * bytes trusted.  The digest is a fixed 32-byte tag rather than an unbounded
 * length-prefixed one precisely so the verifier can compare it without first
 * parsing the rest of the manifest.
 *
 * ---- Canonical form ------------------------------------------------------
 *
 * A manifest is canonical or it is rejected.  The signature covers bytes; if two
 * byte sequences meant the same declaration, a signer and a verifier could
 * disagree about what was signed while both were reading the manifest
 * correctly, and that disagreement is exactly the space a forgery needs.
 *
 * The rules, each of which has a distinct failure:
 *
 *   - tags strictly ascend, so there are no duplicates and the order is not a
 *     choice.  A duplicate would otherwise let a parser take the first and an
 *     attacker take the second.
 *   - text values carry no NUL and are valid UTF-8 with no overlong forms, no
 *     surrogates and nothing above U+10FFFF, so a text value is a counted byte
 *     range rather than a string whose meaning depends on where the reader
 *     stopped, and it has one interpretation in every language rather than a
 *     lenient one and a strict one.
 *   - binary values are exactly the size the tag requires, and may hold any
 *     byte.  They are excluded from the rules above deliberately: the digest
 *     algorithm is 01 00 00 00 little-endian, so a rule against NUL applied to
 *     binary values would reject the format's own reference manifest.
 *
 * Unknown tags are accepted and skipped.  Refusing them would make every future
 * extension a compatibility break, and the verifier already treats a tag it
 * does not understand as a claim it does not rely on.  Their values are skipped
 * too, so the text rules above do not apply to them -- a NUL inside an unknown
 * tag's value is harmless precisely because nothing will read it as text.
 *
 * C99 freestanding, fixed-size tables, no dynamic allocation. */
#ifndef OW_CIS_FORMAT_H
#define OW_CIS_FORMAT_H

#include "ow_types.h"
#include "ow_sha256.h"
#include "ow_cis.h"

/* "CICB": Copyleft Integrity Safeguard Block.  Little-endian on disk as the
 * four characters in order, matching how OWX_MAGIC spells "OWX1". */
#define OW_CIS_BLOCK_MAGIC 0x42434943u

#define OW_CIS_BLOCK_HEADER_SIZE  48u
#define OW_CIS_BLOCK_VERSION      1u

/* OW_CIS_SIGNATURE_SIZE comes from ow_cis.h, which the block format shares with
 * the trust store and the measurement log: a signature is 64 bytes everywhere,
 * and two constants for one length is one more place for them to disagree. */

/* The manifest opens with a 32-byte domain separator, zero padded.  Signing a
 * manifest over an image that happens to look like one is exactly the
 * confusion a prefix exists to prevent, and the prefix is inside the signed
 * range, so it cannot be stripped. */
#define OW_CIS_MANIFEST_PREFIX_SIZE 32u
#define OW_CIS_MANIFEST_PREFIX "OWX-CIS-MANIFEST-v1"

/* Largest manifest the parser will look at.  A block is bounded by the image it
 * trails, so this is a sanity bound rather than a policy limit: it stops a
 * corrupt length from turning into a long walk over unmapped memory. */
#define OW_CIS_MAX_MANIFEST_SIZE 0x00010000u /* 64 KiB */

/* TLV tags.  u16, strictly ascending in a manifest, so the numeric gaps are
 * load-bearing only in that no two meanings may ever share a value. */
#define OW_CIS_TAG_LICENSE        0x0001u /* SPDX expression, text,  required */
#define OW_CIS_TAG_DIGEST_ALGO    0x0002u /* u32 LE,             required */
#define OW_CIS_TAG_KEY_ID         0x0003u /* OW_CIS_KEY_ID_SIZE, required */
#define OW_CIS_TAG_CONTENT_DIGEST 0x0004u /* SHA-256, 32 bytes,  required */
#define OW_CIS_TAG_COPYRIGHT      0x0005u /* notice text,        required */
#define OW_CIS_TAG_BUILD_ID       0x0006u /* text,               optional */
#define OW_CIS_TAG_POLICY_CLASS   0x0007u /* text,               optional */
#define OW_CIS_TAG_SOURCE_DIGEST  0x0008u /* SHA-256, 32 bytes,  optional */

/* Only one digest algorithm exists.  Naming it in the block rather than fixing
 * it means a future algorithm is a version bump with a stated intent, not a
 * silent reinterpretation of tag 0x0002. */
#define OW_CIS_DIGEST_ALGO_SHA256 1u

#define OW_CIS_FLAG_NONE 0u

/* Parser outcome.  Kept finer-grained than OW_CIS_VERDICT on purpose: inside
 * the parser, "the length field disagrees with the block size" and "the
 * version is from the future" are different bugs, and a caller that cannot tell
 * them apart will report the wrong reason for a real one.  Everything except
 * OW_CIS_FORMAT_OK collapses to OW_CIS_VERDICT_REJECT_MALFORMED at the
 * verification boundary. */
typedef enum _OW_CIS_FORMAT_STATUS {
    OW_CIS_FORMAT_OK = 0,
    OW_CIS_FORMAT_NULL_ARGUMENT,
    OW_CIS_FORMAT_BAD_MAGIC,
    OW_CIS_FORMAT_UNSUPPORTED_VERSION,
    OW_CIS_FORMAT_BAD_HEADER_SIZE,
    OW_CIS_FORMAT_BAD_BLOCK_SIZE,
    OW_CIS_FORMAT_BLOCK_TOO_LARGE,
    OW_CIS_FORMAT_MANIFEST_TOO_LARGE,
    OW_CIS_FORMAT_RESERVED_NOT_ZERO,
    OW_CIS_FORMAT_BAD_PREFIX,
    OW_CIS_FORMAT_TAGS_NOT_ASCENDING,
    OW_CIS_FORMAT_DUPLICATE_TAG,
    OW_CIS_FORMAT_BAD_TAG_LENGTH,
    OW_CIS_FORMAT_VALUE_HAS_NUL,
    OW_CIS_FORMAT_VALUE_NOT_UTF8,
    OW_CIS_FORMAT_MISSING_REQUIRED_TAG,
    OW_CIS_FORMAT_UNSUPPORTED_DIGEST_ALGO,
    OW_CIS_FORMAT_TOO_MANY_TAGS
} OW_CIS_FORMAT_STATUS;

/* A parsed block.  Every pointer refers into the caller's buffer and is valid
 * only while that buffer is; nothing here owns storage, and nothing here is
 * allocated.  A field is NULL when the tag carrying it was absent, which for the
 * required tags cannot survive a successful parse. */
typedef struct _OW_CIS_BLOCK {
    const uint8_t* Buffer;      /* start of the block                        */
    uint32_t       BlockSize;   /* bytes occupied, signature included        */
    uint32_t       ManifestSize;

    /* The exact bytes to verify, and how many.  Handed to the signature
     * verifier as-is; the caller must not rebuild them. */
    const uint8_t* Signed;
    uint32_t       SignedSize;

    const uint8_t* Signature;   /* OW_CIS_SIGNATURE_SIZE bytes at the end    */

    /* Contents of the required tags, already range-checked. */
    uint32_t       DigestAlgorithm;
    uint8_t        KeyId[OW_CIS_KEY_ID_SIZE];
    uint8_t        ContentDigest[OW_SHA256_DIGEST_SIZE];

    /* Contents of the text tags, as byte ranges.  Not NUL terminated: the value
     * is a counted range by construction, and appending a terminator would put
     * a byte in the value that the signature never covered. */
    const uint8_t* License;
    uint32_t       LicenseSize;
    const uint8_t* Copyright;
    uint32_t       CopyrightSize;
    const uint8_t* BuildId;     /* NULL when absent */
    uint32_t       BuildIdSize;
    const uint8_t* PolicyClass; /* NULL when absent, e.g. "CORE_KERNEL" */
    uint32_t       PolicyClassSize;
    const uint8_t* SourceDigest;/* NULL when absent, 32 bytes SHA-256 */
    uint32_t       SourceDigestSize;

    uint32_t       TagCount;
} OW_CIS_BLOCK;

/* Parse a block occupying the whole of [Block, Block + Available), where
 * Available is everything from the block's first byte to the end of the file.
 * Trailing bytes past the block are ignored.
 *
 * Rejects: a bad magic or version, a header_size other than 48, reserved fields
 * that are not zero, a block_size that does not equal header_size +
 * manifest_size + 64, a manifest longer than OW_CIS_MAX_MANIFEST_SIZE, a
 * block that runs past Available, a manifest without its 32-byte prefix,
 * tags that do not strictly ascend, a required tag that is missing or the
 * wrong length, a NUL inside a *text* value, text that is not valid UTF-8,
 * and a digest algorithm other than SHA-256.
 *
 * Returns OW_CIS_FORMAT_OK and fills *Out, or leaves *Out untouched and
 * returns the specific reason.  Nothing in this function hashes, verifies, or
 * looks at a key: parsing and deciding are separate steps so that "this block
 * is malformed" stays distinguishable from "this block is not trusted". */
OW_CIS_FORMAT_STATUS OwCisFormatParse(const void* Block, uint32_t Available,
                                      OW_CIS_BLOCK* Out);

/* Human-readable name for a parse failure, for the load-path log. */
const char* OwCisFormatStatusName(OW_CIS_FORMAT_STATUS Status);

/* True when `Value[0..Size)` is well-formed UTF-8 under the rules above.
 * Exposed because the host test drives it directly over a crafted corpus, and a
 * validator reachable only through a full parse cannot be given a case that the
 * surrounding lengths would reject first. */
bool OwCisFormatIsValidUtf8(const uint8_t* Value, uint32_t Size);

/* True when the value contains no NUL byte. */
bool OwCisFormatHasNoNul(const uint8_t* Value, uint32_t Size);

/* Little-endian 16- and 32-bit readers.  Named rather than cast so that no
 * signed byte sequence is ever produced by dereferencing a misaligned or
 * wrongly-endian load. */
uint16_t OwCisFormatReadU16(const uint8_t* P);
uint32_t OwCisFormatReadU32(const uint8_t* P);

#endif /* OW_CIS_FORMAT_H */