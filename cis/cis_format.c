/* cis_format.c - the CIS block parser
 *
 * Strictly a parser.  It reads bytes, proves they are canonical, and reports
 * what they say.  It does not hash, does not verify a signature, does not
 * consult the trust store, and cannot return anything but OK or a reason the
 * bytes are unusable.  Every one of those decisions belongs to cis_verify.c,
 * and keeping them apart is what lets a log say "malformed" when the block was
 * nonsense and "untrusted" when the block was fine but nobody signed it.
 *
 * The bounds discipline throughout: a length is added to an offset only after
 * both have been shown to fit in a uint32_t, and every comparison is against
 * `Available` rather than against a trusted `BlockSize`, because BlockSize is
 * the number an hostile writer controls.  Nothing is indexed before its bounds
 * are established, and no pointer is formed from an unchecked arithmetic
 * result.
 *
 * C99 freestanding, no dynamic allocation, no floating point. */

#include "../inc/ow_cis_format.h"
#include "../inc/ow_mem.h"

/* Field offsets, spelled out.  These are the signed bytes' meaning; see the
 * header for why there is no struct. */
#define CIS_OFF_MAGIC          0x00u
#define CIS_OFF_BLOCK_VERSION  0x04u
#define CIS_OFF_HEADER_SIZE    0x06u
#define CIS_OFF_BLOCK_SIZE     0x08u
#define CIS_OFF_MANIFEST_SIZE  0x0Cu
#define CIS_OFF_RESERVED0      0x10u
#define CIS_OFF_FLAGS          0x14u
#define CIS_OFF_RESERVED1      0x18u
#define CIS_OFF_RESERVED2      0x28u

#define CIS_SIZE_MAGIC         4u
#define CIS_SIZE_U16           2u
#define CIS_SIZE_U32           4u
#define CIS_SIZE_RESERVED1     16u
#define CIS_SIZE_RESERVED2     8u

/* A TLV header is u16 tag + u16 length. */
#define CIS_TLV_HEADER_SIZE 4u

uint16_t OwCisFormatReadU16(const uint8_t* P) {
    return (uint16_t)((uint16_t)P[0] | (uint16_t)((uint16_t)P[1] << 8));
}

uint32_t OwCisFormatReadU32(const uint8_t* P) {
    return (uint32_t)P[0] | ((uint32_t)P[1] << 8) | ((uint32_t)P[2] << 16) |
           ((uint32_t)P[3] << 24);
}

bool OwCisFormatHasNoNul(const uint8_t* Value, uint32_t Size) {
    uint32_t i;

    for (i = 0U; i < Size; i++) {
        if (Value[i] == 0U) {
            return false;
        }
    }
    return true;
}

/* UTF-8 validation, written to reject the encodings a decoder is entitled to
 * treat as errors in different ways.  A permissive validator and a strict one
 * both "accept" the same overlong form; they differ on what they mean by
 * accept, and the signer here is a different program from the verifier.  So the
 * narrow rules are the only ones used:
 *
 *   - 1 byte:  0x01..0x7F   (0x00 is separately rejected as a NUL)
 *   - 2 bytes: 0xC2..0xDF 0x80..0xBF
 *   - 3 bytes: 0xE0 0xA0..0xBF 0x80..0xBF        (excludes overlong)
 *              0xE1..0xEC 0x80..0xBF 0x80..0xBF
 *              0xED 0x80..0x9F 0x80..0xBF        (excludes surrogates)
 *              0xEE..0xEF 0x80..0xBF 0x80..0xBF
 *   - 4 bytes: 0xF0 0x90..0xBF 0x80..0xBF 0x80..0xBF   (excludes overlong)
 *              0xF1..0xF3 0x80..0xBF 0x80..0xBF 0x80..0xBF
 *              0xF4 0x80..0x8F 0x80..0xBF 0x80..0xBF   (caps at U+10FFFF)
 *
 * Truncated sequences at the end of the value fail, so a value is never
 * interpreted as text plus a silently dropped tail. */
bool OwCisFormatIsValidUtf8(const uint8_t* Value, uint32_t Size) {
    uint32_t i = 0U;

    if (!Value) {
        return false;
    }
    while (i < Size) {
        uint8_t b0 = Value[i];

        if (b0 == 0x00u) {
            /* Not a UTF-8 error in the abstract, but a NUL inside a counted
             * value is exactly what the canonical form forbids. */
            return false;
        }
        if (b0 < 0x80u) {
            i += 1U;
            continue;
        }
        if (b0 >= 0xC2u && b0 <= 0xDFu) {
            if (i + 1U >= Size) {
                return false;
            }
            if ((Value[i + 1u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 2U;
            continue;
        }
        if (b0 == 0xE0u) {
            if (i + 2U >= Size) {
                return false;
            }
            if (Value[i + 1u] < 0xA0u || Value[i + 1u] > 0xBFu) {
                return false;
            }
            if ((Value[i + 2u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 3U;
            continue;
        }
        if ((b0 >= 0xE1u && b0 <= 0xECu) || b0 == 0xEEu || b0 == 0xEFu) {
            if (i + 2U >= Size) {
                return false;
            }
            if ((Value[i + 1u] & 0xC0u) != 0x80u ||
                (Value[i + 2u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 3U;
            continue;
        }
        if (b0 == 0xEDu) {
            /* Surrogate range D800..DFFF is not a character. */
            if (i + 2U >= Size) {
                return false;
            }
            if (Value[i + 1u] < 0x80u || Value[i + 1u] > 0x9Fu) {
                return false;
            }
            if ((Value[i + 2u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 3U;
            continue;
        }
        if (b0 == 0xF0u) {
            if (i + 3U >= Size) {
                return false;
            }
            if (Value[i + 1u] < 0x90u || Value[i + 1u] > 0xBFu) {
                return false;
            }
            if ((Value[i + 2u] & 0xC0u) != 0x80u ||
                (Value[i + 3u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 4U;
            continue;
        }
        if (b0 >= 0xF1u && b0 <= 0xF3u) {
            if (i + 3U >= Size) {
                return false;
            }
            if ((Value[i + 1u] & 0xC0u) != 0x80u ||
                (Value[i + 2u] & 0xC0u) != 0x80u ||
                (Value[i + 3u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 4U;
            continue;
        }
        if (b0 == 0xF4u) {
            if (i + 3U >= Size) {
                return false;
            }
            if (Value[i + 1u] < 0x80u || Value[i + 1u] > 0x8Fu) {
                return false;
            }
            if ((Value[i + 2u] & 0xC0u) != 0x80u ||
                (Value[i + 3u] & 0xC0u) != 0x80u) {
                return false;
            }
            i += 4U;
            continue;
        }
        /* 0x80..0xC1 and 0xF5..0xFF have no valid form. */
        return false;
    }
    return true;
}

/* True when every byte of [0, Reserved1 + Reserved2) following the flags field is
 * zero.  Read as a range rather than field by field so a future reserved field
 * is covered by construction instead of by remembering to add a check. */
static bool cis_reserved_clear(const uint8_t* P) {
    uint32_t i;
    const uint32_t size = CIS_SIZE_RESERVED1 + CIS_SIZE_RESERVED2;

    for (i = 0U; i < size; i++) {
        if (P[i] != 0U) {
            return false;
        }
    }
    return true;
}

/* Whether a tag's value must be valid UTF-8.  Binary tags have a fixed width,
 * and running a text rule over them would reject bytes that are perfectly good
 * key identifiers. */
static bool cis_tag_is_text(uint16_t Tag) {
    switch (Tag) {
    case OW_CIS_TAG_LICENSE:
    case OW_CIS_TAG_COPYRIGHT:
    case OW_CIS_TAG_BUILD_ID:
        return true;
    default:
        return false;
    }
}

/* The exact width a binary tag must have, or 0 for tags with no fixed width
 * (text, and unknown). */
static uint32_t cis_tag_fixed_size(uint16_t Tag) {
    switch (Tag) {
    case OW_CIS_TAG_DIGEST_ALGO:    return CIS_SIZE_U32;
    case OW_CIS_TAG_KEY_ID:         return OW_CIS_KEY_ID_SIZE;
    case OW_CIS_TAG_CONTENT_DIGEST: return OW_SHA256_DIGEST_SIZE;
    default:                        return 0u;
    }
}



/* Walk the TLVs once, checking order and value shape, and copy out the tags the
 * caller needs.  A single pass with a `previous` tag rather than a per-tag scan
 * is what makes duplicates and reordering impossible: with ascending order
 * enforced, a second occurrence of a tag is by construction not greater than
 * the last one seen. */
static OW_CIS_FORMAT_STATUS cis_scan_tlvs(const uint8_t* Manifest,
                                          uint32_t Size,
                                          OW_CIS_BLOCK* Out) {
    uint32_t offset = OW_CIS_MANIFEST_PREFIX_SIZE;
    uint16_t previous = 0U;
    bool have_previous = false;
    uint32_t count = 0U;

    /* Required tags, tracked as seen/not seen.  A bitmap indexed by tag would
     * be 8 KiB for a 16-bit tag space; the count of required tags is small and
     * known, so they are tracked directly. */
    bool seen_license = false;
    bool seen_algo = false;
    bool seen_key_id = false;
    bool seen_digest = false;
    bool seen_copyright = false;

    while (offset < Size) {
        uint16_t tag;
        uint16_t value_size;
        const uint8_t* value;
        uint32_t fixed;

        /* A TLV needs its header plus at least a byte of value.  Testing the
         * header alone would let a trailing 2 bytes be read as a length with
         * nothing behind it. */
        if ((uint64_t)Size - offset < CIS_TLV_HEADER_SIZE) {
            return OW_CIS_FORMAT_TAGS_NOT_ASCENDING;
        }
        tag = OwCisFormatReadU16(&Manifest[offset]);
        value_size = OwCisFormatReadU16(&Manifest[offset + CIS_SIZE_U16]);
        offset += CIS_TLV_HEADER_SIZE;

        if (have_previous && tag <= previous) {
            return (tag == previous) ? OW_CIS_FORMAT_DUPLICATE_TAG
                                     : OW_CIS_FORMAT_TAGS_NOT_ASCENDING;
        }
        previous = tag;
        have_previous = true;

        if ((uint64_t)Size - offset < value_size) {
            return OW_CIS_FORMAT_BAD_TAG_LENGTH;
        }
        value = &Manifest[offset];
        offset += value_size;

        fixed = cis_tag_fixed_size(tag);
        if (fixed != 0U && (uint32_t)value_size != fixed) {
            return OW_CIS_FORMAT_BAD_TAG_LENGTH;
        }

        /* Text values must be free of NUL.  Binary values need not be, and rejecting
         * them for one would reject the digest algorithm -- which is 01 00 00 00
         * little-endian, so three NULs in four bytes.  The rule is about the
         * difference between a counted byte range and a C string, and that
         * difference only exists for values that are meant to be read as text. */
        if (cis_tag_is_text(tag) &&
            OwCisFormatHasNoNul(value, (uint32_t)value_size) == false) {
            return OW_CIS_FORMAT_VALUE_HAS_NUL;
        }
        if (cis_tag_is_text(tag) &&
            OwCisFormatIsValidUtf8(value, (uint32_t)value_size) == false) {
            return OW_CIS_FORMAT_VALUE_NOT_UTF8;
        }

        /* Each TLV consumed at least CIS_TLV_HEADER_SIZE bytes, so the manifest
         * length already bounds the tag count.  Checked rather than assumed:
         * the manifest size is a field this parser has proved consistent with
         * the block size, but "proved consistent" is not "proved small", and a
         * count that cannot exceed the manifest is worth saying out loud. */
        count++;
        if ((uint64_t)count * CIS_TLV_HEADER_SIZE > (uint64_t)Size) {
            return OW_CIS_FORMAT_TOO_MANY_TAGS;
        }

        switch (tag) {
        case OW_CIS_TAG_LICENSE:
            Out->License = value;
            Out->LicenseSize = (uint32_t)value_size;
            seen_license = true;
            break;
        case OW_CIS_TAG_DIGEST_ALGO:
            Out->DigestAlgorithm = OwCisFormatReadU32(value);
            seen_algo = true;
            break;
        case OW_CIS_TAG_KEY_ID:
            ow_memcpy(Out->KeyId, value, OW_CIS_KEY_ID_SIZE);
            seen_key_id = true;
            break;
        case OW_CIS_TAG_CONTENT_DIGEST:
            ow_memcpy(Out->ContentDigest, value, OW_SHA256_DIGEST_SIZE);
            seen_digest = true;
            break;
        case OW_CIS_TAG_COPYRIGHT:
            Out->Copyright = value;
            Out->CopyrightSize = (uint32_t)value_size;
            seen_copyright = true;
            break;
        case OW_CIS_TAG_BUILD_ID:
            Out->BuildId = value;
            Out->BuildIdSize = (uint32_t)value_size;
            break;
        default:
            /* Unknown tag, accepted and not relied on.  The bounds above have
             * already proved the value lies inside the manifest. */
            break;
        }
    }

    /* Each missing required tag is reported as such.  They share one status
     * because they mean the same thing -- the manifest cannot be evaluated --
     * and the log line naming the verdict does not gain anything from
     * distinguishing which of the five was absent. */
    if (!seen_license) {
        return OW_CIS_FORMAT_MISSING_REQUIRED_TAG;
    }
    if (!seen_algo) {
        return OW_CIS_FORMAT_MISSING_REQUIRED_TAG;
    }
    if (!seen_key_id) {
        return OW_CIS_FORMAT_MISSING_REQUIRED_TAG;
    }
    if (!seen_digest) {
        return OW_CIS_FORMAT_MISSING_REQUIRED_TAG;
    }
    if (!seen_copyright) {
        return OW_CIS_FORMAT_MISSING_REQUIRED_TAG;
    }

    Out->TagCount = count;
    return OW_CIS_FORMAT_OK;
}

OW_CIS_FORMAT_STATUS OwCisFormatParse(const void* Block, uint32_t Available,
                                      OW_CIS_BLOCK* Out) {
    const uint8_t* p = (const uint8_t*)Block;
    uint32_t block_size;
    uint32_t manifest_size;
    uint32_t header_size;
    uint16_t version;
    uint32_t minimal;
    OW_CIS_BLOCK parsed;

    if (!p || !Out) {
        return OW_CIS_FORMAT_NULL_ARGUMENT;
    }

    /* A block cannot be smaller than its own header.  Checked against
     * `Available`, which is the only length the caller vouches for. */
    if (Available < OW_CIS_BLOCK_HEADER_SIZE) {
        return OW_CIS_FORMAT_BAD_MAGIC;
    }
    if (OwCisFormatReadU32(&p[CIS_OFF_MAGIC]) != OW_CIS_BLOCK_MAGIC) {
        return OW_CIS_FORMAT_BAD_MAGIC;
    }

    version = OwCisFormatReadU16(&p[CIS_OFF_BLOCK_VERSION]);
    if (version != OW_CIS_BLOCK_VERSION) {
        /* Not "malformed": a future version is a format this parser was not
         * written for, and guessing at its layout is how a parser ends up
         * accepting something it never checked. */
        return OW_CIS_FORMAT_UNSUPPORTED_VERSION;
    }

    header_size = (uint32_t)OwCisFormatReadU16(&p[CIS_OFF_HEADER_SIZE]);
    if (header_size != OW_CIS_BLOCK_HEADER_SIZE) {
        /* A header_size other than 48 describes a different header, so the
         * offsets above cannot be trusted to describe this one. */
        return OW_CIS_FORMAT_BAD_HEADER_SIZE;
    }

    if (OwCisFormatReadU32(&p[CIS_OFF_RESERVED0]) != 0U) {
        return OW_CIS_FORMAT_RESERVED_NOT_ZERO;
    }
    if (OwCisFormatReadU32(&p[CIS_OFF_FLAGS]) != OW_CIS_FLAG_NONE) {
        /* No flag is defined.  A non-zero value means the writer set a bit this
         * verifier has never had to interpret, which is not a reason to refuse
         * today but is emphatically not a reason to ignore it silently. */
        return OW_CIS_FORMAT_RESERVED_NOT_ZERO;
    }
    if (cis_reserved_clear(&p[CIS_OFF_RESERVED1]) == false) {
        return OW_CIS_FORMAT_RESERVED_NOT_ZERO;
    }

    block_size = OwCisFormatReadU32(&p[CIS_OFF_BLOCK_SIZE]);
    manifest_size = OwCisFormatReadU32(&p[CIS_OFF_MANIFEST_SIZE]);

    /* One layout, not offsets to cross-check: the block is exactly the header,
     * the manifest, and the signature.  Written as an inequality that cannot
     * wrap, since a 32-bit sum of three u32 fields would. */
    minimal = OW_CIS_BLOCK_HEADER_SIZE + OW_CIS_SIGNATURE_SIZE;
    if (block_size < minimal) {
        return OW_CIS_FORMAT_BAD_BLOCK_SIZE;
    }
    if ((uint64_t)block_size !=
        (uint64_t)OW_CIS_BLOCK_HEADER_SIZE + (uint64_t)manifest_size +
            (uint64_t)OW_CIS_SIGNATURE_SIZE) {
        return OW_CIS_FORMAT_BAD_BLOCK_SIZE;
    }
    if (manifest_size > OW_CIS_MAX_MANIFEST_SIZE) {
        return OW_CIS_FORMAT_MANIFEST_TOO_LARGE;
    }
    if (block_size > Available) {
        return OW_CIS_FORMAT_BAD_BLOCK_SIZE;
    }
    

    /* The manifest must fit inside the block with room for the signature.  The
     * equality above already guarantees this; the explicit test is what lets a
     * reader see that the manifest pointer is bounded, rather than inferring it
     * from a distance. */
    if ((uint64_t)OW_CIS_BLOCK_HEADER_SIZE + (uint64_t)manifest_size >
        (uint64_t)block_size - (uint64_t)OW_CIS_SIGNATURE_SIZE) {
        return OW_CIS_FORMAT_BAD_BLOCK_SIZE;
    }

    /* The domain separator: 23 characters of prefix followed by 9 bytes of zero
     * padding to fill the 32.  Compared as a byte string rather than read as a
     * C string, because a string comparison would stop at the padding and accept
     * any bytes there -- which are signed bytes, and so part of the domain. */
    {
        const uint8_t* prefix = &p[OW_CIS_BLOCK_HEADER_SIZE];
        const uint32_t text = (uint32_t)(sizeof(OW_CIS_MANIFEST_PREFIX) - 1u);
        uint32_t i;

        if (ow_memcmp(prefix, OW_CIS_MANIFEST_PREFIX, (size_t)text) != 0) {
            return OW_CIS_FORMAT_BAD_PREFIX;
        }
        for (i = text; i < OW_CIS_MANIFEST_PREFIX_SIZE; i++) {
            if (prefix[i] != 0U) {
                return OW_CIS_FORMAT_BAD_PREFIX;
            }
        }
    }

    /* Build into a local and commit on success, so a caller that passes an
     * OW_CIS_BLOCK it still cares about does not get a half-populated struct
     * from a failed parse. */
    ow_memset(&parsed, 0, sizeof(parsed));
    parsed.Buffer = p;
    parsed.BlockSize = block_size;
    parsed.ManifestSize = manifest_size;
    parsed.Signed = p;
    parsed.SignedSize = block_size - OW_CIS_SIGNATURE_SIZE;
    parsed.Signature = &p[block_size - OW_CIS_SIGNATURE_SIZE];

    {
        OW_CIS_FORMAT_STATUS status =
            cis_scan_tlvs(p + OW_CIS_BLOCK_HEADER_SIZE, manifest_size, &parsed);
        if (status != OW_CIS_FORMAT_OK) {
            return status;
        }
    }

    if (parsed.DigestAlgorithm != OW_CIS_DIGEST_ALGO_SHA256) {
        return OW_CIS_FORMAT_UNSUPPORTED_DIGEST_ALGO;
    }

    *Out = parsed;
    return OW_CIS_FORMAT_OK;
}

const char* OwCisFormatStatusName(OW_CIS_FORMAT_STATUS Status) {
    switch (Status) {
    case OW_CIS_FORMAT_OK:                       return "ok";
    case OW_CIS_FORMAT_NULL_ARGUMENT:            return "null argument";
    case OW_CIS_FORMAT_BAD_MAGIC:                return "bad magic";
    case OW_CIS_FORMAT_UNSUPPORTED_VERSION:      return "unsupported version";
    case OW_CIS_FORMAT_BAD_HEADER_SIZE:          return "bad header size";
    case OW_CIS_FORMAT_BAD_BLOCK_SIZE:           return "bad block size";
    case OW_CIS_FORMAT_BLOCK_TOO_LARGE:          return "block too large";
    case OW_CIS_FORMAT_MANIFEST_TOO_LARGE:       return "manifest too large";
    case OW_CIS_FORMAT_RESERVED_NOT_ZERO:        return "reserved field not zero";
    case OW_CIS_FORMAT_BAD_PREFIX:               return "bad manifest prefix";
    case OW_CIS_FORMAT_TAGS_NOT_ASCENDING:       return "tags not ascending";
    case OW_CIS_FORMAT_DUPLICATE_TAG:            return "duplicate tag";
    case OW_CIS_FORMAT_BAD_TAG_LENGTH:           return "bad tag length";
    case OW_CIS_FORMAT_VALUE_HAS_NUL:            return "NUL in value";
    case OW_CIS_FORMAT_VALUE_NOT_UTF8:           return "value is not UTF-8";
    case OW_CIS_FORMAT_MISSING_REQUIRED_TAG:     return "missing required tag";
    case OW_CIS_FORMAT_UNSUPPORTED_DIGEST_ALGO:  return "unsupported digest algorithm";
    case OW_CIS_FORMAT_TOO_MANY_TAGS:            return "too many tags";
    default:                                     return "invalid";
    }
}