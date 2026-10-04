/* cis_verify.c - Copyleft Integrity Safeguard: the verification decision
 *
 * This is where a block becomes a verdict.  Everything here exists to turn a
 * buffer of image bytes plus an optional trailing block into exactly one
 * OW_CIS_VERDICT, and the shape of the function is the shape of that decision:
 *
 *     not armed -> bounds -> parse -> digest -> trust -> signature -> policy
 *
 * The order is neither arbitrary nor negotiable.  Each step is a precondition
 * for the next, so running them out of order would mean answering a question
 * about bytes that were never shown to be well formed.  It also makes the
 * verdicts disjoint by construction: a block that is both unsigned and has a
 * bad digest is reported as unsigned, because "nobody signed this" is the more
 * informative answer and the digest question would not have been reached.
 *
 * The three properties ow_cis.h keeps apart are kept apart here as well.  A
 * verdict of TRUSTED means all of:
 *
 *   the block parsed                      it is well formed
 *   SHA-256(image) == the manifest digest these are the bytes that were signed
 *   the key id names a pinned key         someone we trust signed it
 *   that key is not revoked
 *   the signature verifies over the block it really is their signature
 *   the key may sign this kind of image
 *   policy permits the licence            and permits it
 *
 * and each has its own rejection verdict when it fails.  In particular a valid
 * signature over a valid digest still returns REJECT_POLICY when the licence is
 * refused: a signature is a statement about the bytes, not an override of the
 * policy, and collapsing the two would make the licence check decorative.
 *
 * Fail closed throughout.  An unparsed block, an unrecognised digest algorithm
 * and a trust store with no keys all produce refusals, and no branch anywhere in
 * this file says "if we could not tell, allow".  Adding one would be the single
 * change that turns the subsystem into decoration.
 *
 * C99 freestanding, fixed-size tables, no dynamic allocation. */

#include "../inc/ow_cis.h"
#include "../inc/ow_cis_format.h"
#include "../inc/ow_ed25519.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_owx.h"
#include "../inc/ow_sha256.h"

/* Longest licence expression the policy table will consider.  Longer is not
 * "probably the same licence" -- it is a string this code has no basis to
 * reason about, so it is refused. */
#define OW_CIS_LICENSE_MAX 64u

/* Licence expressions this build accepts.
 *
 * A fixed table, and deliberately a short one.  An entry here is a claim about
 * what this project is willing to execute, and the table is where that claim
 * lives so it can be read rather than inferred.  Adding an entry is a policy
 * decision with a review attached, which is the entire reason the check is a
 * table lookup and not a licence-expression parser: a parser in the kernel
 * would be a much larger thing to get right, and would make the same decision
 * three different ways depending on how the string was written. */
static const char* const cis_accepted_licenses[] = {
    "MIT",
    "MIT OR Apache-2.0",
    "Apache-2.0",
    "BSD-3-Clause",
    "BSD-2-Clause"
};

#define CIS_ACCEPTED_LICENSE_COUNT \
    (sizeof(cis_accepted_licenses) / sizeof(cis_accepted_licenses[0]))

/* Compare a counted byte range against a NUL-terminated literal.
 *
 * Not a strcmp and not a memcmp either.  The manifest's licence value is a byte
 * range, not a string: there is no terminator in it, because a terminator would
 * be a byte the signature never covered and a parser might read past.  So the
 * length has to be part of the comparison, and it has to be checked first --
 * otherwise "MIT" would match the prefix of "MIT-0" and a refusal would become
 * a pass on the strength of its first three letters. */
static bool cis_equals_literal(const uint8_t* Value, uint32_t Size,
                               const char* Literal) {
    uint32_t i;

    if (!Value || !Literal) {
        return false;
    }
    for (i = 0U; Literal[i] != '\0'; i++) {
        if (i >= Size) {
            return false;
        }
        if (Value[i] != (uint8_t)Literal[i]) {
            return false;
        }
    }
    /* The literal is exhausted; the value must be too, or the value is longer
     * than the thing it was being compared against. */
    return i == Size;
}

static bool cis_license_permitted(const uint8_t* License, uint32_t Size) {
    uint32_t i;

    /* All three preconditions below are redundant with the comparison itself,
     * and deliberately so.  Each is checked because the cost of being wrong is
     * asymmetric: the comparison fails closed on all three anyway (an oversized
     * string matches no short literal, a zero-length one matches nothing, and
     * the parser already guarantees a non-NULL pointer when it reports a
     * licence), so a reader cannot tell from the mutation tests whether these
     * lines matter.  Keeping them means the function states its own
     * preconditions instead of relying on a caller's guarantee.  Their absence
     * would not be a defect today; their presence keeps that true if the parser
     * or the table ever changes underneath it. */
    if (License == (const uint8_t*)0 || Size == 0U ||
        Size > OW_CIS_LICENSE_MAX) {
        return false;
    }
    for (i = 0U; i < CIS_ACCEPTED_LICENSE_COUNT; i++) {
        if (cis_equals_literal(License, Size, cis_accepted_licenses[i])) {
            return true;
        }
    }
    return false;
}

/* Evaluate active policy class and license compliance.
 *
 * For CORE_KERNEL:
 *   - must declare policy class "CORE_KERNEL"
 *   - must carry an authenticated "GPL-3.0-or-later" license expression
 *   - must carry an authenticated 32-byte source manifest digest
 *
 * For generic/userspace:
 *   - must satisfy cis_accepted_licenses table (MIT, Apache-2.0, BSD)
 */
static bool cis_policy_permitted(const OW_CIS_BLOCK* Block, uint32_t Subsystem) {
    if (!Block) {
        return false;
    }

    /* An image declaring CORE_KERNEL or mapped as the native kernel subsystem
     * must satisfy the CORE_KERNEL copyleft policy. */
    if (Block->PolicyClass != (const uint8_t*)0 || Subsystem == OWX_SUBSYSTEM_NATIVE) {
        if (Block->PolicyClass == (const uint8_t*)0 ||
            !cis_equals_literal(Block->PolicyClass, Block->PolicyClassSize, "CORE_KERNEL")) {
            ow_kprintf("[CIS] policy refused: kernel image missing or invalid CORE_KERNEL policy class\r\n");
            return false;
        }

        /* CORE_KERNEL policy requires GPL copyleft compliance. */
        if (!cis_equals_literal(Block->License, Block->LicenseSize, "GPL-3.0-or-later")) {
            ow_kprintf("[CIS] policy refused: CORE_KERNEL requires GPL-3.0-or-later\r\n");
            return false;
        }

        /* CORE_KERNEL policy requires bound source/license manifest provenance. */
        if (Block->SourceDigest == (const uint8_t*)0 ||
            Block->SourceDigestSize != OW_SHA256_DIGEST_SIZE) {
            ow_kprintf("[CIS] policy refused: CORE_KERNEL requires source manifest digest\r\n");
            return false;
        }

        return true;
    }

    /* Userspace and subsystem-level policy (MIT, Apache-2.0, BSD). */
    return cis_license_permitted(Block->License, Block->LicenseSize);
}

/* Does this key carry the authority to sign an image of this kind?
 *
 * Checked rather than assumed from the key being pinned.  A key provisioned for
 * recovery images is not thereby entitled to sign a release image, and a trust
 * store that cannot express the difference should say so rather than let the
 * presence of a key imply the authority. */
static bool cis_key_may_sign(uint32_t KeyFlags, uint32_t Subsystem) {
    if (Subsystem == OWX_SUBSYSTEM_RECOVERY) {
        return (KeyFlags &
                (OW_CIS_KEY_FLAG_RELEASE | OW_CIS_KEY_FLAG_RECOVERY)) != 0U;
    }
    return (KeyFlags & OW_CIS_KEY_FLAG_RELEASE) != 0U;
}

/* Record the decision and hand it back, so no path through this file can return
 * a verdict without also leaving it in the measurement log.  A log that
 * disagreed with the return value would make every audit of the subsystem
 * worthless, and the two are easy to let drift apart in a function this branchy. */
static OW_CIS_VERDICT cis_record(const char* Image, const uint8_t* Digest,
                                 uint32_t ImageSize, const uint8_t* KeyId,
                                 uint32_t Subsystem, uint32_t SourcePid,
                                 uint32_t Flags, OW_CIS_VERDICT Verdict,
                                 OW_STATUS Detail) {
    /* Substituted here rather than at each call site so that every path records
     * the same placeholder.  Left to OwCisRecordVerdict, a NULL name would store
     * an empty string: indistinguishable in the log from an image whose name
     * genuinely was empty, which is precisely the ambiguity a placeholder exists
     * to remove. */
    (void)OwCisRecordVerdict(Image != NULL ? Image : "<unnamed>", Digest,
                             ImageSize, Subsystem, SourcePid, Flags, Verdict,
                             Detail, KeyId);
    return Verdict;
}

/* Print a key id as hex.  Written out rather than formatted through a helper
 * because the kernel has no printf hex verb and because a truncated key id in a
 * log is worse than a long one: an operator matching it against a trust store
 * needs all 32 hex digits. */
static void cis_log_key_id(const uint8_t* KeyId) {
    uint32_t i;

    if (KeyId == (const uint8_t*)0) {
        ow_kprintf("<none>");
        return;
    }
    for (i = 0U; i < OW_CIS_KEY_ID_SIZE; i++) {
        ow_kprintf("%02X", KeyId[i]);
    }
}

OW_CIS_VERDICT OwCisVerifyImage(const void* Image, uint32_t ImageSize,
                                uint32_t Available, uint32_t Subsystem,
                                uint32_t SourcePid, const char* ImageName,
                                uint32_t Flags) {
    const OW_CIS_POLICY* policy;
    const OW_CIS_TRUST_KEY* key;
    OW_CIS_BLOCK block;
    OW_CIS_FORMAT_STATUS fmt;
    uint8_t actual[OW_SHA256_DIGEST_SIZE];

    /* ---- not armed ------------------------------------------------------
     * Distinguished from every content verdict because the answer is "CIS did
     * not run", not "CIS said no".  An operator chasing a boot failure needs to
     * see that difference, and this branch is the only one that can produce it:
     * once past here, CIS has spoken. */
    if (OwCisIsReady() == false) {
        ow_kprintf("[CIS] %s refused: enforcement is not armed\r\n",
                   ImageName ? ImageName : "<unnamed>");
        return OW_CIS_VERDICT_ERROR;
    }

/* A NULL name is not an error here.  The name is a reporting label, and
     * OwCisRecordVerdict already substitutes "<unnamed>" for it; refusing a load
     * because a log line had no label would turn a cosmetic defect into an
     * outage, and would make the label's presence a de facto authorisation.  A
     * NULL image is different -- there is nothing to evaluate. */
    if (Image == (const void*)0) {
        return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                          (const uint8_t*)0, Subsystem, SourcePid, Flags,
                          OW_CIS_VERDICT_ERROR, OW_ERR_NULL_POINTER);
    }

    policy = OwCisPolicy();

    /* ---- bounds before work ---------------------------------------------
     * A huge ImageSize is refused without being hashed, so the cost of refusing
     * a lie does not scale with the size of the lie. */
    if (ImageSize < OWX_HEADER_SIZE) {
        return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                          (const uint8_t*)0, Subsystem, SourcePid, Flags,
                          OW_CIS_VERDICT_REJECT_MALFORMED, OW_ERR_CORRUPT);
    }
    if (policy->MaxImageSize != 0U && ImageSize > policy->MaxImageSize) {
        ow_kprintf("[CIS] %s refused: %u bytes is over the %u-byte bound\r\n",
                   ImageName, (unsigned)ImageSize,
                   (unsigned)policy->MaxImageSize);
        return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                          (const uint8_t*)0, Subsystem, SourcePid, Flags,
                          OW_CIS_VERDICT_REJECT_POLICY, OW_ERR_INSUFFICIENT);
    }
    if (Available < ImageSize) {
        /* Fewer bytes in hand than the image claims to need: the file is
         * truncated, so there is nothing to evaluate.  Not the same as a
         * malformed block, and worth not conflating.
         *
         * This guard is load-bearing in a way the verdict cannot show.  Past it
         * the parser is handed Available - ImageSize, so without the check that
         * subtraction wraps to roughly four billion and the parser is pointed at
         * a four-billion-byte range starting here.  The result is still
         * MALFORMED either way -- the bytes past the end are not a CIS block --
         * which is exactly why it is easy to delete this and see no difference.
         * test_truncation_cannot_read_past_available in tools/hosttest puts the
         * image against an unreadable page so the overread faults instead of
         * quietly reading whatever the allocator left next to the buffer. */
        return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                          (const uint8_t*)0, Subsystem, SourcePid, Flags,
                          OW_CIS_VERDICT_REJECT_MALFORMED, OW_ERR_CORRUPT);
    }

    /* ---- no block --------------------------------------------------------
     * Distinguished from a broken block, because the two call for different
     * responses.  "There is no signature at all" is the expected state of every
     * unsigned image ever shipped and is a fact about how the file was built;
     * "there is a signature and it is malformed" means someone appended
     * something.  Reporting both as MALFORMED would bury the second inside the
     * first, which is the wrong way round: the interesting case is the rarer
     * one.
     *
     * REJECT_UNSIGNED is also what policy.RequireSignature asks for.  The field
     * is read here rather than only at the loader so the verdict and the policy
     * cannot disagree about which images require a signature.
     *
     * Policy.AllowUnsignedRecovery is deliberately not consulted.  Every verdict
     * OwCisVerdictAllowsExecution accepts is TRUSTED, so permitting an unsigned
     * recovery image from inside this function would mean returning TRUSTED for
     * an image with no signature -- a lie in the only field anyone audits.  The
     * relaxation belongs in the loader, at the point where it decides to enter
     * the recovery path at all, and is recorded as a distinct flag there rather
     * than smuggled in here. */
    if (Available == ImageSize) {
        if (policy->RequireSignature) {
            ow_kprintf("[CIS] %s refused: no signature\r\n", ImageName);
            return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                              (const uint8_t*)0, Subsystem, SourcePid, Flags,
                              OW_CIS_VERDICT_REJECT_UNSIGNED, OW_SUCCESS);
        }
        /* RequireSignature off is not reachable from any API, so this branch is
         * the shape a relaxation would take.  It still refuses rather than
         * passing, because the only verdict that would authorise a mapping is
         * TRUSTED and nothing here has established trust. */
        return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                          (const uint8_t*)0, Subsystem, SourcePid, Flags,
                          OW_CIS_VERDICT_REJECT_UNSIGNED, OW_SUCCESS);
    }

    /* ---- parse ----------------------------------------------------------
     * The block is the bytes from ImageSize to the end of the file.  Nothing
     * here tries the other interpretation -- a block starting somewhere else --
     * because then a signed block could be appended past a forged image_size and
     * ignored, or an unsigned image given a length that placed its bytes inside
     * a signed block's range.  One rule, stated once, is what keeps the digest
     * and the signature covering the same bytes. */
    fmt = OwCisFormatParse((const uint8_t*)Image + ImageSize,
                           Available - ImageSize, &block);
    if (fmt != OW_CIS_FORMAT_OK) {
        ow_kprintf("[CIS] %s refused: block is malformed (%s)\r\n", ImageName,
                   OwCisFormatStatusName(fmt));
        return cis_record(ImageName, (const uint8_t*)0, ImageSize,
                          (const uint8_t*)0, Subsystem, SourcePid, Flags,
                          OW_CIS_VERDICT_REJECT_MALFORMED, OW_ERR_CORRUPT);
    }

    /* ---- digest ---------------------------------------------------------
     * Over exactly the bytes that will be mapped: [0, ImageSize).  The block is
     * not in that range, so it is not in the digest -- it is covered by the
     * signature instead.  Comparing the computed digest against the manifest's
     * before touching the signature is deliberate: "these bytes are not the ones
     * that were signed" is the finding, and it holds regardless of whether the
     * signature is any good. */
    ow_sha256(Image, (size_t)ImageSize, actual);
    if (ow_memcmp(actual, block.ContentDigest, OW_SHA256_DIGEST_SIZE) != 0) {
        ow_kprintf("[CIS] %s refused: content digest does not match the signed "
                   "digest\r\n", ImageName);
        return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                          SourcePid, Flags, OW_CIS_VERDICT_REJECT_DIGEST_MISMATCH,
                          OW_SUCCESS);
    }

    /* ---- trust ----------------------------------------------------------
     * "Nobody we know signed this" and "that signature is wrong" are the two
     * findings an operator acts on most differently -- the first means find out
     * who holds the key, the second means find out what changed -- so the key
     * lookup is a verdict of its own and is never collapsed into "invalid". */
    key = OwCisLookupKeyId(block.KeyId);
    if (key == (const OW_CIS_TRUST_KEY*)0) {
        ow_kprintf("[CIS] %s refused: no pinned key matches key id ", ImageName);
        cis_log_key_id(block.KeyId);
        ow_kprintf("\r\n");
        return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                          SourcePid, Flags, OW_CIS_VERDICT_REJECT_UNKNOWN_KEY,
                          OW_SUCCESS);
    }
    if (key->Revoked) {
        ow_kprintf("[CIS] %s refused: key %s is revoked\r\n", ImageName,
                   key->Name);
        return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                          SourcePid, Flags, OW_CIS_VERDICT_REJECT_KEY_REVOKED,
                          OW_SUCCESS);
    }

    /* ---- signature -------------------------------------------------------
     * The signed message is the block's own bytes up to the signature: a
     * pointer into the caller's buffer, not a reassembly from fields.  A
     * reassembly would be a second copy that could disagree with the first, and
     * the only byte excluded from the signed range is the signature itself, by
     * construction. */
    if (ow_crypto_ed25519_verify(key->PublicKey, block.Signature, block.Signed,
                                 (size_t)block.SignedSize) == false) {
        ow_kprintf("[CIS] %s refused: signature does not verify under %s\r\n",
                   ImageName, key->Name);
        return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                          SourcePid, Flags, OW_CIS_VERDICT_REJECT_BAD_SIGNATURE,
                          OW_SUCCESS);
    }

    /* ---- policy ----------------------------------------------------------
     * Everything above established that these exact bytes carry a signature from
     * a key we trust.  This asks a different question -- whether the declaration
     * those bytes carry is one we are willing to execute -- and can still
     * refuse.  Keeping it last is what makes POLICY a real outcome rather than
     * a formality, and it is the reason a valid signature is not an answer. */
    if (cis_key_may_sign(key->Flags, Subsystem) == false) {
        ow_kprintf("[CIS] %s refused: %s may not sign subsystem %u\r\n", ImageName,
                   key->Name, (unsigned)Subsystem);
        return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                          SourcePid, Flags, OW_CIS_VERDICT_REJECT_POLICY,
                          OW_SUCCESS);
    }
    if (cis_policy_permitted(&block, Subsystem) == false) {
        ow_kprintf("[CIS] %s refused: policy refused\r\n", ImageName);
        return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                          SourcePid, Flags, OW_CIS_VERDICT_REJECT_POLICY,
                          OW_SUCCESS);
    }

    ow_kprintf("[CIS] %s: TRUSTED, signed by %s, licence accepted\r\n",
               ImageName, key->Name);
    return cis_record(ImageName, actual, ImageSize, block.KeyId, Subsystem,
                      SourcePid, Flags, OW_CIS_VERDICT_TRUSTED, OW_SUCCESS);
}