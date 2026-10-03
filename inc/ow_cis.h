/* ow_cis.h - Copyleft Integrity Safeguard (CIS)
 *
 * CIS is the Ring 0 enforcement point for Copyleft Integrity.  It answers one
 * question and refuses everything it cannot answer affirmatively: may these
 * exact bytes be mapped as an executable image?
 *
 * Authority lives here, in the kernel, on the load path.  The PID 2 cis.owx
 * service is a reporting and management surface over this state; it is never
 * consulted before a load is allowed, and killing it changes no verdict.  A
 * subsystem whose only authority can be switched off by killing a process is
 * not an authority.
 *
 * Three properties are deliberately kept apart and are never collapsed into
 * one "verified" answer:
 *
 *   integrity     the bytes hashed to the digest the packer stamped in
 *   authenticity  those bytes were signed by a pinned key
 *   compliance    the signed metadata satisfies the active policy
 *
 * A valid signature over a valid digest still fails if policy refuses the
 * licence expression, and a fully compliant licence expression over tampered
 * bytes still fails.  SPDX identifiers in metadata are declarations by the
 * signer, not proof of anything, and are treated as claims to be evaluated
 * against policy rather than as evidence.
 *
 * Fail closed.  Before OwCisInitialize() has run, every verdict is refusal.
 *
 * C99 freestanding, fixed-size tables, no dynamic allocation. */
#ifndef OW_CIS_H
#define OW_CIS_H

#include "ow_types.h"
#include "ow_sha256.h"

/* Ed25519 (RFC 8032).  Verification only: the kernel never holds a signing
 * key and has no code path that could produce one. */
#define OW_CIS_PUBLIC_KEY_SIZE 32
#define OW_CIS_SIGNATURE_SIZE  64
#define OW_CIS_KEY_ID_SIZE     16

#define OW_CIS_MAX_TRUST_KEYS 8
#define OW_CIS_MAX_RECORDS    64
#define OW_CIS_NAME_SIZE       128

/* Verdict.  The distinction between the rejection reasons is the whole point
 * of the subsystem: "nobody signed this" and "the signer is not trusted" and
 * "the signature does not match these bytes" call for three different
 * responses, and collapsing them into one "invalid" is what makes copyleft
 * enforcement unauditable. */
typedef enum _OW_CIS_VERDICT {
    OW_CIS_VERDICT_NONE = 0,
    /* Signed by a pinned, non-revoked key; digest matches; policy permits. */
    OW_CIS_VERDICT_TRUSTED,
    /* Structurally sound but carries no signature. */
    OW_CIS_VERDICT_REJECT_UNSIGNED,
    /* Signature present but does not verify over the signed bytes. */
    OW_CIS_VERDICT_REJECT_BAD_SIGNATURE,
    /* Signature is valid under a key the trust store does not pin. */
    OW_CIS_VERDICT_REJECT_UNKNOWN_KEY,
    /* Key is pinned but revoked. */
    OW_CIS_VERDICT_REJECT_KEY_REVOKED,
    /* Signature covers a different payload than the bytes being loaded. */
    OW_CIS_VERDICT_REJECT_DIGEST_MISMATCH,
    /* Container (.owc) or OWX metadata is malformed or self-inconsistent. */
    OW_CIS_VERDICT_REJECT_MALFORMED,
    /* Signature and digest are good; the policy refuses the contents. */
    OW_CIS_VERDICT_REJECT_POLICY,
    /* Trusted, but the signer asserts non-compliance and policy forbids it. */
    OW_CIS_VERDICT_COMPLIANT_REFUSAL,
    /* Verification could not be completed (bounds, storage, algorithm). */
    OW_CIS_VERDICT_ERROR
} OW_CIS_VERDICT;

#define OW_CIS_KEY_FLAG_RELEASE   0x00000001U /* signs release images      */
#define OW_CIS_KEY_FLAG_RECOVERY  0x00000002U /* signs recovery images    */
#define OW_CIS_KEY_FLAG_TEST_ONLY 0x00000004U /* host builds only         */

typedef struct _OW_CIS_TRUST_KEY {
    char    Name[OW_CIS_NAME_SIZE];
    uint8_t KeyId[OW_CIS_KEY_ID_SIZE];
    uint8_t PublicKey[OW_CIS_PUBLIC_KEY_SIZE];
    uint32_t Flags;
    bool    Revoked;
} OW_CIS_TRUST_KEY;

/* What the loader was asked to do, and what came of it. */
#define OW_CIS_RECORD_BOOT        0x00000001U /* kernel boot hand-off     */
#define OW_CIS_RECORD_SPAWN       0x00000002U /* OW_SYS_PS_SPAWN_OWX      */
#define OW_CIS_RECORD_QUARANTINED 0x00000004U /* payload moved aside      */

typedef struct _OW_CIS_RECORD {
    char           Image[OW_CIS_NAME_SIZE];
    uint8_t        Digest[OW_SHA256_DIGEST_SIZE];
    uint8_t        KeyId[OW_CIS_KEY_ID_SIZE];
    uint32_t       ImageSize;
    uint32_t       Subsystem;
    uint64_t       Timestamp;   /* kernel tick at the decision */
    uint32_t       SourcePid;   /* 0 for the kernel's own boot path */
    OW_CIS_VERDICT Verdict;
    OW_STATUS      Detail;      /* underlying OW_STATUS, OW_SUCCESS when clean */
    uint32_t       Flags;
} OW_CIS_RECORD;

typedef struct _OW_CIS_POLICY {
    /* Mandatory signature enforcement.  Present as a field so the value is
     * explicit and auditable rather than implied by a build flag; the loader
     * refuses to run when it is false rather than downgrading. */
    bool     RequireSignature;
    /* Whether an unsigned recovery image may be entered.  Off by default:
     * a rescue path that skips the integrity check is the easiest way to
     * turn an integrity subsystem into a persistence mechanism. */
    bool     AllowUnsignedRecovery;
    /* Largest image CIS will measure, as a bounds check before hashing. */
    uint32_t MaxImageSize;
} OW_CIS_POLICY;

/* ---- Lifecycle ---------------------------------------------------------- */

/* Arms enforcement.  Must succeed before any image load; the loader refuses
 * everything while this has not run. */
OW_STATUS OwCisInitialize(void);

/* True once enforcement is armed. */
bool OwCisIsReady(void);

/* ---- Trust store -------------------------------------------------------- */

uint32_t OwCisTrustedKeyCount(void);
const OW_CIS_TRUST_KEY* OwCisTrustedKeyAt(uint32_t Index);
const OW_CIS_TRUST_KEY* OwCisLookupKeyId(const uint8_t* KeyId);
const OW_CIS_TRUST_KEY* OwCisLookupKey(const uint8_t* PublicKey);

/* Test-only key injection, compiled into host builds only (OW_HOST_HAL).
 * There is no production caller: the production trust store is the pinned
 * table, and the private key that corresponds to it lives off the machine. */
OW_STATUS OwCisTestInjectKey(const char* Name, const uint8_t* PublicKey,
                             const uint8_t* KeyId, uint32_t Flags);
void     OwCisTestClearInjected(void);

/* Host-build revocation.  Revocation lives on the trust anchor rather than in
 * the block, so no fixture can reach OW_CIS_VERDICT_REJECT_KEY_REVOKED without
 * this; a verdict no test can produce is a verdict nothing holds up. */
OW_STATUS OwCisTestRevokeKeyId(const uint8_t* KeyId);
OW_STATUS OwCisTestUnrevokeKeyId(const uint8_t* KeyId);

/* Host-build disarm, so the harness can reach the branch that refuses while CIS
 * is not armed.  Production has no disarm: OwCisInitialize() is idempotent and no
 * entry point lowers the readiness flag, so once armed there is no way back. */
void     OwCisTestDisarm(void);
OW_STATUS OwCisTestArm(void);

/* ---- Policy ------------------------------------------------------------- */

const OW_CIS_POLICY* OwCisPolicy(void);
OW_STATUS             OwCisSetUnsignedRecoveryAllowed(bool Allow);

/* ---- Verification ------------------------------------------------------ */

/* Decide one OW_CIS_VERDICT for a buffer that holds an image and possibly a
 * trailing CIS block.
 *
 *   Image       first byte of the image; the OWX header starts here
 *   ImageSize   hdr->image_size: the bytes that will be mapped and executed
 *   Available   bytes in hand from Image onward, including any trailing block
 *   Subsystem   OWX_SUBSYSTEM_* from the image header
 *   SourcePid   recorded with the verdict; 0 for the kernel's own boot path
 *   ImageName   label for the measurement log.  May be NULL, and is then
 *               recorded as "<unnamed>"; a missing label is a reporting defect,
 *               not grounds for refusing an otherwise valid image
 *   Flags       OW_CIS_RECORD_* bits to store with the verdict
 *
 * The block, if present, is exactly [Image + ImageSize, Image + Available).
 * Trailing bytes past the block are ignored.
 *
 * Runs parse -> digest -> trust -> signature -> policy, and every step is a
 * precondition for the next, so the verdicts do not overlap: a block that is
 * both unsigned and has a bad digest is reported as unsigned.  Each verdict
 * OwCisVerifyImage can return means a different thing to whoever has to respond
 * to it, and they are never merged into one "invalid".
 *
 * Fail closed.  Not armed, no trust anchors, an unparseable block and a licence
 * outside the accepted set all refuse.  There is no "could not tell, allow"
 * branch, and adding one would defeat the subsystem.
 *
 * Every verdict it returns is also written to the measurement log before it is
 * handed back, so the log and the return value cannot disagree.  The caller
 * still has to check the return value: a TRUSTED return is the only thing that
 * permits a mapping. */
OW_CIS_VERDICT OwCisVerifyImage(const void* Image, uint32_t ImageSize,
                                uint32_t Available, uint32_t Subsystem,
                                uint32_t SourcePid, const char* ImageName,
                                uint32_t Flags);

/* ---- Measurements ------------------------------------------------------- */

/* Record a decision.  Keeps the table append-only until it is full, then
 * refuses new entries rather than overwriting history; the counts are what a
 * human needs, and silently recycling the log destroys the only evidence a
 * quarantined system has. */
OW_STATUS OwCisRecordVerdict(const char* Image,
                             const uint8_t* Digest,
                             uint32_t ImageSize,
                             uint32_t Subsystem,
                             uint32_t SourcePid,
                             uint32_t Flags,
                             OW_CIS_VERDICT Verdict,
                             OW_STATUS Detail,
                             const uint8_t* KeyId);

/* Snapshot of one measurement, or NULL past the end of the log. */
const OW_CIS_RECORD* OwCisRecordAt(uint32_t Index);
uint32_t              OwCisRecordCount(void);
uint32_t              OwCisRejectedCount(void);
const OW_CIS_RECORD*   OwCisLastRejection(void);
void                   OwCisResetRecords(void);

/* ---- Names -------------------------------------------------------------- */

const char* OwCisVerdictName(OW_CIS_VERDICT Verdict);
bool        OwCisVerdictAllowsExecution(OW_CIS_VERDICT Verdict);

#endif /* OW_CIS_H */
