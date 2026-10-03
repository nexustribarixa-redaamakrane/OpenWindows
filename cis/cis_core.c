/* cis_core.c - Copyleft Integrity Safeguard: enforcement state
 *
 * Stage 1 of CIS: the tables the whole subsystem rests on and nothing else.
 * No verification decision is made here.  What lives here is the trust store,
 * the measurement log, the policy record, and the lifecycle around them.
 *
 * Two properties are load-bearing and are the reason this file is as plain as
 * it is:
 *
 *   1. OwCisIsReady() is false until OwCisInitialize() has returned success,
 *      and the image loader refuses to map anything while it is false.  That
 *      is the fail-closed direction: a CIS that never came up is a machine on
 *      which no executable runs, which is an outage, not a bypass.
 *
 *   2. Nothing in this file can promote a verdict.  Verdict values arrive from
 *      OwCisRecordVerdict() and are recorded verbatim; the only judgement made
 *      locally is whether a verdict permits execution, and that function is a
 *      pure lookup on the enum.  A code path that could quietly turn a
 *      rejection into a pass would make every audit of this subsystem
 *      worthless.
 *
 * C99 freestanding, no dynamic allocation, no floating point. */

#include "../inc/ow_cis.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_ps.h"

#include "cis_keys.h"

#define OW_CIS_MAGIC_READY 0x43495331u /* "CIS1" */

static struct {
    uint32_t            Magic;
    OW_CIS_POLICY       Policy;
    OW_CIS_TRUST_KEY    Keys[OW_CIS_MAX_TRUST_KEYS];
    uint32_t            KeyCount;
    OW_CIS_RECORD       Records[OW_CIS_MAX_RECORDS];
    uint32_t            RecordCount;
    uint32_t            RejectedCount;
    uint32_t            LastRejection;
    bool                HasLastRejection;
} g_Cis;

/* Bounded copy of a caller-supplied name.  The name is used for reporting, so
 * a missing or oversized one must degrade to something printable rather than
 * become a wild pointer in the log. */
static void cis_copy_name(char* Dst, size_t DstSize, const char* Src) {
    size_t i = 0;

    if (DstSize == 0) {
        return;
    }
    if (Src) {
        while (i + 1 < DstSize && Src[i] != '\0') {
            Dst[i] = Src[i];
            i++;
        }
    }
    Dst[i] = '\0';
}

static void cis_copy_bytes(uint8_t* Dst, size_t DstSize, const uint8_t* Src) {
    size_t i;

    if (!Src) {
        ow_memset(Dst, 0, DstSize);
        return;
    }
    for (i = 0; i < DstSize; i++) {
        Dst[i] = Src[i];
    }
}

static bool cis_ready(void) {
    return g_Cis.Magic == OW_CIS_MAGIC_READY;
}

/* Copy the compiled-in trust anchors into the live trust store.  Count is a
 * parameter rather than the macro so the loop survives an unprovisioned build
 * (where the count is 0) without becoming a comparison the compiler can prove
 * dead, which -Werror rejects and which would leave the table never read. */
static void cis_install_pinned(uint32_t Count) {
    uint32_t i;

    for (i = 0; i < Count && i < OW_CIS_MAX_TRUST_KEYS; i++) {
        OW_CIS_TRUST_KEY* key = &g_Cis.Keys[g_Cis.KeyCount];

        ow_memset(key, 0, sizeof(*key));
        cis_copy_name(key->Name, sizeof(key->Name), OW_CIS_PINNED_KEYS[i].Name);
        cis_copy_bytes(key->KeyId, OW_CIS_KEY_ID_SIZE, OW_CIS_PINNED_KEYS[i].KeyId);
        cis_copy_bytes(key->PublicKey, OW_CIS_PUBLIC_KEY_SIZE,
                       OW_CIS_PINNED_KEYS[i].PublicKey);
        key->Flags = OW_CIS_PINNED_KEYS[i].Flags;
        key->Revoked = false;
        g_Cis.KeyCount++;
    }
}

OW_STATUS OwCisInitialize(void) {
    uint32_t i;

    /* Idempotent, because a boot that re-runs initialization must not be able
     * to clear the measurement log and start the subsystem over. */
    if (cis_ready()) {
        return OW_SUCCESS;
    }

    for (i = 0; i < OW_CIS_MAX_TRUST_KEYS; i++) {
        ow_memset(&g_Cis.Keys[i], 0, sizeof(g_Cis.Keys[i]));
    }
    for (i = 0; i < OW_CIS_MAX_RECORDS; i++) {
        ow_memset(&g_Cis.Records[i], 0, sizeof(g_Cis.Records[i]));
    }
    g_Cis.KeyCount = 0;
    g_Cis.RecordCount = 0;
    g_Cis.RejectedCount = 0;
    g_Cis.LastRejection = 0;
    g_Cis.HasLastRejection = false;

    /* Defaults fail closed on every axis that matters.  RequireSignature is
     * true and there is no path here that turns it off; the field exists so
     * the value is visible in one place rather than implied by which build
     * variant is running. */
    g_Cis.Policy.RequireSignature = true;
    g_Cis.Policy.AllowUnsignedRecovery = false;
    g_Cis.Policy.MaxImageSize = OW_CIS_DEFAULT_MAX_IMAGE_SIZE;

    /* The count is passed in rather than read from the macro inside the loop:
     * an unprovisioned build has OW_CIS_PINNED_KEY_COUNT == 0, and a loop
     * bounded by that constant directly is a comparison the compiler proves
     * can never succeed -- which -Werror refuses, and rightly, because it
     * would mean the body was never even type-checked against the table. */
    cis_install_pinned(OW_CIS_PINNED_KEY_COUNT);

    /* Armed last.  Nothing above this line can observe a half-built trust
     * store, because the loader's readiness check does not pass until it. */
    g_Cis.Magic = OW_CIS_MAGIC_READY;

    ow_kprintf("[CIS] enforcement armed: %u pinned key(s), signatures "
               "mandatory, unsigned recovery %s\r\n",
               (unsigned)g_Cis.KeyCount,
               g_Cis.Policy.AllowUnsignedRecovery ? "allowed" : "refused");
    if (g_Cis.KeyCount == 0) {
        ow_kprintf("[CIS] no pinned keys: every image will be refused until a "
                   "release key is provisioned\r\n");
    }

    return OW_SUCCESS;
}

bool OwCisIsReady(void) {
    return cis_ready();
}

uint32_t OwCisTrustedKeyCount(void) {
    return g_Cis.KeyCount;
}

const OW_CIS_TRUST_KEY* OwCisTrustedKeyAt(uint32_t Index) {
    if (Index >= g_Cis.KeyCount) {
        return (const OW_CIS_TRUST_KEY*)0;
    }
    return &g_Cis.Keys[Index];
}

const OW_CIS_TRUST_KEY* OwCisLookupKeyId(const uint8_t* KeyId) {
    uint32_t i;

    if (!KeyId) {
        return (const OW_CIS_TRUST_KEY*)0;
    }
    for (i = 0; i < g_Cis.KeyCount; i++) {
        if (ow_memcmp(g_Cis.Keys[i].KeyId, KeyId, OW_CIS_KEY_ID_SIZE) == 0) {
            return &g_Cis.Keys[i];
        }
    }
    return (const OW_CIS_TRUST_KEY*)0;
}

const OW_CIS_TRUST_KEY* OwCisLookupKey(const uint8_t* PublicKey) {
    uint32_t i;

    if (!PublicKey) {
        return (const OW_CIS_TRUST_KEY*)0;
    }
    for (i = 0; i < g_Cis.KeyCount; i++) {
        if (ow_memcmp(g_Cis.Keys[i].PublicKey, PublicKey,
                      OW_CIS_PUBLIC_KEY_SIZE) == 0) {
            return &g_Cis.Keys[i];
        }
    }
    return (const OW_CIS_TRUST_KEY*)0;
}

#ifdef OW_HOST_HAL
/* Host-build test injection.  Under this guard the trust store is writable so
 * the host harness can prove the accept path end to end; the production build
 * has no such call, and the production private key is not on the machine in
 * either case.  Both facts are asserted by the host test. */
OW_STATUS OwCisTestInjectKey(const char* Name, const uint8_t* PublicKey,
                             const uint8_t* KeyId, uint32_t Flags) {
    OW_CIS_TRUST_KEY* key;

    if (!cis_ready()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!PublicKey || !KeyId) {
        return OW_ERR_NULL_POINTER;
    }
    if (g_Cis.KeyCount >= OW_CIS_MAX_TRUST_KEYS) {
        return OW_ERR_INSUFFICIENT;
    }
    key = &g_Cis.Keys[g_Cis.KeyCount];
    ow_memset(key, 0, sizeof(*key));
    cis_copy_name(key->Name, sizeof(key->Name), Name);
    cis_copy_bytes(key->KeyId, OW_CIS_KEY_ID_SIZE, KeyId);
    cis_copy_bytes(key->PublicKey, OW_CIS_PUBLIC_KEY_SIZE, PublicKey);
    key->Flags = Flags;
    key->Revoked = false;
    g_Cis.KeyCount++;
    return OW_SUCCESS;
}

void OwCisTestClearInjected(void) {
    uint32_t i;

    if (!cis_ready()) {
        return;
    }
    for (i = OW_CIS_PINNED_KEY_COUNT; i < g_Cis.KeyCount; i++) {
        ow_memset(&g_Cis.Keys[i], 0, sizeof(g_Cis.Keys[i]));
    }
    g_Cis.KeyCount = OW_CIS_PINNED_KEY_COUNT;
}

/* Host-build revocation.
 *
 * Revocation is a property of the trust anchor, not of the block, so nothing in
 * the file format can reach OW_CIS_VERDICT_REJECT_KEY_REVOKED.  Without this call
 * that verdict is unreachable from every test, which is the same as untested: a
 * verifier that ran the signature check before the revoked check would still
 * pass the suite, and that ordering is precisely the bug where a revoked key
 * keeps working.  Injection above exists for the same reason.
 *
 * There is no production caller.  A production build's revocation state comes
 * from the pinned table, which is a build-time decision. */
OW_STATUS OwCisTestRevokeKeyId(const uint8_t* KeyId) {
    uint32_t i;

    if (!cis_ready()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!KeyId) {
        return OW_ERR_NULL_POINTER;
    }
    for (i = 0U; i < g_Cis.KeyCount; i++) {
        if (ow_memcmp(g_Cis.Keys[i].KeyId, KeyId, OW_CIS_KEY_ID_SIZE) == 0) {
            g_Cis.Keys[i].Revoked = true;
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

/* The inverse, so a revocation test does not have to run last and poison every
 * test after it.  Order dependence in a suite is its own kind of lie: a test
 * that only passes in one sequence is not asserting anything. */
OW_STATUS OwCisTestUnrevokeKeyId(const uint8_t* KeyId) {
    uint32_t i;

    if (!cis_ready()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!KeyId) {
        return OW_ERR_NULL_POINTER;
    }
    for (i = 0U; i < g_Cis.KeyCount; i++) {
        if (ow_memcmp(g_Cis.Keys[i].KeyId, KeyId, OW_CIS_KEY_ID_SIZE) == 0) {
            g_Cis.Keys[i].Revoked = false;
            return OW_SUCCESS;
        }
    }
    return OW_ERR_NOT_FOUND;
}

/* Host-build arm and disarm.
 *
 * Disarming is the direction that matters, and it exists only so the harness can
 * reach the one branch that production cannot be talked out of.  OwCisInitialize()
 * is idempotent and every other entry point refuses to lower the readiness flag,
 * so once armed there is no way back -- which is the point: a subsystem whose
 * readiness some caller could clear is not an authority, and a test that could
 * only ever observe the armed state would never prove that the unready state
 * refuses.  A mutation that deletes the readiness check in OwCisVerifyImage
 * passes every other test in the suite and fails only here.
 *
 * Nothing in the kernel calls this.  There is no production disarm. */
void OwCisTestDisarm(void) {
    g_Cis.Magic = 0u;
}

/* Re-arm through the real entry point rather than by setting the flag directly,
 * so the trust store and policy are rebuilt by the same code that builds them at
 * boot rather than by a test-only shortcut that could differ.
 *
 * Note the consequence: a disarmed subsystem is not ready, so this path runs the
 * full initialization and clears the measurement log.  That is the correct
 * reading of the state -- a subsystem that was not armed has no history to
 * preserve, since it was refusing everything and recording nothing -- but it
 * means a test that disarms mid-suite loses the log, and must not assert on
 * counts taken before the disarm. */
OW_STATUS OwCisTestArm(void) {
    if (OwCisInitialize() != OW_SUCCESS) {
        return OW_ERR_NOT_INITIALIZED;
    }
    return OW_SUCCESS;
}
#endif /* OW_HOST_HAL */
const OW_CIS_POLICY* OwCisPolicy(void) {
    return &g_Cis.Policy;
}

OW_STATUS OwCisSetUnsignedRecoveryAllowed(bool Allow) {
    if (!cis_ready()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    /* RequireSignature is not negotiable through this API and never is.
     * Unsigned recovery is a policy relaxation, not a signature relaxation,
     * so it can be argued with separately and only while CIS is armed. */
    g_Cis.Policy.AllowUnsignedRecovery = Allow;
    return OW_SUCCESS;
}

OW_STATUS OwCisRecordVerdict(const char* Image,
                             const uint8_t* Digest,
                             uint32_t ImageSize,
                             uint32_t Subsystem,
                             uint32_t SourcePid,
                             uint32_t Flags,
                             OW_CIS_VERDICT Verdict,
                             OW_STATUS Detail,
                             const uint8_t* KeyId) {
    OW_CIS_RECORD* rec;

    if (!cis_ready()) {
        return OW_ERR_NOT_INITIALIZED;
    }
    if (!Image) {
        return OW_ERR_NULL_POINTER;
    }
    if (g_Cis.RecordCount >= OW_CIS_MAX_RECORDS) {
        /* The table is append-only.  Refusing the new entry keeps every
         * decision already taken, which is the only useful thing a full log
         * can do; overwriting the oldest would leave the subsystem reporting
         * a clean history that it no longer has. */
        return OW_ERR_INSUFFICIENT;
    }

    rec = &g_Cis.Records[g_Cis.RecordCount];
    ow_memset(rec, 0, sizeof(*rec));
    cis_copy_name(rec->Image, sizeof(rec->Image), Image);
    if (Digest) {
        cis_copy_bytes(rec->Digest, OW_SHA256_DIGEST_SIZE, Digest);
    }
    if (KeyId) {
        cis_copy_bytes(rec->KeyId, OW_CIS_KEY_ID_SIZE, KeyId);
    }
    rec->ImageSize = ImageSize;
    rec->Subsystem = Subsystem;
    rec->Timestamp = (uint64_t)OwPsGetTickCount();
    rec->SourcePid = SourcePid;
    rec->Verdict = Verdict;
    rec->Detail = Detail;
    rec->Flags = Flags;

    if (!OwCisVerdictAllowsExecution(Verdict)) {
        g_Cis.RejectedCount++;
        g_Cis.LastRejection = g_Cis.RecordCount;
        g_Cis.HasLastRejection = true;
    }

    g_Cis.RecordCount++;
    return OW_SUCCESS;
}

const OW_CIS_RECORD* OwCisRecordAt(uint32_t Index) {
    if (Index >= g_Cis.RecordCount) {
        return (const OW_CIS_RECORD*)0;
    }
    return &g_Cis.Records[Index];
}

uint32_t OwCisRecordCount(void) {
    return g_Cis.RecordCount;
}

uint32_t OwCisRejectedCount(void) {
    return g_Cis.RejectedCount;
}

const OW_CIS_RECORD* OwCisLastRejection(void) {
    if (!g_Cis.HasLastRejection) {
        return (const OW_CIS_RECORD*)0;
    }
    return &g_Cis.Records[g_Cis.LastRejection];
}

void OwCisResetRecords(void) {
    uint32_t i;

    for (i = 0; i < OW_CIS_MAX_RECORDS; i++) {
        ow_memset(&g_Cis.Records[i], 0, sizeof(g_Cis.Records[i]));
    }
    g_Cis.RecordCount = 0;
    g_Cis.RejectedCount = 0;
    g_Cis.LastRejection = 0;
    g_Cis.HasLastRejection = false;
}

const char* OwCisVerdictName(OW_CIS_VERDICT Verdict) {
    switch (Verdict) {
    case OW_CIS_VERDICT_NONE:                    return "NONE";
    case OW_CIS_VERDICT_TRUSTED:                 return "TRUSTED";
    case OW_CIS_VERDICT_REJECT_UNSIGNED:         return "UNSIGNED";
    case OW_CIS_VERDICT_REJECT_BAD_SIGNATURE:    return "BAD-SIGNATURE";
    case OW_CIS_VERDICT_REJECT_UNKNOWN_KEY:      return "UNKNOWN-KEY";
    case OW_CIS_VERDICT_REJECT_KEY_REVOKED:      return "KEY-REVOKED";
    case OW_CIS_VERDICT_REJECT_DIGEST_MISMATCH:  return "DIGEST-MISMATCH";
    case OW_CIS_VERDICT_REJECT_MALFORMED:        return "MALFORMED";
    case OW_CIS_VERDICT_REJECT_POLICY:           return "POLICY-REFUSED";
    case OW_CIS_VERDICT_COMPLIANT_REFUSAL:       return "NONCOMPLIANT";
    case OW_CIS_VERDICT_ERROR:                   return "ERROR";
    default:                                     return "INVALID";
    }
}

bool OwCisVerdictAllowsExecution(OW_CIS_VERDICT Verdict) {
    /* Only TRUSTED and NONE permit a mapping.  NONE is what a caller passes
     * when it has not asked CIS at all; the loader never treats a NONE it did
     * not request as an answer, so including it here is about keeping this
     * function a total function of its argument, not about opening a door. */
    return Verdict == OW_CIS_VERDICT_TRUSTED || Verdict == OW_CIS_VERDICT_NONE;
}
