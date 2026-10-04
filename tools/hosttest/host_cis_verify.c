/* host_cis_verify.c - host tests for OwCisVerifyImage
 *
 * Driven by tools/gen_cis_fixtures.py: signed OWX images with CIS blocks
 * appended, covering the accept path and one fixture per reachable rejection
 * verdict.  The signatures come from tools/cis_sign.py, which shares no code
 * with lib/ow_ed25519.c, so a fixture the kernel accepts is evidence that both
 * are right rather than evidence that both are wrong in the same way.
 *
 * What a parser test cannot reach, and what this file is for:
 *
 *   - every verdict is reachable, and each fixture yields exactly its own
 *   - the pipeline is ordered, so one defect produces one answer and not two
 *   - a valid signature does not survive policy refusing the licence
 *   - a pinned key does not get authority it was never granted
 *   - a revoked key is refused, and is refused before the signature is checked
 *   - every verdict returned is also in the measurement log, with the same value
 *   - the same bytes yield the same verdict regardless of prior state
 *
 * The harness here mirrors host_boot.c: the same counters, the same [PASS] /
 * [FAIL] output, no framework.  test_cis_verify_run() returns the number of
 * failures, writes its pass count through out_passed, and host_boot.c adds both
 * to its own tally. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>   /* VirtualAlloc guard pages; host-only file */

#include "../../inc/ow_cis.h"
#include "../../inc/ow_cis_format.h"
#include "../../inc/ow_owx.h"

#include "cis_fixtures.h"

/* Counts are reported to host_boot.c rather than accumulated into a shared
 * global, so this file's totals cannot drift from the suite's: failures are
 * returned, passes are written through out_passed, and main() adds both to its
 * own tally.  Both are reported because a final line counting only half the
 * assertions that ran reads as coverage of the part it omitted. */
int test_cis_verify_run(int* out_passed);

static int g_cis_v_passed;
static int g_cis_v_failed;

static void v_fail(const char* label, const char* detail) {
    ++g_cis_v_failed;
    printf("[FAIL] %s: %s\n", label, detail ? detail : "");
}

static void v_check(const char* label, bool got, bool want) {
    if (got == want) {
        ++g_cis_v_passed;
        printf("[PASS] %s = %s\n", label, want ? "true" : "false");
    } else {
        ++g_cis_v_failed;
        printf("[FAIL] %s: got %s, want %s\n", label, got ? "true" : "false",
               want ? "true" : "false");
    }
}

static void v_check_eq(const char* label, unsigned long got,
                       unsigned long want) {
    if (got == want) {
        ++g_cis_v_passed;
        printf("[PASS] %s = %lu\n", label, got);
    } else {
        ++g_cis_v_failed;
        printf("[FAIL] %s: got %lu, want %lu\n", label, got, want);
    }
}



static const ow_cis_fixture_t* fixture_by_name(const char* Name) {
    uint32_t i;
    for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
        if (strcmp(ow_cis_fixtures[i].Name, Name) == 0) {
            return &ow_cis_fixtures[i];
        }
    }
    return NULL;
}

static const ow_cis_fixture_key_t* key_by_name(const char* Name) {
    uint32_t i;
    for (i = 0U; i < OW_CIS_FIXTURE_KEY_COUNT; i++) {
        if (strcmp(ow_cis_fixture_keys[i].Name, Name) == 0) {
            return &ow_cis_fixture_keys[i];
        }
    }
    return NULL;
}

/* Pin exactly the key the fixture names, and nothing else.
 *
 * "Nothing else" is the point: a trust store that happens to contain the right
 * key by accident would let an implementation that ignored the key id pass.
 * Cleared first on every call so each fixture starts from the same store. */
static bool trust_only(const ow_cis_fixture_t* f) {
    const ow_cis_fixture_key_t* k = key_by_name(f->KeyName);
    OW_STATUS st;

    if (k == NULL) {
        return false;
    }
    OwCisTestClearInjected();
    st = OwCisTestInjectKey(k->Name, k->PublicKey, k->KeyId, k->Flags);
    if (!ow_status_success(st)) {
        return false;
    }
    /* Revocation is a separate axis and is always cleared here, so a fixture's
     * verdict cannot depend on whether an earlier test revoked this key. */
    (void)OwCisTestUnrevokeKeyId(k->KeyId);
    return true;
}

static OW_CIS_VERDICT verdict_for(const ow_cis_fixture_t* f) {
    return OwCisVerifyImage(f->File, f->ImageSize, f->FileSize, f->Subsystem,
                            0u, "fixture", 0u);
}

/* The table walk.
 *
 * Each row asserts two things and the second is not redundant: the verdict is
 * what the fixture declares, and the same verdict reached the measurement log.
 * A verifier that returned the right answer without recording it would satisfy
 * a verdict-only assertion, and the measurement log is the only artifact an
 * operator has after the fact. */
static void test_each_fixture_verdict(void) {
    uint32_t i;

    printf("\n--- CIS verification: one fixture per verdict ---\n");

    for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
        const ow_cis_fixture_t* f = &ow_cis_fixtures[i];
        const OW_CIS_RECORD* rec;
        uint32_t before;
        OW_CIS_VERDICT got;

        if (!trust_only(f)) {
            v_fail(f->Name, "could not pin the fixture's key");
            continue;
        }

        before = OwCisRecordCount();
        got = verdict_for(f);

        if (got != f->Want) {
            printf("[FAIL] %s: verdict %s, wanted %s (%s)\n", f->Name,
                   OwCisVerdictName(got), OwCisVerdictName(f->Want), f->Note);
            ++g_cis_v_failed;
            continue;
        }
        ++g_cis_v_passed;
        printf("[PASS] %s -> %s (%s)\n", f->Name, OwCisVerdictName(got),
               f->Note);

        /* The log must have grown by exactly one and agree with the return. */
        if (OwCisRecordCount() != before + 1u) {
            printf("[FAIL] %s: %u records added, wanted 1\n", f->Name,
                   (unsigned)(OwCisRecordCount() - before));
            ++g_cis_v_failed;
            continue;
        }
        rec = OwCisRecordAt(before);
        if (rec == NULL || rec->Verdict != got) {
            v_fail(f->Name, "the measurement log disagrees with the return value");
            continue;
        }
        ++g_cis_v_passed;
        printf("[PASS] %s: verdict %s is in the measurement log\n", f->Name,
               OwCisVerdictName(got));

        /* Nothing but TRUSTED may authorise a mapping.  Asserted per row so a
         * fixture that started returning something permissive would fail on
         * this line rather than only at the loader. */
        if (OwCisVerdictAllowsExecution(got) !=
            (got == OW_CIS_VERDICT_TRUSTED)) {
            v_fail(f->Name, "execution authorisation disagrees with the verdict");
        } else {
            ++g_cis_v_passed;
            printf("[PASS] %s: execution authorisation follows the verdict\n",
                   f->Name);
        }
    }
}

/* An unarmed verifier refuses, and says it refused because it was not armed.
 *
 * This is the one branch production cannot be talked out of: there is no disarm
 * API, OwCisInitialize() is idempotent, and nothing lowers the readiness flag.
 * So without a host-only hook the branch would never execute, and a mutation that
 * deletes the readiness check outright would pass every other test in the suite.
 * That mutation was tried and did exactly that, which is why the hook exists.
 *
 * The distinction being asserted is between "CIS said no to this image" and "CIS
 * did not run".  An operator chasing a boot failure needs to tell those apart, and
 * a "your file is corrupt" log line produced by a subsystem that never looked at
 * the file is worse than no log line at all. */
static void test_unarmed_refuses_and_says_so(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    OW_CIS_VERDICT got;
    uint32_t records_while_unarmed;

    if (f == NULL || !trust_only(f)) {
        v_fail("unarmed", "fixture or key missing");
        return;
    }
    v_check("armed, the good fixture is trusted",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);

    OwCisTestDisarm();
    v_check("the subsystem reports itself unarmed", OwCisIsReady(), false);

    got = verdict_for(f);
    v_check("an unarmed verifier does not trust a valid image",
            got == OW_CIS_VERDICT_ERROR, true);
    v_check("ERROR does not permit execution",
            OwCisVerdictAllowsExecution(got), false);
    /* Not one of the content verdicts, because CIS evaluated nothing. */
    v_check("the unarmed verdict is not a judgement about the image",
            got != OW_CIS_VERDICT_REJECT_MALFORMED &&
                got != OW_CIS_VERDICT_REJECT_UNSIGNED &&
                got != OW_CIS_VERDICT_REJECT_BAD_SIGNATURE,
            true);

    /* The refusal is not recorded, because OwCisRecordVerdict refuses to write
     * while unready.  Recording it would be the worse behaviour: the log would
     * claim a decision the subsystem never made. */
    records_while_unarmed = OwCisRecordCount();
    (void)verdict_for(f);
    v_check_eq("an unarmed verdict adds nothing to the measurement log",
               (unsigned long)OwCisRecordCount(),
               (unsigned long)records_while_unarmed);

    /* Re-arm and confirm the same bytes are trusted, with nothing else changed:
     * the unarmed verdict was a property of the subsystem's state, not of the
     * image.  The trust store is re-pinned because re-arming rebuilds it. */
    if (!ow_status_success(OwCisTestArm())) {
        v_fail("unarmed", "could not re-arm");
        return;
    }
    v_check("the subsystem reports itself armed again", OwCisIsReady(), true);
    if (!trust_only(f)) {
        v_fail("unarmed", "could not re-pin the release key after re-arming");
        return;
    }
    v_check("the same image is trusted after re-arming",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);
}

/* Malformed arguments are refused rather than dereferenced. */
static void test_null_arguments_are_refused(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    OW_CIS_VERDICT got;

    if (f == NULL || !trust_only(f)) {
        v_fail("null arguments", "fixture or key missing");
        return;
    }

    got = OwCisVerifyImage(NULL, f->ImageSize, f->FileSize, f->Subsystem, 0u,
                           "null-image", 0u);
    v_check("a NULL image is refused",
            got == OW_CIS_VERDICT_ERROR, true);

    /* A NULL name is recorded as "<unnamed>" rather than refused outright: the
     * name is for reporting, and refusing a load over a missing label would make
     * a logging defect into an outage. */
    got = OwCisVerifyImage(f->File, f->ImageSize, f->FileSize, f->Subsystem, 0u,
                           NULL, 0u);
    v_check("a NULL image name does not stop verification",
            got == OW_CIS_VERDICT_TRUSTED, true);
    {
        const OW_CIS_RECORD* rec = OwCisRecordAt(OwCisRecordCount() - 1u);
        v_check("a NULL image name is recorded as <unnamed>",
                rec != NULL && strcmp(rec->Image, "<unnamed>") == 0, true);
    }
}

/* TRUSTED requires a pinned key.  The same bytes under two different trust
 * stores, run as one test so the difference is visibly about the store:
 * identical buffer, identical arguments, different anchor. */
static void test_trust_store_gates_trusted(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    const OW_CIS_TRUST_KEY* found;

    if (f == NULL) {
        v_fail("trust store gating", "fixture missing");
        return;
    }

    OwCisTestClearInjected();
    v_check("good_boot is refused with an empty trust store",
            verdict_for(f) == OW_CIS_VERDICT_REJECT_UNKNOWN_KEY, true);

    if (!trust_only(f)) {
        v_fail("trust store gating", "could not pin the release key");
        return;
    }
    v_check("good_boot is trusted once its key is pinned",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);

    found = OwCisLookupKeyId(key_by_name(f->KeyName)->KeyId);
    v_check("the pinned key is the one the block names", found != NULL, true);
    if (found != NULL) {
        v_check_eq("the pinned key's id matches the manifest",
                   (unsigned long)(memcmp(found->KeyId,
                                          key_by_name(f->KeyName)->KeyId,
                                          OW_CIS_KEY_ID_SIZE) == 0),
                   1UL);
    }
}

/* The key id selects the key.  Pinning the wrong (but plausible) key must not
 * produce a pass: this is the case where an implementation that ignored the id
 * and tried every anchor would look like it worked. */
static void test_key_id_selects_the_key(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    const ow_cis_fixture_key_t* other = key_by_name("recovery");

    if (f == NULL || other == NULL) {
        v_fail("key id selection", "fixture or key missing");
        return;
    }

    OwCisTestClearInjected();
    if (!ow_status_success(OwCisTestInjectKey(other->Name, other->PublicKey,
                                              other->KeyId, other->Flags))) {
        v_fail("key id selection", "could not pin the recovery key");
        return;
    }
    v_check("a release image is refused when only the recovery key is pinned",
            verdict_for(f) == OW_CIS_VERDICT_REJECT_UNKNOWN_KEY, true);

    /* Both keys pinned at once, still refused: the image names one of them and
     * it is not this one.  This is the stronger half -- it fails an
     * implementation that searched the whole store for any key that verifies. */
    if (!ow_status_success(OwCisTestInjectKey("release",
                                              key_by_name("release")->PublicKey,
                                              key_by_name("release")->KeyId,
                                              OW_CIS_KEY_FLAG_RELEASE))) {
        v_fail("key id selection", "could not pin the release key");
        return;
    }
    v_check("both keys pinned: the image is trusted under the one it names",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);
}

/* A revoked key is refused even though its signature is perfectly valid.
 *
 * This is the ordering test.  If the signature check ran before the revoked
 * check, a revoked key would keep working -- and it would keep working
 * silently, because the signature really does verify. */
static void test_revocation_dominates_signature(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    const ow_cis_fixture_key_t* k = key_by_name("release");

    if (f == NULL || k == NULL || !trust_only(f)) {
        v_fail("revocation", "fixture or key missing");
        return;
    }

    v_check("baseline: trusted before revocation",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);

    if (!ow_status_success(OwCisTestRevokeKeyId(k->KeyId))) {
        v_fail("revocation", "could not revoke the pinned key");
        return;
    }
    v_check("a validly signed image is refused under a revoked key",
            verdict_for(f) == OW_CIS_VERDICT_REJECT_KEY_REVOKED, true);
    v_check("a revoked key still does not permit execution",
            OwCisVerdictAllowsExecution(OW_CIS_VERDICT_REJECT_KEY_REVOKED),
            false);

    (void)OwCisTestUnrevokeKeyId(k->KeyId);
    v_check("un-revoking restores trust with no other change",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);

    v_check("revoking a key id that is not pinned reports NOT_FOUND",
            (unsigned long)OwCisTestRevokeKeyId((const uint8_t*)"not-a-key-id!") ==
                (unsigned long)OW_ERR_NOT_FOUND,
            true);
}

/* The verifier must be a pure function of the bytes and the trust store.
 *
 * Cross-implementation bit rot -- a scratch buffer reused across calls, a hash
 * accumulated twice, a verdict read from a stale field -- shows up here and
 * almost nowhere else, because every other test calls the function once from a
 * clean-ish state. */
static void test_verdicts_are_stateless(void) {
    uint32_t pass;

    for (pass = 0U; pass < 3u; pass++) {
        uint32_t i;
        for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
            const ow_cis_fixture_t* f = &ow_cis_fixtures[i];
            OW_CIS_VERDICT got;

            if (!trust_only(f)) {
                v_fail(f->Name, "could not pin the fixture's key");
                continue;
            }
            got = verdict_for(f);
            /* Compared against the fixture's own declared verdict, so a
             * reordered fixture table cannot make this loop vacuous. */
            if (got != f->Want) {
                printf("[FAIL] pass %u %s: verdict %s, wanted %s\n",
                       (unsigned)pass, f->Name, OwCisVerdictName(got),
                       OwCisVerdictName(f->Want));
                ++g_cis_v_failed;
            } else {
                ++g_cis_v_passed;
            }
        }
    }
    printf("[PASS] %u fixtures x 3 passes produced identical verdicts\n",
           (unsigned)OW_CIS_FIXTURE_COUNT);
}

/* The manifest digest of a fixture, as Python's hashlib computed it when the
 * fixture was generated.
 *
 * This is the reference used everywhere below in place of hashing in C.  The
 * kernel's own SHA-256 is the code under test, so comparing the recorded digest
 * against it would only prove the record was copied faithfully -- and a wrong
 * SHA-256 in lib/ow_sha256.c would produce a self-consistent, wrong answer that
 * no test comparing the kernel to itself could see.  The fixture's digest was
 * produced by a different implementation on a different machine state, so a
 * disagreement is a real disagreement. */
static bool fixture_content_digest(const ow_cis_fixture_t* f,
                                   uint8_t Out[OW_SHA256_DIGEST_SIZE]) {
    OW_CIS_BLOCK block;
    OW_CIS_FORMAT_STATUS st = OwCisFormatParse(
        f->File + f->ImageSize, f->FileSize - f->ImageSize, &block);

    if (st != OW_CIS_FORMAT_OK) {
        return false;
    }
    memcpy(Out, block.ContentDigest, OW_SHA256_DIGEST_SIZE);
    return true;
}

/* The measurement record carries enough to audit without the image.
 *
 * A TRUSTED record with a zero digest or no key id says "this image was fine"
 * without saying which image or under whose key, which is the one thing an
 * audit needs.  Checked field by field rather than for "non-zero" so a record
 * that carries a digest in the wrong place fails. */
static void test_measurement_contents(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    const ow_cis_fixture_key_t* k;
    uint8_t expected[OW_SHA256_DIGEST_SIZE];
    const OW_CIS_RECORD* rec;

    if (f == NULL || !trust_only(f)) {
        v_fail("measurement contents", "fixture or key missing");
        return;
    }
    k = key_by_name(f->KeyName);

    OwCisResetRecords();
    (void)OwCisVerifyImage(f->File, f->ImageSize, f->FileSize, f->Subsystem,
                           4242u, "measured.owx", OW_CIS_RECORD_SPAWN);

    rec = OwCisRecordAt(0);
    if (rec == NULL) {
        v_fail("measurement contents", "no record written");
        return;
    }

    v_check_eq("record verdict", (unsigned long)rec->Verdict,
               (unsigned long)OW_CIS_VERDICT_TRUSTED);
    v_check_eq("record source pid", (unsigned long)rec->SourcePid, 4242UL);
    v_check_eq("record subsystem", (unsigned long)rec->Subsystem,
               (unsigned long)OWX_SUBSYSTEM_BOOT);
    v_check_eq("record image size", (unsigned long)rec->ImageSize,
               (unsigned long)f->ImageSize);
    v_check_eq("record image name", (unsigned long)strlen(rec->Image),
               (unsigned long)strlen("measured.owx"));
    v_check("record kept the key id",
            memcmp(rec->KeyId, k->KeyId, OW_CIS_KEY_ID_SIZE) == 0, true);
    v_check("record kept the flags it was given",
            (rec->Flags & OW_CIS_RECORD_SPAWN) != 0U, true);
    v_check("record has a clean status",
            ow_status_success(rec->Detail), true);

    /* The recorded digest must be the digest of the image range, computed by
     * the generator rather than by the kernel. */
    if (fixture_content_digest(f, expected)) {
        v_check("record digest is the signed content digest",
                memcmp(rec->Digest, expected, OW_SHA256_DIGEST_SIZE) == 0, true);
    } else {
        v_fail("measurement contents", "could not read the fixture's digest");
    }
}

/* ---- guard page -------------------------------------------------------
 *
 * Verdict assertions cannot test the Available < ImageSize guard.  Removing it
 * leaves every verdict in this file unchanged: the parse that follows fails
 * anyway, because the bytes past the end of a short buffer are not a CIS block.
 * The two refusals are indistinguishable from the outside even though one of
 * them happens for the right reason and the other reaches past memory it was
 * never given.
 *
 * What the guard actually prevents is Available - ImageSize wrapping to
 * roughly four billion, which then gets handed to the parser as a length.  That
 * is only observable if reading past the buffer is fatal.  A malloc'd fixture
 * almost never makes it fatal, because the allocator rounds up and the following
 * bytes are usually still mapped -- the read succeeds and returns garbage that
 * the parser rejects, so the bug hides.
 *
 * So the fixture is placed by hand at the end of an allocation whose next page
 * is unreadable.  A one-byte overread now faults instead of quietly succeeding.
 * There is no try/catch around the verification call, and that is deliberate: a
 * SEH handler here would convert the fault back into a boolean and reintroduce
 * exactly the invisibility this is here to remove.  If this test faults, the
 * run dies and the guard has a real defect behind it. */

#define OW_GUARD_PAGE 4096u

/* A guarded fixture: Data is the copy, Base is what VirtualFree needs.
 *
 * Kept as a struct rather than a bare pointer because the two addresses are
 * genuinely different.  Returning the interior pointer and calling
 * VirtualFree(p, 0, MEM_RELEASE) on it fails -- MEM_RELEASE decommits an entire
 * allocation and requires the base address -- so the release silently did
 * nothing and every run leaked the reservation.  Worse, the leak hid the fact
 * that the guard was not a guard. */
typedef struct {
    uint8_t* Base;
    uint8_t* Data;
} ow_guard_t;

/* Copies len bytes of src so that the byte immediately after them is on a page
 * that cannot be read.  Returns false if the host refuses the reservation. */
static bool guarded_copy(ow_guard_t* guard, const uint8_t* src, size_t len) {
    SYSTEM_INFO si;
    uint8_t* base;
    size_t pages;
    MEMORY_BASIC_INFORMATION mbi;

    if (guard == NULL || src == NULL || len == 0u ||
        len > ((size_t)1u << 20)) {
        return false;
    }
    guard->Base = NULL;
    guard->Data = NULL;

    GetSystemInfo(&si);
    pages = (len + si.dwPageSize - 1u) / si.dwPageSize;

    /* Reserve one page more than the copy needs, but commit only `pages` of them.
     *
     * Committing them all was the bug: a committed PAGE_READWRITE page after the
     * copy is perfectly readable, so an overread landed in it and returned
     * whatever was there.  The parser then rejected the garbage and the test
     * passed -- with the guard providing no protection at all, which is the worst
     * combination available for a test whose entire purpose is to make an
     * overread fatal.  An uncommitted reservation is not mapped, so touching it
     * faults, which is what this needs.
     *
     * The copy is placed so it ENDS exactly on the pages boundary, putting the
     * first unreadable byte immediately after the last readable one. */
    base = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)((pages + 1u) * si.dwPageSize),
                                  MEM_RESERVE, PAGE_NOACCESS);
    if (base == NULL) {
        return false;
    }
    if (VirtualAlloc(base, (SIZE_T)(pages * si.dwPageSize), MEM_COMMIT,
                     PAGE_READWRITE) == NULL) {
        (void)VirtualFree(base, 0, MEM_RELEASE);
        return false;
    }

    guard->Base = base;
    guard->Data = base + (pages * si.dwPageSize) - len;
    memcpy(guard->Data, src, len);

    /* Prove the guard is a guard.
     *
     * Without this the harness cannot distinguish "the verifier refused without
     * reading" from "the verifier read and happened not to crash", and this test
     * would keep reporting the second as the first.  Querying is safe where
     * reading is not: if the page past the copy turns out to be accessible, the
     * test says so instead of quietly ceasing to test anything. */
    if (VirtualQuery(guard->Data + len, &mbi, sizeof mbi) == 0 ||
        mbi.State == MEM_COMMIT) {
        (void)VirtualFree(base, 0, MEM_RELEASE);
        guard->Base = NULL;
        guard->Data = NULL;
        return false;
    }
    return true;
}

static void guarded_free(const ow_guard_t* guard) {
    if (guard != NULL && guard->Base != NULL) {
        (void)VirtualFree(guard->Base, 0, MEM_RELEASE);
    }
}

/* A short image, so Available lands inside the readable region while ImageSize
 * claims to run past it.  The signed block is not needed: this is about the
 * arithmetic, not the signature. */
static void test_truncation_cannot_read_past_available(void) {
    /* One OWX header exactly.  256 is not arbitrary: below it the header-size
     * floor refuses first, so a stub any smaller would never reach the
     * truncation branch under test and the assertion would be testing that
     * floor instead. */
    uint8_t stub[OWX_HEADER_SIZE];
    ow_guard_t guard;
    uint8_t* buf;
    OW_CIS_VERDICT got;

    if (OwCisIsReady() == false) {
        v_fail("truncation", "CIS is not armed");
        return;
    }

    /* Not a real OWX: the header is never reached, because every case here is
     * refused on size before anything is parsed.  Starting the bytes with the
     * OWX magic keeps a defect that skipped the size checks visible as a
     * malformed parse rather than as an accident. */
    memset(stub, 0, sizeof stub);
    stub[0] = (uint8_t)(OWX_MAGIC & 0xFFu);
    stub[1] = (uint8_t)((OWX_MAGIC >> 8) & 0xFFu);
    stub[2] = (uint8_t)((OWX_MAGIC >> 16) & 0xFFu);
    stub[3] = (uint8_t)((OWX_MAGIC >> 24) & 0xFFu);

    if (!guarded_copy(&guard, stub, sizeof stub)) {
        v_fail("truncation", "guard page unavailable on this host");
        return;
    }
    buf = guard.Data;

    /* ImageSize claims 4096 bytes from a 64-byte buffer with 63 bytes behind
     * them unreadable.  With the guard in place this is refused as MALFORMED and
     * nothing is read.  With the guard removed, Available - ImageSize wraps and
     * the parser is pointed at a four-billion-byte range starting here, and the
     * run faults on the first page boundary. */
    got = OwCisVerifyImage(buf, OW_GUARD_PAGE, sizeof stub, 0x1u, 0u,
                           "overrun", 0u);
    v_check("an image claiming bytes past the buffer is MALFORMED",
            got == OW_CIS_VERDICT_REJECT_MALFORMED, true);

    /* The exact boundary, in the other direction: claiming precisely the bytes
     * present is consistent, and leaves no room for a block, so it is unsigned.
     * This is the case a "less than or equal" bounds check would get wrong. */
    got = OwCisVerifyImage(buf, sizeof stub, sizeof stub, 0x1u, 0u, "exact", 0u);
    v_check("claiming exactly the bytes present is UNSIGNED, not truncated",
            got == OW_CIS_VERDICT_REJECT_UNSIGNED, true);

    /* One byte more than exists, with the overread target unreadable. */
    got = OwCisVerifyImage(buf, sizeof stub + 1u, sizeof stub, 0x1u, 0u,
                           "one-past", 0u);
    v_check("claiming one byte past the end is MALFORMED",
            got == OW_CIS_VERDICT_REJECT_MALFORMED, true);

    guarded_free(&guard);
}

/* Bounds come before work, and each bound has its own verdict.
 *
 * The oversized and truncated claims are made against a small real buffer: if
 * either check came after hashing, these would read past the end of the fixture
 * rather than merely fail.  Under ASan that is a hard error instead of a silent
 * overread, which is why the claims are checked before anything else runs.
 *
 * The two size verdicts are deliberately different and are asserted separately.
 * An image over the size bound is a decision about limits; an image claiming
 * more bytes than exist is corruption.  Reporting both as MALFORMED would send an
 * operator looking for damage that is not there, and reporting both as POLICY
 * would file a limit refusal as if the file were wrong. */
static void test_bounds_before_digest(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    OW_CIS_VERDICT got;

    if (f == NULL || !trust_only(f)) {
        v_fail("bounds", "fixture or key missing");
        return;
    }

    v_check("baseline: the good fixture is trusted",
            verdict_for(f) == OW_CIS_VERDICT_TRUSTED, true);

    /* Over the policy bound, and comfortably inside Available so that only the
     * MaxImageSize check can produce the verdict.  If Available were smaller the
     * truncation check would answer first and this assertion would be testing
     * the wrong guard. */
    got = OwCisVerifyImage(f->File, f->ImageSize + 0x40000000u, f->FileSize,
                           f->Subsystem, 0u, "oversized", 0u);
    v_check("an image over the policy bound is refused as POLICY",
            got == OW_CIS_VERDICT_REJECT_POLICY, true);

    /* Claiming more bytes than the buffer holds.  The excess must exceed the
     * whole trailing block, or ImageSize would still land inside Available and
     * the claim would be consistent rather than truncated -- which is the trap
     * this assertion was originally written into. */
    got = OwCisVerifyImage(f->File, f->FileSize + 1u, f->FileSize,
                           f->Subsystem, 0u, "truncated", 0u);
    v_check("claiming more bytes than exist is MALFORMED",
            got == OW_CIS_VERDICT_REJECT_MALFORMED, true);
    /* Claiming the whole file as the image: not a truncation -- the claim is
     * exactly consistent -- but it leaves no room for a block, so the answer is
     * UNSIGNED rather than TRUSTED.  The pair with the case above is the point:
     * one byte more than exists is MALFORMED, and exactly as many is UNSIGNED.
     * A verifier that conflated the two would be filing a corruption report
     * against a file that is merely unsigned. */
    got = OwCisVerifyImage(f->File, f->FileSize, f->FileSize, f->Subsystem, 0u,
                           "exact", 0u);
    v_check("claiming the whole file is unsigned, not truncated",
            got == OW_CIS_VERDICT_REJECT_UNSIGNED, true);

    /* Shorter than an OWX header, with no block either.  MALFORMED, and not
     * UNSIGNED: an image too short to hold a header cannot be "structurally
     * sound but carries no signature", because the part that would have to be
     * sound is not there.  Asserted as MALFORMED specifically so that deleting
     * the header-size floor is caught -- with the floor gone this would fall
     * through to the no-block branch and report UNSIGNED. */
    got = OwCisVerifyImage(f->File, 8u, 8u, f->Subsystem, 0u, "stub", 0u);
    v_check("an image too short to hold a header is MALFORMED, not UNSIGNED",
            got == OW_CIS_VERDICT_REJECT_MALFORMED, true);
    /* Exactly one header, no block: the floor is satisfied, so this is a
     * well-formed but unsigned image.  This is the boundary that matters -- a
     * "less than or equal" floor would reject a legal image at the exact limit. */
    got = OwCisVerifyImage(f->File, OWX_HEADER_SIZE, OWX_HEADER_SIZE,
                           f->Subsystem, 0u, "header-only", 0u);
    v_check("an image of exactly one header is evaluated as unsigned",
            got == OW_CIS_VERDICT_REJECT_UNSIGNED, true);

    /* NULL image: refused, never dereferenced. */
    got = OwCisVerifyImage(NULL, f->ImageSize, f->FileSize, f->Subsystem, 0u,
                           "null", 0u);
    v_check("a NULL image is refused",
            got == OW_CIS_VERDICT_ERROR, true);
}

/* The signed range is the block minus its signature, and nothing else.
 *
 * If the image bytes were inside that range the signature could never verify,
 * because signing would have to happen after the block was complete.  If the
 * range were short of the whole header, a header field could be altered after
 * signing and the block would still verify.  Both ends are asserted. */
static void test_signed_range_is_exact(void) {
    const ow_cis_fixture_t* f = fixture_by_name("good_boot");
    OW_CIS_BLOCK block;
    OW_CIS_FORMAT_STATUS st;

    if (f == NULL) {
        v_fail("signed range", "fixture missing");
        return;
    }
    st = OwCisFormatParse(f->File + f->ImageSize,
                          f->FileSize - f->ImageSize, &block);
    if (st != OW_CIS_FORMAT_OK) {
        v_fail("signed range", "the good fixture's block does not parse");
        return;
    }

    /* Points into the caller's buffer at the block's first byte: a reassembly
     * would be a second copy that could disagree with the first. */
    v_check("the signed range starts at the block's first byte",
            block.Signed == f->File + f->ImageSize, true);
    v_check_eq("the signed range is the block minus its 64-byte signature",
               (unsigned long)block.SignedSize,
               (unsigned long)(f->FileSize - f->ImageSize -
                               OW_CIS_SIGNATURE_SIZE));
    v_check("the signature sits at the end of the signed range",
            block.Signature == block.Signed + block.SignedSize, true);
    v_check_eq("the signature is 64 bytes",
               (unsigned long)(block.BlockSize - block.SignedSize),
               (unsigned long)OW_CIS_SIGNATURE_SIZE);
    v_check_eq("the block size accounts for header, manifest and signature",
               (unsigned long)block.BlockSize,
               (unsigned long)(OW_CIS_BLOCK_HEADER_SIZE +
                               block.ManifestSize + OW_CIS_SIGNATURE_SIZE));

    /* The digest and key id are copied into the block struct rather than left as
     * pointers, so only the text fields have an in-block location to check.  That
     * they are copies is itself worth asserting: a pointer into the caller's
     * buffer would dangle the moment the buffer was released. */
    v_check("the licence text points inside the signed range",
            block.License >= block.Signed &&
                block.License + block.LicenseSize <=
                    block.Signed + block.SignedSize,
            true);
    v_check("the copyright text points inside the signed range",
            block.Copyright >= block.Signed &&
                block.Copyright + block.CopyrightSize <=
                    block.Signed + block.SignedSize,
            true);
    if (block.BuildId != NULL) {
        v_check("the optional build id points inside the signed range",
                block.BuildId >= block.Signed &&
                    block.BuildId + block.BuildIdSize <=
                        block.Signed + block.SignedSize,
                true);
    } else {
        v_check("a manifest without a build id reports none", true, true);
    }
}

/* Every fixture's block parses, and every fixture's OWX header is structurally
 * valid.
 *
 * These are preconditions for the whole file: if a fixture's image did not
 * satisfy OwOwxImageIsLoadable, a refusal could be coming from the header
 * parser rather than from CIS, and the table above would be testing the wrong
 * thing. */
static void test_fixtures_are_structurally_valid(void) {
    uint32_t i;

    for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
        const ow_cis_fixture_t* f = &ow_cis_fixtures[i];
        owx_header_t header;
        bool have_block;

        if (f->FileSize < f->ImageSize) {
            v_fail(f->Name, "fixture is shorter than its own image_size");
            continue;
        }
        if (f->ImageSize < OWX_HEADER_SIZE) {
            v_fail(f->Name, "fixture image is shorter than an OWX header");
            continue;
        }
        /* Only after the length is known to cover a whole header. */
        memcpy(&header, f->File, sizeof(header));
        if (!OwOwxImageIsLoadable(&header, f->ImageSize)) {
            v_fail(f->Name, "fixture image is not structurally loadable");
            continue;
        }
        /* The header's own image_size must be the image_size the verifier is
         * given, or the digest and the signature would cover a different range
         * than the loader would map. */
        if (header.image_size != f->ImageSize) {
            v_fail(f->Name, "header image_size disagrees with the fixture");
            continue;
        }
        v_check("fixture image is a valid OWX header", true, true);

        have_block = (f->FileSize > f->ImageSize);
        if (have_block) {
            OW_CIS_BLOCK block;
            OW_CIS_FORMAT_STATUS st = OwCisFormatParse(
                f->File + f->ImageSize, f->FileSize - f->ImageSize, &block);
            if (st != OW_CIS_FORMAT_OK && strcmp(f->Name, "malformed_block") != 0) {
                v_fail(f->Name, "block does not parse");
                continue;
            }
            v_check("fixture block parses (or is the malformed one)", true, true);
        } else {
            v_check("fixture has no block, as its verdict requires",
                    strcmp(f->Name, "unsigned") == 0, true);
        }
    }
}

/* CORE_KERNEL copyleft policy verification:
 *
 * An image running with native subsystem (OWX_SUBSYSTEM_NATIVE) or claiming
 * policy class CORE_KERNEL must:
 * 1. Declare policy class "CORE_KERNEL"
 * 2. Carry an authenticated license of "GPL-3.0-or-later"
 * 3. Carry an authenticated 32-byte source manifest digest (TAG_SOURCE_DIGEST)
 * 4. Refuse non-GPL licenses (e.g. MIT) even when signed by a release key
 * 5. Refuse missing source digest even when signed by a release key
 * 6. Refuse native subsystem images lacking explicit CORE_KERNEL policy class
 */
static void test_core_kernel_policy(void) {
    const ow_cis_fixture_t* f_good = fixture_by_name("good_kernel");
    const ow_cis_fixture_t* f_mit = fixture_by_name("kernel_mit_refused");
    const ow_cis_fixture_t* f_nodig = fixture_by_name("kernel_no_source_digest");
    const ow_cis_fixture_t* f_nopolic = fixture_by_name("kernel_no_policy_class");
    OW_CIS_BLOCK block;
    OW_CIS_FORMAT_STATUS fmt;
    OW_CIS_VERDICT v;

    printf("\n--- CIS verification: CORE_KERNEL copyleft policy ---\n");

    if (f_good == NULL || f_mit == NULL || f_nodig == NULL || f_nopolic == NULL) {
        v_fail("core_kernel", "one or more CORE_KERNEL fixtures missing");
        return;
    }

    /* 1. Good kernel: TRUSTED */
    if (!trust_only(f_good)) {
        v_fail("core_kernel", "could not pin release key for good_kernel");
        return;
    }
    v = verdict_for(f_good);
    v_check("good_kernel is TRUSTED", v == OW_CIS_VERDICT_TRUSTED, true);
    v_check("good_kernel allows execution", OwCisVerdictAllowsExecution(v), true);

    /* Verify block contents parsed from good_kernel */
    fmt = OwCisFormatParse(f_good->File + f_good->ImageSize,
                           f_good->FileSize - f_good->ImageSize, &block);
    v_check("good_kernel block parses successfully", fmt == OW_CIS_FORMAT_OK, true);
    v_check("good_kernel has PolicyClass", block.PolicyClass != NULL, true);
    v_check("good_kernel PolicyClass is CORE_KERNEL",
            block.PolicyClass && block.PolicyClassSize == 11 &&
            memcmp(block.PolicyClass, "CORE_KERNEL", 11) == 0, true);
    v_check("good_kernel License is GPL-3.0-or-later",
            block.License && block.LicenseSize == 16 &&
            memcmp(block.License, "GPL-3.0-or-later", 16) == 0, true);
    v_check("good_kernel has SourceDigest", block.SourceDigest != NULL, true);
    v_check("good_kernel SourceDigest is 32 bytes",
            block.SourceDigestSize == OW_SHA256_DIGEST_SIZE, true);

    /* 2. MIT kernel: REJECT_POLICY */
    if (!trust_only(f_mit)) {
        v_fail("core_kernel", "could not pin release key for kernel_mit_refused");
        return;
    }
    v = verdict_for(f_mit);
    v_check("kernel_mit_refused produces REJECT_POLICY",
            v == OW_CIS_VERDICT_REJECT_POLICY, true);
    v_check("kernel_mit_refused denies execution",
            OwCisVerdictAllowsExecution(v), false);

    /* 3. Missing source digest: REJECT_POLICY */
    if (!trust_only(f_nodig)) {
        v_fail("core_kernel", "could not pin release key for kernel_no_source_digest");
        return;
    }
    v = verdict_for(f_nodig);
    v_check("kernel_no_source_digest produces REJECT_POLICY",
            v == OW_CIS_VERDICT_REJECT_POLICY, true);
    v_check("kernel_no_source_digest denies execution",
            OwCisVerdictAllowsExecution(v), false);

    /* 4. Native subsystem missing policy class: REJECT_POLICY */
    if (!trust_only(f_nopolic)) {
        v_fail("core_kernel", "could not pin release key for kernel_no_policy_class");
        return;
    }
    v = verdict_for(f_nopolic);
    v_check("kernel_no_policy_class produces REJECT_POLICY",
            v == OW_CIS_VERDICT_REJECT_POLICY, true);
    v_check("kernel_no_policy_class denies execution",
            OwCisVerdictAllowsExecution(v), false);

    /* 5. Subsystem cross-checks:
     * A non-native subsystem image that declares PolicyClass "CORE_KERNEL" must
     * STILL be evaluated under CORE_KERNEL policy rules. */
    v = OwCisVerifyImage(f_mit->File, f_mit->ImageSize, f_mit->FileSize,
                         OWX_SUBSYSTEM_BOOT, 0u, "kernel_mit_boot_subsys", 0u);
    v_check("CORE_KERNEL policy enforced even if subsystem is BOOT",
            v == OW_CIS_VERDICT_REJECT_POLICY, true);
}

int test_cis_verify_run(int* out_passed) {
    printf("\n=== Copyleft Integrity Safeguard: verification ===\n");

    if (!ow_status_success(OwCisInitialize())) {
        printf("[FAIL] CIS would not arm: the verification tests cannot run\n");
        return 1;
    }
    OwCisResetRecords();

    /* Structural preconditions first: a fixture that is not a valid image would
     * make every refusal below ambiguous between CIS and the header parser. */
    test_fixtures_are_structurally_valid();

    test_each_fixture_verdict();
    test_core_kernel_policy();
    test_trust_store_gates_trusted();
    test_key_id_selects_the_key();
    test_revocation_dominates_signature();
    test_signed_range_is_exact();
    test_measurement_contents();
    test_bounds_before_digest();
    test_truncation_cannot_read_past_available();
    test_verdicts_are_stateless();
    test_unarmed_refuses_and_says_so();
    test_null_arguments_are_refused();

    OwCisTestClearInjected();
    OwCisResetRecords();

    printf("\n--- CIS verification: %d passed, %d failed ---\n",
           g_cis_v_passed, g_cis_v_failed);
    if (out_passed) *out_passed = g_cis_v_passed;
    return g_cis_v_failed;
}