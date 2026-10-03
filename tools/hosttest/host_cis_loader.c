/* host_cis_loader.c - CIS enforcement at the loader boundary.
 *
 * host_cis_verify.c proves the verifier reaches the right verdict.  That is one
 * layer down from the property that matters, and it does not imply it.  A
 * verifier that is correct but invoked after the mapping loop would pass every
 * verifier test and still leave a window in which unsigned code is resident and
 * executable.  Wiring is the part that regresses quietly, so it gets its own
 * tests.
 *
 * The property, per refused image:
 *
 *   EntryPoint == 0, VadRoot == NULL, no frames charged.
 *
 * All three, not just the status.  A loader that returned OW_ERR_CIS_UNSIGNED
 * while leaving a VAD behind would satisfy a status-only assertion and would
 * still have executed attacker-supplied bytes.
 *
 * The other half is the control.  Every fixture the corpus expects to be TRUSTED
 * is loaded through the same call and must actually map and produce an entry
 * point.  Without it, a loader that refused everything -- a build with no trust
 * anchors, a gate wired to `return OW_ERR_CIS_UNSIGNED;` -- would pass all the
 * negative assertions.  The suite is only meaningful because both halves run.
 *
 * What this catches, established by mutation rather than assumed.  Moving the
 * gate to the end of the host parse -- after Proc->EntryPoint is published --
 * was tried, and every refused fixture fails "sets no entry point" plus the
 * matching boot-harness assertion.  Moving the gate below the *target* mapping
 * loop is not observable here: the host loader maps nothing, which is exactly
 * why the VAD and frame-charge assertions are compiled out below rather than
 * left in as a green line that proves nothing.  Those two properties need a
 * target or page-table harness to cover, and until one exists this suite does
 * not claim them.
 *
 * The corpus is cis_fixtures.h, shared with the verifier tests.  Reusing it
 * rather than generating loader-specific images is deliberate: a second image
 * builder would be a second place for the OWX layout to drift, and the cases
 * worth testing at this boundary are the same bytes, reached by a different
 * caller.
 *
 * Host-only file: it inspects Proc->VadRoot and Proc->FrameRun directly rather
 * than through an API, because the point is that no mapping happened and there is
 * deliberately no "did you map anything" API to ask with.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../inc/ow_memory.h"
#include "../../inc/ow_owx.h"
#include "../../inc/ow_ps.h"

#include "cis_fixtures.h"

/* A local copy rather than host_cis_verify.c's, which is static to that file.
 * Six lines of table walk, and coupling these two files through a shared
 * declaration would mean a change to one corpus reader silently changing the
 * other's behaviour -- which is the exact drift this suite exists to catch. */
static const ow_cis_fixture_t* loader_fixture_by_name(const char* name) {
    uint32_t i;
    for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
        if (strcmp(ow_cis_fixtures[i].Name, name) == 0) {
            return &ow_cis_fixtures[i];
        }
    }
    return NULL;
}

/* Counts are returned to host_boot.c rather than accumulated into a shared
 * global, so this file's totals cannot drift from the suite's. */
int test_cis_loader_run(int* out_passed);

static int g_cis_l_passed;
static int g_cis_l_failed;

static void l_fail(const char* label, const char* detail) {
    ++g_cis_l_failed;
    printf("[FAIL] %s: %s\n", label, detail ? detail : "");
}

static void l_check(const char* label, bool got, bool want) {
    if (got == want) {
        ++g_cis_l_passed;
        printf("[PASS] %s = %s\n", label, want ? "true" : "false");
    } else {
        ++g_cis_l_failed;
        printf("[FAIL] %s: got %s, want %s\n", label, got ? "true" : "false",
               want ? "true" : "false");
    }
}

static const ow_cis_fixture_key_t* key_by_name(const char* name) {
    uint32_t i;
    for (i = 0U; i < OW_CIS_FIXTURE_KEY_COUNT; i++) {
        if (strcmp(ow_cis_fixture_keys[i].Name, name) == 0) {
            return &ow_cis_fixture_keys[i];
        }
    }
    return NULL;
}

/* Pin exactly the key the fixture's block names.  Not always the key that
 * signed it: the unknown_key fixture is signed by a real key that this harness
 * deliberately refuses to pin, which is what makes it a trust failure rather
 * than a cryptography one. */
static bool pin_only(const ow_cis_fixture_t* f) {
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
    /* Revocation is a separate axis and is cleared here, so one fixture's
     * verdict cannot depend on whether an earlier test revoked this key. */
    (void)OwCisTestUnrevokeKeyId(k->KeyId);
    return true;
}

#ifndef OW_HOST_HAL
/* Nodes in the VAD tree, walked iteratively.
 *
 * The tree is balanced, so recursion would terminate, but a walk that recurses
 * on kernel data is the kind of thing that turns a corrupt tree into a stack
 * overflow inside the thing being tested.  Fixed stack, bounded pushes: if the
 * tree ever exceeds the bound the count saturates, which can only make an
 * assertion stricter, never looser.
 *
 * Not compiled on a host build: the loader publishes no VADs there, so a count
 * of zero is the answer for every image and the function has nothing to say. */
static uint32_t count_vads(const OW_VAD_NODE* root) {
    const OW_VAD_NODE* stack[64];
    uint32_t top = 0U;
    uint32_t seen = 0U;

    if (root == NULL) {
        return 0U;
    }
    stack[top++] = root;

    while (top > 0U) {
        const OW_VAD_NODE* node = stack[--top];

        ++seen;
        if (seen > 4096U) {
            return seen;
        }
        if (node->LeftChild != NULL && top < 64U) {
            stack[top++] = node->LeftChild;
        }
        if (node->RightChild != NULL && top < 64U) {
            stack[top++] = node->RightChild;
        }
    }
    return seen;
}
#endif /* !OW_HOST_HAL */

/* Load one fixture and assert the whole postcondition.
 *
 * Return value is the number of failures, so the caller can aggregate. */
static uint32_t load_and_assert(const ow_cis_fixture_t* f) {
    OW_PROCESS_OBJECT* proc;
    OW_STATUS st;
    OW_CIS_VERDICT verdict;
    bool trusted;
#ifndef OW_HOST_HAL
    uint32_t vads;
#endif
    uint32_t before_failed = g_cis_l_failed;
    char label[160];

    if (!pin_only(f)) {
        l_fail(f->Name, "could not pin the fixture's key");
        return g_cis_l_failed - before_failed;
    }

    proc = OwPsCreateProcess(f->Name, OW_PS_PID_KERNEL);
    if (proc == NULL) {
        l_fail(f->Name, "could not create a process to load into");
        return g_cis_l_failed - before_failed;
    }

    /* Provenance is the boot one, matching every other owinit load in this
     * harness.  The suite exercises the gate, not the provenance field: a
     * separate test covers what the loader does with an unrecognised value. */
    st = OwPsLoadImage(proc, f->File, f->FileSize,
                       (uint32_t)OW_CIS_RECORD_BOOT);
    verdict = OwPsLastCisVerdict();
    trusted = (verdict == OW_CIS_VERDICT_TRUSTED);

    /* The verdict the loader reports is the one the fixture declares.  Checked
     * before the state assertions so a failure there still tells us which side
     * of the gate the image landed on. */
    if (verdict != f->Want) {
        printf("[FAIL] %s: loader verdict %s, wanted %s (%s)\n", f->Name,
               OwCisVerdictName(verdict), OwCisVerdictName(f->Want), f->Note);
        ++g_cis_l_failed;
    } else {
        ++g_cis_l_passed;
        printf("[PASS] %s -> loader verdict %s\n", f->Name,
               OwCisVerdictName(verdict));
    }

    if (OwCisVerdictAllowsExecution(verdict) != trusted) {
        l_fail(f->Name, "execution authorisation disagrees with the verdict");
    } else {
        ++g_cis_l_passed;
        printf("[PASS] %s: execution authorisation follows the verdict\n",
               f->Name);
    }

    if (!trusted) {
        /* The properties, each asserted separately because each has failed on
         * its own before: a status-only test missed a leaked VAD, and an
         * entry-point-only test missed charged frames. */
        snprintf(label, sizeof(label), "%s: refusal status is in the CIS family",
                 f->Name);
        l_check(label, (st & OW_ERR_CIS_FAMILY_MASK) != 0U, true);

        snprintf(label, sizeof(label), "%s: a refused image sets no entry point",
                 f->Name);
        l_check(label, proc->EntryPoint == 0U, true);

        snprintf(label, sizeof(label), "%s: a refusal creates no thread",
                 f->Name);
        l_check(label, proc->ThreadCount == 0U, true);

#ifndef OW_HOST_HAL
        /* Target-only.  On a host build the loader maps nothing and publishes no
         * VADs for ANY image, so the same assertions here would pass for a
         * trusted load too -- they would be checking that the stub does nothing,
         * not that the gate stopped it.  Compiled out rather than left in,
         * because a vacuous assertion reads as coverage. */
        snprintf(label, sizeof(label), "%s: a refused image publishes no VAD",
                 f->Name);
        l_check(label, proc->VadRoot == NULL, true);

        snprintf(label, sizeof(label), "%s: a refused image charges no frame",
                 f->Name);
        l_check(label, proc->FrameRun.Committed == 0U, true);
#endif
    } else {
        /* The control half.  A trusted image must pass the loader's real checks
         * and produce a usable entry point, or the refusals above would prove
         * nothing about which path they took. */
        snprintf(label, sizeof(label), "%s: a trusted image loads", f->Name);
        l_check(label, ow_status_success(st), true);

        snprintf(label, sizeof(label), "%s: a trusted image sets an entry point",
                 f->Name);
        l_check(label, proc->EntryPoint != 0U, true);

        /* The entry point must land inside this process's user window.  These
         * fixtures declare a preferred base of 0x140000000, far outside it, so
         * a nonzero entry point is not enough on its own: the loader has to have
         * biased the image down into the window, which means it also walked the
         * section table and passed the window-fit check on the way. */
        snprintf(label, sizeof(label),
                 "%s: the relocated entry point is inside the user window "
                 "(0x%llX)", f->Name,
                 (unsigned long long)proc->EntryPoint);
        l_check(label, OwMemInUserWindow(proc->EntryPoint), true);

#ifndef OW_HOST_HAL
        vads = count_vads(proc->VadRoot);

        snprintf(label, sizeof(label), "%s: a trusted image publishes a VAD",
                 f->Name);
        l_check(label, proc->VadRoot != NULL, true);

        snprintf(label, sizeof(label),
                 "%s: a trusted image maps at least one section (%u VADs)",
                 f->Name, (unsigned)vads);
        l_check(label, vads > 0U, true);
#endif
    }

    /* Free whatever was mapped.  Skipped for refusals, which map nothing, so
     * the teardown cannot paper over a leak in the assertions above. */
    if (trusted && ow_status_success(st)) {
        OwPsTerminateProcess(proc, 0U);
    }

    return g_cis_l_failed - before_failed;
}

/* The refusal must not be a side effect of the header parser refusing first.
 *
 * Both would produce a failed load, and an operator would see two entirely
 * different causes reported identically.  Every fixture except the malformed
 * ones is structurally valid OWX, which the verifier tests already assert; this
 * restates it here so that a future fixture added to the corpus without that
 * property is caught at the boundary where it would mislead. */
static void test_fixtures_are_loadable_shape(void) {
    uint32_t i;

    printf("\n--- CIS loader boundary: fixture shape ---\n");

    for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
        const ow_cis_fixture_t* f = &ow_cis_fixtures[i];
        const owx_header_t* hdr = (const owx_header_t*)f->File;
        bool size_ok = hdr->image_size == f->ImageSize;
        bool trailer_fits = f->ImageSize <= f->FileSize;

        if (!size_ok) {
            printf("[FAIL] %s: header image_size %u, corpus says %u\n", f->Name,
                   (unsigned)hdr->image_size, (unsigned)f->ImageSize);
            ++g_cis_l_failed;
            continue;
        }
        ++g_cis_l_passed;
        printf("[PASS] %s: header image_size matches the corpus\n", f->Name);

        if (!trailer_fits) {
            printf("[FAIL] %s: FileSize %u < ImageSize %u\n", f->Name,
                   (unsigned)f->FileSize, (unsigned)f->ImageSize);
            ++g_cis_l_failed;
            continue;
        }
        ++g_cis_l_passed;
        printf("[PASS] %s: the trailer, if any, starts at or after image_size\n",
               f->Name);
    }
}

/* The loader's size contract, at the loader.
 *
 * OwPsLoadImage takes the caller's own byte count and the image's own
 * image_size, and CIS is asked about exactly the range [0, image_size).  These
 * two fixtures are the ones that make the difference visible: one has no
 * trailer at all, the other has bytes past image_size that are inside the
 * caller's count but outside the signed range.  If the loader ever passed the
 * caller's count as the signed range, the second would stop being trusted --
 * which is the whole reason the two arguments are separate. */
static void test_signed_range_at_the_loader(void) {
    const ow_cis_fixture_t* plain = loader_fixture_by_name("unsigned");
    const ow_cis_fixture_t* trailing = loader_fixture_by_name("trailing_bytes");

    printf("\n--- CIS loader boundary: signed range ---\n");

    if (plain == NULL || trailing == NULL) {
        l_fail("signed range", "fixture missing");
        return;
    }

    /* Neither has a caller count equal to its signed range, so the loader is
     * being asked the question that the two-argument contract exists for. */
    l_check("the unsigned fixture has no trailer",
            plain->FileSize == plain->ImageSize, true);
    l_check("the trailing-bytes fixture has a trailer",
            trailing->FileSize > trailing->ImageSize, true);

    /* trailing_bytes is expected TRUSTED by the verifier.  Assert the same
     * expectation here explicitly: if it were ever changed to a refusal, the
     * bytes past image_size would be inside the caller's count, and the
     * interesting property is that they are still not covered by the signature.
     * A fixture that quietly became a refusal case would stop testing that. */
    l_check("bytes past image_size are outside the signed range",
            trailing->Want == OW_CIS_VERDICT_TRUSTED, true);
}

/* Provenance is a parameter, and an unrecognised one is refused.
 *
 * Without this test the flag would be a comment: passing 0, or a bit nobody
 * defined, would still verify and still load, and the only evidence it was
 * checked would be reading the source.  The loader refuses an unknown value on
 * purpose -- a third caller path has to name itself rather than be recorded as a
 * boot or a spawn -- so the refusal is the behaviour worth pinning.
 *
 * Also asserted here because it is the sharpest available statement of the whole
 * design: an unrecognised provenance produces OW_ERR_CIS_ERROR, the same status
 * as a verifier that could not run at all.  There is no flag, and no bit pattern
 * in any of these, that turns verification off. */
static void test_unrecognised_provenance_is_refused(void) {
    static const uint32_t bad[] = {
        0x00000000u,                             /* nothing at all */
        OW_CIS_RECORD_BOOT | OW_CIS_RECORD_SPAWN, /* two claims at once */
        0x80000000u,                             /* an undefined bit */
    };
    const ow_cis_fixture_t* f = loader_fixture_by_name("good_boot");
    uint32_t i;

    printf("\n--- CIS loader boundary: provenance ---\n");

    if (f == NULL || !pin_only(f)) {
        l_fail("provenance", "could not pin the release key");
        return;
    }

    for (i = 0U; i < (uint32_t)(sizeof(bad) / sizeof(bad[0])); i++) {
        OW_PROCESS_OBJECT* proc = OwPsCreateProcess(f->Name, OW_PS_PID_KERNEL);
        OW_STATUS st;
        char label[160];

        if (proc == NULL) {
            l_fail("provenance", "could not create a process");
            return;
        }

        st = OwPsLoadImage(proc, f->File, f->FileSize, bad[i]);

        snprintf(label, sizeof(label),
                 "provenance 0x%08X is refused, not treated as a boot",
                 (unsigned)bad[i]);
        l_check(label, ow_status_error(st), true);

        snprintf(label, sizeof(label),
                 "provenance 0x%08X refusal is in the CIS family",
                 (unsigned)bad[i]);
        l_check(label, (st & OW_ERR_CIS_FAMILY_MASK) != 0U, true);

        snprintf(label, sizeof(label),
                 "provenance 0x%08X sets no entry point", (unsigned)bad[i]);
        l_check(label, proc->EntryPoint == 0U, true);

        snprintf(label, sizeof(label),
                 "provenance 0x%08X leaves no thread", (unsigned)bad[i]);
        l_check(label, proc->ThreadCount == 0U, true);
    }

    /* And the recognised values are not refused by the check itself: the same
     * image, the same key, the same bytes, one flag different.  Without this the
     * provenance test could be satisfied by a loader that refuses everything. */
    {
        OW_PROCESS_OBJECT* proc = OwPsCreateProcess(f->Name, OW_PS_PID_KERNEL);
        OW_STATUS st = OW_ERR_CORRUPT;

        if (proc != NULL) {
            st = OwPsLoadImage(proc, f->File, f->FileSize,
                               (uint32_t)OW_CIS_RECORD_BOOT);
        }
        l_check("the same image loads with OW_CIS_RECORD_BOOT",
                proc != NULL && ow_status_success(st), true);
        if (proc != NULL && ow_status_success(st)) {
            OwPsTerminateProcess(proc, 0U);
        }
    }
}

int test_cis_loader_run(int* out_passed) {
    uint32_t i;

    printf("\n=== CIS loader boundary tests ===\n");

    test_fixtures_are_loadable_shape();

    printf("\n--- CIS loader boundary: one load per fixture ---\n");

    for (i = 0U; i < OW_CIS_FIXTURE_COUNT; i++) {
        (void)load_and_assert(&ow_cis_fixtures[i]);
    }

    test_signed_range_at_the_loader();
    test_unrecognised_provenance_is_refused();

    OwCisTestClearInjected();
    OwCisResetRecords();

    printf("\n--- CIS loader boundary: %d passed, %d failed ---\n",
           g_cis_l_passed, g_cis_l_failed);
    if (out_passed) *out_passed = g_cis_l_passed;
    return g_cis_l_failed;
}