/*
 * host_boot.c - Host boot harness for openwinkrnl.owx
 *
 * Executes the same boot sequence as core/main.c::_start, then drives
 * the Ring-0 debug shell through scripted host UART input and validates
 * the resulting transcript.
 *
 * Host file access deliberately avoids:
 *   fopen / fread / fseek / ftell
 *   strcpy / strlen / strstr
 *   malloc / free
 *   snprintf
 *
 * Windows uses _sopen_s/_read/_close.
 * POSIX hosts use open/read/close.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <share.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "../../cis/cis_keys.h"
#include "../../inc/ow_alpc.h"
#include "../../inc/ow_cis.h"
#include "../../inc/ow_cis_format.h"
#include "../../inc/ow_diag.h"
#include "../../inc/ow_ed25519.h"
#include "../../inc/ow_ed25519_test.h"
#include "../../inc/ow_sha512.h"
#include "crypto_vectors.h"
#include "cis_fixtures.h"

/* Implemented in host_cis_verify.c.  Returns that file's failure count, which
 * main() adds to its own tally; the two files keep separate counters so a
 * mismatch between them is visible rather than averaged away. */
int test_cis_verify_run(int* out_passed);
/* Implemented in host_cis_loader.c.  Same counter discipline: its failure count
 * is added to main()'s, never folded into it. */
int test_cis_loader_run(int* out_passed);

#include "../../inc/ow_ecosys.h"
#include "../../inc/ow_hal.h"
#include "../../inc/ow_kprintf.h"
/* Resolved on the include path, not by relative path: the generated header
 * lives in the build tree -- boot/ under the Makefile, <build>/generated under
 * CMake.  Naming that directory here would bind one build system's layout into
 * a source file both of them need. */
#include "owinit_image.h"
#include "../../inc/ow_memory.h"
#include "../../inc/ow_net.h"
#include "../../inc/ow_object.h"
#include "../../inc/ow_owx.h"
#include "../../inc/ow_ps.h"
#include "../../inc/ow_runlevel.h"
#include "../../inc/ow_sentinel.h"
#include "../../inc/ow_shell.h"
#include "../../inc/ow_syscall.h"
#include "../../inc/ow_userspace.h"
#include "../../inc/ow_vfs.h"
#include "../../emergency/owinitv_image.h"
#include "../../emergency/owrs_image.h"
#include "../../inc/ow_types.h"
#include "../../inc/ow_vfs.h"
#include "../../storage/owdisk.h"

#include <stdio.h>
#include <string.h>
#include "../../inc/ow_ed25519.h"
#include "../../inc/ow_ed25519_test.h"
#include "../../inc/ow_sha512.h"
#include "crypto_vectors.h"

/* -------------------------------------------------------------------------
 */
/* Host HAL */
/* -------------------------------------------------------------------------
 */

char *HostHalOutput(void);
size_t HostHalOutputLen(void);
void HostHalSetInputScript(const char *script);

/* ------------------------------------------------------------------------- */
/* Harness state                                                              */
/* ------------------------------------------------------------------------- */

static const char *g_script = "exit\n";

static int g_failures = 0;
static int g_passed = 0;

/* How many trust anchors this build pins before the harness injects any: zero in
 * a default build, one dev anchor under CIS_DEV_TRUST.  Captured once from the
 * live count so the assertions that depend on it do not have to repeat the
 * conditional, and so none of them can silently assume the default build. */
static unsigned long g_CisHarnessPinned = 0UL;

/* ------------------------------------------------------------------------- */
/* Tiny local string helpers                                                  */
/* ------------------------------------------------------------------------- */

static size_t ow_strlen(const char *text) {
  size_t length = 0;

  if (text == NULL)
    return 0;

  while (text[length] != '\0')
    ++length;

  return length;
}

/*
 * Bounded string copy.
 *
 * Returns true when the complete string fitted.
 * Returns false when truncation would have occurred.
 */
static bool ow_strcopy(char *destination, size_t destination_size,
                       const char *source) {
  size_t i;

  if (destination == NULL || source == NULL || destination_size == 0) {
    return false;
  }

  for (i = 0; i + 1 < destination_size && source[i] != '\0'; ++i) {
    destination[i] = source[i];
  }

  destination[i] = '\0';

  return source[i] == '\0';
}

/*
 * Small byte-copy helper.
 *
 * Used instead of strcpy/memcpy for the tiny host-side buffers here.
 */
static void ow_copy_bytes(uint8_t *destination, const uint8_t *source,
                          size_t count) {
  size_t i;

  if (destination == NULL || source == NULL)
    return;

  for (i = 0; i < count; ++i)
    destination[i] = source[i];
}

/* ------------------------------------------------------------------------- */
/* Local substring search                                                     */
/* ------------------------------------------------------------------------- */

static const char *ow_strfind(const char *haystack, const char *needle) {
  size_t needle_length;
  size_t i;

  if (haystack == NULL || needle == NULL)
    return NULL;

  needle_length = ow_strlen(needle);

  if (needle_length == 0)
    return haystack;

  for (i = 0; haystack[i] != '\0'; ++i) {
    size_t j;

    for (j = 0; j < needle_length; ++j) {
      if (haystack[i + j] == '\0')
        break;

      if (haystack[i + j] != needle[j])
        break;
    }

    if (j == needle_length)
      return &haystack[i];
  }

  return NULL;
}

static size_t count_occ(const char *haystack, const char *needle) {
  size_t count = 0;
  size_t needle_length;
  const char *current;

  if (haystack == NULL || needle == NULL)
    return 0;

  needle_length = ow_strlen(needle);

  if (needle_length == 0)
    return 0;

  current = haystack;

  while ((current = ow_strfind(current, needle)) != NULL) {
    ++count;
    current += needle_length;
  }

  return count;
}

/* ------------------------------------------------------------------------- */
/* Transcript verification                                                    */
/* ------------------------------------------------------------------------- */

/* ------------------------------------------------------------------------- */
/* User-window address validation: alignment split (regression)              */
/* ------------------------------------------------------------------------- */

/*
 * Two predicates with deliberately different contracts, kept apart on purpose:
 *
 *   OwMemIsUserWindow()  page-granular. True only for a page BASE that lies
 *                        inside the window.  Required wherever the address
 *                        names a mapping or a VAD endpoint, because those are
 *                        always page-aligned by construction.
 *
 *   OwMemInUserWindow()  address-level. True for ANY byte address inside the
 *                        window.  Required for real instruction/data
 *                        addresses, which are routinely mid-page.
 *
 * Regression history: the entry point of a relocated OWX image is mid-page
 * (image base + the entry RVA), and a thread's initial RSP sits just under a
 * page top.  Both are legal.  When the page-aligned predicate was applied to
 * them, a correct image was rejected as "outside window" -- and once the
 * stricter check was bypassed for the entry, the two predicates were easy to
 * confuse again in review.  These cases pin both contracts down.
 */
static void check_window(const char *label, bool got, bool want) {
  if (got == want) {
    ++g_passed;
    printf("[PASS] %s = %s\n", label, want ? "true" : "false");
  } else {
    ++g_failures;
    printf("[FAIL] %s: got %s, want %s\n", label, got ? "true" : "false",
           want ? "true" : "false");
  }
}

/* -------------------------------------------------------------------- */
/* Import rejection (regression)                                         */
/* -------------------------------------------------------------------- */
/* OWX1 has no import entry structure, no import table and no relocation
 * table, so the loader cannot bind an imported symbol; it rejects any image
 * that declares one via OwOwxImageIsSelfContained().
 *
 * This matters because the failure it replaces was silent and misleading.  An
 * image whose imports were never bound still loads: its IAT slots hold RVAs
 * into its own hint/name table rather than callable addresses, the uniform
 * load bias cannot repair that, and the process only faults much later, at
 * CPL3, on its first call through one of those slots.  The fault address points
 * nowhere near the cause.  Rejecting at load time reports the actual problem.
 *
 * The cases below pin both halves of that contract: the predicate refuses a
 * declared import, and the owinit image the kernel actually ships is genuinely
 * self-contained.  The second half is the one that regressed: owinit.owx
 * imported kconf64_init and kconf64_get_string, and the packer reported
 * import_count = 0 regardless while discarding .idata, so the image claimed to
 * be self-contained and was not. */
static void test_import_rejection(void) {
  owx_header_t probe;
  const owx_header_t *shipped = (const owx_header_t *)(const void *)g_owinit_image;

  printf("\n=== Import rejection ===\n");

  memset(&probe, 0, sizeof(probe));
  probe.magic = OWX_MAGIC;
  probe.import_count = 0u;
  check_window("OwOwxImageIsSelfContained(import_count=0)", OwOwxImageIsSelfContained(&probe), true);

  probe.import_count = 1u;
  check_window("OwOwxImageIsSelfContained(import_count=1)", OwOwxImageIsSelfContained(&probe), false);

  probe.import_count = 2u;
  check_window("OwOwxImageIsSelfContained(import_count=2)", OwOwxImageIsSelfContained(&probe), false);

  check_window("OwOwxImageIsSelfContained(NULL)", OwOwxImageIsSelfContained(NULL), false);

  /* The real artifact.  owinit_main calls kconf64_init and
   * kconf64_get_string, so this fails the moment kconf64 stops being linked
   * into owinit.owx -- which is the point: it must be resolved at link time,
   * not at load time, because nothing in the kernel can resolve it. */
  if (OWINIT_IMAGE_SIZE < sizeof(owx_header_t)) {
    check_window("shipped owinit image is large enough for a header", false, true);
  } else {
    check_window("shipped owinit image is large enough for a header", true, true);
    check_window("shipped owinit image declares no imports",
                 OwOwxImageIsSelfContained(shipped), true);
    if (shipped->import_count != 0u) {
      printf("       shipped image declares %u import(s)\n",
             (unsigned)shipped->import_count);
    }
  }
}

/* -------------------------------------------------------------------- */
/* Entry point is the real owinit_main, not the stub (regression)         */
/* -------------------------------------------------------------------- */
/* The stub and the real function are both "an .owx entry that returns", so
 * proving the launch path works does not tell you which one ran.  Until the
 * entry was repointed, every CPL3 result was satisfied by `xor eax,eax; ret`
 * -- and a test that only asserts "the entry stub ran" would keep passing if
 * the entry silently reverted, which is precisely the regression worth
 * catching.
 *
 * This checks the shipped image itself rather than trusting the link:
 *   - the entry must fall inside a section the packer typed as CODE, since
 *     a data or BSS entry would fault on NX and mean nothing else;
 *   - the first three bytes at the entry must not be owx_entry_stub's
 *     `xor eax,%eax; ret` (31 C0 C3).
 * Together those say the entry is real executable code that is not the stub.
 *
 * The two classifiers below are factored out so they can be unit tested in
 * band: a signature check that silently stopped matching would otherwise let a
 * reverted owinit pass unnoticed, which is the exact failure this guards. */
static int bytes_are_entry_stub(const unsigned char *p) {
  return (p[0] == 0x31u && p[1] == 0xC0u && p[2] == 0xC3u);
}

/* owinit_main opens with the SysV frame setup `sub $0x28,%rsp`
 * (48 83 EC 28) followed by a direct relative call (E8) to kconf64_init.
 * Asserting the call opcode too means an unrelated 3-byte stack adjustment
 * cannot masquerade as the real entry. */
static int bytes_are_owinit_main(const unsigned char *p) {
  return (p[0] == 0x48u && p[1] == 0x83u && p[2] == 0xECu &&
          p[3] == 0x28u && p[4] == 0xE8u);
}

static void test_entry_classifiers(void) {
  /* Both prologues as they actually link today, captured from the shipped
   * images rather than transcribed by hand. */
  static const unsigned char stub[8] = {0x31, 0xC0, 0xC3, 0x90, 0x90,
                                        0x90, 0x90, 0x90};
  static const unsigned char real[8] = {0x48, 0x83, 0xEC, 0x28, 0xE8,
                                        0xF7, 0x04, 0x00};

  printf("\n=== Entry signature classifiers (negative self-test) ===\n");

  check_window("stub classifier accepts xor eax,eax; ret",
               bytes_are_entry_stub(stub) == 1, true);
  check_window("stub classifier rejects owinit_main's prologue",
               bytes_are_entry_stub(real) == 0, true);
  check_window("owinit_main classifier accepts sub rsp,0x28; call",
               bytes_are_owinit_main(real) == 1, true);
  check_window("owinit_main classifier rejects the stub",
               bytes_are_owinit_main(stub) == 0, true);
}

static void test_entry_is_owinit_main(void) {
  const owx_header_t *h = (const owx_header_t *)(const void *)g_owinit_image;
  const owx_section_entry_t *secs;
  const unsigned char *img = g_owinit_image;
  uint64_t entry = 0;
  int32_t hit = -1;

  printf("\n=== Entry point identity ===\n");

  if (OWINIT_IMAGE_SIZE < sizeof(owx_header_t)) {
    check_window("image large enough for an OWX header", false, true);
    return;
  }
  check_window("image large enough for an OWX header", true, true);

  if (h->section_table_offset == 0u ||
      h->section_count == 0u || h->section_count > OWX_MAX_SECTIONS) {
    check_window("section table is usable", false, true);
    return;
  }
  check_window("section table is usable", true, true);

  entry = h->entry_point;
  secs = (const owx_section_entry_t *)(const void *)(img + h->section_table_offset);

  for (uint32_t i = 0; i < h->section_count; ++i) {
    if (entry >= secs[i].virtual_addr &&
        entry < secs[i].virtual_addr + secs[i].size) {
      hit = (int32_t)i;
      break;
    }
  }

  check_window("entry lies inside a section", hit >= 0, true);
  check_window("entry section is typed CODE",
               hit >= 0 && secs[hit].type == OWX_SECTION_CODE, true);

  /* The RVA comes from the header's own preferred_base rather than a constant
   * baked into this test, so a base change cannot silently shift the target. */
  if (h->preferred_base != 0u && entry > h->preferred_base) {
    uint64_t rva = entry - h->preferred_base;
    printf("       entry rva: 0x%llX (base 0x%llX)\n",
           (unsigned long long)rva, (unsigned long long)h->preferred_base);
    check_window("entry RVA is 0x1000 (owinit_main)", rva == 0x1000u, true);
  } else {
    check_window("entry RVA is 0x1000 (owinit_main)", false, true);
  }

  if (hit >= 0) {
    const owx_section_entry_t *sec = &secs[hit];
    uint64_t delta = entry - sec->virtual_addr;
    uint64_t off = sec->file_offset + delta;
    const unsigned char *p;

    if (off + 8u > OWINIT_IMAGE_SIZE) {
      check_window("entry instruction is inside the image file", false, true);
      return;
    }
    check_window("entry instruction is inside the image file", true, true);

    p = img + off;
    printf("       entry bytes:");
    for (unsigned k = 0; k < 8u; ++k) printf(" %02X", p[k]);
    printf("\n");

    check_window("entry is not owx_entry_stub (xor eax,eax; ret)",
                 !bytes_are_entry_stub(p), true);
    check_window("entry bytes are owinit_main's prologue "
                 "(sub rsp,0x28; call kconf64_init)",
                 bytes_are_owinit_main(p), true);
  }
}

static void test_user_window_predicates(void) {
  printf("\n=== User-window address validation ===\n");

  /* --- Address-level: mid-page addresses MUST be accepted. ------------- */

  /* A real owinit entry: OW_USER_IMAGE_BASE + the packed entry RVA 0x40. */
  check_window("OwMemInUserWindow(0x4000040) /* owinit entry */",
               OwMemInUserWindow(0x4000040u), true);

  /* A real initial user RSP: stack page top - 8 (the C-ABI return slot). */
  check_window("OwMemInUserWindow(0x41FEFF8) /* resume rsp */",
               OwMemInUserWindow(0x41FEFF8u), true);

  /* Last byte of the window is inside; first byte past it is not. */
  check_window("OwMemInUserWindow(0x41FFFFF) /* last byte */",
               OwMemInUserWindow(0x41FFFFFu), true);
  check_window("OwMemInUserWindow(0x4200000) /* one past end */",
               OwMemInUserWindow(0x4200000u), false);
  check_window("OwMemInUserWindow(0x3FFFFFF) /* one below start */",
               OwMemInUserWindow(0x3FFFFFFu), false);

  /* The guard band is inside the window by address but must not be treated as
   * ordinary user stack/data; the aligned predicate is what gates mapping, and
   * the address-level one is what gates "may this instruction address run". */
  check_window("OwMemIsUserWindow(0x41F9000) /* guard base page */",
               OwMemIsUserWindow(0x41F9000u), true);

  /* --- Page-granular: alignment MUST still be required. ---------------- */

  check_window("OwMemIsUserWindow(0x4000000) /* page base */",
               OwMemIsUserWindow(0x4000000u), true);
  check_window("OwMemIsUserWindow(0x4000040) /* mid-page rejected */",
               OwMemIsUserWindow(0x4000040u), false);
  check_window("OwMemIsUserWindow(0x41FEFF8) /* mid-page rejected */",
               OwMemIsUserWindow(0x41FEFF8u), false);

  /* Last mappable page base, and the first page base past the window. */
  check_window("OwMemIsUserWindow(0x41FF000) /* last page base */",
               OwMemIsUserWindow(0x41FF000u), true);
  check_window("OwMemIsUserWindow(0x4200000) /* past window */",
               OwMemIsUserWindow(0x4200000u), false);

  /* --- The two predicates must not be interchangeable. ------------------ */

  check_window("aligned base is also an in-window address",
               OwMemInUserWindow(0x4000000u), true);
  check_window("mid-page address is NOT a valid mapping target",
               OwMemIsUserWindow(0x4000040u), false);
}

/* -------------------------------------------------------------------- */
/* Userspace boot policy: the three owinit states                       */
/* -------------------------------------------------------------------- */
/* The classifier is a pure function of the probe, which is the only reason all
 * three states are testable at all: state 3 panics the machine and state 2 needs
 * a real volume and a real hand-off, so neither can be reached by simply running
 * a boot and looking at the log.  Every combination below is a volume that can
 * exist, so every one of them gets a verdict asserted.
 *
 * The cases are written as full field sets rather than as a base plus deltas on
 * purpose.  The distinction that matters between two of them -- present vs
 * present-and-valid -- is exactly the distinction a "fill in the interesting
 * field" style of test would stop expressing the moment someone reorders the
 * struct. */

static void probe_clear(OW_USERSPACE_PROBE *probe) {
  memset(probe, 0, sizeof(*probe));
  probe->PrimaryStatus = OW_ERR_NOT_FOUND;
  probe->EmergencyStatus = OW_ERR_NOT_FOUND;
  probe->RescueStatus = OW_ERR_NOT_FOUND;
}

static void probe_mark_primary(OW_USERSPACE_PROBE *probe, bool present,
                               bool valid) {
  probe->PrimaryPresent = present;
  probe->PrimaryValid = valid;
  probe->PrimaryStatus = valid ? OW_SUCCESS : OW_ERR_CORRUPT;
}

static void probe_mark_emergency(OW_USERSPACE_PROBE *probe, bool present,
                                 bool valid) {
  probe->EmergencyPresent = present;
  probe->EmergencyValid = valid;
  probe->EmergencyStatus = valid ? OW_SUCCESS : OW_ERR_CORRUPT;
}

static void probe_mark_rescue(OW_USERSPACE_PROBE *probe, bool present,
                              bool valid) {
  probe->RescuePresent = present;
  probe->RescueValid = valid;
  probe->RescueStatus = valid ? OW_SUCCESS : OW_ERR_CORRUPT;
}

static void check_state(const char *label, const OW_USERSPACE_PROBE *probe,
                        OW_USERSPACE_STATE want) {
  OW_USERSPACE_STATE got = OwBootClassifyUserspace(probe);
  const char *got_name = OwBootUserspaceStateName(got);
  const char *want_name = OwBootUserspaceStateName(want);

  if (got == want) {
    ++g_passed;
    printf("[PASS] %s = %s\n", label, want_name);
  } else {
    ++g_failures;
    printf("[FAIL] %s: got %s, want %s\n", label, got_name, want_name);
  }
}

static void test_userspace_states(void) {
  OW_USERSPACE_PROBE probe;

  printf("\n=== Userspace boot state classification ===\n");

  /* --- State 1: a usable primary. ------------------------------------- */

  /* The complete volume: all three images present and intact.  This is the
   * normal test image, and the assertion that matters is the negative one
   * below -- that the emergency pair being present changes nothing. */
  probe_clear(&probe);
  probe_mark_primary(&probe, true, true);
  probe_mark_emergency(&probe, true, true);
  probe_mark_rescue(&probe, true, true);
  check_state("all three images valid", &probe, OW_USERSPACE_PRIMARY);

  /* owinit alone, with no emergency pair at all: still state 1.  A volume
   * carrying nothing but the orchestrator is the most ordinary volume there
   * is, and the emergency images must not be a precondition for it. */
  probe_clear(&probe);
  probe_mark_primary(&probe, true, true);
  check_state("owinit valid, no emergency images", &probe,
              OW_USERSPACE_PRIMARY);

  /* A corrupt owinit.owx does NOT fall to state 1 even though both emergency
   * images are sitting right there waiting to be used. */
  probe_clear(&probe);
  probe_mark_primary(&probe, true, false);
  probe_mark_emergency(&probe, true, true);
  probe_mark_rescue(&probe, true, true);
  check_state("owinit present but corrupt", &probe, OW_USERSPACE_EMERGENCY);

  /* --- State 2: no usable primary, an enterable emergency init. -------- */

  /* The emergency test image: no owinit.owx at all. */
  probe_clear(&probe);
  probe_mark_emergency(&probe, true, true);
  probe_mark_rescue(&probe, true, true);
  check_state("owinit absent, owinitv+owrs valid", &probe,
              OW_USERSPACE_EMERGENCY);

  /* owinitv alone.  A rescue shell with no init is a degraded rescue shell, and
   * the machine is still bootable -- so this must NOT be state 3. */
  probe_clear(&probe);
  probe_mark_emergency(&probe, true, true);
  check_state("owinitv valid, owrs absent", &probe, OW_USERSPACE_EMERGENCY);

  /* owinitv present but corrupt, owrs intact.  This is state 3 and the single
   * most important case in the set: owrs.owx is a rescue SHELL, and a shell is
   * not something the kernel can enter as PID 1.  Classifying this as
   * EMERGENCY because "some emergency bytes are present" would select a state
   * the hand-off cannot execute, and the machine would fall out of the boot with
   * no init and no diagnostic. */
  probe_clear(&probe);
  probe_mark_emergency(&probe, true, false);
  probe_mark_rescue(&probe, true, true);
  check_state("owinitv corrupt, owrs valid (lone shell)", &probe,
              OW_USERSPACE_ABSENT);

  /* owinitv intact, owrs corrupt.  State 2: the init is enterable, the shell
   * is not, and owinitv reports the missing shell rather than dying. */
  probe_clear(&probe);
  probe_mark_emergency(&probe, true, true);
  probe_mark_rescue(&probe, true, false);
  check_state("owinitv valid, owrs corrupt", &probe, OW_USERSPACE_EMERGENCY);

  /* --- State 3: nothing to enter. ------------------------------------- */

  /* The validation image: no userspace at all. */
  probe_clear(&probe);
  check_state("no userspace images at all", &probe, OW_USERSPACE_ABSENT);

  /* All three present, none usable.  Corruption everywhere is still state 3. */
  probe_clear(&probe);
  probe_mark_primary(&probe, true, false);
  probe_mark_emergency(&probe, true, false);
  probe_mark_rescue(&probe, true, false);
  check_state("all three present but all corrupt", &probe, OW_USERSPACE_ABSENT);

  /* Lone owrs.owx.  The reason this is a case at all is the "and/or" in the
   * specification: a volume that has emergency bytes but no emergency INIT is
   * not an emergency userspace, and saying so is the difference between a
   * panic that says "reinstall owinitv.owx" and one that says "the disk is
   * empty". */
  probe_clear(&probe);
  probe_mark_rescue(&probe, true, true);
  check_state("lone owrs, no owinitv", &probe, OW_USERSPACE_ABSENT);

  /* The predicates the classifier is built from, asserted separately so a
   * failure points at the specific promise that broke. */
  probe_clear(&probe);
  probe_mark_rescue(&probe, true, true);
  check_window("OwUserSpaceEmergencyBytes() with a lone owrs", 
               OwUserSpaceEmergencyBytes(&probe), true);
  check_window("OwUserSpaceEmergencyAvailable() with a lone owrs",
               OwUserSpaceEmergencyAvailable(&probe), false);

  probe_clear(&probe);
  check_window("OwUserSpaceEmergencyBytes() on an empty volume",
               OwUserSpaceEmergencyBytes(&probe), false);
  check_window("OwUserSpaceEmergencyAvailable() on an empty volume",
               OwUserSpaceEmergencyAvailable(&probe), false);

  probe_mark_emergency(&probe, true, true);
  check_window("OwUserSpaceEmergencyAvailable() with a valid owinitv",
               OwUserSpaceEmergencyAvailable(&probe), true);

  /* A null probe is state 3, not a crash.  The classifier is called from boot
   * code where a NULL would be a bug worth surviving. */
  check_state("NULL probe", (const OW_USERSPACE_PROBE *)0, OW_USERSPACE_ABSENT);
}

/* -------------------------------------------------------------------- */
/* Emergency image integrity                                              */
/* -------------------------------------------------------------------- */
/* Two things are checked here, and the second is the one that matters.
 *
 * First: the emergency pair really is present in the build and passes the
 * verdict the boot survey acts on.  A missing owinitv.owx would make the state-2
 * test image silently unbootable, and it would do so at the moment someone
 * wanted to reproduce a failure.
 *
 * Second: corrupting a byte makes them fail it.  This is the assertion the whole
 * "invalid" half of the policy rests on.  Without it, "invalid" is only ever
 * demonstrated by a header with a wrong magic number, and a bit-rot in a code
 * section -- which passes every structural check the loader makes -- would still
 * be classified PRIMARY and then fault at CPL3. */
static void test_emergency_images(void) {
  static unsigned char scratch[OW_USERSPACE_IMAGE_MAX];
  size_t i;

  printf("\n=== Emergency image integrity ===\n");

  check_window("owinitv.owx is present in the build",
               OWINITV_IMAGE_SIZE > 0u, true);
  check_window("owrs.owx is present in the build", OWRS_IMAGE_SIZE > 0u, true);

  check_window("owinitv.owx passes OwOwxImageIsUsable",
               OwOwxImageIsUsable(g_owinitv_image, OWINITV_IMAGE_SIZE), true);
  check_window("owrs.owx passes OwOwxImageIsUsable",
               OwOwxImageIsUsable(g_owrs_image, OWRS_IMAGE_SIZE), true);

  check_window("owinit.owx passes OwOwxImageIsUsable",
               OwOwxImageIsUsable(g_owinit_image, OWINIT_IMAGE_SIZE), true);

  /* Both emergency images must be loadable AND self-contained.  An import
   * descriptor means the loader refuses the image outright, so the emergency
   * path would exist on paper only. */
  {
    const owx_header_t *hv = (const owx_header_t *)(const void *)g_owinitv_image;
    const owx_header_t *hr = (const owx_header_t *)(const void *)g_owrs_image;
    check_window("owinitv.owx declares no imports", hv->import_count == 0u, true);
    check_window("owrs.owx declares no imports", hr->import_count == 0u, true);
    check_window("owinitv.owx subsystem is RECOVERY",
                 hv->subsystem == OWX_SUBSYSTEM_RECOVERY, true);
    check_window("owrs.owx subsystem is RECOVERY",
                 hr->subsystem == OWX_SUBSYSTEM_RECOVERY, true);
  }

  /* Corruption, one byte at a time through the OWX image.
   *
   * The positions are all inside the OWX image rather than the file, because the
   * two are no longer the same length: a signed image is image||CICB, so
   * OWRS_IMAGE_SIZE covers the block as well and a spot chosen by absolute file
   * offset can land in the trailer on one build and in a section on another.
   * The bound used here is the header's image_size, which is the same quantity
   * the structural checks range over.
   *
   * The interesting positions are the ones a real failure produces: inside the
   * header (a truncated or re-flashed image), inside the section table (a bad
   * table entry that the structural checks cannot see), and deep in a code
   * section (bit rot, which is the case a header-only test would miss
   * entirely). */
  {
    const owx_header_t *h = (const owx_header_t *)(const void *)g_owrs_image;
    const uint32_t image_size = h->image_size;
    const size_t spots[] = {
        0x0000u,  /* magic */
        0x0040u,  /* section_count */
        0x0100u,  /* first section table entry */
        0x0100u + 24u, /* a section's checksum field */
        0x1000u + 8u,  /* into the code section */
        0x2000u         /* past the first section */
    };
    const char *labels[] = {
        "magic", "section_count", "section table entry", "section checksum",
        "code section", "second section"
    };
    size_t s;

    check_window("the owrs OWX image is inside its own file",
                 image_size <= OWRS_IMAGE_SIZE, true);

    for (s = 0; s < sizeof(spots) / sizeof(spots[0]); s++) {
      if (spots[s] >= image_size) continue;
      memcpy(scratch, g_owrs_image, OWRS_IMAGE_SIZE);
      scratch[spots[s]] ^= 0xFFu;
      if (OwOwxImageIsUsable(scratch, OWRS_IMAGE_SIZE)) {
        ++g_failures;
        printf("[FAIL] owrs.owx with a flipped byte at 0x%04X (%s) is still "
               "reported usable\n", (unsigned)spots[s], labels[s]);
      } else {
        ++g_passed;
        printf("[PASS] owrs.owx with a flipped byte at 0x%04X (%s) is "
               "unusable\n", (unsigned)spots[s], labels[s]);
      }
    }

    /* A flipped byte in the trailer is a different thing, and it is CIS's job
     * rather than the structural checks'.  Structural validation ranges over
     * [0, image_size) and is supposed to ignore the block entirely, so this is
     * recorded as "still structurally usable" -- the signature is what has to
     * catch it, and the CIS fixture corpus is where that is tested. */
    if (OWRS_IMAGE_SIZE > image_size) {
      memcpy(scratch, g_owrs_image, OWRS_IMAGE_SIZE);
      scratch[OWRS_IMAGE_SIZE - 1u] ^= 0xFFu;
      check_window("a flipped trailer byte is outside OWX structural validation",
                   OwOwxImageIsUsable(scratch, OWRS_IMAGE_SIZE), true);
    }
  }

  /* Truncation: the loader's own bound is image_size <= bytes held, so a short
   * read has to fail before anything is mapped.
   *
   * Measured against image_size, not the file length.  Chopping a byte off the
   * end of a signed image removes a trailer byte, which leaves the OWX image
   * complete and the image genuinely loadable-as-a-OWX; refusing it would be the
   * structural check second-guessing CIS.  Chopping into the image proper is the
   * failure this is actually about. */
  {
    const owx_header_t *h = (const owx_header_t *)(const void *)g_owrs_image;
    const uint32_t image_size = h->image_size;

    for (i = 0; i < 3; i++) {
      uint32_t short_by = (uint32_t)(1u << (8u * i));
      if (short_by >= image_size) continue;
      check_window("owrs.owx truncated inside the OWX image is unusable",
                   OwOwxImageIsUsable(g_owrs_image, image_size - short_by),
                   false);
    }
  }

  /* The two in-kernel CRC32c implementations must agree.
   *
   * ps/owx_loader.c carries its own CRC32c so the OWX format's integrity check
   * lives with the format rather than depending on the VFS.  That leaves two
   * copies of the same polynomial in the tree (this one and
   * OwFsChecksumCalc() in vfs/vfs.c) plus a third in tools/owx_pack.py.  A copy
   * that drifts does not produce a load failure -- it produces an image rejected
   * for no visible reason, or worse, one accepted that should not be.
   *
   * Note what this deliberately does NOT do: reimplement the polynomial a third
   * time to compare against.  A test that carries its own copy of the algorithm
   * it is validating cannot tell "the two implementations agree" from "the test
   * agrees with itself", which is the failure a checksum test is most prone to.
   * It compares the two real functions over a byte-for-byte identical range.
   *
   * The range is [0x10, end) with the image_checksum field read as zero, because
   * that field lies inside its own hash window: the packer hashed it as zero and
   * then wrote the result in, so verifying it requires putting it back. */
  {
/* Over the OWX image, which is the header's image_size rather than the file
   * length: the packer computes image_checksum before appending the CIS block,
   * so a signed image's file length would make this compare the packer's value
   * against a range it never hashed. */
  const owx_header_t *h = (const owx_header_t *)(const void *)g_owrs_image;
  const uint32_t n = h->image_size;
  const uint32_t declared = h->image_checksum;
  uint32_t vfs_crc;

  check_window("the CRC range does not run past the owrs file",
               n <= OWRS_IMAGE_SIZE, true);

  memcpy(scratch, g_owrs_image, n);
    scratch[0x90] = 0;
    scratch[0x91] = 0;
    scratch[0x92] = 0;
    scratch[0x93] = 0;
    vfs_crc = OwFsChecksumCalc(scratch + 0x10, n - 0x10);

    /* Proves the two kernels agree on the same bytes, and that the packer wrote
     * the same value they compute.  All three at once, because any two of them
     * agreeing while the third differs is exactly the drift being guarded. */
    check_window("VFS and OWX CRC32c agree over the image_checksum range",
                 vfs_crc == declared, true);
  }
}

static void expect(const char *needle, size_t minimum_count) {
  char *output;
  size_t count;

  output = HostHalOutput();

  if (output == NULL)
    return;

  count = count_occ(output, needle);

  if (count >= minimum_count) {
    ++g_passed;

    printf("[PASS] <<%s>> x%u\n", needle, (unsigned)count);
  } else {
    ++g_failures;

    printf("[FAIL] <<%s>> expected >=%u, found %u\n", needle,
           (unsigned)minimum_count, (unsigned)count);
  }
}

/* ------------------------------------------------------------------------- */
/* Host file access                                                           */
/* ------------------------------------------------------------------------- */

/*
 * Read a host file into a caller-provided buffer.
 *
 * Returns:
 *   >= 0 : number of bytes read
 *   -1   : failure
 *
 * No stdio file API is used.
 */
static long host_read_file(const char *path, uint8_t *buffer, size_t capacity) {
  int fd;
  long total = 0;

  if (path == NULL || buffer == NULL || capacity == 0) {
    return -1;
  }

#ifdef _WIN32

  {
    errno_t result;

    result = _sopen_s(&fd, path, _O_RDONLY | _O_BINARY, _SH_DENYNO, 0);

    if (result != 0 || fd < 0)
      return -1;
  }

#else

  fd = open(path, O_RDONLY);

  if (fd < 0)
    return -1;

#endif

  while ((size_t)total < capacity) {
    size_t remaining;
    unsigned int request;
    int bytes_read;

    remaining = capacity - (size_t)total;

    /*
     * Keep the read size inside the range accepted by both
     * the Windows CRT and normal POSIX implementations.
     */
    request = (remaining > 0x7FFFFFFFU) ? 0x7FFFFFFFU : (unsigned int)remaining;

#ifdef _WIN32

    bytes_read = _read(fd, buffer + total, request);

#else

    bytes_read = (int)read(fd, buffer + total, request);

#endif

    if (bytes_read < 0) {

#ifdef _WIN32
      _close(fd);
#else
      close(fd);
#endif

      return -1;
    }

    if (bytes_read == 0)
      break;

    total += (long)bytes_read;
  }

#ifdef _WIN32
  _close(fd);
#else
  close(fd);
#endif

  return total;
}

/*
 * Try:
 *
 *   name
 *   build/name
 *   ../name
 *
 * without constructing paths using snprintf/strcpy.
 */
static long host_read_file_candidates(const char *name, uint8_t *buffer,
                                      size_t capacity) {
  static const char *const prefixes[] = {"", "build/", "../"};

  size_t prefix_index;

  if (name == NULL)
    return -1;

  for (prefix_index = 0; prefix_index < sizeof(prefixes) / sizeof(prefixes[0]);
       ++prefix_index) {

    char path[512];
    size_t prefix_length;
    size_t name_length;

    prefix_length = ow_strlen(prefixes[prefix_index]);
    name_length = ow_strlen(name);

    if (prefix_length + name_length + 1 > sizeof(path))
      continue;

    if (prefix_length != 0) {
      ow_copy_bytes((uint8_t *)path, (const uint8_t *)prefixes[prefix_index],
                    prefix_length);
    }

    ow_copy_bytes((uint8_t *)path + prefix_length, (const uint8_t *)name,
                  name_length);

    path[prefix_length + name_length] = '\0';

    {
      long result;

      result = host_read_file(path, buffer, capacity);

      if (result >= 0)
        return result;
    }
  }

  return -1;
}

/* -------------------------------------------------------------------- */
/* Copyleft Integrity Safeguard: enforcement state (Stage 1)             */
/* -------------------------------------------------------------------- */
/*
 * Stage 1 owns no verdict logic, so these cases are about the two properties
 * every later stage leans on rather than about any particular verification:
 *
 *   - An unprovisioned trust store refuses everything.  This build pins zero
 *     keys, so "no keys" must not degrade into "no checking": a subsystem that
 *     waves images through because it has nothing to compare them against is
 *     the exact failure mode CIS exists to prevent.
 *
 *   - The measurement log is append-only and does not recycle.  Once the table
 *     is full the subsystem reports what it already knows instead of
 *     overwriting the oldest decision, because the log is the only record a
 *     quarantined system has of what it refused and why.
 *
 * The trust-store injection used below is host-only (OW_HOST_HAL).  It proves
 * the lookup paths agree with the table layout; it is not a way to make a
 * production kernel accept an unprovisioned key, and no production build
 * compiles the call.
 */
static void check_eq(const char *label, unsigned long got,
                     unsigned long want) {
  if (got == want) {
    ++g_passed;
    printf("[PASS] %s = %lu\n", label, got);
  } else {
    ++g_failures;
    printf("[FAIL] %s: got %lu, want %lu\n", label, got, want);
  }
}

/* -------------------------------------------------------------------- */
/* CIS block format tests                                                */
/* -------------------------------------------------------------------- */
/* check_bytes and check_bytes_v are defined further down, beside the crypto
 * tests that first needed them.  Declared here so this test can use the same
 * comparators rather than a second, near-identical pair. */
static void check_bytes(const char *label, const uint8_t *got,
                        const uint8_t *want, size_t len);
static void check_bytes_v(const char *what, uint32_t index, const uint8_t *got,
                          const uint8_t *want, size_t len);
/*
 * Blocks are built here rather than read from a generated corpus, because the
 * cases worth testing are not "the right bytes" but one field changed from the
 * right bytes: a magic off by a bit, a manifest_size that disagrees with
 * block_size, a tag repeated, a tag moved below its predecessor, an overlong
 * UTF-8 sequence.  A corpus of valid blocks exercises none of those.
 *
 * Each case breaks exactly one thing, so a failure names the rule it broke, and
 * each expects a specific status rather than merely "not OK" -- otherwise a
 * block rejected for the wrong reason still reads as a pass.
 */

#define CIS_TEST_MAX 512u

typedef struct {
  uint8_t bytes[CIS_TEST_MAX];
  uint32_t size;
} cis_test_block;

/* The append helpers bounds-check against CIS_TEST_MAX rather than trusting the
 * caller: a builder that can overrun its buffer turns a parser bug into a
 * harness crash, which reports the wrong defect. */
static bool cis_test_put(cis_test_block *b, uint8_t v) {
  if (b->size >= CIS_TEST_MAX) {
    return false;
  }
  b->bytes[b->size++] = v;
  return true;
}

static bool cis_test_put_u16(cis_test_block *b, uint16_t v) {
  return cis_test_put(b, (uint8_t)(v & 0xFFu)) &&
         cis_test_put(b, (uint8_t)((v >> 8) & 0xFFu));
}

static bool cis_test_put_u32(cis_test_block *b, uint32_t v) {
  return cis_test_put(b, (uint8_t)(v & 0xFFu)) &&
         cis_test_put(b, (uint8_t)((v >> 8) & 0xFFu)) &&
         cis_test_put(b, (uint8_t)((v >> 16) & 0xFFu)) &&
         cis_test_put(b, (uint8_t)((v >> 24) & 0xFFu));
}

static bool cis_test_put_bytes(cis_test_block *b, const uint8_t *p, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (!cis_test_put(b, p[i])) {
      return false;
    }
  }
  return true;
}

static bool cis_test_put_tlv(cis_test_block *b, uint16_t tag,
                             const uint8_t *value, uint16_t len) {
  return cis_test_put_u16(b, tag) && cis_test_put_u16(b, len) &&
         cis_test_put_bytes(b, value, (size_t)len);
}

static void cis_test_put_tlv_text(cis_test_block *b, uint16_t tag,
                                  const char *s) {
  (void)cis_test_put_tlv(b, tag, (const uint8_t *)s, (uint16_t)strlen(s));
}

/* The reference manifest's text values, named once so the assertions below
 * compare against strlen rather than a literal that can drift from the string. */
#define CIS_TEST_LICENSE   "MIT"
#define CIS_TEST_COPYRIGHT "(c) OpenWindows"

/* The key id and content digest the reference manifest carries, so the parse
 * can be compared against them by name instead of by a byte offset computed
 * from the layout. */
static void cis_test_expected_ids(uint8_t *key_id, uint8_t *digest) {
  size_t i;
  for (i = 0; i < OW_CIS_KEY_ID_SIZE; i++) {
    key_id[i] = (uint8_t)(0x10u + i);
  }
  for (i = 0; i < OW_SHA256_DIGEST_SIZE; i++) {
    digest[i] = (uint8_t)(0x20u + i);
  }
}

/* A well-formed manifest: the 32-byte prefix, then the five required tags in
 * ascending order.  build-id (6) is left out so the optional path is exercised
 * by the good case as well as the bad ones.  The signature is all zeros: the
 * builder knows no key, and the parser must not care. */
static bool cis_test_build_manifest(cis_test_block *m) {
  uint8_t key_id[OW_CIS_KEY_ID_SIZE];
  uint8_t digest[OW_SHA256_DIGEST_SIZE];
  uint8_t algo[4];
  size_t i;
  const size_t prefix_len = sizeof(OW_CIS_MANIFEST_PREFIX) - 1u;

  memset(m, 0, sizeof(*m));
  if (!cis_test_put_bytes(m, (const uint8_t *)OW_CIS_MANIFEST_PREFIX,
                          prefix_len)) {
    return false;
  }
  for (i = prefix_len; i < OW_CIS_MANIFEST_PREFIX_SIZE; i++) {
    if (!cis_test_put(m, 0U)) {
      return false;
    }
  }

  cis_test_expected_ids(key_id, digest);
  algo[0] = (uint8_t)(OW_CIS_DIGEST_ALGO_SHA256 & 0xFFu);
  algo[1] = (uint8_t)((OW_CIS_DIGEST_ALGO_SHA256 >> 8) & 0xFFu);
  algo[2] = 0U;
  algo[3] = 0U;

  cis_test_put_tlv_text(m, OW_CIS_TAG_LICENSE, CIS_TEST_LICENSE);
  if (!cis_test_put_tlv(m, OW_CIS_TAG_DIGEST_ALGO, algo, 4u) ||
      !cis_test_put_tlv(m, OW_CIS_TAG_KEY_ID, key_id,
                        (uint16_t)sizeof(key_id)) ||
      !cis_test_put_tlv(m, OW_CIS_TAG_CONTENT_DIGEST, digest,
                        (uint16_t)sizeof(digest))) {
    return false;
  }
  cis_test_put_tlv_text(m, OW_CIS_TAG_COPYRIGHT, CIS_TEST_COPYRIGHT);
  return true;
}

/* Wrap a manifest in a well-formed block: 48-byte header, manifest, 64 zero
 * bytes of signature. */
static bool cis_test_build_block(cis_test_block *b,
                                 const cis_test_block *m) {
  const uint32_t block_size = OW_CIS_BLOCK_HEADER_SIZE + m->size +
                              OW_CIS_SIGNATURE_SIZE;
  size_t i;

  memset(b, 0, sizeof(*b));
  if (m->size > OW_CIS_MAX_MANIFEST_SIZE || block_size > CIS_TEST_MAX) {
    return false;
  }
  if (!cis_test_put_u32(b, OW_CIS_BLOCK_MAGIC) ||
      !cis_test_put_u16(b, OW_CIS_BLOCK_VERSION) ||
      !cis_test_put_u16(b, (uint16_t)OW_CIS_BLOCK_HEADER_SIZE) ||
      !cis_test_put_u32(b, block_size) || !cis_test_put_u32(b, m->size)) {
    return false;
  }
  /* reserved0, flags, reserved1 and reserved2 are all zero, which the loop
   * below writes out to the end of the header. */
  for (i = b->size; i < OW_CIS_BLOCK_HEADER_SIZE; i++) {
    if (!cis_test_put(b, 0U)) {
      return false;
    }
  }
  if (!cis_test_put_bytes(b, m->bytes, m->size)) {
    return false;
  }
  for (i = 0U; i < OW_CIS_SIGNATURE_SIZE; i++) {
    if (!cis_test_put(b, 0U)) {
      return false;
    }
  }
  return true;
}

/* Locate a tag's value inside a built manifest.  Used instead of hardcoded
 * offsets, so the mutation cases keep saying what they mean when the reference
 * manifest changes.  Returns 0xFFFFFFFF when the tag is absent. */
static uint32_t cis_test_find_tlv(const cis_test_block *m, uint16_t want_tag) {
  uint32_t at = OW_CIS_MANIFEST_PREFIX_SIZE;

  while (at + 4u <= m->size) {
    uint16_t tag = (uint16_t)((uint16_t)m->bytes[at] |
                              ((uint16_t)m->bytes[at + 1u] << 8));
    uint16_t len = (uint16_t)((uint16_t)m->bytes[at + 2u] |
                              ((uint16_t)m->bytes[at + 3u] << 8));
    if (tag == want_tag) {
      return at + 4u;
    }
    if ((uint64_t)at + 4u + len > m->size) {
      break;
    }
    at += 4u + (uint32_t)len;
  }
  return 0xFFFFFFFFu;
}

/* The declared length of a tag's value, or 0xFFFFFFFF when the tag is absent.
 * The tag-removal cases read this rather than hardcoding a length: a hardcoded
 * length that is one byte too long silently underflows the memmove size, and
 * the symptom is a crash in a test helper rather than a failed assertion. */
static uint32_t cis_test_tlv_len(const cis_test_block *m, uint16_t tag) {
  const uint32_t at = cis_test_find_tlv(m, tag);
  const uint32_t hdr = at - 4u;
  return (uint16_t)((uint16_t)m->bytes[hdr + 2u] |
                    ((uint16_t)m->bytes[hdr + 3u] << 8));
}

/* Delete one TLV, closing the gap.  Returns false if the tag is absent or the
 * arithmetic does not close. */
static bool cis_test_remove_tlv(cis_test_block *m, uint16_t tag) {
  const uint32_t value_at = cis_test_find_tlv(m, tag);
  uint32_t tlv_at;
  uint32_t tlv_len;

  if (value_at == 0xFFFFFFFFu || value_at < 4u) {
    return false;
  }
  tlv_at = value_at - 4u;
  tlv_len = 4u + cis_test_tlv_len(m, tag);
  if (tlv_len > m->size || tlv_at > m->size - tlv_len) {
    return false;
  }
  memmove(&m->bytes[tlv_at], &m->bytes[tlv_at + tlv_len],
          m->size - tlv_at - tlv_len);
  m->size -= tlv_len;
  return true;
}

static void cis_check_parse(const char *label, const cis_test_block *b,
                            uint32_t available, OW_CIS_FORMAT_STATUS want) {
  OW_CIS_BLOCK parsed;
  const OW_CIS_FORMAT_STATUS got =
      OwCisFormatParse(b->bytes, available, &parsed);

  if (got == want) {
    ++g_passed;
    if (want == OW_CIS_FORMAT_OK) {
      printf("[PASS] %s = %s\n", label, OwCisFormatStatusName(got));
    } else {
      printf("[PASS] %s rejected as %s\n", label, OwCisFormatStatusName(got));
    }
    return;
  }
  ++g_failures;
  printf("[FAIL] %s: got %s, want %s\n", label, OwCisFormatStatusName(got),
         OwCisFormatStatusName(want));
}

/* Copy a base manifest, append one TLV to it, wrap it in a block, and require a
 * status.  The common shape of most of the TLV cases.  Taking the base as an
 * argument rather than rebuilding the reference is what lets a case start from a
 * manifest that has already been altered. */
static void cis_check_extra_tlv(const char *label, const cis_test_block *base,
                                uint16_t tag, const uint8_t *value,
                                uint16_t len, OW_CIS_FORMAT_STATUS want) {
  cis_test_block m;
  cis_test_block blk;

  if (!base) {
    ++g_failures;
    printf("[FAIL] %s: no base manifest\n", label);
    return;
  }
  m = *base;
  if (!cis_test_put_tlv(&m, tag, value, len)) {
    ++g_failures;
    printf("[FAIL] %s: the extra tag did not fit the test manifest\n", label);
    return;
  }
  if (!cis_test_build_block(&blk, &m)) {
    ++g_failures;
    printf("[FAIL] %s: manifest did not fit the test block\n", label);
    return;
  }
  cis_check_parse(label, &blk, blk.size, want);
}

/* Wrap a manifest in a well-formed block and require a status.  Used for every
 * case that alters the manifest rather than the header: the header is what
 * locates the block, so feeding a bare manifest to the parser would test the
 * magic instead of the rule under examination. */
static void cis_check_manifest_parse(const char *label,
                                     const cis_test_block *m,
                                     OW_CIS_FORMAT_STATUS want) {
  cis_test_block blk;

  if (!cis_test_build_block(&blk, m)) {
    ++g_failures;
    printf("[FAIL] %s: the manifest did not fit the test block\n", label);
    return;
  }
  cis_check_parse(label, &blk, blk.size, want);
}

static void test_cis_format(void) {
  cis_test_block manifest;
  cis_test_block good;
  cis_test_block b;

  printf("\n=== CIS block format ===\n");

  if (!cis_test_build_manifest(&manifest) ||
      !cis_test_build_block(&good, &manifest)) {
    ++g_failures;
    printf("[FAIL] could not build the reference block\n");
    return;
  }
  check_eq("reference block size", good.size,
           OW_CIS_BLOCK_HEADER_SIZE + manifest.size + OW_CIS_SIGNATURE_SIZE);

  /* ---- the reference block parses ------------------------------------- */
  cis_check_parse("the reference block", &good, good.size, OW_CIS_FORMAT_OK);
  {
    OW_CIS_BLOCK parsed;
    uint8_t key_id[OW_CIS_KEY_ID_SIZE];
    uint8_t digest[OW_SHA256_DIGEST_SIZE];

    if (OwCisFormatParse(good.bytes, good.size, &parsed) !=
        OW_CIS_FORMAT_OK) {
      printf("       (field checks skipped, parse failed)\n");
      return;
    }
    check_eq("parsed block size agrees with the bytes", parsed.BlockSize,
             good.size);
    check_eq("parsed manifest size", parsed.ManifestSize, manifest.size);
    check_eq("the signed range excludes exactly the signature",
             parsed.SignedSize,
             OW_CIS_BLOCK_HEADER_SIZE + manifest.size);
    check_window("the signed range starts at the block",
                 parsed.Signed == good.bytes, true);
    check_window("the signature sits at the end of the block",
                 parsed.Signature ==
                     good.bytes + good.size - OW_CIS_SIGNATURE_SIZE,
                 true);
    check_eq("digest algorithm round-trips", parsed.DigestAlgorithm,
             OW_CIS_DIGEST_ALGO_SHA256);
    cis_test_expected_ids(key_id, digest);
    check_bytes("key id round-trips", parsed.KeyId, key_id,
                OW_CIS_KEY_ID_SIZE);
    check_bytes("content digest round-trips", parsed.ContentDigest, digest,
                OW_SHA256_DIGEST_SIZE);
    check_window("licence round-trips",
                 parsed.LicenseSize == strlen(CIS_TEST_LICENSE) &&
                     memcmp(parsed.License, CIS_TEST_LICENSE, strlen(CIS_TEST_LICENSE)) == 0,
                 true);
    check_window("copyright round-trips",
                 parsed.CopyrightSize == strlen(CIS_TEST_COPYRIGHT) &&
                     memcmp(parsed.Copyright, CIS_TEST_COPYRIGHT,
                            strlen(CIS_TEST_COPYRIGHT)) == 0,
                 true);
    check_window("an absent optional tag stays absent", parsed.BuildId == NULL,
                 true);
    check_eq("five tags were seen", parsed.TagCount, 5);
  }

  check_window("every parse status has a printable name",
               strcmp(OwCisFormatStatusName(OW_CIS_FORMAT_OK), "ok") == 0 &&
                   strcmp(OwCisFormatStatusName(OW_CIS_FORMAT_DUPLICATE_TAG),
                          "duplicate tag") == 0,
               true);

  /* ---- trailing bytes past the block are ignored ----------------------- */
  /* The loader already ignores them, so a format that refused them would reject
   * files it can otherwise read for no security gain. */
  {
    cis_test_block padded = good;
    uint32_t i;
    for (i = 0U; i < 7U; i++) {
      (void)cis_test_put(&padded, (uint8_t)(0xDEu + i));
    }
    cis_check_parse("trailing bytes past the block", &padded, padded.size,
                    OW_CIS_FORMAT_OK);
  }

  /* ---- argument handling ----------------------------------------------- */
  {
    OW_CIS_BLOCK parsed;
    check_eq("a null block is refused",
             (unsigned long)OwCisFormatParse(NULL, 128u, &parsed),
             (unsigned long)OW_CIS_FORMAT_NULL_ARGUMENT);
    check_eq("a null output is refused",
             (unsigned long)OwCisFormatParse(good.bytes, good.size, NULL),
             (unsigned long)OW_CIS_FORMAT_NULL_ARGUMENT);
  }

  /* ---- header fields, one broken at a time ----------------------------- */
  {
    /* Magic. */
    b = good;
    b.bytes[0] ^= 0x01u;
    cis_check_parse("magic changed", &b, b.size, OW_CIS_FORMAT_BAD_MAGIC);
    b = good;
    b.bytes[1] = 0x00u;
    cis_check_parse("magic truncated to three bytes", &b, b.size,
                    OW_CIS_FORMAT_BAD_MAGIC);
    b = good;
    b.bytes[3] = 0x00u;
    cis_check_parse("magic's last byte cleared", &b, b.size,
                    OW_CIS_FORMAT_BAD_MAGIC);

    /* Version: a future version is refused, not guessed at. */
    b = good;
    b.bytes[0x04] = 2U;
    cis_check_parse("a future version", &b, b.size,
                    OW_CIS_FORMAT_UNSUPPORTED_VERSION);
    b = good;
    b.bytes[0x04] = 0U;
    cis_check_parse("version zero", &b, b.size,
                    OW_CIS_FORMAT_UNSUPPORTED_VERSION);

    /* A header_size other than 48 describes a different header, so every
     * offset this parser used would stop meaning what it means. */
    b = good;
    b.bytes[0x06] = 64U;
    cis_check_parse("header_size other than 48", &b, b.size,
                    OW_CIS_FORMAT_BAD_HEADER_SIZE);
    b = good;
    b.bytes[0x06] = 0U;
    cis_check_parse("header_size zero", &b, b.size,
                    OW_CIS_FORMAT_BAD_HEADER_SIZE);

    /* Reserved fields and flags.  A flag bit this build has never had to
     * interpret is not a reason to ignore it silently. */
    b = good;
    b.bytes[0x10] = 1U;
    cis_check_parse("reserved0 non-zero", &b, b.size,
                    OW_CIS_FORMAT_RESERVED_NOT_ZERO);
    b = good;
    b.bytes[0x14] = 1U;
    cis_check_parse("an undefined flag bit", &b, b.size,
                    OW_CIS_FORMAT_RESERVED_NOT_ZERO);
    b = good;
    b.bytes[0x18] = 1U;
    cis_check_parse("reserved1 non-zero", &b, b.size,
                    OW_CIS_FORMAT_RESERVED_NOT_ZERO);
    b = good;
    b.bytes[0x27] = 1U;
    cis_check_parse("the last byte of reserved1 non-zero", &b, b.size,
                    OW_CIS_FORMAT_RESERVED_NOT_ZERO);
    b = good;
    b.bytes[0x28] = 1U;
    cis_check_parse("reserved2 non-zero", &b, b.size,
                    OW_CIS_FORMAT_RESERVED_NOT_ZERO);
    b = good;
    b.bytes[0x2F] = 1U;
    cis_check_parse("the last byte of reserved2 non-zero", &b, b.size,
                    OW_CIS_FORMAT_RESERVED_NOT_ZERO);
  }

  /* ---- size fields ------------------------------------------------------ */
  {
    b = good;
    b.bytes[0x08] = (uint8_t)(b.bytes[0x08] - 1u);
    cis_check_parse("block_size one short", &b, b.size,
                    OW_CIS_FORMAT_BAD_BLOCK_SIZE);
    b = good;
    b.bytes[0x08] = (uint8_t)(b.bytes[0x08] + 1u);
    cis_check_parse("block_size one over", &b, b.size,
                    OW_CIS_FORMAT_BAD_BLOCK_SIZE);
    b = good;
    b.bytes[0x0C] = (uint8_t)(b.bytes[0x0C] + 1u);
    cis_check_parse("manifest_size one over", &b, b.size,
                    OW_CIS_FORMAT_BAD_BLOCK_SIZE);
    b = good;
    memset(&b.bytes[0x08], 0, 4u);
    cis_check_parse("block_size zero", &b, b.size,
                    OW_CIS_FORMAT_BAD_BLOCK_SIZE);
    b = good;
    memset(&b.bytes[0x08], 0xFF, 4u);
    memset(&b.bytes[0x0C], 0xFF, 4u);
    cis_check_parse("block_size and manifest_size both 0xFFFFFFFF", &b, b.size,
                    OW_CIS_FORMAT_BAD_BLOCK_SIZE);
    /* A block that claims more than the caller holds.  This is the case a
     * loader hands over when a file is truncated after the image. */
    cis_check_parse("block_size larger than the bytes held", &good,
                    good.size - 1u, OW_CIS_FORMAT_BAD_BLOCK_SIZE);
    cis_check_parse("fewer than 48 bytes available", &good, 8u,
                    OW_CIS_FORMAT_BAD_MAGIC);
    cis_check_parse("exactly 48 bytes available, none of it a block", &good,
                    48u, OW_CIS_FORMAT_BAD_BLOCK_SIZE);

    /* manifest_size past the sanity bound, with block_size kept consistent so
     * the size bound itself is what refuses it.  The parser answers
     * MANIFEST_TOO_LARGE rather than BAD_BLOCK_SIZE because both sizes agree
     * with each other: what is wrong is the magnitude. */
    b = good;
    {
      const uint32_t big = OW_CIS_MAX_MANIFEST_SIZE + 1u;
      const uint32_t total =
          OW_CIS_BLOCK_HEADER_SIZE + big + OW_CIS_SIGNATURE_SIZE;
      b.bytes[0x08] = (uint8_t)(total & 0xFFu);
      b.bytes[0x09] = (uint8_t)((total >> 8) & 0xFFu);
      b.bytes[0x0A] = (uint8_t)((total >> 16) & 0xFFu);
      b.bytes[0x0B] = (uint8_t)((total >> 24) & 0xFFu);
      b.bytes[0x0C] = (uint8_t)(big & 0xFFu);
      b.bytes[0x0D] = (uint8_t)((big >> 8) & 0xFFu);
      b.bytes[0x0E] = (uint8_t)((big >> 16) & 0xFFu);
      b.bytes[0x0F] = (uint8_t)((big >> 24) & 0xFFu);
    }
    cis_check_parse("manifest_size over the sanity bound", &b, b.size,
                    OW_CIS_FORMAT_MANIFEST_TOO_LARGE);

    /* A block whose manifest is exactly at the bound: the bound is a limit, not
     * an off-by-one that rejects the last legal size. */
    b = good;
    {
      const uint32_t exact = OW_CIS_MAX_MANIFEST_SIZE;
      const uint32_t total =
          OW_CIS_BLOCK_HEADER_SIZE + exact + OW_CIS_SIGNATURE_SIZE;
      b.bytes[0x08] = (uint8_t)(total & 0xFFu);
      b.bytes[0x09] = (uint8_t)((total >> 8) & 0xFFu);
      b.bytes[0x0A] = (uint8_t)((total >> 16) & 0xFFu);
      b.bytes[0x0B] = (uint8_t)((total >> 24) & 0xFFu);
      b.bytes[0x0C] = (uint8_t)(exact & 0xFFu);
      b.bytes[0x0D] = (uint8_t)((exact >> 8) & 0xFFu);
      b.bytes[0x0E] = (uint8_t)((exact >> 16) & 0xFFu);
      b.bytes[0x0F] = (uint8_t)((exact >> 24) & 0xFFu);
    }
    cis_check_parse("manifest_size exactly at the sanity bound", &b, b.size,
                    OW_CIS_FORMAT_BAD_BLOCK_SIZE);
  }

  /* ---- the domain separator -------------------------------------------- */
  {
    b = good;
    b.bytes[OW_CIS_BLOCK_HEADER_SIZE] = 'X';
    cis_check_parse("manifest prefix altered", &b, b.size,
                    OW_CIS_FORMAT_BAD_PREFIX);
    b = good;
    b.bytes[OW_CIS_BLOCK_HEADER_SIZE + 22u] = ' ';
    cis_check_parse("manifest prefix last character altered", &b, b.size,
                    OW_CIS_FORMAT_BAD_PREFIX);
    /* The 9 bytes of padding after the 23-character prefix are signed too, so
     * a non-zero byte there is a different domain rather than an equivalent
     * encoding. */
    b = good;
    b.bytes[OW_CIS_BLOCK_HEADER_SIZE + 23u] = 0x01u;
    cis_check_parse("manifest prefix padding not zero", &b, b.size,
                    OW_CIS_FORMAT_BAD_PREFIX);
    b = good;
    b.bytes[OW_CIS_BLOCK_HEADER_SIZE + 31u] = 0x01u;
    cis_check_parse("the last prefix padding byte non-zero", &b, b.size,
                    OW_CIS_FORMAT_BAD_PREFIX);
  }

  /* ---- TLV ordering ----------------------------------------------------- */
  {
    cis_test_block m;
    uint32_t at;

    /* The first tag raised above the second. */
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_LICENSE);
      if (at != 0xFFFFFFFFu && at >= 4u) {
        m.bytes[at - 4u] = 0x09u;   /* 0x0009 > 0x0002 */
        m.bytes[at - 3u] = 0x00u;
        cis_check_manifest_parse("a tag raised above its successor", &m,
                        OW_CIS_FORMAT_TAGS_NOT_ASCENDING);
      }
    }

    /* The same tag twice, with the second occurrence strictly higher: not a
     * duplicate but a reordering, and it must fail as one. */
    if (cis_test_build_manifest(&m)) {
      static const uint8_t extra[2] = {'h', 'i'};
      (void)cis_test_put_tlv(&m, OW_CIS_TAG_BUILD_ID, extra, 2u);
      (void)cis_test_put_tlv(&m, OW_CIS_TAG_LICENSE, extra, 2u);
      cis_check_manifest_parse("a tag repeated below its successor", &m,
                      OW_CIS_FORMAT_TAGS_NOT_ASCENDING);
    }

/* The same tag twice, adjacent, with equal values: a duplicate.  Adjacency is
     * what makes this a duplicate rather than a reordering -- a repeated tag
     * below its successor is the previous case, and must be reported
     * differently, because "this appears twice" and "these are out of order"
     * are different defects even though both are refused. */
    if (cis_test_build_manifest(&m)) {
      (void)cis_test_put_tlv(&m, OW_CIS_TAG_BUILD_ID,
                             (const uint8_t *)"hi", 2u);
      (void)cis_test_put_tlv(&m, OW_CIS_TAG_BUILD_ID,
                             (const uint8_t *)"hi", 2u);
      cis_check_manifest_parse("a tag repeated exactly", &m,
                               OW_CIS_FORMAT_DUPLICATE_TAG);
    }

    /* A TLV header with no room for a value. */
    if (cis_test_build_manifest(&m)) {
      (void)cis_test_put_u16(&m, 0x0080u);
      cis_check_manifest_parse("a TLV header with nothing after it", &m,
                      OW_CIS_FORMAT_TAGS_NOT_ASCENDING);
    }
  }

  /* ---- required tags ---------------------------------------------------- */
  {
    /* One required tag removed at a time.  The length comes from the manifest
     * rather than from a literal, because a literal one byte too long turns the
     * closing memmove into a size_t underflow. */
    static const struct {
      uint16_t tag;
      const char *label;
    } required[] = {
        {OW_CIS_TAG_LICENSE, "the licence tag removed"},
        {OW_CIS_TAG_DIGEST_ALGO, "the digest-algo tag removed"},
        {OW_CIS_TAG_KEY_ID, "the key id tag removed"},
        {OW_CIS_TAG_CONTENT_DIGEST, "the content digest tag removed"},
        {OW_CIS_TAG_COPYRIGHT, "the copyright tag removed"}
    };
    uint32_t i;

    for (i = 0U; i < sizeof(required) / sizeof(required[0]); i++) {
      cis_test_block m;
      if (!cis_test_build_manifest(&m)) {
        ++g_failures;
        printf("[FAIL] %s: could not build the reference manifest\n",
               required[i].label);
        continue;
      }
      if (!cis_test_remove_tlv(&m, required[i].tag)) {
        ++g_failures;
        printf("[FAIL] %s: could not remove tag 0x%04x\n", required[i].label,
               required[i].tag);
        continue;
      }
      cis_check_manifest_parse(required[i].label, &m,
                      OW_CIS_FORMAT_MISSING_REQUIRED_TAG);
    }

    /* Two required tags removed at once: still one missing-tag answer, not a
     * different one. */
    {
      cis_test_block m;
      if (cis_test_build_manifest(&m)) {
        (void)cis_test_remove_tlv(&m, OW_CIS_TAG_LICENSE);
        (void)cis_test_remove_tlv(&m, OW_CIS_TAG_COPYRIGHT);
        cis_check_manifest_parse("two required tags removed", &m,
                        OW_CIS_FORMAT_MISSING_REQUIRED_TAG);
      }
    }

    /* Only the optional tag removed: everything required is still there, so
     * this must still parse.  It is the other half of the missing-tag rule --
     * without it, a parser that wrongly required build-id would pass every case
     * above.  The tag is appended first, since the reference manifest has none. */
    {
      cis_test_block m;
      if (cis_test_build_manifest(&m)) {
        (void)cis_test_put_tlv(&m, OW_CIS_TAG_BUILD_ID,
                               (const uint8_t *)"build-1", 7u);
        if (cis_test_remove_tlv(&m, OW_CIS_TAG_BUILD_ID)) {
          cis_check_manifest_parse("the optional build-id removed", &m,
                          OW_CIS_FORMAT_OK);
        } else {
          ++g_failures;
          printf("[FAIL] could not remove the optional build-id tag\n");
        }
      }
    }
  }

  /* ---- tag widths and lengths ------------------------------------------ */
  {
    cis_test_block m;
    uint32_t at;

    /* A binary tag with too few bytes. */
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_DIGEST_ALGO);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at - 2u] = 3U;
        m.bytes[at - 1u] = 0U;
        cis_check_manifest_parse("digest-algo declared one byte short", &m,
                        OW_CIS_FORMAT_BAD_TAG_LENGTH);
      }
    }
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_KEY_ID);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at - 2u] = (uint8_t)(OW_CIS_KEY_ID_SIZE - 1u);
        m.bytes[at - 1u] = 0U;
        cis_check_manifest_parse("key id declared one byte short", &m,
                        OW_CIS_FORMAT_BAD_TAG_LENGTH);
      }
    }
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_CONTENT_DIGEST);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at - 2u] = (uint8_t)(OW_SHA256_DIGEST_SIZE + 1u);
        m.bytes[at - 1u] = 0U;
        cis_check_manifest_parse("content digest declared one byte long", &m,
                        OW_CIS_FORMAT_BAD_TAG_LENGTH);
      }
    }
    /* A value length running past the end of the manifest. */
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_LICENSE);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at - 2u] = 0xFFu;
        m.bytes[at - 1u] = 0xFFu;
        cis_check_manifest_parse("a value length past the manifest", &m,
                        OW_CIS_FORMAT_BAD_TAG_LENGTH);
      }
    }
    /* A length whose high byte is set, which is where a 16-bit overflow would
     * hide if the subtraction were done in 16 bits. */
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_LICENSE);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at - 2u] = 0x00u;
        m.bytes[at - 1u] = 0x80u;
        cis_check_manifest_parse("a value length of 0x8000", &m,
                        OW_CIS_FORMAT_BAD_TAG_LENGTH);
      }
    }
  }

  /* ---- NUL inside a value ---------------------------------------------- */
  /* The NUL rule is for text values.  A binary value may hold any byte, and the
   * digest algorithm already proves why: it is 01 00 00 00 little-endian. */
  {
    static const uint8_t with_nul[5] = {'M', 'I', 'T', 0x00u, 'X'};
    cis_check_extra_tlv("a NUL inside a text value", &manifest,
                        OW_CIS_TAG_BUILD_ID, with_nul, 5u,
                        OW_CIS_FORMAT_VALUE_HAS_NUL);
    cis_check_extra_tlv("a NUL as the first byte of a text value", &manifest,
                        OW_CIS_TAG_BUILD_ID, with_nul, 4u,
                        OW_CIS_FORMAT_VALUE_HAS_NUL);
    {
      /* A binary value may hold any byte.  Appended under an unknown tag so it
       * cannot collide with the real key-id tag: the point is that a NUL is
       * not what makes a binary value legal, its width is. */
      static const uint8_t all_zero[OW_CIS_KEY_ID_SIZE] = {0U};
      cis_check_extra_tlv("an all-zero binary value is legal", &manifest,
                          0x0F01u, all_zero, (uint16_t)sizeof(all_zero),
                          OW_CIS_FORMAT_OK);
    }
    {
      /* An unknown tag's value is skipped, so the text rules do not apply to it:
       * the rules protect values the verifier reads.  Stated as a test so the
       * two cases cannot be conflated later. */
      static const uint8_t opaque[4] = {0xDEu, 0xADu, 0x00u, 0xBEu};
      cis_check_extra_tlv("a NUL inside an unknown tag's value", &manifest,
                          0x0F00u, opaque, 4u, OW_CIS_FORMAT_OK);
    }
    {
      static const uint8_t bad_utf8[3] = {0xFFu, 0xFFu, 0xFFu};
      cis_check_extra_tlv("invalid UTF-8 inside an unknown tag's value",
                          &manifest, 0x0F00u, bad_utf8, 3u,
                          OW_CIS_FORMAT_OK);
    }
  }

  /* ---- UTF-8 in text tags ---------------------------------------------- */
  {
    static const uint8_t overlong2[3] = {0xC1u, 0x81u, 0x42u};
    static const uint8_t overlong3[3] = {0xE0u, 0x80u, 0x41u};
    static const uint8_t overlong4[4] = {0xF0u, 0x80u, 0x80u, 0x41u};
    static const uint8_t surrogate[3] = {0xEDu, 0xA0u, 0x80u};
    static const uint8_t too_high[4] = {0xF4u, 0x90u, 0x80u, 0x80u};
    static const uint8_t lone_cont[1] = {0x80u};
    static const uint8_t truncated[2] = {0xE2u, 0x82u};
    static const uint8_t bad_cont[3] = {0xE2u, 0x82u, 0x41u};
    /* U+00E9, U+20AC, U+1F600: the boundaries a validator has to get right for
     * the rule above to be a UTF-8 rule and not "reject everything above
     * ASCII". */
    static const uint8_t valid[9] = {0xC3u, 0xA9u,              /* e-acute */
                                     0xE2u, 0x82u, 0xACu,       /* euro    */
                                     0xF0u, 0x9Fu, 0x98u, 0x80u};

    cis_check_extra_tlv("an overlong two-byte sequence", &manifest,
                        OW_CIS_TAG_BUILD_ID, overlong2, 3u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("an overlong three-byte sequence", &manifest,
                        OW_CIS_TAG_BUILD_ID, overlong3, 3u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("an overlong four-byte sequence", &manifest,
                        OW_CIS_TAG_BUILD_ID, overlong4, 4u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("a UTF-16 surrogate", &manifest,
                        OW_CIS_TAG_BUILD_ID, surrogate, 3u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("a code point above U+10FFFF", &manifest,
                        OW_CIS_TAG_BUILD_ID, too_high, 4u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("a lone continuation byte", &manifest,
                        OW_CIS_TAG_BUILD_ID, lone_cont, 1u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("a sequence truncated at the end of the value",
                        &manifest, OW_CIS_TAG_BUILD_ID, truncated, 2u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("a bad continuation byte", &manifest,
                        OW_CIS_TAG_BUILD_ID, bad_cont, 3u,
                        OW_CIS_FORMAT_VALUE_NOT_UTF8);
    cis_check_extra_tlv("valid multi-byte UTF-8", &manifest,
                        OW_CIS_TAG_BUILD_ID, valid, 9u, OW_CIS_FORMAT_OK);
  }

  /* ---- unknown tags ---------------------------------------------------- */
  {
    static const uint8_t opaque[6] = {0xDEu, 0xADu, 0xBEu, 0xEFu, 0x01u, 0x02u};
    /* Forward compatibility is why the rule is "skip what you do not
     * understand", not "refuse it". */
    cis_check_extra_tlv("an unknown tag above every known tag", &manifest,
                        0xFFFFu, opaque, 6u, OW_CIS_FORMAT_OK);
    cis_check_extra_tlv("an empty unknown tag", &manifest, 0x0F00u, opaque, 0u,
                        OW_CIS_FORMAT_OK);
    cis_check_extra_tlv("an unknown tag holding binary, not text", &manifest,
                        0x0F00u, opaque, 6u, OW_CIS_FORMAT_OK);

    /* An unknown tag below every known tag has to be inserted rather than
     * appended, because ascending order means it cannot be appended at all.  It
     * is the case that matters for forward compatibility: a verifier built
     * before a tag existed still has to accept a manifest that uses it. */
    {
      cis_test_block m;
      cis_test_block ins;
      const uint32_t at = OW_CIS_MANIFEST_PREFIX_SIZE;

      memset(&ins, 0, sizeof(ins));
      if (cis_test_build_manifest(&m) &&
          cis_test_put_tlv(&ins, 0x0000u, opaque, 6u)) {
        /* Insert right after the prefix, shifting the rest up. */
        memmove(&m.bytes[at + ins.size], &m.bytes[at], m.size - at);
        memcpy(&m.bytes[at], ins.bytes, ins.size);
        m.size += ins.size;
        cis_check_manifest_parse("an unknown tag below every known tag", &m,
                                 OW_CIS_FORMAT_OK);
      }
    }
  }

  /* ---- digest algorithm ------------------------------------------------ */
  {
    cis_test_block m;
    uint32_t at;

    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_DIGEST_ALGO);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at] = 2U;
        cis_check_manifest_parse("digest algorithm 2", &m,
                        OW_CIS_FORMAT_UNSUPPORTED_DIGEST_ALGO);
      }
    }
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_DIGEST_ALGO);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at] = 0U;
        cis_check_manifest_parse("digest algorithm 0", &m,
                        OW_CIS_FORMAT_UNSUPPORTED_DIGEST_ALGO);
      }
    }
    if (cis_test_build_manifest(&m)) {
      at = cis_test_find_tlv(&m, OW_CIS_TAG_DIGEST_ALGO);
      if (at != 0xFFFFFFFFu) {
        m.bytes[at] = 0xFFu;
        cis_check_manifest_parse("digest algorithm 255", &m,
                        OW_CIS_FORMAT_UNSUPPORTED_DIGEST_ALGO);
      }
    }
  }

  /* ---- the UTF-8 validator, driven directly --------------------------- */
  /* Reachable directly because a validator that can only be exercised through a
   * full parse cannot be handed a case the surrounding lengths would reject
   * first. */
  {
    static const struct {
      const char *label;
      uint8_t data[5];
      uint8_t size;
      bool want;
    } cases[] = {
        {"empty", {0U}, 0U, true},
        {"ascii", {'o', 'k', 0U}, 2U, true},
        {"all seven-bit bytes", {0x01u, 0x7Fu, 0x41u}, 3U, true},
        {"NUL", {0x00u}, 1U, false},
        {"0x80 lone continuation", {0x80u}, 1U, false},
        {"0xBF lone continuation", {0xBFu}, 1U, false},
        {"0xC0 overlong", {0xC0u, 0x80u}, 2U, false},
        {"0xC1 overlong", {0xC1u, 0x80u}, 2U, false},
        {"0xC2 0x80 lowest two-byte", {0xC2u, 0x80u}, 2U, true},
        {"0xDF 0xBF highest two-byte", {0xDFu, 0xBFu}, 2U, true},
        {"0xE0 0x9F overlong", {0xE0u, 0x9Fu, 0x80u}, 3U, false},
        {"0xE0 0xA0 lowest three-byte", {0xE0u, 0xA0u, 0x80u}, 3U, true},
        {"0xED 0x9F highest non-surrogate", {0xEDu, 0x9Fu, 0xBFu}, 3U, true},
        {"0xED 0xA0 lowest surrogate", {0xEDu, 0xA0u, 0x80u}, 3U, false},
        {"0xEF 0xBF 0xBF highest three-byte", {0xEFu, 0xBFu, 0xBFu}, 3U, true},
        {"0xF0 0x8F overlong", {0xF0u, 0x8Fu, 0x80u, 0x80u}, 4U, false},
        {"0xF0 0x90 lowest four-byte", {0xF0u, 0x90u, 0x80u, 0x80u}, 4U, true},
        {"0xF4 0x8F 0xBF 0xBF is U+10FFFF", {0xF4u, 0x8Fu, 0xBFu, 0xBFu}, 4U, true},
        {"0xF4 0x90 above U+10FFFF", {0xF4u, 0x90u, 0x80u, 0x80u}, 4U, false},
        {"0xF5 out of range", {0xF5u, 0x80u, 0x80u, 0x80u}, 4U, false},
        {"0xFF out of range", {0xFFu}, 1U, false},
        {"two-byte lead at end", {0xC3u}, 1U, false},
        {"three-byte lead one short", {0xE2u, 0x82u}, 2U, false},
        {"four-byte lead one short", {0xF0u, 0x9Fu, 0x98u}, 3U, false},
        {"bad continuation after two-byte", {0xC3u, 0x41u}, 2U, false},
        {"bad continuation after three-byte", {0xE2u, 0x82u, 0x41u}, 3U, false},
        {"bad continuation after four-byte", {0xF0u, 0x9Fu, 0x41u, 0x80u}, 4U,
         false},
        {"text then a bad sequence", {'a', 'b', 0xFFu}, 3U, false},
        {"good then a bad sequence", {0xC3u, 0xA9u, 0xFFu}, 3U, false},
        {"a bad sequence then good text", {0xFFu, 'a', 'b'}, 3U, false}
    };
    const uint32_t n = (uint32_t)(sizeof(cases) / sizeof(cases[0]));
    uint32_t i;

    for (i = 0U; i < n; i++) {
      const bool got = OwCisFormatIsValidUtf8(cases[i].data, cases[i].size);
      if (got == cases[i].want) {
        ++g_passed;
      } else {
        ++g_failures;
        printf("[FAIL] UTF-8 %s: got %s, want %s\n", cases[i].label,
               got ? "true" : "false", cases[i].want ? "true" : "false");
      }
    }
    printf("[PASS] %u UTF-8 cases\n", (unsigned)n);
  }

  /* ---- the NUL helper, driven directly -------------------------------- */
  {
    static const uint8_t clean[4] = {'a', 'b', 'c', 'd'};
    static const uint8_t middle[4] = {'a', 0x00u, 'c', 'd'};
    static const uint8_t leading[4] = {0x00u, 'b', 'c', 'd'};
    static const uint8_t trailing[4] = {'a', 'b', 'c', 0x00u};
    check_window("HasNoNul accepts a clean value",
                 OwCisFormatHasNoNul(clean, 4u), true);
    check_window("HasNoNul accepts an empty value",
                 OwCisFormatHasNoNul(clean, 0u), true);
    check_window("HasNoNul rejects a NUL in the middle",
                 OwCisFormatHasNoNul(middle, 4u), false);
    check_window("HasNoNul rejects a leading NUL",
                 OwCisFormatHasNoNul(leading, 4u), false);
    check_window("HasNoNul rejects a trailing NUL",
                 OwCisFormatHasNoNul(trailing, 4u), false);
    /* The first byte alone is not a NUL, so a one-byte window over it is
     * clean: the helper scans what it is given, not the whole buffer. */
    check_window("HasNoNul reads only the length it is given",
                 OwCisFormatHasNoNul(middle, 1u), true);
  }

  /* ---- little-endian readers ------------------------------------------ */
  {
    static const uint8_t le16[2] = {0x34u, 0x12u};
    static const uint8_t le32[4] = {0x78u, 0x56u, 0x34u, 0x12u};
    static const uint8_t ones[4] = {0xFFu, 0xFFu, 0xFFu, 0xFFu};
    check_eq("u16 reads little-endian", OwCisFormatReadU16(le16), 0x1234u);
    check_eq("u32 reads little-endian", OwCisFormatReadU32(le32), 0x12345678u);
    check_eq("u32 of all ones", OwCisFormatReadU32(ones), 0xFFFFFFFFu);
  }

  printf("--- CIS block format verified\n");
}

static void test_cis_core(void) {
  const OW_CIS_POLICY *policy;
  const OW_CIS_TRUST_KEY *found;
  const OW_CIS_RECORD *last;
  uint8_t public_key[OW_CIS_PUBLIC_KEY_SIZE];
  uint8_t other_key[OW_CIS_PUBLIC_KEY_SIZE];
  uint8_t key_id[OW_CIS_KEY_ID_SIZE];
  char long_name[OW_CIS_NAME_SIZE + 64];
  uint32_t i;
  uint32_t before;

  printf("\n=== Copyleft Integrity Safeguard: enforcement state ===\n");

  /* ---- armed --------------------------------------------------------- */
  check_window("CIS is armed", OwCisIsReady(), true);

  policy = OwCisPolicy();
  check_window("CIS policy requires a signature", policy->RequireSignature,
               true);
  check_window("CIS policy refuses unsigned recovery by default",
               policy->AllowUnsignedRecovery, false);
  check_window("CIS policy bounds image size",
               policy->MaxImageSize > 0U, true);

  /* ---- fail closed with no trust anchors ------------------------------ */
  /* A default build pins zero keys: nothing may be trusted, and the subsystem
   * must say so through its own state rather than by accident.
   *
   * A CIS_DEV_TRUST build pins exactly the one dev anchor, and that is a
   * different assertion rather than a weakened one -- so the count is checked
   * against what the build was configured to pin, and the "nothing is trusted"
   * claims below only hold in the default case.  The alternative, pinning the
   * count to zero unconditionally, would have made this test fail under the
   * opt-in and invited someone to special-case it away. */
  {
    const unsigned long pinned = (unsigned long)OwCisTrustedKeyCount();
#ifdef CIS_DEV_TRUST
    const unsigned long expected = 1UL;

    check_eq("a CIS_DEV_TRUST build pins exactly the dev anchor", pinned,
             expected);
    /* Every pinned anchor must be marked test-only.  Asserted by iterating
     * rather than by looking up the dev key id, because that is the property
     * that actually matters: a build carrying the dev anchor must not be able to
     * carry one that is not flagged as non-production. */
    {
      int all_test_only = 1;
      for (i = 0; i < (uint32_t)pinned; i++) {
        const OW_CIS_TRUST_KEY *k = OwCisTrustedKeyAt(i);
        if (k == NULL || (k->Flags & OW_CIS_KEY_FLAG_TEST_ONLY) == 0U) {
          all_test_only = 0;
        }
      }
      check_window("every pinned anchor in a CIS_DEV_TRUST build is test-only",
                   all_test_only, true);
    }
#else
    const unsigned long expected = 0UL;

    check_eq("a default build pins no trust anchors", pinned, expected);
    check_window("no trust anchors means no lookup hits",
                 OwCisLookupKey(public_key) != NULL, false);
    check_window("no trust anchors means no key-id hits",
                 OwCisLookupKeyId(key_id) != NULL, false);
#endif

    /* Overridable so the fill loop and the counts after it stay correct without
     * repeating this #ifdef. */
    g_CisHarnessPinned = expected;
  }
  check_window("only TRUSTED permits execution",
               OwCisVerdictAllowsExecution(OW_CIS_VERDICT_TRUSTED), true);
  check_window("UNSIGNED does not permit execution",
               OwCisVerdictAllowsExecution(OW_CIS_VERDICT_REJECT_UNSIGNED),
               false);
  check_window("UNKNOWN-KEY does not permit execution",
               OwCisVerdictAllowsExecution(OW_CIS_VERDICT_REJECT_UNKNOWN_KEY),
               false);
  check_window("ERROR does not permit execution",
               OwCisVerdictAllowsExecution(OW_CIS_VERDICT_ERROR), false);

  /* ---- initialization is idempotent and preserves history ------------- */
  before = OwCisRecordCount();
  check_eq("re-initializing CIS succeeds", (unsigned long)OwCisInitialize(),
           (unsigned long)OW_SUCCESS);
  check_eq("re-initializing CIS preserves the measurement log",
           OwCisRecordCount(), before);

  /* ---- measurement log ------------------------------------------------ */
  OwCisResetRecords();
  check_eq("measurement log starts empty", OwCisRecordCount(), 0);

  for (i = 0; i < OW_CIS_PUBLIC_KEY_SIZE; i++) {
    public_key[i] = (uint8_t)(0xA0 + i);
    other_key[i] = (uint8_t)(0x10 + i);
  }
  for (i = 0; i < OW_CIS_KEY_ID_SIZE; i++) {
    key_id[i] = (uint8_t)(0x30 + i);
  }

  for (i = 0; i < OW_CIS_MAX_RECORDS; i++) {
    OW_CIS_VERDICT verdict = (i % 2u == 0u) ? OW_CIS_VERDICT_TRUSTED
                                            : OW_CIS_VERDICT_REJECT_UNSIGNED;
    OW_STATUS st = OwCisRecordVerdict("probe.owx", public_key, 4096u, 0x04u,
                                      0u, OW_CIS_RECORD_BOOT, verdict,
                                      OW_SUCCESS, key_id);
    if (!ow_status_success(st)) {
      ++g_failures;
      printf("[FAIL] recording measurement %u: 0x%X\n", (unsigned)i,
             (unsigned)st);
      return;
    }
  }
  check_eq("measurement log holds a full table", OwCisRecordCount(),
           OW_CIS_MAX_RECORDS);
  check_eq("rejections counted separately", OwCisRejectedCount(),
           OW_CIS_MAX_RECORDS / 2u);
  check_eq("a full measurement table refuses new entries",
           (unsigned long)OwCisRecordVerdict("overflow.owx", public_key, 1u,
                                             0x04u, 0u, 0u,
                                             OW_CIS_VERDICT_TRUSTED, OW_SUCCESS,
                                             key_id),
           (unsigned long)OW_ERR_INSUFFICIENT);
  check_eq("refusing a new entry did not grow the log", OwCisRecordCount(),
           OW_CIS_MAX_RECORDS);

  last = OwCisLastRejection();
  check_window("last rejection is retrievable", last != NULL, true);
  if (last) {
    check_eq("last rejection reports its verdict", (unsigned long)last->Verdict,
             (unsigned long)OW_CIS_VERDICT_REJECT_UNSIGNED);
    check_window("last rejection kept the image name",
                 ow_strlen(last->Image) > 0, true);
  }
  check_window("a record past the end reads as NULL",
               OwCisRecordAt(OW_CIS_MAX_RECORDS) != NULL, false);
  check_eq("a NULL image name is refused",
           (unsigned long)OwCisRecordVerdict(NULL, public_key, 1u, 0x04u, 0u,
                                             0u, OW_CIS_VERDICT_TRUSTED,
                                             OW_SUCCESS, key_id),
           (unsigned long)OW_ERR_NULL_POINTER);

  /* ---- an over-long name is truncated, not walked --------------------- */
  for (i = 0; i < sizeof(long_name) - 1u; i++) {
    long_name[i] = 'x';
  }
  long_name[sizeof(long_name) - 1u] = '\0';
  OwCisResetRecords();
  (void)OwCisRecordVerdict(long_name, public_key, 1u, 0x04u, 0u, 0u,
                           OW_CIS_VERDICT_TRUSTED, OW_SUCCESS, key_id);
  last = OwCisRecordAt(0);
  check_window("measurement recorded after truncation", last != NULL, true);
  if (last) {
    check_eq("an over-long image name is bounded, not overrun",
             ow_strlen(last->Image), OW_CIS_NAME_SIZE - 1u);
  }

  /* ---- trust store lookups -------------------------------------------- */
  OwCisResetRecords();
  check_eq("injecting a test trust anchor succeeds",
           (unsigned long)OwCisTestInjectKey("harness", public_key, key_id,
                                             OW_CIS_KEY_FLAG_TEST_ONLY),
           (unsigned long)OW_SUCCESS);
  check_eq("the injected anchor is in the store",
           (unsigned long)OwCisTrustedKeyCount(), g_CisHarnessPinned + 1UL);
  found = OwCisLookupKey(public_key);
  check_window("lookup by public key finds it", found != NULL, true);
  found = OwCisLookupKeyId(key_id);
  check_window("lookup by key id finds it", found != NULL, true);
  check_window("a different public key does not match",
               OwCisLookupKey(other_key) != NULL, false);
  if (found) {
    check_window("the injected anchor is marked test-only",
                 (found->Flags & OW_CIS_KEY_FLAG_TEST_ONLY) != 0u, true);
    check_window("the injected anchor starts unrevoked", found->Revoked,
                 false);
  }
  for (i = OwCisTrustedKeyCount(); i < OW_CIS_MAX_TRUST_KEYS; i++) {
    uint8_t filler[OW_CIS_PUBLIC_KEY_SIZE];
    for (uint32_t b = 0; b < OW_CIS_PUBLIC_KEY_SIZE; b++) {
      filler[b] = (uint8_t)(0xE0 ^ b ^ i);
    }
    (void)OwCisTestInjectKey("filler", filler, key_id,
                             OW_CIS_KEY_FLAG_TEST_ONLY);
  }
  check_eq("the trust store fills to its capacity", OwCisTrustedKeyCount(),
           OW_CIS_MAX_TRUST_KEYS);
  check_eq("injection past the table capacity is refused",
           (unsigned long)OwCisTestInjectKey("overflow", other_key, key_id,
                                             OW_CIS_KEY_FLAG_TEST_ONLY),
           (unsigned long)OW_ERR_INSUFFICIENT);

  OwCisTestClearInjected();
  check_eq("clearing injected anchors restores the pinned set",
           OwCisTrustedKeyCount(), OW_CIS_PINNED_KEY_COUNT);
  check_window("a cleared anchor no longer matches",
               OwCisLookupKey(public_key) != NULL, false);

  /* ---- policy relaxation is separate from signature enforcement ------- */
  check_eq("unsigned recovery can be relaxed explicitly",
           (unsigned long)OwCisSetUnsignedRecoveryAllowed(true),
           (unsigned long)OW_SUCCESS);
  check_window("the relaxation took effect",
               OwCisPolicy()->AllowUnsignedRecovery, true);
  check_window("relaxing recovery does not relax the signature requirement",
               OwCisPolicy()->RequireSignature, true);
  (void)OwCisSetUnsignedRecoveryAllowed(false);

  printf("--- CIS stage 1 state verified\n");
}

/* -------------------------------------------------------------------- */
/* Ed25519 regression tests                                             */
/* -------------------------------------------------------------------- */
/*
 * These exist because a signature-level known-answer test can only say
 * "rejected".  Every bug found while writing lib/ow_ed25519.c was invisible at
 * that level and obvious one level down, so the tests are layered:
 *
 *   SHA-512      what every signature is built on
 *   field        add / sub / mul, where a bad carry or borrow shows up
 *   scalar       reduction mod L, including the exactly-L case
 *   points       decoding, canonicality, the group law, [L]B
 *   constants    identities the frozen constants have to satisfy
 *   verify       the top layer, and the only one the kernel uses
 *
 * Expected values come from crypto_vectors.h, generated by
 * tools/gen_crypto_vectors.py from tools/cis_sign.py -- a separate derivation of
 * the same curve that shares no code with the C.  Two independent derivations
 * agreeing is stronger evidence than one implementation agreeing with a table,
 * because a table cannot tell you whether it was ever right.
 */

static void check_bytes(const char *label, const uint8_t *got,
                        const uint8_t *want, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (got[i] != want[i]) {
      ++g_failures;
      printf("[FAIL] %s: byte %u is 0x%02x, want 0x%02x\n", label, (unsigned)i,
             got[i], want[i]);
      return;
    }
  }
  ++g_passed;
  printf("[PASS] %s\n", label);
}

/* Byte-exact comparison that names the vector index, for the table-driven loops
 * where one assertion runs hundreds of times.  Reports the first mismatching
 * byte, so a failure identifies the operand that produced it. */
static void check_bytes_v(const char *what, uint32_t index, const uint8_t *got,
                          const uint8_t *want, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (got[i] != want[i]) {
      ++g_failures;
      printf("[FAIL] %s vector %u: byte %u is 0x%02x, want 0x%02x\n", what,
             (unsigned)index, (unsigned)i, got[i], want[i]);
      return;
    }
  }
  ++g_passed;
  printf("[PASS] %s vector %u\n", what, (unsigned)index);
}

static const uint8_t *field_const(const char *name) {
  uint32_t i;
  for (i = 0U; i < OW_FIELD_CONSTANT_COUNT; i++) {
    if (strcmp(ow_field_constants[i].name, name) == 0) {
      return ow_field_constants[i].value;
    }
  }
  ++g_failures;
  printf("[FAIL] field constant \"%s\" is missing from the vector set\n", name);
  return ow_field_constants[0].value;
}

/* The field element 1 as a readable operand.  ow_ed_test_fe_one() only fills an
 * output, and several identities below need to compare against one, so it is
 * named once here.  ow_ed_test_fe is an array type, so it decays to a pointer at
 * each use -- that is intended, not an oversight. */
static const ow_ed_test_fe k_field_one = {1U};

static const uint8_t *point_const(const char *name) {
  uint32_t i;
  for (i = 0U; i < OW_POINT_CONSTANT_COUNT; i++) {
    if (strcmp(ow_point_constants[i].name, name) == 0) {
      return ow_point_constants[i].enc;
    }
  }
  ++g_failures;
  printf("[FAIL] point constant \"%s\" is missing from the vector set\n", name);
  return ow_point_constants[0].enc;
}

/* True when the 32-byte little-endian value is strictly below p.  Every field
 * result must satisfy this.  An unreduced or once-reduced result is a real
 * defect that a comparison against the reference can miss, because two
 * non-canonical forms of the same element are different byte strings -- and it
 * is a defect that later signs bytes differently for the same value. */
static bool fe_bytes_below_p(const uint8_t v[32]) {
  const uint8_t *p = field_const("p");
  int i;
  for (i = 31; i >= 0; i--) {
    if (v[i] != p[i]) {
      return v[i] < p[i];
    }
  }
  return false; /* equal to p is not below p */
}

/* ---- SHA-512 ------------------------------------------------------------- */

static void test_sha512(void) {
  uint8_t got[OW_SHA512_DIGEST_SIZE];
  uint8_t whole[OW_SHA512_DIGEST_SIZE];
  ow_sha512_ctx_t ctx;
  uint32_t i;
  size_t split;
  uint32_t split_bad = 0U;

  printf("\n=== SHA-512 (FIPS 180-4) ===\n");
  printf("    %u known-answer vectors\n", (unsigned)OW_SHA512_VECTOR_COUNT);

  for (i = 0U; i < OW_SHA512_VECTOR_COUNT; i++) {
    const ow_sha512_vector *v = &ow_sha512_vectors[i];
    ow_sha512(v->msg, v->msg_len, got);
    check_bytes_v("SHA-512", i, got, v->want, sizeof(got));
  }

  /* Streaming must agree with one-shot at every split point.  Checking only the
   * whole-buffer path leaves a defect in the update boundary or the buffer carry
   * in place, and that is exactly where one hides: a message hashed in two
   * pieces gives the same digest only if both halves are right. */
  for (i = 0U; i < OW_SHA512_VECTOR_COUNT; i++) {
    const ow_sha512_vector *v = &ow_sha512_vectors[i];
    ow_sha512(v->msg, v->msg_len, whole);
    for (split = 0U; split <= v->msg_len; split++) {
      ow_sha512_init(&ctx);
      ow_sha512_update(&ctx, v->msg, split);
      ow_sha512_update(&ctx, v->msg + split, v->msg_len - split);
      ow_sha512_final(&ctx, got);
      if (memcmp(got, whole, sizeof(whole)) != 0) {
        if (split_bad < 3U) {
          printf("       vector %u: split at %u disagrees with one-shot\n",
                 (unsigned)i, (unsigned)split);
        }
        ++split_bad;
      }
    }
  }
  check_window("streaming SHA-512 matches one-shot at every split point",
               split_bad == 0U, true);

  /* A zero-length update must be a no-op, including between real updates: the
   * verifier hashes R, the public key and then a message that may be empty. */
  {
    static const uint8_t probe[8] = {1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U};
    ow_sha512_init(&ctx);
    ow_sha512_update(&ctx, NULL, 0U);
    ow_sha512_update(&ctx, probe, sizeof(probe));
    ow_sha512_update(&ctx, NULL, 0U);
    ow_sha512_update(&ctx, NULL, 0U);
    ow_sha512_final(&ctx, got);
    ow_sha512(probe, sizeof(probe), whole);
    check_window("a zero-length update does not disturb the digest",
                 memcmp(got, whole, sizeof(whole)) == 0, true);
  }

  printf("--- SHA-512 verified\n");
}

/* ---- field arithmetic ---------------------------------------------------- */
/*
 * The operand set is chosen so the arithmetic has to be correct rather than
 * merely plausible.  Sixteen limbs of 16 bits span 2^256, and 2^256 is not
 * congruent to zero mod p -- it is 38.  So a product that overflows limb 15 by
 * more than one has to fold that carry back in scaled by 38, and a product above
 * 2p has to be reduced more than once.  (P-1)*(P-1) and (P-1)*(P-2) are in the
 * set for exactly that reason: they are the cases where a flat 38 instead of
 * 38 * carry passes, and every other pair agrees.
 */
static void test_ed25519_field(void) {
  ow_ed_test_fe a, b, got, want;
  uint8_t buf[32];
  uint32_t i;
  uint32_t bad = 0U;
  uint32_t noncanonical = 0U;
  uint32_t rt_bad = 0U;

  printf("\n=== Ed25519 field arithmetic over GF(2^255-19) ===\n");
  printf("    %u field vectors, three operations each\n",
         (unsigned)OW_FIELD_VECTOR_COUNT);

  for (i = 0U; i < OW_FIELD_VECTOR_COUNT; i++) {
    const ow_field_vector *v = &ow_field_vectors[i];

    ow_ed_test_fe_decode(a, v->a);
    ow_ed_test_fe_decode(b, v->b);

    /* Operands must round-trip through the encoding helpers, or the comparisons
     * below are not comparing what they claim to. */
    ow_ed_test_fe_encode(buf, a);
    if (memcmp(buf, v->a, 32) != 0) {
      ++rt_bad;
    }
    ow_ed_test_fe_encode(buf, b);
    if (memcmp(buf, v->b, 32) != 0) {
      ++rt_bad;
    }

    ow_ed_test_fe_add(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    if (memcmp(buf, v->add, 32) != 0) {
      if (bad < 3U) {
        printf("[FAIL] vector %u: add mismatch\n", (unsigned)i);
      }
      ++bad;
    }
    if (!fe_bytes_below_p(buf)) {
      ++noncanonical;
    }

    /* a - b where a < b is the underflow path.  A limb-wise subtraction that
     * borrows produces a wrapped result that is NOT congruent to (a-b) mod p,
     * and adding p back to it cannot repair that; the only correct move is to
     * compute the magnitude and return p - (b - a). */
    ow_ed_test_fe_sub(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    if (memcmp(buf, v->sub, 32) != 0) {
      if (bad < 3U) {
        printf("[FAIL] vector %u: sub mismatch\n", (unsigned)i);
      }
      ++bad;
    }
    if (!fe_bytes_below_p(buf)) {
      ++noncanonical;
    }

    ow_ed_test_fe_mul(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    if (memcmp(buf, v->mul, 32) != 0) {
      if (bad < 3U) {
        printf("[FAIL] vector %u: mul mismatch\n", (unsigned)i);
      }
      ++bad;
    }
    if (!fe_bytes_below_p(buf)) {
      ++noncanonical;
    }
  }

  if (rt_bad == 0U) {
    ++g_passed;
    printf("[PASS] every operand round-trips through its encoding\n");
  } else {
    g_failures += (int)rt_bad;
    printf("[FAIL] %u operand round-trip failures\n", (unsigned)rt_bad);
  }

  if (bad == 0U) {
    ++g_passed;
    printf("[PASS] all %u vectors: add, sub and mul match the reference\n",
           (unsigned)OW_FIELD_VECTOR_COUNT);
  } else {
    g_failures += (int)bad;
    printf("[FAIL] %u field operation mismatches across %u vectors\n",
           (unsigned)bad, (unsigned)OW_FIELD_VECTOR_COUNT);
  }

  if (noncanonical == 0U) {
    ++g_passed;
    printf("[PASS] every field result is fully reduced below p\n");
  } else {
    g_failures += (int)noncanonical;
    printf("[FAIL] %u field results were not fully reduced\n",
           (unsigned)noncanonical);
  }

  /* ---- identities -------------------------------------------------------- */

  /* Zero and one are spelled out as byte patterns rather than computed, so a
   * broken fe_0 or fe_1 cannot certify itself. */
  {
    static const uint8_t zero[32] = {0U};
    static const uint8_t one[32] = {1U, 0U};

    ow_ed_test_fe_zero(a);
    ow_ed_test_fe_encode(buf, a);
    check_bytes("field zero encodes as 32 zero bytes", buf, zero, 32);

    ow_ed_test_fe_one(b);
    ow_ed_test_fe_encode(buf, b);
    check_bytes("field one encodes as 0x01 then zeros", buf, one, 32);
  }

  /* (P-1) + 1 == 0 exactly.  This is the case where reduction has to commit a
   * subtraction that leaves no borrow at all.  Committing only when the
   * subtraction borrowed, and committing unconditionally, both fail here in
   * opposite directions. */
  {
    uint8_t p_minus_1[32];
    static const uint8_t zero[32] = {0U};

    memcpy(p_minus_1, field_const("p"), 32);
    p_minus_1[0] = (uint8_t)(p_minus_1[0] - 1U); /* p - 1 == ...FFEC */

    ow_ed_test_fe_decode(a, p_minus_1);
    ow_ed_test_fe_one(b);
    ow_ed_test_fe_add(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("(P-1) + 1 reduces to exactly zero", buf, zero, 32);

    ow_ed_test_fe_mul(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("(P-1) * 1 is P-1", buf, p_minus_1, 32);

    ow_ed_test_fe_sub(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("(P-1) - 1 reduces to P-2", buf, field_const("p_minus_2"), 32);

    ow_ed_test_fe_zero(b);
    ow_ed_test_fe_sub(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("(P-1) - 0 is P-1", buf, p_minus_1, 32);
  }

  /* 2^256 == 38 mod p, which is why an overflowing product folds its carry in
   * scaled by 38.  2^128 * 2^128 is 2^256 exactly, so this is the one product
   * whose limbs span the whole 512-bit accumulator and force both the
   * high-limb carry and the fold.
   *
   * This states the fact; it does not substitute for the product vectors,
   * because a fold that adds a flat 38 still satisfies it. */
  {
    static const uint8_t thirty_eight[32] = {38U, 0U};
    static const uint8_t two_pow_128[32] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        1U};
    ow_ed_test_fe_decode(a, two_pow_128);
    ow_ed_test_fe_decode(b, two_pow_128);
    ow_ed_test_fe_mul(got, a, b);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("2^128 * 2^128 is 38, i.e. 2^256 == 38 mod p", buf,
                thirty_eight, 32);
  }

  /* Reducing an already-canonical value must be a no-op, and reducing p must
   * give exactly zero rather than p. */
  {
    static const uint8_t zero[32] = {0U};

    ow_ed_test_fe_zero(a);
    ow_ed_test_fe_reduce(got, a);
    check_window("reducing zero leaves zero", ow_ed_test_fe_is_zero(got), true);

    ow_ed_test_fe_decode(a, field_const("p"));
    ow_ed_test_fe_reduce(got, a);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("reducing p gives exactly zero, not p", buf, zero, 32);

    ow_ed_test_fe_decode(a, field_const("p_minus_2"));
    ow_ed_test_fe_reduce(got, a);
    ow_ed_test_fe_encode(buf, got);
    check_bytes("reducing p-2 leaves it unchanged", buf,
                field_const("p_minus_2"), 32);
  }

  /* Every constant in the table must already be reduced.  A constant stored
   * above p makes every operation on it arithmetically correct and every
   * encoding of it wrong.
   *
   * p itself is the one exception: it is the modulus, so "below p" cannot apply
   * to it.  It is excluded by name rather than by position so that inserting a
   * constant does not silently change which one is skipped. */
  {
    uint32_t bad_const = 0U;
    for (i = 0U; i < OW_FIELD_CONSTANT_COUNT; i++) {
      if (strcmp(ow_field_constants[i].name, "p") == 0) {
        continue;
      }
      if (!fe_bytes_below_p(ow_field_constants[i].value)) {
        ++bad_const;
        printf("       constant \"%s\" is not below p\n",
               ow_field_constants[i].name);
      }
    }
    check_window("every curve constant is stored reduced", bad_const == 0U,
                 true);
  }

  /* fe_sq must agree with fe_mul(x, x) everywhere.  They are separate code
   * paths, and a defect in one does not show up in the other's tests. */
  {
    uint32_t sq_bad = 0U;
    for (i = 0U; i < OW_FIELD_VECTOR_COUNT; i++) {
      const ow_field_vector *v = &ow_field_vectors[i];
      ow_ed_test_fe_decode(a, v->a);
      ow_ed_test_fe_sq(got, a);
      ow_ed_test_fe_mul(want, a, a);
      if (!ow_ed_test_fe_equal(got, want)) {
        ++sq_bad;
      }
    }
    check_window("fe_sq agrees with fe_mul(x, x) on every vector", sq_bad == 0U,
                 true);
  }

  /* Inversion, stated as a^(p-2) * a == 1.
   *
   * This test exists because of a defect the rest of the file could not see.
   * fe_pow walks its exponent most significant bit first, so the exponent has to
   * be big-endian; the constant was stored little-endian, holding p rather than
   * p-2.  Square-and-multiply then produced a perfectly well-formed field
   * element for every input -- it was just a^(byte-reversed p-2).  Nothing above
   * this point failed: the field vectors, the constant identities, and the RFC
   * 8032 signatures all passed, because verification never inverts anything.
   *
   * That is the shape of the defect worth recording.  "It returns a plausible
   * field element" is not the same as "it is the right one", and only an
   * identity with an independently known answer distinguishes them. */
  {
    uint32_t inv_bad = 0U;
    for (i = 0U; i < OW_FIELD_VECTOR_COUNT; i++) {
      const ow_field_vector *v = &ow_field_vectors[i];
      ow_ed_test_fe a, inv, prod;
      ow_ed_test_fe_one(prod);
      ow_ed_test_fe_decode(a, v->a);
      if (ow_ed_test_fe_is_zero(a)) {
        continue;
      }
      if (!ow_ed_test_fe_invert(inv, a)) {
        ++inv_bad;
        continue;
      }
      ow_ed_test_fe_mul(prod, a, inv);
      if (!ow_ed_test_fe_equal(prod, k_field_one)) {
        if (inv_bad < 5U) {
          printf("       vector %u: a * a^-1 is not 1\n", (unsigned)i);
        }
        ++inv_bad;
      }
    }
    check_window("a * a^-1 == 1 on every vector (a^(p-2) with a big-endian p-2)",
                 inv_bad == 0U, true);
  }

  /* The exact inverse of 4, as bytes.  a^(p-2) * a == 1 already pins the
   * exponent, but this states the value the reference produced, so a wrong
   * exponent that happens to be self-consistent is still caught. */
  {
    static const uint8_t four[32] = {4U, 0U};
    ow_ed_test_fe a, inv, prod;
    ow_ed_test_fe_decode(a, four);
    if (ow_ed_test_fe_invert(inv, a)) {
      ow_ed_test_fe_mul(prod, a, inv);
      check_window("4 * 4^-1 == 1", ow_ed_test_fe_equal(prod, k_field_one),
                   true);
      ow_ed_test_fe_encode(buf, inv);
      check_bytes("4^-1 matches the reference", buf, field_const("inv4"), 32);
    } else {
      ++g_failures;
      printf("[FAIL] 4 has no inverse\n");
    }
  }

  /* Zero has no inverse, and the accessor says so rather than returning zero,
   * which would make a ^-1 * 0 == 1 test pass by accident. */
  {
    ow_ed_test_fe zero, inv;
    ow_ed_test_fe_zero(zero);
    check_window("zero has no inverse", ow_ed_test_fe_invert(inv, zero) == false,
                 true);
  }

  /* fe_pow with an all-zero exponent is 1 for any base, including zero.  A
   * square-and-multiply that starts from the base instead of from 1 gets this
   * wrong, and it is the cheapest way to see whether the loop is initialised. */
  {
    static const uint8_t zero_exp[32] = {0U};
    ow_ed_test_fe a, r;
    ow_ed_test_fe_decode(a, field_const("d"));
    ow_ed_test_fe_pow(r, a, zero_exp);
    check_window("d^0 is 1", ow_ed_test_fe_equal(r, k_field_one),
                 true);
  }

  /* Exponent byte order, called out directly: raising 2 to the little-endian
   * bytes of 4 and to the big-endian bytes of 4 must differ, and only the
   * big-endian reading may give 16. */
  {
    static const uint8_t exp_be_4[32] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 4U};
    static const uint8_t exp_le_4[32] = {
        4U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U};
    static const uint8_t sixteen[32] = {16U, 0U};
    ow_ed_test_fe two, r;

    ow_ed_test_fe_decode(two, field_const("two"));
    ow_ed_test_fe_pow(r, two, exp_be_4);
    ow_ed_test_fe_encode(buf, r);
    check_bytes("2^4 with a big-endian exponent is 16", buf, sixteen, 32);

    ow_ed_test_fe_pow(r, two, exp_le_4);
    ow_ed_test_fe_encode(buf, r);
    check_window("2^4 read little-endian is a different value",
                 memcmp(buf, sixteen, 32) != 0, true);
  }

  printf("--- Ed25519 field arithmetic verified\n");
}

/* ---- scalar reduction mod L --------------------------------------------- */
/*
 * The load-bearing case is S == L exactly.  Reduction has to return zero for
 * it, and the subtraction producing zero leaves no borrow -- so an
 * implementation that commits its result only when the subtraction borrowed
 * returns L instead of 0.  That defect is invisible from a signature test,
 * because a wrong scalar reduction fails to verify either way.
 */
static void test_ed25519_scalars(void) {
  uint8_t got[32];
  uint8_t order_L[32];
  uint8_t input[64];
  uint32_t i;

  printf("\n=== Ed25519 scalar reduction mod L ===\n");
  printf("    %u reduction vectors, %u canonicality vectors\n",
         (unsigned)OW_SCALAR_VECTOR_COUNT, (unsigned)OW_SCALAR_CANON_COUNT);

  ow_ed_test_scalar_order_L(order_L);
  check_bytes("the implementation's L matches the reference", order_L,
              field_const("L"), 32);

  for (i = 0U; i < OW_SCALAR_VECTOR_COUNT; i++) {
    const ow_scalar_vector *v = &ow_scalar_vectors[i];
    ow_ed_test_sc_reduce(got, v->in);
    check_bytes_v("scalar reduction", i, got, v->want, 32);
  }

  /* L itself must reduce to zero.  Spelled out as well as tabulated, because it
   * is the most load-bearing value in the file. */
  memset(input, 0, sizeof(input));
  memcpy(input, order_L, 32);
  ow_ed_test_sc_reduce(got, input);
  {
    static const uint8_t zero[32] = {0U};
    check_bytes("L reduces to exactly zero", got, zero, 32);
  }

  /* L + 1 reduces to 1, which also proves the comparison is against L and not
   * against L - 1. */
  memcpy(input, order_L, 32);
  input[0] = (uint8_t)(input[0] + 1U);
  ow_ed_test_sc_reduce(got, input);
  {
    static const uint8_t one[32] = {1U, 0U};
    check_bytes("L + 1 reduces to exactly one", got, one, 32);
  }

  /* 2 * L reduces to zero, so reduction is right at more than one multiple. */
  {
    uint32_t carry = 0U;
    uint32_t k;
    uint8_t doubled[32];
    static const uint8_t zero[32] = {0U};

    for (k = 0U; k < 16U; k++) {
      uint32_t sum = (uint32_t)order_L[2 * k] +
                     ((uint32_t)order_L[2 * k + 1] << 8) + carry;
      doubled[2 * k] = (uint8_t)(sum & 0xFFU);
      doubled[2 * k + 1] = (uint8_t)((sum >> 8) & 0xFFU);
      carry = sum >> 16;
    }
    check_window("doubling L fits in 32 bytes", carry == 0U, true);

    memset(input, 0, sizeof(input));
    memcpy(input, doubled, 32);
    ow_ed_test_sc_reduce(got, input);
    check_bytes("2 * L reduces to zero", got, zero, 32);
  }

  /* Canonicality boundaries.  Enforcing S < L is what stops the S-forgery lever:
   * without it, a valid signature can be re-signed with S + L and still pass.
   * The largest 32-byte scalar is far above L and must be rejected. */
  {
    uint8_t max_scalar[32];
    uint8_t lm1[32];

    memset(max_scalar, 0xFF, sizeof(max_scalar));
    check_window("2^256-1 is non-canonical",
                 ow_ed_test_sc_is_canonical(max_scalar), false);

    memcpy(lm1, field_const("L"), 32);
    lm1[0] = (uint8_t)(lm1[0] - 1U); /* L has a non-zero low byte */
    check_window("L - 1 is canonical", ow_ed_test_sc_is_canonical(lm1), true);
    check_window("L itself is non-canonical",
                 ow_ed_test_sc_is_canonical(field_const("L")), false);
  }

  for (i = 0U; i < OW_SCALAR_CANON_COUNT; i++) {
    const ow_scalar_canon_vector *v = &ow_scalar_canon_vectors[i];
    bool canon = ow_ed_test_sc_is_canonical(v->s);
    if (canon == (v->canonical != 0)) {
      ++g_passed;
      printf("[PASS] S canonicality vector %u\n", (unsigned)i);
    } else {
      ++g_failures;
      printf("[FAIL] S canonicality vector %u: got %s, want %s\n",
             (unsigned)i, canon ? "true" : "false",
             (v->canonical != 0) ? "true" : "false");
    }
  }

  printf("--- Ed25519 scalar reduction verified\n");
}

/* ---- point decoding, canonicality, group law ---------------------------- */
/*
 * Two properties are pinned here, and one absence is deliberate.
 *
 * Canonicality: a y at or above p is not a canonical encoding of any point, and
 * two distinct byte strings naming the same point is exactly the malleability
 * that makes naive signature comparison unsafe.  So y >= p must be refused, and
 * x == 0 with the sign bit set must be refused, which RFC 8032 requires.  Both
 * live in ge_frombytes and both are checked here.
 *
 * The small-order subgroup: all eight of its points are valid curve points, so
 * decompression MUST accept them.  Rejecting them would not be a security
 * property, it would be a deviation from the curve.  What makes them dangerous
 * is the cofactorless verification equation -- a key drawn from that subgroup
 * has no secret to protect.  The kernel never accepts a caller-supplied key;
 * every key comes from the pinned trust store, so such a key cannot reach this
 * code.  ow_ed25519.h states the limitation and says what must move first if a
 * caller-supplied key ever becomes possible.  These tests assert the decode
 * behaviour that actually exists rather than the reassuring behaviour that does
 * not.
 */

static void test_ed25519_points(void) {
  uint8_t identity[32];
  uint8_t order_L[32];
  uint8_t out[32];
  uint8_t out2[32];
  uint8_t scalar[32];
  uint8_t public_key[32];
  const uint8_t *base;
  uint32_t i;

  printf("\n=== Ed25519 point decoding and group law ===\n");

  ow_ed_test_point_identity(identity);
  ow_ed_test_scalar_order_L(order_L);
  base = point_const("base");

  /* Every torsion point decodes, round-trips, and has the order claimed.  The
   * order claim is checked rather than trusted: [order]P must be the identity,
   * which is what makes the label mean something. */
  for (i = 0U; i < OW_TORSION_VECTOR_COUNT; i++) {
    const ow_torsion_vector *v = &ow_torsion_vectors[i];
    uint32_t k = v->order;
    int bit = 0;

    if (!ow_ed_test_point_decode(v->enc)) {
      ++g_failures;
      printf("[FAIL] small-order point %u must decode\n", (unsigned)i);
      continue;
    }
    ++g_passed;
    printf("[PASS] small-order point %u decodes, order %u\n", (unsigned)i,
           (unsigned)v->order);

    if (!ow_ed_test_point_encode(out, v->enc) ||
        memcmp(out, v->enc, 32) != 0) {
      ++g_failures;
      printf("[FAIL] small-order point %u does not round-trip\n", (unsigned)i);
    } else {
      ++g_passed;
      printf("[PASS] small-order point %u round-trips\n", (unsigned)i);
    }

    memset(scalar, 0, sizeof(scalar));
    while (k > 0U) {
      if ((k & 1U) != 0U) {
        scalar[bit >> 3] |= (uint8_t)(1U << (bit & 7));
      }
      k >>= 1;
      ++bit;
    }
    if (ow_ed_test_point_mul(out, scalar, v->enc) &&
        memcmp(out, identity, 32) == 0) {
      ++g_passed;
      printf("[PASS] [%u]P is the identity\n", (unsigned)v->order);
    } else {
      ++g_failures;
      printf("[FAIL] [%u]P is not the identity\n", (unsigned)v->order);
    }
  }

  /* Non-canonical and off-curve encodings must be refused.  Each is a real byte
   * string rather than corruption, so each exercises one specific rule. */
  for (i = 0U; i < OW_MALFORMED_POINT_COUNT; i++) {
    if (ow_ed_test_point_decode(ow_malformed_points[i])) {
      ++g_failures;
      printf("[FAIL] malformed point %u must be refused\n", (unsigned)i);
    } else {
      ++g_passed;
      printf("[PASS] malformed point %u refused\n", (unsigned)i);
    }
  }

  for (i = 0U; i < OW_POINT_IDENTITY_COUNT; i++) {
    const ow_point_identity *v = &ow_point_identities[i];
    if (!ow_ed_test_point_add(out, v->a, v->b) ||
        memcmp(out, v->want, 32) != 0) {
      ++g_failures;
      printf("[FAIL] point identity %u: add mismatch\n", (unsigned)i);
    } else {
      ++g_passed;
      printf("[PASS] point identity %u\n", (unsigned)i);
    }
  }

  /* [L]B == identity.  This is the property that makes every signature equation
   * in the file mean what it claims: S is reduced mod L precisely so that [S]B
   * is well defined on the prime-order subgroup.  If L were wrong, or if scalar
   * multiplication dropped or reordered a bit, this is the assertion that
   * fails. */
  if (ow_ed_test_point_mul_base(out, order_L) &&
      memcmp(out, identity, 32) == 0) {
    ++g_passed;
    printf("[PASS] [L]B is the identity\n");
  } else {
    ++g_failures;
    printf("[FAIL] [L]B is not the identity\n");
  }

  /* [L]A for a real public key is also the identity: L is the order of the whole
   * group here, and A need not be the base point. */
  memcpy(public_key,
         "\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a"
         "\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a",
         32);
  if (ow_ed_test_point_mul(out, order_L, public_key) &&
      memcmp(out, identity, 32) == 0) {
    ++g_passed;
    printf("[PASS] [L]A is the identity for a real public key\n");
  } else {
    ++g_failures;
    printf("[FAIL] [L]A is not the identity for a real public key\n");
  }

  /* Small scalars must not be special-cased.  [1]B is B, [0]B is the identity,
   * [2]B is B doubled -- bracketing the range from nothing to the whole group. */
  memset(scalar, 0, sizeof(scalar));
  scalar[0] = 1U;
  if (ow_ed_test_point_mul_base(out, scalar) && memcmp(out, base, 32) == 0) {
    ++g_passed;
    printf("[PASS] [1]B is B\n");
  } else {
    ++g_failures;
    printf("[FAIL] [1]B is not B\n");
  }

  memset(scalar, 0, sizeof(scalar));
  if (ow_ed_test_point_mul_base(out2, scalar) &&
      memcmp(out2, identity, 32) == 0) {
    ++g_passed;
    printf("[PASS] [0]B is the identity\n");
  } else {
    ++g_failures;
    printf("[FAIL] [0]B is not the identity\n");
  }

  memset(scalar, 0, sizeof(scalar));
  scalar[0] = 2U;
  if (ow_ed_test_point_mul_base(out2, scalar) &&
      ow_ed_test_point_double(out, base) && memcmp(out2, out, 32) == 0) {
    ++g_passed;
    printf("[PASS] [2]B equals B doubled\n");
  } else {
    ++g_failures;
    printf("[FAIL] [2]B does not equal B doubled\n");
  }

  /* Equality must be projective, not structural.  Two routes to the same point
   * need not produce the same coordinates, so a comparison of the raw tuples
   * would report a correct point as different.  Both routes here are computed
   * independently, and they must agree as encodings and as points. */
  memset(scalar, 0, sizeof(scalar));
  scalar[0] = 2U;
  if (ow_ed_test_point_mul_base(out, scalar) &&
      ow_ed_test_point_double(out2, base) &&
      memcmp(out, out2, 32) == 0 && ow_ed_test_point_equal(out, out2)) {
    ++g_passed;
    printf("[PASS] 2B reached two ways compares equal\n");
  } else {
    ++g_failures;
    printf("[FAIL] 2B reached two ways does not compare equal\n");
  }

  printf("--- Ed25519 point decoding and group law verified\n");
}

/* ---- derived constants -------------------------------------------------- */
/*
 * lib/ow_ed25519.c derives its constants numerically and then freezes them.  A
 * frozen constant still has to be the right constant, and these identities say
 * so without quoting a second copy of the number:
 *
 *   d * 121666 == -121665                pins the curve parameter
 *   d2 == d + d                          pins what the addition formula uses
 *   sqrt(-1)^2 == p - 1                  pins the square root
 *   -bx^2 + by^2 == 1 + d*bx^2*by^2      pins the base point
 *   bt == bx * by                        pins the base point's T
 *   8 * ((p-5)/8) == p - 5               pins the square-root exponent
 *
 * sqrt(-1) is the one that bit during development: a single mistyped limb
 * (0x0A0B for 0xA0B0) leaves a plausible constant in the source, and the
 * resulting failure looks like a broken curve rather than a transcription slip.
 */
static void test_ed25519_constants(void) {
  ow_ed_test_fe bx, by, bt, dval, scratch;
  uint8_t buf[32];
  const uint8_t *p = field_const("p");
  const uint8_t *base = point_const("base");

  printf("\n=== Ed25519 derived constants ===\n");

  /* p = 2^255 - 19, so every limb is at its maximum except limb 0 (0xFFED) and
   * the top limb (0x7FFF).  Checking the shape is enough to catch a wrong p,
   * because p is what makes 2^256 == 38. */
  {
    uint32_t k;
    uint32_t bad_limb = 0U;
    for (k = 1U; k < 15U; k++) {
      if (p[k * 2] != 0xFFU || p[k * 2 + 1] != 0xFFU) {
        ++bad_limb;
      }
    }
    check_window("p has the 2^255 - 19 shape in limbs 1..14", bad_limb == 0U,
                 true);
    check_window("p limb 0 is 0xffed", p[0] == 0xEDU && p[1] == 0xFFU, true);
    check_window("p top limb is 0x7fff", p[30] == 0xFFU && p[31] == 0x7FU, true);
  }

  /* p - 2 is what the inversion in point encoding uses, and p - 1 is -1.  The
   * accessor computes p - 2 by subtraction rather than transcribing it, so
   * agreeing with the reference means both routes agree. */
  ow_ed_test_field_p_minus_2(buf);
  check_bytes("the implementation's p-2 matches the reference", buf,
              field_const("p_minus_2"), 32);

  /* d * 121666 + 121665 == 0 pins the ratio rather than either number alone. */
  ow_ed_test_fe_decode(dval, field_const("d"));
  ow_ed_test_fe_decode(scratch, field_const("d_denom"));
  ow_ed_test_fe_mul(scratch, dval, scratch);
  ow_ed_test_fe_decode(by, field_const("d_neg_num"));
  ow_ed_test_fe_add(scratch, scratch, by);
  check_window("d * 121666 + 121665 == 0", ow_ed_test_fe_is_zero(scratch), true);

  /* d2 == d + d.  The addition formula multiplies by 2d, and a wrong d2 produces
   * sums that still decode as plausible points, so nothing above would notice. */
  ow_ed_test_fe_add(scratch, dval, dval);
  ow_ed_test_fe_encode(buf, scratch);
  check_bytes("d2 == d + d", buf, field_const("d2"), 32);

  /* sqrt(-1)^2 == p - 1.  This is the identity that catches the mistyped limb
   * which cost the most time during development. */
  ow_ed_test_fe_decode(scratch, field_const("sqrtm1"));
  ow_ed_test_fe_sq(scratch, scratch);
  ow_ed_test_fe_encode(buf, scratch);
  {
    uint8_t p_minus_1[32];
    memcpy(p_minus_1, p, 32);
    p_minus_1[0] = (uint8_t)(p_minus_1[0] - 1U);
    check_bytes("sqrt(-1)^2 == p - 1", buf, p_minus_1, 32);
  }

  /* 8 * ((p-5)/8) == p - 5, the exponent square-root recovery uses. */
  ow_ed_test_fe_decode(scratch, field_const("exp_sqrt_m5"));
  ow_ed_test_fe_add(by, scratch, scratch);   /* 2x */
  ow_ed_test_fe_add(bt, by, by);             /* 4x */
  ow_ed_test_fe_add(scratch, bt, bt);        /* 8x */
  ow_ed_test_fe_encode(buf, scratch);
  check_bytes("8 * ((p-5)/8) == p - 5", buf, field_const("p_minus_5"), 32);

  /* The base point satisfies -x^2 + y^2 == 1 + d*x^2*y^2, and T == X*Y.  Both
   * are computed from the stored constants, so a wrong bx, by or bt is caught
   * here even though it would still decode as a point. */
  ow_ed_test_fe_decode(bx, field_const("bx"));
  ow_ed_test_fe_decode(by, field_const("by"));
  ow_ed_test_fe_decode(bt, field_const("bt"));

  /* -x^2 + y^2 == 1 + d*x^2*y^2, rearranged so both sides can be built from
   * bx and by without a division.  On the curve this must hold exactly; a wrong
   * bx or by violates it even though the pair still decompresses. */
  {
    ow_ed_test_fe lhs, rhs, one;

    ow_ed_test_fe_sq(lhs, by);             /* y^2 */
    ow_ed_test_fe_sq(rhs, bx);             /* x^2 */
    ow_ed_test_fe_sub(lhs, lhs, rhs);      /* y^2 - x^2 */
    ow_ed_test_fe_one(one);
    ow_ed_test_fe_sub(lhs, lhs, one);      /* y^2 - x^2 - 1 */

    ow_ed_test_fe_sq(rhs, bx);             /* x^2 */
    ow_ed_test_fe_sq(scratch, by);         /* y^2 */
    ow_ed_test_fe_mul(rhs, rhs, scratch);  /* x^2 * y^2 */
    ow_ed_test_fe_mul(rhs, rhs, dval);     /* d * x^2 * y^2 */

    check_window("the base point satisfies -x^2 + y^2 == 1 + d*x^2*y^2",
                 ow_ed_test_fe_equal(lhs, rhs), true);
  }

  ow_ed_test_fe_mul(scratch, bx, by);
  ow_ed_test_fe_encode(buf, scratch);
  check_bytes("bt == bx * by", buf, field_const("bt"), 32);

  /* The base point must decompress and round-trip, which ties the constants to
   * the decompression path: if d, sqrt(-1) or the exponent were wrong, the
   * encoding would not survive a decode. */
  if (ow_ed_test_point_decode(base)) {
    ++g_passed;
    printf("[PASS] the base point decompresses\n");
  } else {
    ++g_failures;
    printf("[FAIL] the base point does not decompress\n");
  }
  if (ow_ed_test_point_encode(buf, base) && memcmp(buf, base, 32) == 0) {
    ++g_passed;
    printf("[PASS] the base point round-trips through its encoding\n");
  } else {
    ++g_failures;
    printf("[FAIL] the base point does not round-trip\n");
  }

  printf("--- Ed25519 derived constants verified\n");
}

/* ---- signature verification ---------------------------------------------- */
/*
 * The top layer, and the only one the kernel itself uses.  Everything above
 * exists to explain a failure here.
 *
 * The vector set mixes RFC 8032 known answers, round trips across message
 * lengths that straddle the SHA-512 block boundary, and negatives that each
 * probe one refusal the verifier is supposed to make: an altered message, the
 * wrong key, an altered R or S, a non-reduced S including exactly L, a
 * non-canonical or off-curve R, and a public key that is not a canonical point.
 *
 * The identity and order-2 public keys are negatives for a reason worth
 * stating plainly: a signature that verifies under such a key is not a defect in
 * the verifier, it is the cofactorless equation doing what cofactorless means.
 * Because the kernel never accepts a caller-supplied key, those keys cannot be
 * presented to it.  If a later stage introduces caller-supplied keys, these
 * expectations must be revisited before that code is written.
 */
static void test_ed25519_verify(void) {
  uint32_t i;
  uint32_t positive = 0U;
  uint32_t negative = 0U;

  printf("\n=== Ed25519 signature verification (RFC 8032) ===\n");
  printf("    %u signature vectors\n", (unsigned)OW_ED25519_VECTOR_COUNT);

  for (i = 0U; i < OW_ED25519_VECTOR_COUNT; i++) {
    const ow_ed25519_vector *v = &ow_ed25519_vectors[i];
    bool got = ow_crypto_ed25519_verify(v->pub, v->sig, v->msg, v->msg_len);
    if (got == (v->expect != 0)) {
      ++g_passed;
      if (v->expect) {
        ++positive;
      } else {
        ++negative;
      }
    } else {
      ++g_failures;
      printf("[FAIL] signature vector %u: expected %s\n", (unsigned)i,
             v->expect ? "accept" : "reject");
    }
  }

  printf("[PASS] %u vectors accepted, %u vectors rejected\n", positive,
         negative);
  ++g_passed;

  /* NULL handling is part of the contract: a zero-length message must not need
   * a special case at the call site, and a NULL must be refused rather than
   * dereferenced. */
  {
    static const uint8_t pub[32] = {
        0xD7U, 0x5AU, 0x98U, 0x01U, 0x82U, 0xB1U, 0x0AU, 0xB7U,
        0xD5U, 0x4BU, 0xFEU, 0xD3U, 0xC9U, 0x64U, 0x07U, 0x3AU,
        0x0EU, 0xE1U, 0x72U, 0xF3U, 0xDAU, 0xA6U, 0x23U, 0x25U,
        0xAFU, 0x02U, 0x1AU, 0x68U, 0xF7U, 0x07U, 0x51U, 0x1AU};
    static const uint8_t sig[64] = {
        0x90U, 0x5FU, 0x0CU, 0x6EU, 0x66U, 0x58U, 0x7CU, 0xD6U,
        0x60U, 0xDEU, 0x04U, 0xCBU, 0xF8U, 0x89U, 0x33U, 0x94U,
        0xBCU, 0x69U, 0x35U, 0x74U, 0x67U, 0x5BU, 0xE0U, 0x5AU,
        0xC8U, 0x1FU, 0x64U, 0xF3U, 0x1FU, 0x46U, 0x1CU, 0x22U,
        0x77U, 0x07U, 0x77U, 0x74U, 0x54U, 0x76U, 0x0AU, 0xC1U,
        0xD6U, 0x21U, 0x77U, 0x66U, 0x8CU, 0x20U, 0x97U, 0x63U,
        0x96U, 0x0FU, 0xE1U, 0xF8U, 0x33U, 0xA1U, 0x4DU, 0xAEU};

    check_window("a NULL message with non-zero length is refused",
                 ow_crypto_ed25519_verify(pub, sig, NULL, 8U), false);
    check_window("a NULL message with zero length is refused, not a crash",
                 ow_crypto_ed25519_verify(pub, sig, NULL, 0U), false);
    check_window("a NULL public key is refused",
                 ow_crypto_ed25519_verify(NULL, sig, NULL, 0U), false);
    check_window("a NULL signature is refused",
                 ow_crypto_ed25519_verify(pub, NULL, NULL, 0U), false);
  }

  printf("--- Ed25519 signature verification verified\n");
}

/* ------------------------------------------------------------------------- */
/* Main                                                                       */
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
  OW_STATUS st;

  /* Sub-suite tallies.  The CIS suites keep their own counters so a mismatch
   * between a sub-suite and the suite total stays visible; these collect them so
   * the final RESULT line counts every assertion that ran, not only the ones
   * made directly in main().  Reporting 406 passes while 600 ran would be a
   * number that looks like coverage and is not. */
  int sub_passed = 0;

  printf("=== OpenWindows kernel host boot harness ===\n");

  fflush(stdout);

  /* ------------------------------------------------------------------ */
  /* Phase 1: HAL                                                       */
  /* ------------------------------------------------------------------ */

  st = OwHalInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] HAL failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 2: Memory Manager                                            */
  /* ------------------------------------------------------------------ */

  st = OwMemInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] Memory init failed\n");
    return 1;
  }

  (void)OwMemAllocatePage();

  /* ------------------------------------------------------------------ */
  /* Phase 3: Object Manager                                            */
  /* ------------------------------------------------------------------ */

  st = OwObjInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] Object init failed\n");
    return 1;
  }

  (void)OwObjCreateDirectory("\\", (void *)0);
  (void)OwObjCreateDirectory("Device", (void *)0);
  (void)OwObjCreateDirectory("DosDevices", (void *)0);
  (void)OwObjCreateDirectory("Kernel", (void *)0);
  (void)OwObjCreateDirectory("Drivers", (void *)0);

  /* ------------------------------------------------------------------ */
  /* Phase 4: Diagnostic Engine + ALPC                                  */
  /* ------------------------------------------------------------------ */

  st = OwDiagInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] Diag init failed\n");
    return 1;
  }

  st = OwAlpcInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] ALPC init failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Runlevel subsystem                                                 */
  /* ------------------------------------------------------------------ */

  st = OwRunlevelInitialize(OW_RUNLEVEL_BOOT_DEFAULT);

  if (!ow_status_success(st)) {
    printf("[BOOT] Runlevel init failed\n");
    return 1;
  }

  ow_kprintf("[RUNLVL] boot target: %d (%s) - "
             "runlevel subsystem online\r\n",
             OwRunlevelGetTarget(), OwRunlevelName(OwRunlevelGetTarget()));

  /* ------------------------------------------------------------------ */
  /* Phase 4b: SUCS + SUTF                                              */
  /* ------------------------------------------------------------------ */

  OwSucsInitialize();
  (void)OwSucsCommitBoot();

  if (OwSucsSelfTest()) {

    ow_kprintf("[SUTF] Codec self-test: OK "
               "(Base SUCS / SUTF-8 active)\r\n");

  } else {

    printf("[BOOT] SUTF self-test failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 4c: Process / Thread subsystem                               */
  /* ------------------------------------------------------------------ */

  st = OwPsInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] PS init failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Copyleft Integrity Safeguard                                        */
  /* ------------------------------------------------------------------ */
  /* Placed where the kernel arms it: after the process subsystem and before
   * anything can map an executable. */

  st = OwCisInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] CIS init failed\n");
    return 1;
  }

  ow_kprintf("[CIS] enforcement armed (signatures mandatory)\r\n");

  /* ------------------------------------------------------------------ */
  /* Phase 5: VFS                                                       */
  /* ------------------------------------------------------------------ */

  st = OwVfsMountPrimary();

  if (!ow_status_success(st)) {
    printf("[BOOT] VFS primary failed\n");
    return 1;
  }

  st = OwVfsMountSecure();

  if (!ow_status_success(st)) {
    printf("[BOOT] VFS secure failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5b: Physical storage                                         */
  /* ------------------------------------------------------------------ */

  st = OwDiskInitialize();

  if (!ow_status_success(st)) {
    printf("[BOOT] OwDiskInitialize failed\n");
    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Kernel provenance policy (absence handling)                        */
  /* ------------------------------------------------------------------ */
  /* The freshly formatted volume carries no openwinkrnl.owx yet.  The two
   * outcomes that must never be conflated are pinned here: a development
   * policy tolerates absence but reports it as NOT verified, and a production
   * policy refuses absence outright.  Neither may return OW_SUCCESS, so a
   * missing kernel image can never be laundered into a passing check. */
  {
    const OW_CIS_POLICY *kpol = OwCisPolicy();
    bool saved = (kpol != NULL) ? kpol->RequireKernelImage : false;
    OW_STATUS rst;

    ow_kprintf("[STARTED] Kernel Provenance Policy\r\n");

    (void)OwCisSetRequireKernelImage(false);
    rst = OwSentinelVerifyKernelProvenanceFromVolume();
    check_eq("development policy: absent kernel image is skipped, not verified",
             (unsigned long)rst, (unsigned long)OW_WRN_NOT_VERIFIED);
    check_window("development policy: skipped is not a claimed success",
                 ow_status_success(rst), false);

    (void)OwCisSetRequireKernelImage(true);
    rst = OwSentinelVerifyKernelProvenanceFromVolume();
    check_eq("production policy: absent kernel image is refused",
             (unsigned long)rst, (unsigned long)OW_ERR_NOT_FOUND);
    check_window("production policy: refusal is never a success",
                 ow_status_success(rst), false);

    (void)OwCisSetRequireKernelImage(saved);
    ow_kprintf("[FINISHED] Kernel Provenance Policy\r\n");
  }

  /* ------------------------------------------------------------------ */
  /* Provision owinit.owx                                               */
  /* ------------------------------------------------------------------ */

  {
    uint32_t ino = 0;

    st = OwFsOwfsCreate(OW_INIT_EXEC_NAME, &ino);

    if (!ow_status_success(st)) {
      printf("[BOOT] owinit create failed\n");
      return 1;
    }

    st = OwFsOwfsWrite(OW_INIT_EXEC_NAME, g_owinit_image, OWINIT_IMAGE_SIZE);

    if (!ow_status_success(st)) {
      printf("[BOOT] owinit write failed\n");
      return 1;
    }

    printf("[BOOT] provisioned %s on host OWFS "
           "(ino %u)\n",
           OW_INIT_EXEC_NAME, (unsigned)ino);
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5c: owinit provisioning check                                */
  /* ------------------------------------------------------------------ */

  ow_kprintf("[STARTED] owinit\r\n");

  if (OwDiskOwinitPresent()) {

    ow_kprintf("[FINISHED] owinit\r\n");

  } else {

    printf("[BOOT] owinit executable missing on host OWFS\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5c.5: owinit process hand-off                                */
  /* ------------------------------------------------------------------ */

  {
    static uint8_t s_OwinitImage[64U * 1024U];

    uint32_t read_len = 0;
    OW_STATUS read_status;

    read_status = OwFsOwfsRead(OW_INIT_EXEC_NAME, s_OwinitImage,
                               (uint32_t)sizeof(s_OwinitImage), &read_len);

    if (!ow_status_success(read_status) || read_len == 0) {

      printf("[BOOT] owinit.owx read failed "
             "(st=0x%x, len=%u)\n",
             (unsigned)read_status, (unsigned)read_len);

      return 1;
    }

    {
      OW_PROCESS_OBJECT *process;

      process = OwPsCreateProcess("owinit", OW_PS_PID_KERNEL);

      if (process == NULL) {

        printf("[BOOT] owinit process create failed\n");

        return 1;
      }

      /* The outcome is asserted rather than assumed.
       *
       * A default build pins no trust anchors and its owinit.owx carries no
       * signature, so this load is *supposed* to fail, and the suite passes when
       * it does: refusing to boot is the working state, not a harness error.  A
       * CIS_DEV_TRUST build has both an anchor and a signed image, so the same
       * load is supposed to succeed.  Treating either outcome as the only
       * correct one would have meant choosing which build gets a regression
       * suite, and the wrong choice is the one that stops checking that unsigned
       * code does not run.
       *
       * The thread is created only on success, so a refusal cannot be laundered
       * into a running process by a later step. */
      {
        OW_STATUS load_status = OwPsLoadImage(process, s_OwinitImage, read_len,
                                              (uint32_t)OW_CIS_RECORD_BOOT);
        OW_CIS_VERDICT verdict = OwPsLastCisVerdict();

        if (ow_status_success(load_status)) {
          OW_THREAD_OBJECT *thread;

          check_window("a trusted owinit image loads",
                       verdict == OW_CIS_VERDICT_TRUSTED, true);

          thread = OwPsCreateThread(process, process->EntryPoint, 0);

          if (thread == NULL) {

            printf("[BOOT] owinit thread create failed\n");

            return 1;

          }

          printf("[BOOT] owinit enqueued as PID 1 "
                 "thread %u\n",
                 (unsigned)thread->Tid);
        } else {
          /* Refused.  Two properties make this a refusal rather than a load that
           * stumbled: a CIS-specific status, and no executable state left
           * behind. */
          printf("[BOOT] owinit refused as configured "
                 "(status 0x%08X, verdict %u)\n",
                 (unsigned)load_status, (unsigned)verdict);

          check_window("a refused image reports a CIS-specific status",
                       (load_status & OW_ERR_CIS_FAMILY_MASK) != 0u, true);
          check_window("a refused image leaves no entry point",
                       process->EntryPoint == 0u, true);

#ifdef CIS_DEV_TRUST
          /* With the anchor present, a refusal means the opt-in build cannot
           * boot.  Asserting it here names the cause where it happens rather
           * than leaving a confusing failure further on. */
          check_window("a CIS_DEV_TRUST build accepts its own signed owinit",
                       verdict == OW_CIS_VERDICT_TRUSTED, true);
#else
          check_window("a build with no anchors reports UNSIGNED",
                       verdict == OW_CIS_VERDICT_REJECT_UNSIGNED, true);
#endif
        }
      }
    }
  }

  /* ------------------------------------------------------------------ */
  /* Provision openwinkrnl.chk                                          */
  /* ------------------------------------------------------------------ */

  {
    static const char kDefaultChecksum[] =
        "e925ab4e3f175405000000000000000000000000000000000000000000000000\n";

    uint8_t checksum_buffer[256];
    uint32_t checksum_inode = 0;
    long checksum_length;

    checksum_length = host_read_file_candidates(
        "openwinkrnl.chk", checksum_buffer, sizeof(checksum_buffer) - 1);

    if (checksum_length < 0) {

      /*
       * No host checksum was found.
       * Use the built-in test checksum.
       */
      if (!ow_strcopy((char *)checksum_buffer, sizeof(checksum_buffer),
                      kDefaultChecksum)) {

        printf("[BOOT] default checksum copy failed\n");

        return 1;
      }

      checksum_length = (long)ow_strlen((const char *)checksum_buffer);

    } else {

      checksum_buffer[checksum_length] = '\0';
    }

    st = OwFsOwfsCreate(OW_KERNEL_CHK_NAME, &checksum_inode);

    if (!ow_status_success(st)) {

      printf("[BOOT] openwinkrnl.chk create failed\n");

      return 1;
    }

    st = OwFsOwfsWrite(OW_KERNEL_CHK_NAME, checksum_buffer,
                       (uint32_t)checksum_length);

    if (!ow_status_success(st)) {

      printf("[BOOT] openwinkrnl.chk write failed\n");

      return 1;
    }

    printf("[BOOT] provisioned %s on host OWFS "
           "(ino %u, len %u)\n",
           OW_KERNEL_CHK_NAME, (unsigned)checksum_inode,
           (unsigned)checksum_length);
  }

  /* ------------------------------------------------------------------ */
  /* Provision openwinkrnl.owx                                          */
  /* ------------------------------------------------------------------ */

  {
    /*
     * Static storage intentionally replaces malloc/free.
     *
     * Increase this if OpenWindows kernel images can exceed 1 MiB.
     */
    static uint8_t kernel_image[1024U * 1024U];

    uint32_t kernel_inode = 0;
    long kernel_size;

    kernel_size = host_read_file_candidates("openwinkrnl.owx", kernel_image,
                                            sizeof(kernel_image));

    if (kernel_size > 0) {

      st = OwFsOwfsCreate(OW_KERNEL_IMG_NAME, &kernel_inode);

      if (!ow_status_success(st)) {

        printf("[BOOT] %s create failed\n", OW_KERNEL_IMG_NAME);

        return 1;
      }

      st = OwFsOwfsWrite(OW_KERNEL_IMG_NAME, kernel_image,
                         (uint32_t)kernel_size);

      if (!ow_status_success(st)) {

        printf("[BOOT] %s write failed\n", OW_KERNEL_IMG_NAME);

        return 1;
      }

      printf("[BOOT] provisioned %s on host OWFS "
             "(ino %u, size %ld)\n",
             OW_KERNEL_IMG_NAME, (unsigned)kernel_inode, kernel_size);
    }
  }

  /* ------------------------------------------------------------------ */
  /* Phase 5d: Kernel integrity                                         */
  /* ------------------------------------------------------------------ */

  ow_kprintf("[STARTED] Kernel Integrity\r\n");

  st = OwSentinelVerifyKernelChecksum();

  if (ow_status_success(st)) {

    ow_kprintf("[FINISHED] Kernel Integrity\r\n");

  } else {

    printf("[BOOT] Kernel integrity check failed (0x%X)\n", (unsigned)st);

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 6: Network Router                                            */
  /* ------------------------------------------------------------------ */

  st = OwNetInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Net init failed\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 6b: UniVIP + FVIP                                            */
  /* ------------------------------------------------------------------ */

  if (!OwVipIsUp()) {

    uint32_t vip_code;

    vip_code = OwVipInitialize();

    if (!OwVipIsSuccessCode(vip_code)) {

      printf("[BOOT] VIP init failed (0x%X)\n", (unsigned)vip_code);

      return 1;
    }
  }

  if (OwVipIsUp()) {

    ow_kprintf("[VIP] UniVIP online: root volume %u @ LBA %llu, "
               "FVIP index ready\r\n",
               OW_VIP_ROOT_VOLUME, (unsigned long long)OW_VIP_ROOT_BASE_SECTOR);
  }

  /* ------------------------------------------------------------------ */
  /* Phase 7: Sentinel                                                  */
  /* ------------------------------------------------------------------ */

  st = OwSentinelInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Sentinel init failed\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 8: Syscall gateway                                           */
  /* ------------------------------------------------------------------ */

  st = OwSyscallInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Syscall init failed\n");

    return 1;
  }

  /* ------------------------------------------------------------------ */
  /* Phase 9: Scheduler hand-off                                        */
  /* ------------------------------------------------------------------ */

  OwPsCaptureBootContext();
  OwPsStartScheduler();

  /* ------------------------------------------------------------------ */
  /* Phase 9: Debug shell                                                */
  /* ------------------------------------------------------------------ */

  st = OwShellInitialize();

  if (!ow_status_success(st)) {

    printf("[BOOT] Shell init failed\n");

    return 1;
  }

  /*
   * Build the optional custom shell command without snprintf.
   *
   * argc == 1:
   *     exit
   *
   * argc == 2:
   *     argv[1]
   *     exit
   *
   * argc >= 3:
   *     argv[1] argv[2]
   *     exit
   */
  if (argc > 1) {

    static char custom_script[256];

    size_t position = 0;
    size_t i;

    /* First argument. */
    for (i = 0; argv[1][i] != '\0' && position + 1 < sizeof(custom_script);
         ++i) {

      custom_script[position++] = argv[1][i];
    }

    /* Optional second argument. */
    if (argc > 2 && position + 1 < sizeof(custom_script)) {

      custom_script[position++] = ' ';

      for (i = 0; argv[2][i] != '\0' && position + 1 < sizeof(custom_script);
           ++i) {

        custom_script[position++] = argv[2][i];
      }
    }

    /* Newline after command. */
    if (position + 1 < sizeof(custom_script))
      custom_script[position++] = '\n';

    /* "exit\n" */
    if (position + 5 < sizeof(custom_script)) {

      custom_script[position++] = 'e';
      custom_script[position++] = 'x';
      custom_script[position++] = 'i';
      custom_script[position++] = 't';
      custom_script[position++] = '\n';
    }

    custom_script[position] = '\0';

    HostHalSetInputScript(custom_script);

  } else {

    HostHalSetInputScript(g_script);
  }

  (void)OwShellRun();

  /* ------------------------------------------------------------------ */
  /* User-window address validation (regression)                         */
  /* ------------------------------------------------------------------ */

  test_user_window_predicates();

  /* ------------------------------------------------------------------ */
  /* Import rejection (regression)                                       */
  /* ------------------------------------------------------------------ */

  test_import_rejection();

  /* ------------------------------------------------------------------ */
  /* Entry point identity (regression)                                  */
  /* ------------------------------------------------------------------ */

  test_entry_classifiers();
  test_entry_is_owinit_main();

  /* ------------------------------------------------------------------ */
  /* Userspace boot policy and emergency image integrity                 */
  /* ------------------------------------------------------------------ */

  test_userspace_states();
  test_emergency_images();

  /* ------------------------------------------------------------------ */
  /* Copyleft Integrity Safeguard                                        */
  /* ------------------------------------------------------------------ */

  test_cis_format();
  test_cis_core();
  g_failures += test_cis_verify_run(&sub_passed);
  g_passed  += sub_passed;

  /* ------------------------------------------------------------------ */
  /* CIS at the loader boundary                                          */
  /* ------------------------------------------------------------------ */

  /* After the verifier suite, not beside it.  These loads need a live process
   * table and a memory manager, and the harness has only finished standing those
   * up by this point in the run.  Ordering them after the verifier tests also
   * means the corpus has just been walked once, so a fixture the verifier
   * already rejected is not being re-litigated here for a different reason. */
  g_failures += test_cis_loader_run(&sub_passed);
  g_passed  += sub_passed;

  /* ------------------------------------------------------------------ */
  /* Ed25519 and SHA-512 (CIS signature primitives)                      */
  /* ------------------------------------------------------------------ */

  test_sha512();
  test_ed25519_field();
  test_ed25519_scalars();
  test_ed25519_points();
  test_ed25519_constants();
  test_ed25519_verify();

  /* ------------------------------------------------------------------ */
  /* Custom trap verification                                            */
  /* ------------------------------------------------------------------ */

  if (argc > 1) {

    printf("\n=== Custom Trap Execution Verification ===\n");

    if (count_occ(HostHalOutput(), "You need to restart your device.") > 0) {
      expect("You need to restart your device.", 1);
    } else {
      expect("SYSTEM HALTED", 1);
    }

    expect("SYSTEM HALTED", 1);

    expect("#######", 1);

    printf("\n=== RESULT: %d passed, %d failed ===\n", g_passed, g_failures);

    fflush(stdout);

    return (g_failures == 0) ? 0 : 1;
  }

  /* ------------------------------------------------------------------ */
  /* Normal transcript verification                                     */
  /* ------------------------------------------------------------------ */

  printf("\n=== Transcript verification ===\n");

  fflush(stdout);

  expect("[SUTF] Codec self-test: OK", 1);

  expect("[RUNLVL] boot target: 5 (FULL)", 1);

  expect("[RUNLVL] current=5 (FULL)", 1);

  expect("[RUNLVL] config: verbosity=1 "
         "watchdogMs=0 heapKB=262144 "
         "maxHandles=65536",
         1);

  expect("[RUNLVL] profile: level 3, name NETWORK", 1);

  expect("[RUNLVL]   + NETWORK", 1);

  expect("[RUNLVL]   + AI", 1);

  expect("[FINISHED] owinit", 1);

  expect("[FINISHED] Kernel Integrity", 1);

  expect("[PS] process/thread subsystem initialized", 1);

  expect("[PS] owinit: process created (PID 1)", 1);

  /* The thread line is printed only when the image was trusted and loaded, so
   * it is asserted in the configuration where that happens.  In a default build
   * the refusal above IS the outcome, and this line being absent is part of it:
   * a thread for a refused image would be the bug, not the fix. */
#ifdef CIS_DEV_TRUST
  expect("[PS] owinit: thread 1 created, entry 0x", 1);
#else
  expect("[PS] owinit: thread 1 created, entry 0x", 0);
#endif

  expect("[PS] boot context captured (thread 0)", 1);

  expect("[PS] scheduler started (100 Hz)", 1);

  expect("[VIP] UniVIP online: root volume 0 @ LBA 131200", 1);

  expect("[VIP] mount code 0x11AD02", 1);

  expect("[VIP] volume 1 base LBA 131200", 1);

  expect("[VIP] '/boot/bootvid.owd' sector_offset=12 flags=0x3", 1);

  expect("[VIP] lookup miss code 0x11AEE2", 1);

  expect("[VIP] integrity code 0x", 1);

  expect("[FS] format: OK", 1);

  expect("[FS] owfs mount: OK", 1);

  expect("[FS] mkdir 'System': OK", 1);

  expect("[FS] create 'bootvid.owd': OK", 1);

  expect("[FS] write 'bootvid.owd': OK", 1);

  expect("[FS] OWFS: MOUNTED", 1);

  expect("[FS] USFS: MOUNTED", 1);

  expect("OpenWindows storage live", 2);

  expect("[SUCS] request: staged, reboot required", 1);

  expect("[SHUTDOWN] Exiting...", 1);

  /* ------------------------------------------------------------------ */
  /* Final result                                                        */
  /* ------------------------------------------------------------------ */

  printf("\n=== RESULT: %d passed, %d failed ===\n", g_passed, g_failures);

  fflush(stdout);

  return (g_failures == 0) ? 0 : 1;
}
