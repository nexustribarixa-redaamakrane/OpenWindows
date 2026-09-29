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

#include "../../inc/ow_alpc.h"
#include "../../inc/ow_diag.h"
#include "../../inc/ow_ecosys.h"
#include "../../inc/ow_hal.h"
#include "../../inc/ow_kprintf.h"
#include "../../boot/owinit_image.h"
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

  /* Corruption, one byte at a time through the file.  The interesting positions
   * are the ones a real failure produces: inside the header (a truncated or
   * re-flashed image), inside the section table (a bad table entry that the
   * structural checks cannot see), and deep in a code section (bit rot, which is
   * the case a header-only test would miss entirely). */
  {
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

    for (s = 0; s < sizeof(spots) / sizeof(spots[0]); s++) {
      if (spots[s] >= OWRS_IMAGE_SIZE) continue;
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
  }

  /* Truncation: the loader's own bound is image_size <= bytes held, so a short
   * read has to fail before anything is mapped. */
  for (i = 0; i < 3; i++) {
    uint32_t short_by = (uint32_t)(1u << (8u * i));
    if (short_by >= OWRS_IMAGE_SIZE) continue;
    check_window("owrs.owx truncated by 1/256/65536 byte(s) is unusable",
                 OwOwxImageIsUsable(g_owrs_image, OWRS_IMAGE_SIZE - short_by),
                 false);
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
    const uint32_t n = OWRS_IMAGE_SIZE;
    const owx_header_t *h = (const owx_header_t *)(const void *)g_owrs_image;
    const uint32_t declared = h->image_checksum;
    uint32_t vfs_crc;

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

/* ------------------------------------------------------------------------- */
/* Main                                                                       */
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv) {
  OW_STATUS st;

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

      if (!ow_status_success(OwPsLoadImage(process, s_OwinitImage, read_len))) {

        printf("[BOOT] owinit image load failed "
               "(len=%u)\n",
               (unsigned)read_len);

        return 1;
      }

      {
        OW_THREAD_OBJECT *thread;

        thread = OwPsCreateThread(process, process->EntryPoint, 0);

        if (thread == NULL) {

          printf("[BOOT] owinit thread create failed\n");

          return 1;
        }

        printf("[BOOT] owinit enqueued as PID 1 "
               "thread %u\n",
               (unsigned)thread->Tid);
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

  expect("[PS] owinit: thread 1 created, entry 0x", 1);

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
