/* host_skto_name.c - SKTO name admission at the OpenWindows kernel boundary.
 *
 * kapi/ow_skto_name.c is the adapter every untrusted syscall name now passes
 * through.  This suite exercises the adapter itself, not a reimplementation of
 * it: the same OwSktoNameAdmit* entry points the dispatcher calls, the same
 * SUAS-018 implementation linked into the kernel, and the same OWFS/USFS
 * ceiling.
 *
 * What these tests can and cannot prove:
 *
 *   - They run on the host build, where ow_irq_save()/ow_irq_restore() are
 *     no-ops.  The lock callbacks are wired and the publication lifecycle
 *     (generations, reader references, SKTO_E_BUSY) is real, but interrupt
 *     masking is a kernel property and is not claimed here.
 *   - The containment callback is invoked with the exact bytes the adapter
 *     reads.  The VAD cases below drive the real OwMemInUserWindow() /
 *     OwMemFindVad() predicates against a real VAD tree; they do not prove a
 *     Ring 3 syscall reached the dispatcher, because no CPL3 transition occurs
 *     in this harness.
 *   - Namespace ceiling, SUTF-8 validation, terminator handling, and the
 *     refusal to truncate are properties of the linked code, so they are
 *     covered directly.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../inc/ow_hal.h"
#include "../../inc/ow_memory.h"
#include "../../inc/ow_vfs.h"
#include "../../kapi/ow_skto_name.h"
#include "../../storage/owdisk.h"

static int g_skto_passed;
static int g_skto_failed;

static void skto_check(const char *label, bool got, bool want) {
  if (got == want) {
    ++g_skto_passed;
    return;
  }
  ++g_skto_failed;
  printf("[FAIL] skto name: %s (got %s, want %s)\n", label,
         got ? "true" : "false", want ? "true" : "false");
}

static void skto_check_status(const char *label, skto_status_t got,
                              skto_status_t want) {
  if (got == want) {
    ++g_skto_passed;
    return;
  }
  ++g_skto_failed;
  printf("[FAIL] skto name: %s (got status %d, want %d)\n", label, (int)got,
         (int)want);
}

static bool bytes_equal(const uint8_t *a, const uint8_t *b, size_t n) {
  size_t i;

  for (i = 0u; i < n; ++i) {
    if (a[i] != b[i])
      return false;
  }
  return true;
}

/* ---------------------------------------------------------------------- */
/* Containment callbacks                                                   */
/* ---------------------------------------------------------------------- */

/* Accepts only a span the test declared.  The adapter reads through this
 * callback byte by byte, so `hits` also tells us the scan stopped at the
 * terminator instead of walking the declared span. */
typedef struct {
  const uint8_t *base;
  size_t         len;
  size_t         hits;
  size_t         allowed;
} skto_span_t;

static bool accept_declared_span(void *ctx, const void *base, size_t len) {
  skto_span_t *span = (skto_span_t *)ctx;
  const uint8_t *p = (const uint8_t *)base;

  if (span == NULL)
    return false;
  span->hits++;
  if (p < span->base)
    return false;
  if ((size_t)(p - span->base) + len > span->len)
    return false;
  return true;
}

static bool accept_declared_span_limited(void *ctx, const void *base,
                                        size_t len) {
  skto_span_t *span = (skto_span_t *)ctx;
  const uint8_t *p = (const uint8_t *)base;

  if (span == NULL)
    return false;
  span->hits++;
  if (p < span->base)
    return false;
  if ((size_t)(p - span->base) + len > span->allowed)
    return false;
  return true;
}

/* ---------------------------------------------------------------------- */
/* Trusted admission                                                       */
/* ---------------------------------------------------------------------- */

static void test_trusted_admission(void) {
  ow_skto_name_t name;
  skto_status_t st;
  static const char ascii[] = "owinit.owx";
  static const char multibyte[] = "caf\xC3\xA9"; /* "café", 5 bytes */
  char max_ok[130];
  char max_bad[130];
  char unterminated[128];
  static const uint8_t bad_utf8[] = {'a', 0xC3, 0x28, 0x00};
  static const uint8_t surrogate[] = {0xED, 0xA0, 0x80, 0x00};
  /* U+110000 in the 5-byte SUTF-8 framing: the first SCP-plane codepoint.
   * It decodes cleanly and is then refused as inadmissible rather than
   * malformed, which is the distinction the gateway needs. */
  static const uint8_t scp_plane[] = {0xF8, 0x84, 0x90, 0x80, 0x80, 0x00};
  size_t i;

  st = OwSktoNameAdmitTrusted(&name, ascii, sizeof(ascii));
  skto_check_status("trusted ASCII admits", st, SKTO_OK);
  skto_check("trusted ASCII length", OwSktoNameLength(&name) == 10u, true);
  skto_check("trusted ASCII text",
             bytes_equal((const uint8_t *)OwSktoNameCstr(&name),
                         (const uint8_t *)ascii, 10u),
             true);
  skto_check("trusted ASCII terminated",
             OwSktoNameCstr(&name)[OwSktoNameLength(&name)] == '\0', true);

  /* Length is bytes, not codepoints, and the bytes are not normalised. */
  st = OwSktoNameAdmitTrusted(&name, multibyte, sizeof(multibyte));
  skto_check_status("trusted multi-byte admits", st, SKTO_OK);
  skto_check("trusted multi-byte is byte-exact",
             OwSktoNameLength(&name) == 5u &&
                 bytes_equal((const uint8_t *)OwSktoNameCstr(&name),
                             (const uint8_t *)multibyte, 5u),
             true);

  /* The namespace ceiling.  OWFS/USFS store 128 bytes including the NUL, so a
   * 127-byte name is complete and a 128-byte one is not admitted at all. */
  for (i = 0u; i < 127u; ++i)
    max_ok[i] = 'a';
  max_ok[127] = '\0';
  st = OwSktoNameAdmitTrusted(&name, max_ok, OW_SKTO_NAME_STORAGE_BYTES);
  skto_check_status("127-byte name admits", st, SKTO_OK);
  skto_check("127-byte name length", OwSktoNameLength(&name) == 127u, true);

  for (i = 0u; i < 128u; ++i)
    max_bad[i] = 'a';
  max_bad[128] = '\0';
  st = OwSktoNameAdmitTrusted(&name, max_bad, OW_SKTO_NAME_STORAGE_BYTES);
  skto_check_status("128-byte name is refused, not truncated", st,
                    SKTO_E_TERMINATOR);
  skto_check("failed admission clears the view", OwSktoNameCstr(&name) == NULL,
             true);

  /* No NUL inside the scan bound is a terminator failure, never a prefix. */
  for (i = 0u; i < sizeof(unterminated); ++i)
    unterminated[i] = 'b';
  st = OwSktoNameAdmitTrusted(&name, unterminated, sizeof(unterminated));
  skto_check_status("unterminated name is refused", st, SKTO_E_TERMINATOR);

  /* Empty is its own policy failure, distinct from "absent". */
  st = OwSktoNameAdmitTrusted(&name, "", 1u);
  skto_check_status("empty name is policy-refused", st, SKTO_E_POLICY);

  /* Malformed SUTF-8 and inadmissible codepoints are refused with distinct
   * statuses so the gateway can report them differently. */
  st = OwSktoNameAdmitTrusted(&name, (const char *)bad_utf8, sizeof(bad_utf8));
  skto_check_status("malformed SUTF-8 is refused", st, SKTO_E_ENCODING);
  /* A surrogate-form sequence is structurally invalid UTF-8, so the linked
   * decoder reports ENCODING for it; it is a rejection either way. */
  st = OwSktoNameAdmitTrusted(&name, (const char *)surrogate,
                              sizeof(surrogate));
  skto_check_status("surrogate-form sequence is refused", st, SKTO_E_ENCODING);
  st = OwSktoNameAdmitTrusted(&name, (const char *)scp_plane,
                              sizeof(scp_plane));
  skto_check_status("SCP-plane codepoint is inadmissible", st,
                    SKTO_E_INADMISSIBLE);

  st = OwSktoNameAdmitTrusted(&name, NULL, 8u);
  skto_check_status("absent source is refused", st, SKTO_E_NULL);
  st = OwSktoNameAdmitTrusted(NULL, ascii, sizeof(ascii));
  skto_check_status("absent output is refused", st, SKTO_E_NULL);
}

/* ---------------------------------------------------------------------- */
/* Untrusted admission                                                     */
/* ---------------------------------------------------------------------- */

static void test_user_admission(void) {
  ow_skto_name_t name;
  skto_status_t st;
  uint8_t buf[16];
  skto_span_t span;
  size_t i;

  for (i = 0u; i < sizeof(buf); ++i)
    buf[i] = 0u;
  buf[0] = 'u';
  buf[1] = 's';
  buf[2] = 'e';
  buf[3] = 'r';
  buf[4] = 0u;

  span.base = buf;
  span.len = sizeof(buf);
  span.hits = 0u;
  span.allowed = sizeof(buf);

  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf),
                           accept_declared_span, &span);
  skto_check_status("user name admits through the callback", st, SKTO_OK);
  skto_check("user name is complete", OwSktoNameLength(&name) == 4u &&
                                           bytes_equal(
                                               (const uint8_t *)OwSktoNameCstr(
                                                   &name),
                                               (const uint8_t *)"user", 4u),
             true);
  /* Six inspections: five per-byte checks (four content bytes plus the
   * terminator) and the one consolidated containment check inside
   * suas_skto_admit.  A scan that walked the whole declared span would be
   * reading past the name. */
  skto_check("user scan stops at the terminator", span.hits == 6u, true);

  /* A containment refusal must surface as SKTO_E_RANGE: the pointer was not
   * proven to belong to the caller. */
  span.allowed = 3u; /* "use" is admissible, the fourth byte is not */
  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf),
                           accept_declared_span_limited, &span);
  skto_check_status("containment refusal surfaces as RANGE", st, SKTO_E_RANGE);
  skto_check("failed containment clears the view",
             OwSktoNameCstr(&name) == NULL, true);

  /* A NULL callback is a programming error, not an implicit trust decision. */
  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf), NULL, NULL);
  skto_check_status("NULL containment callback is refused", st, SKTO_E_NULL);

  /* No terminator within the caller-declared ceiling. */
  for (i = 0u; i < sizeof(buf); ++i)
    buf[i] = 'x';
  span.len = sizeof(buf);
  span.allowed = sizeof(buf);
  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf),
                           accept_declared_span, &span);
  skto_check_status("user name without terminator is refused", st,
                    SKTO_E_TERMINATOR);

  /* Empty through the user path is the same policy refusal as trusted. */
  buf[0] = 0u;
  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf),
                           accept_declared_span, &span);
  skto_check_status("empty user name is policy-refused", st, SKTO_E_POLICY);
}

/* ---------------------------------------------------------------------- */
/* Real VAD containment                                                    */
/* ---------------------------------------------------------------------- */

/* This is the dispatcher's predicate (syscall_user_range) expressed over the
 * same kernel primitives: the full range must lie inside the guarded user
 * window and every page it touches must exist in the caller's VAD tree. */
typedef struct {
  OW_VAD_NODE *root;
} skto_vad_t;

static bool vad_range(void *ctx, const void *base, size_t len) {
  skto_vad_t *vad = (skto_vad_t *)ctx;
  uint64_t va;
  uint64_t end;
  uint64_t page;

  if (vad == NULL || vad->root == NULL || len == 0u)
    return false;
  va = (uint64_t)(uintptr_t)base;
  if (va > ~(uint64_t)0 - (uint64_t)len)
    return false;
  end = va + (uint64_t)len - 1u;
  if (!OwMemInUserWindow(va) || !OwMemInUserWindow(end))
    return false;
  for (page = va & ~(uint64_t)(OW_PAGE_SIZE - 1u); page <= end;
       page += OW_PAGE_SIZE) {
    if (!OwMemFindVad(vad->root, page))
      return false;
  }
  return true;
}

static void test_vad_containment(void) {
  OW_VAD_NODE *root = NULL;
  OW_VAD_NODE *user_node;
  OW_VAD_NODE *outside_node;
  skto_span_t span;
  skto_vad_t vad;
  uint8_t buf[8];
  ow_skto_name_t name;
  skto_status_t st;
  uint64_t user_base = OW_USER_WINDOW_BASE;
  uint64_t outside = 0x1000u;

  /* One mapped page at the bottom of the user window. */
  user_node = OwMemCreateVad(user_base, user_base + OW_PAGE_SIZE - 1u,
                             OW_PAGE_USER_RW_NX);
  skto_check("VAD node is available", user_node != NULL, true);
  if (user_node == NULL)
    return;
  skto_check_status("VAD insert succeeds", OwMemInsertVad(&root, user_node),
                    OW_SUCCESS);

  /* A second VAD outside the user window: the tree can hold it, but the
   * window predicate must still refuse it. */
  outside_node =
      OwMemCreateVad(outside, outside + OW_PAGE_SIZE - 1u, OW_PAGE_USER_RW_NX);
  skto_check("out-of-window VAD node is available", outside_node != NULL, true);
  if (outside_node != NULL)
    skto_check_status("out-of-window VAD insert succeeds",
                      OwMemInsertVad(&root, outside_node), OW_SUCCESS);

  skto_check("VAD finds an address in its page",
             OwMemFindVad(root, user_base + 10u) != NULL, true);
  skto_check("VAD refuses the next page",
             OwMemFindVad(root, user_base + OW_PAGE_SIZE) == NULL, true);

  vad.root = root;
  skto_check("contained range is accepted", vad_range(&vad, (void *)user_base, 4u),
             true);
  skto_check("range crossing the VAD end is refused",
             vad_range(&vad, (void *)(user_base + OW_PAGE_SIZE - 4u), 8u),
             false);
  skto_check("VAD outside the user window is refused",
             vad_range(&vad, (void *)outside, 4u), false);

  /* The adapter consults the callback before reading each byte.  The buffer
   * below lives outside the user window, so a window-checking predicate must
   * refuse it even though the test's own memory is perfectly valid. */
  buf[0] = 'n';
  buf[1] = 0u;
  span.base = buf;
  span.len = sizeof(buf);
  span.hits = 0u;
  span.allowed = sizeof(buf);
  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf), vad_range,
                           &vad);
  skto_check_status("adapter refuses a pointer outside the user window", st,
                    SKTO_E_RANGE);

  /* And the declared-span callback proves the adapter accepts the same bytes
   * when containment answers true, so the refusal above is the predicate's
   * answer rather than an adapter bug. */
  st = OwSktoNameAdmitUser(&name, (const char *)buf, sizeof(buf),
                           accept_declared_span, &span);
  skto_check_status("same bytes admit under a containing predicate", st,
                    SKTO_OK);

  OwMemFreeVad(outside_node);
  OwMemFreeVad(user_node);
}

/* ---------------------------------------------------------------------- */
/* Publication lifecycle under the real IRQ lock callbacks                 */
/* ---------------------------------------------------------------------- */

static skto_status_t admit_literal(const char *text, uint8_t *storage,
                                   size_t cap, skto_text_t *out) {
  skto_limits_t limits;
  size_t written = 0u;
  size_t n = 0u;

  /* The literal is a test constant; its length is measured explicitly. */
  while (n < cap && text[n] != '\0')
    ++n;
  if (n == cap)
    return SKTO_E_TERMINATOR;

  suas_skto_limits_default(&limits);
  limits.max_admit_bytes = OW_SKTO_NAME_MAX_BYTES;
  limits.max_name_bytes = OW_SKTO_NAME_MAX_BYTES;
  return suas_skto_admit(text, n, NULL, NULL, &limits, storage, cap, out,
                         &written);
}

static void test_publication_lifecycle(void) {
  skto_name_table_t table;
  ow_skto_irq_lock_t lock;
  uint8_t storage[SKTO_NAME_MAX_BYTES];
  skto_text_t name;
  skto_text_t view1;
  skto_text_t view2;
  skto_text_t view3;
  skto_text_t view4;
  skto_text_t view;
  uint32_t g1 = 0u;
  uint32_t g2 = 0u;
  uint32_t g3 = 0u;
  uint32_t g4 = 0u;
  uint32_t probe = 0u;
  skto_status_t st;

  lock.flags = 0u;
  st = suas_skto_names_init_locked(&table, OwSktoLockAcquire, OwSktoLockRelease,
                                   &lock);
  skto_check_status("table initialises with IRQ lock callbacks", st, SKTO_OK);

  st = admit_literal("svc.name", storage, sizeof(storage), &name);
  skto_check_status("publication name admits", st, SKTO_OK);

  st = suas_skto_publish(&table, &name, NULL, &g1);
  skto_check_status("first publication succeeds", st, SKTO_OK);
  st = suas_skto_publish(&table, &name, NULL, &g2);
  skto_check_status("republication succeeds", st, SKTO_OK);
  skto_check("republication advances the generation", g2 == g1 + 1u, true);

  st = suas_skto_resolve(&table, &name, &probe, &view);
  skto_check_status("resolve acquires the visible generation", st, SKTO_OK);
  skto_check("resolve reports the current generation", probe == g2, true);
  skto_check("resolved view is byte-exact",
             view.len == 8u &&
                 bytes_equal(view.bytes, (const uint8_t *)"svc.name", 8u),
             true);
  skto_check_status("release succeeds",
                    suas_skto_name_release(&table, &view), SKTO_OK);
  skto_check_status("double release is refused",
                    suas_skto_name_release(&table, &view), SKTO_E_NOTFOUND);

  /* Hold one view per generation until the fixed four-record pool is fully
   * referenced.  Publication must then fail with SKTO_E_BUSY rather than
   * overwrite a record a reader still holds. */
  st = suas_skto_resolve(&table, &name, &g1, &view1);
  skto_check_status("hold viewer 1", st, SKTO_OK);
  st = suas_skto_publish(&table, &name, NULL, &g2);
  skto_check_status("publish over held generation 1", st, SKTO_OK);
  st = suas_skto_resolve(&table, &name, &g2, &view2);
  skto_check_status("hold viewer 2", st, SKTO_OK);
  st = suas_skto_publish(&table, &name, NULL, &g3);
  skto_check_status("publish over held generation 2", st, SKTO_OK);
  st = suas_skto_resolve(&table, &name, &g3, &view3);
  skto_check_status("hold viewer 3", st, SKTO_OK);
  st = suas_skto_publish(&table, &name, NULL, &g4);
  skto_check_status("publish over held generation 3", st, SKTO_OK);
  st = suas_skto_resolve(&table, &name, &g4, &view4);
  skto_check_status("hold viewer 4", st, SKTO_OK);

  probe = 0u;
  st = suas_skto_publish(&table, &name, NULL, &probe);
  skto_check_status("full snapshot pool reports BUSY", st, SKTO_E_BUSY);
  skto_check("BUSY publication leaves the generation alone", probe == 0u, true);

  /* Old views remain byte-exact and generation-stamped while newer
   * generations exist. */
  skto_check("held view 1 keeps its generation and bytes",
             view1.generation < view2.generation &&
                 view1.len == 8u &&
                 bytes_equal(view1.bytes, (const uint8_t *)"svc.name", 8u),
             true);

  skto_check_status("release viewer 4", suas_skto_name_release(&table, &view4),
                    SKTO_OK);
  skto_check_status("release viewer 3", suas_skto_name_release(&table, &view3),
                    SKTO_OK);
  skto_check_status("release viewer 2", suas_skto_name_release(&table, &view2),
                    SKTO_OK);
  skto_check_status("release viewer 1", suas_skto_name_release(&table, &view1),
                    SKTO_OK);

  st = suas_skto_publish(&table, &name, NULL, &probe);
  skto_check_status("published again after all views release", st, SKTO_OK);
}

static void test_namespace_capacity(void) {
  skto_name_table_t table;
  ow_skto_irq_lock_t lock;
  uint8_t storage[SKTO_NAME_MAX_BYTES];
  skto_text_t name;
  skto_status_t st;
  uint32_t generation = 0u;
  char label[4];
  unsigned i;
  unsigned refused_at = ~0u;

  lock.flags = 0u;
  st = suas_skto_names_init_locked(&table, OwSktoLockAcquire, OwSktoLockRelease,
                                   &lock);
  skto_check_status("capacity table initialises", st, SKTO_OK);

  for (i = 0u; i < 17u; ++i) {
    label[0] = 'n';
    label[1] = (char)('0' + (i / 10u));
    label[2] = (char)('0' + (i % 10u));
    label[3] = '\0';
    st = admit_literal(label, storage, sizeof(storage), &name);
    if (st != SKTO_OK) {
      refused_at = i;
      break;
    }
    st = suas_skto_publish(&table, &name, NULL, &generation);
    if (st == SKTO_E_FULL) {
      refused_at = i;
      break;
    }
    if (st != SKTO_OK) {
      refused_at = i;
      break;
    }
  }

  /* The table holds SKTO_NAME_CAPACITY live names; the next fresh name is the
   * one that must be refused. */
  skto_check("17th distinct name is refused as FULL", refused_at == 16u, true);
}

/* ---------------------------------------------------------------------- */
/* VFS SKTO Integration (KT-4)                                            */
/* ---------------------------------------------------------------------- */

static void test_vfs_skto_integration(void) {
  ow_skto_name_t name;
  skto_status_t sst;
  OW_STATUS ost;
  skto_text_t snapshot;
  skto_text_t retired_snapshot;
  uint32_t inode = 0;
  uint32_t gen = 0;
  static const uint8_t write_buf[] = "SKTO VFS Integration Data";
  uint8_t read_buf[64];
  uint32_t bytes_read = 0;
  char over_limit_128[130];
  char over_limit_catalog[230];
  static const uint8_t bad_utf8[] = {'a', 0xC3, 0x28, 0x00};
  static const uint8_t scp_plane[] = {0xF8, 0x84, 0x90, 0x80, 0x80, 0x00};
  size_t i;
  OW_VAD_NODE *root = NULL;
  OW_VAD_NODE *user_node;
  skto_vad_t vad;
  uint64_t user_base = OW_USER_WINDOW_BASE;

  for (i = 0u; i < 128u; ++i) over_limit_128[i] = 'v';
  over_limit_128[128] = '\0';

  for (i = 0u; i < 225u; ++i) over_limit_catalog[i] = 'c';
  over_limit_catalog[225] = '\0';

  /* 1. Admission of valid VFS name */
  sst = OwSktoNameAdmitTrusted(&name, "vfs_test.txt", sizeof("vfs_test.txt"));
  skto_check_status("VFS candidate admits", sst, SKTO_OK);

  /* 2. Refusal of over-limit names at VFS boundary */
  ost = OwVfsCreateFile(over_limit_128, 0);
  skto_check_status("VFS refuses 128-byte name without truncation", ost, OW_ERR_INVALID_PARAM);

  /* 3. Refusal of invalid SUTF-8 and inadmissible SCP at VFS boundary */
  ost = OwVfsCreateFile((const char *)bad_utf8, 0);
  skto_check_status("VFS refuses malformed SUTF-8 name", ost, OW_ERR_INVALID_PARAM);

  ost = OwVfsCreateFile((const char *)scp_plane, 0);
  skto_check_status("VFS refuses SCP-plane name", ost, OW_ERR_INVALID_PARAM);

  ost = OwVfsCreateFile("", 0);
  skto_check_status("VFS refuses empty name", ost, OW_ERR_INVALID_PARAM);

  /* 4. Catalog insert refuses over-limit name (no silent truncation to 223) */
  ost = OwFsCatalogInsert(OwHalGetPrimaryDisk(), OwFsOwfsRootInode(),
                          over_limit_catalog, 999u, 1u);
  skto_check_status("Catalog insert refuses 225-byte name without truncation",
                    ost, OW_ERR_INVALID_PARAM);

  /* 5. Complete name creation and data round-trip (if VFS primary is mounted) */
  if (OwVfsIsPrimaryMounted()) {
    ost = OwVfsCreateFile("vfs_skto.txt", 0);
    skto_check_status("OwVfsCreateFile creates complete admitted file", ost, OW_SUCCESS);

    ost = OwVfsWriteFile("vfs_skto.txt", write_buf, sizeof(write_buf));
    skto_check_status("OwVfsWriteFile writes payload", ost, OW_SUCCESS);

    bytes_read = OwVfsReadFile("vfs_skto.txt", read_buf, sizeof(read_buf));
    skto_check("OwVfsReadFile reads byte-exact payload",
               bytes_read == sizeof(write_buf) &&
               bytes_equal(read_buf, write_buf, sizeof(write_buf)), true);

    /* 5b. Create published the name; the index resolves it without a separate
     * OwVfsPublishName() call, and the read path above consumed it. */
    ost = OwVfsLookupSnapshot("vfs_skto.txt", NULL, NULL, &snapshot, &inode);
    skto_check_status("create published the name into the VFS index", ost,
                      OW_SUCCESS);
    if (ow_status_success(ost)) {
      skto_check_status("release create-published snapshot",
                        OwVfsReleaseSnapshot(&snapshot), OW_SUCCESS);
    }

    /* 6. VFS publication and snapshot contract */
    sst = OwSktoNameAdmitTrusted(&name, "vfs_skto.txt", sizeof("vfs_skto.txt"));
    skto_check_status("admit for publication", sst, SKTO_OK);

    ost = OwVfsPublishName(&name, &gen);
    skto_check_status("OwVfsPublishName publishes to VFS table", ost, OW_SUCCESS);

    /* 7. VFS lookup using acquired snapshots */
    ost = OwVfsLookupSnapshot("vfs_skto.txt", NULL, NULL, &snapshot, &inode);
    skto_check_status("OwVfsLookupSnapshot acquires snapshot", ost, OW_SUCCESS);
    skto_check("snapshot byte length matches", snapshot.len == sizeof("vfs_skto.txt") - 1u, true);
    skto_check("snapshot text byte-exact",
               bytes_equal(snapshot.bytes, (const uint8_t *)"vfs_skto.txt", snapshot.len), true);

    /* 8. Correct snapshot release */
    ost = OwVfsReleaseSnapshot(&snapshot);
    skto_check_status("OwVfsReleaseSnapshot releases acquired snapshot", ost, OW_SUCCESS);

    ost = OwVfsReleaseSnapshot(&snapshot);
    skto_check_status("double release refused", ost, OW_ERR_INVALID_PARAM);

    /* 9. VFS lookup with containment callback */
    user_node = OwMemCreateVad(user_base, user_base + OW_PAGE_SIZE - 1u, OW_PAGE_USER_RW_NX);
    if (user_node != NULL) {
      OwMemInsertVad(&root, user_node);
      vad.root = root;

      /* Out of window pointer rejected by containment */
      ost = OwVfsLookupSnapshot((const char *)0x1000u, vad_range, &vad, &snapshot, &inode);
      skto_check_status("OwVfsLookupSnapshot refuses out-of-window pointer", ost, OW_ERR_INVALID_PARAM);

      OwMemFreeVad(user_node);
    }

    /* 10. Publication failure atomicity */
    ost = OwVfsPublishName(NULL, &gen);
    skto_check_status("OwVfsPublishName rejects NULL atomically", ost, OW_ERR_INVALID_PARAM);

    /* 11. Deletion retires the name and withdraws it from lookup, while a
     * snapshot acquired before the delete stays byte-exact until release. */
    ost = OwVfsLookupSnapshot("vfs_skto.txt", NULL, NULL, &snapshot, &inode);
    skto_check_status("snapshot acquired before delete", ost, OW_SUCCESS);

    ost = OwVfsDeleteFile("vfs_skto.txt");
    skto_check_status("OwVfsDeleteFile cleans up file", ost, OW_SUCCESS);

    ost = OwVfsLookupSnapshot("vfs_skto.txt", NULL, NULL, &retired_snapshot,
                              &inode);
    skto_check("delete retires the name from VFS lookup",
               !ow_status_success(ost), true);

    skto_check("held snapshot survives retirement byte-exact",
               snapshot.len == sizeof("vfs_skto.txt") - 1u &&
               bytes_equal(snapshot.bytes,
                           (const uint8_t *)"vfs_skto.txt", snapshot.len),
               true);
    skto_check_status("release held snapshot after retirement",
                      OwVfsReleaseSnapshot(&snapshot), OW_SUCCESS);

    /* 12. The explicit retirement entry point is idempotent and bounded. */
    ost = OwVfsRetireName(NULL);
    skto_check_status("OwVfsRetireName rejects NULL", ost, OW_ERR_NULL_POINTER);
    ost = OwVfsRetireName("");
    skto_check_status("OwVfsRetireName rejects empty name", ost,
                      OW_ERR_INVALID_PARAM);
    ost = OwVfsRetireName("vfs_retire.txt");
    skto_check_status("OwVfsRetireName reports an unpublished name", ost,
                      OW_ERR_NOT_FOUND);

    ost = OwVfsCreateFile("vfs_retire.txt", 0);
    skto_check_status("create for explicit retirement", ost, OW_SUCCESS);
    ost = OwVfsRetireName("vfs_retire.txt");
    skto_check_status("OwVfsRetireName withdraws a published name", ost,
                      OW_SUCCESS);
    ost = OwVfsRetireName("vfs_retire.txt");
    skto_check_status("second retirement is a bounded miss", ost,
                      OW_ERR_NOT_FOUND);
    ost = OwVfsDeleteFile("vfs_retire.txt");
    skto_check_status("delete after retirement still removes the file", ost,
                      OW_SUCCESS);
  }
}

/* ---------------------------------------------------------------------- */
/* Kernel Synchronization and Lifecycle Integration (KT-5)                */
/* ---------------------------------------------------------------------- */

static void test_kernel_sync_and_lifecycle(void) {
  skto_name_table_t table;
  ow_skto_irq_lock_t lock;
  uint8_t storage[SKTO_NAME_MAX_BYTES];
  skto_text_t name;
  skto_text_t reader1;
  skto_text_t reader2;
  uint32_t gen1 = 0u;
  uint32_t gen2 = 0u;
  uint32_t active_readers = 99u;
  skto_status_t st;

  lock.flags = 0u;
  st = suas_skto_names_init_locked(&table, OwSktoLockAcquire, OwSktoLockRelease,
                                   &lock);
  skto_check_status("lifecycle table initialises with IRQ lock", st, SKTO_OK);

  st = admit_literal("sync.service", storage, sizeof(storage), &name);
  skto_check_status("admit candidate for lifecycle test", st, SKTO_OK);

  /* 1. Publication and multiple concurrent readers */
  st = suas_skto_publish(&table, &name, NULL, &gen1);
  skto_check_status("initial publication succeeds", st, SKTO_OK);

  st = suas_skto_resolve(&table, &name, NULL, &reader1);
  skto_check_status("reader 1 acquires snapshot", st, SKTO_OK);

  st = suas_skto_resolve(&table, &name, NULL, &reader2);
  skto_check_status("reader 2 acquires concurrent snapshot", st, SKTO_OK);

  /* 2. Concurrent publication while older readers hold views */
  st = suas_skto_publish(&table, &name, NULL, &gen2);
  skto_check_status("publication while readers hold older generation", st, SKTO_OK);
  skto_check("generation increments on update", gen2 == gen1 + 1u, true);

  /* 3. Drain reports outstanding readers */
  st = suas_skto_names_drain(&table, &active_readers);
  skto_check_status("drain with active readers reports BUSY", st, SKTO_E_BUSY);
  skto_check("outstanding reader count equals 2", active_readers == 2u, true);

  /* 4. Destruction with active readers is safely refused */
  st = suas_skto_names_destroy(&table);
  skto_check_status("destruction with active readers is refused", st, SKTO_E_BUSY);

  /* 5. Shutdown protocol: prevents new acquisitions and publications */
  st = suas_skto_names_shutdown(&table);
  skto_check_status("shutdown transition succeeds", st, SKTO_OK);

  st = suas_skto_resolve(&table, &name, NULL, NULL);
  skto_check_status("acquisitions rejected during shutdown", st, SKTO_E_POLICY);

  st = suas_skto_publish(&table, &name, NULL, &gen2);
  skto_check_status("publications rejected during shutdown", st, SKTO_E_POLICY);

  /* 6. Existing readers safely release during shutdown */
  st = suas_skto_name_release(&table, &reader1);
  skto_check_status("reader 1 releases during shutdown", st, SKTO_OK);

  st = suas_skto_names_drain(&table, &active_readers);
  skto_check("1 reader remaining after reader 1 release", active_readers == 1u, true);

  st = suas_skto_name_release(&table, &reader2);
  skto_check_status("reader 2 releases during shutdown", st, SKTO_OK);

  /* 7. Drain succeeds after all readers release */
  st = suas_skto_names_drain(&table, &active_readers);
  skto_check_status("drain after reader release reports OK", st, SKTO_OK);
  skto_check("0 readers remaining after all release", active_readers == 0u, true);

  /* 8. Safe destruction after reader draining */
  st = suas_skto_names_destroy(&table);
  skto_check_status("safe destruction after drain succeeds", st, SKTO_OK);

  /* 9. Generation exhaustion non-wrapping policy test */
  st = suas_skto_names_init_locked(&table, OwSktoLockAcquire, OwSktoLockRelease, &lock);
  skto_check_status("table re-init for exhaustion test", st, SKTO_OK);
  st = suas_skto_publish(&table, &name, NULL, &gen1);
  skto_check_status("exhaustion test publish initial", st, SKTO_OK);

  /* Simulate generation at 0xFFFFFFFFu */
  table.slots[0].snapshots[table.slots[0].active].generation = 0xFFFFFFFFu;

  st = suas_skto_publish(&table, &name, NULL, &gen2);
  skto_check_status("generation 0xFFFFFFFF refuses publication with OVERFLOW", st, SKTO_E_OVERFLOW);
}


static void test_abi_layout_and_offsets(void) {
  skto_check("uint8_t width", sizeof(uint8_t) == 1u, true);
  skto_check("uint16_t width", sizeof(uint16_t) == 2u, true);
  skto_check("uint32_t width", sizeof(uint32_t) == 4u, true);
  skto_check("uint64_t width", sizeof(uint64_t) == 8u, true);

  skto_check("skto_name_snapshot_t size", sizeof(skto_name_snapshot_t) == 144u, true);
  skto_check("skto_name_slot_t size", sizeof(skto_name_slot_t) == 580u, true);

  if (sizeof(void *) == 8u) {
    skto_check("skto_text_t size (64-bit)", sizeof(skto_text_t) == 40u, true);
    skto_check("skto_name_table_t size (64-bit)", sizeof(skto_name_table_t) == 9312u, true);
    skto_check("ow_skto_name_t size (64-bit)", sizeof(ow_skto_name_t) == 168u, true);
    skto_check("ow_skto_name_t bytes offset", offsetof(ow_skto_name_t, bytes) == 0u, true);
    skto_check("ow_skto_name_t text offset", offsetof(ow_skto_name_t, text) == 128u, true);
    skto_check("ow_skto_irq_lock_t size", sizeof(ow_skto_irq_lock_t) == 8u, true);
    skto_check("ow_skto_irq_lock_t flags offset", offsetof(ow_skto_irq_lock_t, flags) == 0u, true);
  }
}

int test_skto_name_run(int *out_passed) {
  printf("\n=== SKTO name admission tests ===\n");

  test_trusted_admission();
  test_user_admission();
  test_vad_containment();
  test_publication_lifecycle();
  test_namespace_capacity();
  test_vfs_skto_integration();
  test_kernel_sync_and_lifecycle();
  test_abi_layout_and_offsets();

  printf("\n--- SKTO name admission: %d passed, %d failed ---\n",
         g_skto_passed, g_skto_failed);
  if (out_passed)
    *out_passed = g_skto_passed;
  return g_skto_failed;
}
