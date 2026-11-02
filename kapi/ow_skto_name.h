/* ow_skto_name.h - SKTO name admission for the OpenWindows kernel
 *
 * This is the kernel-side boundary between an untrusted name and the kernel's
 * own text handling. It admits a candidate into caller storage through
 * SUAS-018 (SKTO), so every name the kernel acts on is bounded, explicitly
 * measured, SUTF validated, and complete. It never truncates: a name that
 * does not fit fails with a status the caller must propagate.
 *
 * Two entry points:
 *
 *   OwSktoNameAdmitUser()    takes a pointer that may belong to a CPL3
 *                            process. The caller MUST supply a containment
 *                            callback; the adapter validates each page before
 *                            it reads a byte from that page, then asks SKTO to
 *                            validate the exact candidate.
 *
 *   OwSktoNameAdmitTrusted() takes a kernel-owned pointer. Containment is not
 *                            required because the kernel already owns the
 *                            bytes, but the bound and the encoding rules still
 *                            apply.
 *
 * Both write into the caller's ow_skto_name_t and retain no pointer to the
 * source. No allocation is performed. A failed call leaves the output marked
 * unusable (text.bytes == NULL); a successful call returns a NUL-terminated
 * byte string in the same object for the existing OWFS/USFS interfaces, which
 * still take `const char *`.
 *
 * Namespace ceiling: the adapter storage bound is SKTO_NAME_MAX_BYTES (128)
 * including its terminator, which matches the OWFS/USFS baseline
 * OWFS_NAME_MAX_BYTES. It therefore accepts at most 127 content bytes and
 * refuses a longer name instead of storing a prefix. That is an implementation
 * storage bound under SUAS-018 N5, not a new namespace rule. The historical
 * OW_FS_CATALOG_ENTRY.Name field is larger (224 bytes); the adapter does not
 * raise its ceiling to that legacy field width.
 *
 * Synchronization: the table lock helpers below are the kernel's real
 * single-CPU interrupt-save critical section, not a spinlock and not a
 * lock-free protocol. They are provided for callers that host a
 * skto_name_table_t in the kernel; the adapter's admission functions take no
 * lock and need none.
 */

#ifndef OW_SKTO_NAME_H
#define OW_SKTO_NAME_H

#include <stddef.h>
#include <stdint.h>

#include "../../superunicode/include/suas/suas_skto.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Storage for one complete OWFS/USFS name field, including the NUL. */
#define OW_SKTO_NAME_STORAGE_BYTES ((size_t)SKTO_NAME_MAX_BYTES)

/* Longest content the adapter will publish. */
#define OW_SKTO_NAME_MAX_BYTES ((size_t)SKTO_NAME_MAX_BYTES - 1u)

/* Caller-owned admitted name. `bytes` is a NUL-terminated C string on success;
 * `text` is the same span as an ADMITTED, NUL_SAFE SKTO object. */
typedef struct _OW_SKTO_NAME {
    uint8_t     bytes[OW_SKTO_NAME_STORAGE_BYTES];
    skto_text_t text;
} ow_skto_name_t;

/* Caller-owned flag word for one SKTO table lock. Not reentrant: a single
 * acquire/release pair is the only supported use, which matches the SKTO
 * table lock contract. */
typedef struct _OW_SKTO_IRQ_LOCK {
    uint64_t flags;
} ow_skto_irq_lock_t;

/* Admit a name from a source that may be untrusted.
 *
 * ScanCap bounds the NUL search and therefore the longest accepted name
 * (content bytes = ScanCap - 1). The dispatcher passes OW_USERSPACE_NAME_MAX,
 * the documented Ring 3 ceiling. Range/RangeCtx are required; a NULL Range is
 * refused with SKTO_E_NULL rather than trusted by accident.
 *
 * Returns SKTO_OK, or an explicit SKTO_E_* failure:
 *   SKTO_E_NULL        absent output, source, or containment callback
 *   SKTO_E_RANGE       the containment callback refused a touched page
 *   SKTO_E_TERMINATOR  no NUL inside ScanCap
 *   SKTO_E_ENCODING    malformed SUTF
 *   SKTO_E_INADMISSIBLE SCP, surrogate, trap, or Sentinel
 *   SKTO_E_OVERFLOW    candidate exceeds the admission ceiling
 *   SKTO_E_CAPACITY    destination cannot hold the complete candidate
 *   SKTO_E_POLICY      empty name, interior NUL, or over the namespace ceiling
 */
skto_status_t OwSktoNameAdmitUser(ow_skto_name_t *Out, const char *Src,
                                  size_t ScanCap, skto_range_fn Range,
                                  void *RangeCtx);

/* Admit a name from kernel-owned memory. Range containment is skipped; the
 * bound, SUTF validation, and namespace ceiling are identical. */
skto_status_t OwSktoNameAdmitTrusted(ow_skto_name_t *Out, const char *Src,
                                     size_t ScanCap);

/* The admitted name as a NUL-terminated string, or NULL when the object does
 * not hold a successful admission. */
const char   *OwSktoNameCstr(const ow_skto_name_t *Name);

/* Admitted content length in bytes. */
size_t        OwSktoNameLength(const ow_skto_name_t *Name);

/* SKTO table lock callbacks backed by ow_irq_save()/ow_irq_restore().
 * Ctx must point at an ow_skto_irq_lock_t that outlives the table. */
void OwSktoLockAcquire(void *Ctx);
void OwSktoLockRelease(void *Ctx);

#ifdef __cplusplus
}
#endif

#endif /* OW_SKTO_NAME_H */
