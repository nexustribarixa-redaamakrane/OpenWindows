/* ow_types.h - OpenWindows Core Types */
#ifndef OW_TYPES_H
#define OW_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint32_t OW_STATUS;

#define OW_SUCCESS              0x00000000U
#define OW_ERR_INVALID_PARAM    0x0011AEE0U
#define OW_ERR_NULL_POINTER     0x0011AEE1U
#define OW_ERR_NOT_FOUND        0x0011AEE2U
#define OW_ERR_ALREADY_EXISTS   0x0011AEE3U
#define OW_ERR_INSUFFICIENT     0x0011AEE4U
#define OW_ERR_NOT_INITIALIZED  0x0011AEE9U
/* Well-formed input that this build cannot honour (e.g. an image that needs
 * imports bound, when the loader implements no import table).  Distinct from
 * OW_ERR_INVALID_PARAM so a caller can tell "you asked for something wrong"
 * from "that is a real feature I have not built yet". */
#define OW_ERR_UNSUPPORTED      0x0011AEEAU
#define OW_ERR_IO               0x00000001U
#define OW_ERR_CORRUPT          0x0011A3E0U

/* CIS refusals from the image loader.
 *
 * A distinct status per verdict, not one OW_ERR_CORRUPT for all of them.  The
 * whole point of keeping integrity, authenticity and compliance apart inside
 * cis/cis_verify.c is that "nobody signed this", "the signer is not trusted"
 * and "the signature does not cover these bytes" call for three different
 * responses; collapsing them at the loader boundary would throw that away at
 * exactly the point an operator reads them.
 *
 * 0x0011AFxx, disjoint from every other OW_ERR_* above, so a caller can test
 * for the CIS family by range and still switch on the individual reason.  A
 * caller wanting the full verdict rather than the mapped status reads
 * OwPsLastCisVerdict(). */
#define OW_ERR_CIS_UNSIGNED         0x0011AF01U /* no signature at all        */
#define OW_ERR_CIS_BAD_SIGNATURE    0x0011AF02U /* signature does not verify */
#define OW_ERR_CIS_UNKNOWN_KEY      0x0011AF03U /* no pinned key for this id  */
#define OW_ERR_CIS_KEY_REVOKED      0x0011AF04U /* key was revoked           */
#define OW_ERR_CIS_DIGEST_MISMATCH  0x0011AF05U /* signed a different payload */
#define OW_ERR_CIS_MALFORMED        0x0011AF06U /* OWX metadata is malformed  */
#define OW_ERR_CIS_POLICY           0x0011AF07U /* licence refused by policy  */
#define OW_ERR_CIS_COMPLIANT_REFUSAL 0x0011AF08U/* signer declares non-compliance */
#define OW_ERR_CIS_ERROR            0x0011AF09U /* verification could not run  */
#define OW_ERR_CIS_FAMILY_MASK      0x0000FF00U /* matches every OW_ERR_CIS_*  */
#define OW_ERR_CIS_FAMILY_SHIFT     8u

#define OW_MAX_NAME             256U
#define OW_MAX_PATH             512U

static inline bool ow_status_success(OW_STATUS s) { return s == OW_SUCCESS; }
static inline bool ow_status_error(OW_STATUS s) { return s != OW_SUCCESS; }

#endif /* OW_TYPES_H */
