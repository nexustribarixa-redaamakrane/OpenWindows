/* ow_userspace.h - OpenWindows userspace boot policy
 *
 * The kernel resolves ONE user-mode init at boot, and there are exactly three
 * answers.  Making the alternatives explicit is the whole point of this header:
 * the previous code asked only "is owinit.owx present?", so a volume carrying a
 * corrupt owinit was indistinguishable from one carrying none, and the only
 * remaining behaviour was a halt.
 *
 *   1. PRIMARY   owinit.owx exists AND its OWX1 header is loadable.
 *                Load and enter it as the primary user-mode init (PID 1).
 *                owinitv and owrs are NOT started: this is a healthy boot, and
 *                a rescue shell on a healthy system is a second init nobody
 *                asked for.
 *
 *   2. EMERGENCY owinit.owx is missing or invalid, and the emergency userspace
 *                is available.  owinitv.owx becomes the volatile user-mode init
 *                (PID 1); it brings up the minimum userspace and spawns
 *                owrs.owx as the rescue shell.
 *
 *   3. ABSENT    owinit.owx is missing or invalid AND the emergency userspace
 *                is unavailable.  There is no user-mode init to run and no
 *                rescue path, so this is an unrecoverable boot failure and the
 *                kernel panics.
 *
 * "Invalid" is not a euphemism for "absent".  An image counts as available only
 * when the loader would actually accept it AND its CRC32c checksums verify
 * (OwOwxImageIsUsable): the OWX1 header gate plus the whole-image integrity
 * check the packer stamped into the bytes.  A truncated, garbage-filled or
 * bit-rotted owinit.owx therefore lands the boot in state 2 rather than
 * panicking on a volume that still holds a rescue shell.
 *
 * One asymmetry in state 2 is deliberate and is the only reading under which the
 * state is executable at all: owinitv.owx is REQUIRED and owrs.owx is optional.
 * The kernel enters an init; owinitv.owx is the init.  owrs.owx is a rescue
 * shell, which has no init duties, so a volume carrying only owrs.owx has bytes
 * to rescue with but no process to enter them from -- entering owrs directly
 * would produce a console with nobody to start anything, which is a third
 * behaviour nobody specified.  So a lone owrs.owx is state 3, and the panic says
 * so explicitly (see OwUserSpaceEmergencyBytes) because "there is a rescue shell
 * on this volume and no init to reach it with" is the single most actionable
 * fact in that failure.
 *
 * C99 freestanding, no dynamic allocation. */
#ifndef OW_USERSPACE_H
#define OW_USERSPACE_H

#include "ow_types.h"
#include <stdbool.h>
#include <stdint.h>

/* Survey of the three user-mode images on the primary OWFS volume.
 *
 * Presence and validity are recorded separately and are NOT interchangeable:
 * "no owinit.owx at all" and "a owinit.owx that is not loadable" are different
 * faults with the same state transition but different diagnostics, and a boot
 * log that collapses them sends whoever reads it looking in the wrong place. */
typedef struct _OW_USERSPACE_PROBE {
    bool     PrimaryPresent;    /* owinit.owx  has a root-catalog entry      */
    bool     PrimaryValid;      /* ... and passes the OWX1 load gate          */
    OW_STATUS PrimaryStatus;    /* why not: OW_SUCCESS, OW_ERR_CORRUPT, ...   */
    bool     EmergencyPresent;  /* owinitv.owx has a root-catalog entry      */
    bool     EmergencyValid;
    OW_STATUS EmergencyStatus;
    bool     RescuePresent;     /* owrs.owx    has a root-catalog entry      */
    bool     RescueValid;
    OW_STATUS RescueStatus;
} OW_USERSPACE_PROBE;

typedef enum _OW_USERSPACE_STATE {
    OW_USERSPACE_PRIMARY   = 0,   /* state 1: normal boot, owinit is PID 1    */
    OW_USERSPACE_EMERGENCY = 1,   /* state 2: owinitv is PID 1, spawns owrs   */
    OW_USERSPACE_ABSENT    = 2    /* state 3: unrecoverable, kernel panics     */
} OW_USERSPACE_STATE;

/* True when the kernel can ENTER an emergency userspace, i.e. owinitv.owx is
 * present and usable.  This is the predicate state 2 is built on, and it is
 * the only one that can be true for a boot to actually continue: owinitv is the
 * process the kernel jumps to, so an emergency init that cannot be entered is
 * not an emergency init.
 *
 * owrs.owx does not appear in this expression on purpose -- see the note on the
 * lone-owrs case at the top of this header. */
static inline bool OwUserSpaceEmergencyAvailable(
    const OW_USERSPACE_PROBE* probe) {
    return probe && probe->EmergencyValid;
}

/* True when ANY emergency bytes are on the volume, usable or not.  Diagnostics
 * only; never a transition input.  Its purpose is to let the state-3 panic
 * distinguish "this volume has no emergency userspace at all" from "this volume
 * has a rescue shell but no init that could reach it", which are the same state
 * and completely different faults. */
static inline bool OwUserSpaceEmergencyBytes(const OW_USERSPACE_PROBE* probe) {
    return probe && (probe->EmergencyPresent || probe->RescuePresent);
}

/* OwBootClassifyUserspace: the boot policy, as a pure function of the probe.
 *
 * Split out from _start() and kept free of I/O so that all three states are
 * reachable from a test with a synthetic probe.  The panic in state 3 is a
 * consequence of this function's answer, not part of it: a classifier that
 * halted the machine could not be asked what it would have decided. */
OW_USERSPACE_STATE OwBootClassifyUserspace(const OW_USERSPACE_PROBE* probe);

/* Stable, log-facing name of a state ("PRIMARY" / "EMERGENCY" / "ABSENT"). */
const char* OwBootUserspaceStateName(OW_USERSPACE_STATE state);

#endif /* OW_USERSPACE_H */
