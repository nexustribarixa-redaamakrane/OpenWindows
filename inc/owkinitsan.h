/* owkinitsan.h - OWKInitSan: initialization-order and initialization-state
 * validation (Phase 4)
 *
 * Tracks kernel subsystem initialization: which subsystem began, whether it
 * completed, whether it was initialized twice, and whether code accessed it
 * out of order.  The tracker is always on (static state, ~48 slots); reports
 * flow through the OWKSan core (module "OWKInitSan") subject to the master
 * switch.
 *
 * IMPLEMENTED (all validated with host-side negative tests):
 *   - duplicate initialization detection (phase begun twice),
 *   - re-entrant initialization detection (phase begun while RUNNING),
 *   - initialization ordering violation detection (a phase begun with an Order
 *     lower than a previously seen order),
 *   - end-without-begin and end-of-uninitialized-phase detection,
 *   - initialization-state queries (IsInitialized / PhaseFailed / count),
 *   - boot-phase wiring: every phase in core/main.c::boot_begin /
 *     boot_diag_done / boot_diag_failed / boot_skip_phase is tracked.
 *
 * NOT IMPLEMENTED:
 *   - access-to-uninitialized-subsystem enforcement inside subsystem code
 *     (no in-tree caller consumes the query yet; the API and its tests exist,
 *     wiring call sites is a separate change),
 *   - data-level initialization tracking (this tracks subsystem state, not
 *     whether a particular variable was written),
 *   - dependency graphs beyond the ordering rule above.
 */
#ifndef OW_KINIT_SAN_H
#define OW_KINIT_SAN_H

#include "owksan.h"

#define OW_KINIT_MAX_PHASES 48U
#define OW_KINIT_NAME_MAX   32U

/* Phase states. */
#define OW_KINIT_NOT_STARTED 0U
#define OW_KINIT_RUNNING     1U
#define OW_KINIT_DONE        2U
#define OW_KINIT_FAILED      3U
#define OW_KINIT_SKIPPED     4U

OW_STATUS OwKInitSanRegister(void);

/* Begin a subsystem phase.  Order is the caller's phase sequence; any Order
 * lower than the highest Order seen so far is an ordering violation. */
OW_STATUS OwKInitSanPhaseBegin(const char* Name, uint32_t Order);

/* Mark a phase as skipped (not armed at the active runlevel). */
OW_STATUS OwKInitSanPhaseSkip(const char* Name);

/* End a subsystem phase.  Result OW_SUCCESS marks DONE; anything else marks
 * FAILED.  An end for a phase that was never begun is an error.  An end for
 * a phase already marked SKIPPED is accepted and leaves the SKIPPED state. */
OW_STATUS OwKInitSanPhaseEnd(const char* Name, OW_STATUS Result);

bool     OwKInitSanIsInitialized(const char* Name);
bool     OwKInitSanPhaseFailed(const char* Name);
uint32_t OwKInitSanPhaseCount(void);
void     OwKInitSanReset(void);

/* Require a prerequisite to be initialized before proceeding; reports the
 * violation through the core if not. */
OW_STATUS OwKInitSanRequireInitialized(const char* Prerequisite,
                                       const char* Phase);

#endif /* OW_KINIT_SAN_H */
