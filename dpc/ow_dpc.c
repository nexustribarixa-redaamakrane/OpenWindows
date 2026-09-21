/* dpc/ow_dpc.c - NT-like DPC (Deferred Procedure Call) queue
 *
 * Non-POSIX counterpart of the Linux softirq / tasklet / workqueue ladder.
 * Single FIFO queue drained each PIT tick from OwPsSchedulerTick.  DPC
 * routines run on ISR context and must not block; they may signal
 * dispatcher objects to hand work off to normal threads.
 *
 * Single-CPU, ring-0 only: no lock needed.  C99 freestanding.  */
#include "../inc/ow_dpc.h"
#include "../inc/ow_kprintf.h"

static OW_DPC* s_DpcHead;   /* FIFO head (next to run) */
static OW_DPC* s_DpcTail;   /* FIFO tail (last appended) */

/* ====================================================================== */

void KeInitializeDpc(OW_DPC* Dpc, OW_DPC_ROUTINE Routine, void* Context) {
    if (!Dpc) return;
    Dpc->Routine = Routine;
    Dpc->Context = Context;
    Dpc->NextDpc = (OW_DPC*)0;
    Dpc->Inserted = 0;
}

void KeInsertQueueDpc(OW_DPC* Dpc) {
    if (!Dpc || Dpc->Inserted) return;      /* idempotent */
    Dpc->Inserted = 1;
    Dpc->NextDpc = (OW_DPC*)0;
    if (!s_DpcTail) {
        s_DpcHead = Dpc;
        s_DpcTail = Dpc;
    } else {
        s_DpcTail->NextDpc = Dpc;
        s_DpcTail = Dpc;
    }
}

void KeCancelDpc(OW_DPC* Dpc) {
    OW_DPC** pp;
    OW_DPC* p;

    if (!Dpc) return;
    pp = &s_DpcHead;
    while (*pp) {
        if (*pp == Dpc) {
            *pp = Dpc->NextDpc;
            if (s_DpcTail == Dpc) {
                /* Find the new tail. */
                s_DpcTail = (OW_DPC*)0;
                for (p = s_DpcHead; p; p = p->NextDpc) s_DpcTail = p;
            }
            Dpc->NextDpc = (OW_DPC*)0;
            Dpc->Inserted = 0;
            return;
        }
        pp = &(*pp)->NextDpc;
    }
}

void OwDpcProcessPending(void) {
    OW_DPC* d;

    while (s_DpcHead) {
        d = s_DpcHead;
        s_DpcHead = d->NextDpc;
        if (!s_DpcHead) s_DpcTail = (OW_DPC*)0;
        d->Inserted = 0;
        d->NextDpc = (OW_DPC*)0;
        if (d->Routine) d->Routine(d, d->Context);
    }
}

/* ====================================================================== */
/* Boot-time self-test                                                     */
/* ====================================================================== */

static void st_dpc_routine(OW_DPC* Dpc, void* Context) {
    uint32_t* counter = (uint32_t*)Context;
    (void)Dpc;
    if (counter) (*counter)++;
}

void OwDpcSelfTest(void) {
    static OW_DPC st_dpc;
    uint32_t ran = 0;

    KeInitializeDpc(&st_dpc, st_dpc_routine, &ran);
    KeInsertQueueDpc(&st_dpc);
    KeInsertQueueDpc(&st_dpc);           /* duplicate: must be a no-op */
    OwDpcProcessPending();               /* drain synchronously */
    if (ran != 1) {
        ow_kprintf("[SELFTEST DPC] FAIL: ran=%u\r\n", (unsigned)ran);
        return;
    }
    KeCancelDpc(&st_dpc);                /* not queued: harmless */
    ow_kprintf("[SELFTEST DPC] OK (insert/cancel/drain)\r\n");
}