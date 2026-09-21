/* ow_dpc.h - NT-like DPC (Deferred Procedure Call) queue
 *
 * Non-POSIX counterpart of the Linux softirq / tasklet / workqueue ladder:
 * a single-FIFO, single-CPU deferred-work queue drained each PIT tick
 * (OwDpcProcessPending, hooked into OwPsSchedulerTick).  DPC objects are
 * caller-allocated (embed a OW_DPC in whatever needs deferred work, like
 * Windows KDPC embedded in a device object).
 *
 * DPC routines run on the tick (ISR) context: they must NOT block.  They
 * may signal dispatcher objects (KeSetEvent / KeReleaseSemaphore / wake a
 * thread) to hand work off to a normal kernel thread.  Re-inserting a DPC
 * from within its own routine is allowed and defers the next run.
 *
 * C99 freestanding.  No dynamic allocation.  */
#ifndef OW_DPC_H
#define OW_DPC_H

#include <stdint.h>

struct _OW_DPC;

/* Routine signature: OwDpcProcessPending calls Routine(dpc, context). */
typedef void (*OW_DPC_ROUTINE)(struct _OW_DPC *Dpc, void *Context);

typedef struct _OW_DPC {
  OW_DPC_ROUTINE Routine;  /* deferred routine (non-blocking)   */
  void *Context;           /* caller context                     */
  struct _OW_DPC *NextDpc; /* FIFO linkage                       */
  uint8_t Inserted;        /* 1 = currently queued               */
} OW_DPC;

/* Initialise a caller-provided DPC object (Idle-like, non-queued). */
void KeInitializeDpc(OW_DPC *Dpc, OW_DPC_ROUTINE Routine, void *Context);

/* Append to the DPC queue (idempotent: re-insert while queued is a no-op).
 * Safe to call from ISR context. */
void KeInsertQueueDpc(OW_DPC *Dpc);

/* Dequeue a previously inserted DPC (no-op if not queued). */
void KeCancelDpc(OW_DPC *Dpc);

/* Drain the whole queue.  Called from OwPsSchedulerTick after timer/timeout
 * processing; also usable standalone (host selftest). */
void OwDpcProcessPending(void);

/* Boot-time self-test: schedule a DPC and drain it synchronously. */
void OwDpcSelfTest(void);

#endif /* OW_DPC_H */