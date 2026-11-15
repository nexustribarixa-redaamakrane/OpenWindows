/* kdb_history.c - bounded lifecycle/execution event log.
 *
 * Every state transition that matters to an operator is recorded as a fact:
 * load, start, first dispatch, stop, fault, execution handoff and destruction.
 * The log is a ring so a long-running instance cannot starve the table, and it
 * stores identifiers only -- never pointers into PS objects.
 */
#include "kdb_internal.h"

static OW_KDB_HISTORY_EVENT g_History[OW_KDB_MAX_HISTORY];
static uint32_t             g_Count = 0U;
static uint32_t             g_Head = 0U;

void OwKdbHistoryReset(void) {
    uint32_t i;

    for (i = 0U; i < OW_KDB_MAX_HISTORY; ++i) {
        g_History[i].Event = OW_KDB_EVENT_LOADED;
        g_History[i].Status = OW_SUCCESS;
        g_History[i].InstanceId = OW_KDB_INVALID_ID;
        g_History[i].ProcessId = 0U;
        g_History[i].ThreadId = 0U;
        g_History[i].EntryPoint = 0U;
    }
    g_Count = 0U;
    g_Head = 0U;
}

void OwKdbHistoryRecord(OW_KDB_INSTANCE_EVENT Event, uint32_t InstanceId,
                        OW_STATUS Status, uint32_t ProcessId,
                        uint32_t ThreadId, uint64_t EntryPoint) {
    OW_KDB_HISTORY_EVENT* slot;

    if (g_Count < OW_KDB_MAX_HISTORY) {
        slot = &g_History[(g_Head + g_Count) % OW_KDB_MAX_HISTORY];
        ++g_Count;
    } else {
        slot = &g_History[g_Head];
        g_Head = (g_Head + 1U) % OW_KDB_MAX_HISTORY;
    }

    slot->Event = Event;
    slot->Status = Status;
    slot->InstanceId = InstanceId;
    slot->ProcessId = ProcessId;
    slot->ThreadId = ThreadId;
    slot->EntryPoint = EntryPoint;
}

uint32_t OwKdbHistoryCount(void) {
    return g_Count;
}

OW_STATUS OwKdbGetHistoryEvent(uint32_t Index,
                               OW_KDB_HISTORY_EVENT* OutEvent) {
    if (OutEvent == (OW_KDB_HISTORY_EVENT*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (Index >= g_Count) {
        return OW_ERR_NOT_FOUND;
    }
    *OutEvent = g_History[(g_Head + Index) % OW_KDB_MAX_HISTORY];
    return OW_SUCCESS;
}

uint32_t OwKdbHistoryCountForInstance(uint32_t InstanceId) {
    uint32_t i;
    uint32_t count = 0U;

    if (InstanceId == OW_KDB_INVALID_ID) {
        return 0U;
    }
    for (i = 0U; i < g_Count; ++i) {
        const OW_KDB_HISTORY_EVENT* event =
            &g_History[(g_Head + i) % OW_KDB_MAX_HISTORY];
        if (event->InstanceId == InstanceId) {
            ++count;
        }
    }
    return count;
}

OW_STATUS OwKdbGetHistoryEventForInstance(uint32_t InstanceId, uint32_t Index,
                                          OW_KDB_HISTORY_EVENT* OutEvent) {
    uint32_t i;
    uint32_t seen = 0U;

    if (OutEvent == (OW_KDB_HISTORY_EVENT*)0) {
        return OW_ERR_NULL_POINTER;
    }
    if (InstanceId == OW_KDB_INVALID_ID) {
        return OW_ERR_INVALID_PARAM;
    }
    for (i = 0U; i < g_Count; ++i) {
        const OW_KDB_HISTORY_EVENT* event =
            &g_History[(g_Head + i) % OW_KDB_MAX_HISTORY];
        if (event->InstanceId != InstanceId) {
            continue;
        }
        if (seen == Index) {
            *OutEvent = *event;
            return OW_SUCCESS;
        }
        ++seen;
    }
    return OW_ERR_NOT_FOUND;
}

void OwKdbClearHistory(void) {
    OwKdbHistoryReset();
}

const char* OwKdbInstanceEventName(OW_KDB_INSTANCE_EVENT Event) {
    switch (Event) {
    case OW_KDB_EVENT_LOADED:    return "loaded";
    case OW_KDB_EVENT_STARTED:   return "started";
    case OW_KDB_EVENT_RUNNING:   return "running";
    case OW_KDB_EVENT_STOPPED:   return "stopped";
    case OW_KDB_EVENT_FAULTED:   return "faulted";
    case OW_KDB_EVENT_EXECUTED:  return "executed";
    case OW_KDB_EVENT_DESTROYED: return "destroyed";
    default:                     return "unknown";
    }
}
