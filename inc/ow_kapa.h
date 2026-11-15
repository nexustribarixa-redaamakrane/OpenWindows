/* ow_kapa.h - Kernel-Associated Application Architecture (KAPA) facade
 *
 * KDB is the management plane: it owns the registry, ABI table, loader,
 * associations, instance lifecycle and the Service Bridge.  KAPA is the
 * application-facing architecture built on top of it.  This facade exists so an
 * application is one durable object -- name, association, kernel, instance and
 * observable state -- instead of a caller having to remember the correct KDB
 * call order and re-derive state from three separate tables.
 *
 * The facade deliberately does not add a second state machine.  Application
 * state is refreshed from the live KDB instance every time it is observed, so
 * KAPA cannot report RUNNING for an instance KDB says is READY, or keep an
 * instance link after a fault released it.  Execute still goes through
 * OwKdbExecuteInstance(), which never fabricates execution: on a build without
 * a registered executor it returns OW_ERR_UNSUPPORTED and the application stays
 * LOADED.
 *
 * All storage is static and bounded.  The API is single-threaded kernel code,
 * like KDB itself, and takes no locks.
 */
#ifndef OW_KAPA_H
#define OW_KAPA_H

#include "ow_kdb.h"

#define OW_KAPA_MAX_APPLICATIONS 32U
#define OW_KAPA_MAX_NAME         OW_KDB_MAX_NAME

/* Application-visible lifecycle.  These names describe KAPA's view; the
 * underlying authority remains OW_KDB_INSTANCE_STATE. */
typedef enum _OW_KAPA_STATE {
    OW_KAPA_STATE_ASSOCIATED = 1, /* registered, kernel not loaded            */
    OW_KAPA_STATE_LOADED,         /* instance READY, resources charged        */
    OW_KAPA_STATE_RUNNING,        /* instance RUNNING (really dispatched)     */
    OW_KAPA_STATE_STOPPED,        /* instance stopped/finished                */
    OW_KAPA_STATE_FAULTED         /* instance faulted, resources released     */
} OW_KAPA_STATE;

typedef struct _OW_KAPA_APPLICATION {
    uint32_t       Id;
    char           Name[OW_KAPA_MAX_NAME];
    uint32_t       AssociationId;
    uint32_t       KernelId;
    uint32_t       InstanceId;   /* 0 while no instance is loaded            */
    uint32_t       Capabilities;
    OW_KAPA_STATE  State;
    OW_STATUS      LastStatus;   /* last lifecycle status, OW_SUCCESS if none */
} OW_KAPA_APPLICATION;

typedef struct _OW_KAPA_STATS {
    uint32_t Applications;
    uint32_t Loaded;
    uint32_t Running;
    uint32_t Stopped;
    uint32_t Faulted;
    uint32_t BridgeCalls;
} OW_KAPA_STATS;

/* ---- Initialization / introspection ------------------------------------- */
OW_STATUS    OwKapaInitialize(void);
bool         OwKapaIsReady(void);
const char*  OwKapaStateName(OW_KAPA_STATE State);

/* ---- Application registry ------------------------------------------------ */
/* Registers an application and creates its KDB association in one step.  The
 * kernel must already exist and pass compatibility policy. */
OW_STATUS    OwKapaRegisterApplication(const char* Name, uint32_t KernelId,
                                       uint32_t Capabilities,
                                       uint32_t* OutApplicationId);
/* Destroys any live instance, releases the association and frees the slot. */
OW_STATUS    OwKapaUnregisterApplication(uint32_t ApplicationId);

OW_STATUS    OwKapaGetApplication(uint32_t ApplicationId,
                                  OW_KAPA_APPLICATION* OutApplication);
OW_STATUS    OwKapaFindApplication(const char* Name,
                                   OW_KAPA_APPLICATION* OutApplication);
OW_STATUS    OwKapaGetApplicationByIndex(uint32_t Index,
                                         OW_KAPA_APPLICATION* OutApplication);
uint32_t     OwKapaApplicationCount(void);

/* Compose a custom ABI from one or more manifest files.  This is the KAPA-level
 * entry point to OwKdbAbiComposeCustom(); ownership of the file buffers stays
 * with the caller. */
OW_STATUS    OwKapaComposeAbi(const OW_KDB_MANIFEST_FILE* Files,
                              uint32_t FileCount, uint32_t* OutAbiId);

/* ---- Lifecycle ----------------------------------------------------------- */
/* Associate -> load (READY) -> execute (executor handoff) -> stop/fault ->
 * destroy.  Load refuses a second instance for the same application.  Execute
 * returns OW_ERR_UNSUPPORTED when no executor backend is installed, leaving the
 * application LOADED; it never calls OwKdbStartInstance() on its own. */
OW_STATUS    OwKapaLoad(uint32_t ApplicationId, uint32_t PageLimit);
OW_STATUS    OwKapaExecute(uint32_t ApplicationId);
OW_STATUS    OwKapaStop(uint32_t ApplicationId);
OW_STATUS    OwKapaFault(uint32_t ApplicationId, OW_STATUS FaultStatus);
/* Destroys the loaded instance but keeps the application associated, ready to
 * load again. */
OW_STATUS    OwKapaDestroy(uint32_t ApplicationId);

/* ---- Service Bridge ------------------------------------------------------ */
/* Forwards to OwKdbBridgeCall() using this application's association as the
 * caller identity.  TargetInstanceId == 0 addresses a main-kernel service. */
OW_STATUS    OwKapaBridgeCall(uint32_t ApplicationId, uint32_t TargetInstanceId,
                              uint32_t ServiceId,
                              const void* Request, uint32_t RequestLength,
                              void* Response, uint32_t ResponseCapacity,
                              uint32_t* ResponseLength);

void         OwKapaGetStats(OW_KAPA_STATS* OutStats);

#endif /* OW_KAPA_H */
