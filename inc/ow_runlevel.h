/* ow_runlevel.h - OpenWindows Runlevel Subsystem
 * Each runlevel (-6..6) is a self-contained profile: a level, a name, a
 * description, a subsystem feature bitmask, and custom kernel configuration.
 * Negative levels are progressively richer recovery/maintenance modes,
 * level 0 is the terminal HALT target, and levels 1..6 escalate the runtime
 * toward the full feature set. */
#ifndef OW_RUNLEVEL_H
#define OW_RUNLEVEL_H

#include "ow_types.h"

#define OW_RUNLEVEL_MIN        (-6)
#define OW_RUNLEVEL_MAX        (6)
#define OW_RUNLEVEL_COUNT      13U
#define OW_RUNLEVEL_HALT       0
#define OW_RUNLEVEL_BOOT_DEFAULT (5)

/* -------------------------------------------------------------------------
 * Subsystem feature bits (each maps to a boot phase / subsystem family)
 * ------------------------------------------------------------------------- */
#define OW_RUNLVL_F_HAL         0x00000001U   /* hardware translation layer      */
#define OW_RUNLVL_F_MEMORY      0x00000002U   /* memory manager (VAD/PML4)       */
#define OW_RUNLVL_F_OBJECT      0x00000004U   /* object manager namespaces       */
#define OW_RUNLVL_F_DIAG        0x00000008U   /* BANcode diagnostic engine       */
#define OW_RUNLVL_F_ALPC        0x00000010U   /* Ring 3-to-0 dispatcher channel  */
#define OW_RUNLVL_F_SUCS        0x00000020U   /* SuperUnicode SUCS/SUTF-8 mode   */
#define OW_RUNLVL_F_VFS         0x00000040U   /* OWFS primary volume             */
#define OW_RUNLVL_F_USFS        0x00000080U   /* USFS secure volume              */
#define OW_RUNLVL_F_STORAGE     0x00000100U   /* physical storage / disk engine  */
#define OW_RUNLVL_F_OWINIT      0x00000200U   /* owinit.owx userspace hand-off   */
#define OW_RUNLVL_F_INTEGRITY   0x00000400U   /* kernel checksum verification    */
#define OW_RUNLVL_F_NETWORK     0x00000800U   /* univip 44-bit trie router       */
#define OW_RUNLVL_F_VIP         0x00001000U   /* UniVIP volume/FVIP index        */
#define OW_RUNLVL_F_SENTINEL    0x00002000U   /* damagecntrl active defense      */
#define OW_RUNLVL_F_SYSCALL     0x00004000U   /* system call gateway             */
#define OW_RUNLVL_F_SHELL       0x00008000U   /* Ring 0 debug shell              */
#define OW_RUNLVL_F_AI          0x00010000U   /* AI module ecosystem (optional)  */
#define OW_RUNLVL_F_CIS         0x00020000U   /* Copyleft Integrity Safeguard    */

/* Boot-critical core (armed in every functional profile) */
#define OW_RUNLEVEL_CORE_FEATURES \
    (OW_RUNLVL_F_HAL | OW_RUNLVL_F_MEMORY | OW_RUNLVL_F_OBJECT | OW_RUNLVL_F_DIAG | \
     OW_RUNLVL_F_CIS)

/* -------------------------------------------------------------------------
 * Per-profile flags
 * ------------------------------------------------------------------------- */
#define OW_RUNLVL_FLAG_HALT      0x00000001U   /* terminal teardown profile      */
#define OW_RUNLVL_FLAG_REBOOT    0x00000002U   /* recycle profile                */

/* -------------------------------------------------------------------------
 * Per-runlevel profile definition (custom config + feature set + level)
 * ------------------------------------------------------------------------- */
typedef struct _OW_RUNLEVEL_DEF {
    int         Level;            /* -6 .. 6                                 */
    const char* Name;             /* short mnemonic (e.g. "NETWORK")         */
    const char* Description;      /* human readable meaning                   */
    uint32_t    Features;         /* OW_RUNLVL_F_* armed at this level        */
    uint32_t    Flags;            /* OW_RUNLVL_FLAG_*                         */
    uint32_t    LogVerbosity;     /* 0 (quiet) .. 5 (maximal)                 */
    uint32_t    WatchdogMs;       /* 0 = no watchdog                          */
    uint32_t    HeapBudgetKB;     /* kernel heap budget                       */
    uint32_t    MaxHandles;       /* object manager handle ceiling            */
} OW_RUNLEVEL_DEF;

/* -------------------------------------------------------------------------
 * Subsystem API
 * ------------------------------------------------------------------------- */
OW_STATUS             OwRunlevelInitialize(int target);
OW_STATUS             OwRunlevelSet(int level);
OW_STATUS             OwRunlevelTeardown(int from, int to);
const OW_RUNLEVEL_DEF* OwRunlevelLookup(int level);
const OW_RUNLEVEL_DEF* OwRunlevelCurrent(void);
int                   OwRunlevelGetCurrent(void);
int                   OwRunlevelGetTarget(void);
uint32_t              OwRunlevelActiveFeatures(void);
uint32_t              OwRunlevelActiveFeatureCount(void);
bool                  OwRunlevelRequires(uint32_t feature);
const char*           OwRunlevelName(int level);
const char*           OwRunlevelDescription(int level);
uint32_t              OwRunlevelTransitions(void);
void                  OwRunlevelPrintTable(void);
void                  OwRunlevelPrintFeatures(void);

#endif /* OW_RUNLEVEL_H */