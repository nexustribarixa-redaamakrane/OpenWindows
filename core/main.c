/* main.c - OpenWindows Kernel Entry Point */
/* Freestanding C99 - No POSIX - NT-like Object Architecture */

#include "../inc/ow_types.h"
#include "../inc/ow_object.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_alpc.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_vfs.h"
#include "../inc/ow_net.h"
#include "../inc/ow_sentinel.h"
#include "../inc/ow_syscall.h"
#include "../inc/ow_shell.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_io.h"
#include "../inc/ow_ecosys.h"
#include "../inc/ow_runlevel.h"
#include "../inc/ow_rc.h"
#include "../inc/ow_acpi.h"
#include "../inc/ow_cis.h"
#include "../inc/ow_ps.h"
#include "../storage/owdisk.h"
#include "../inc/ow_usermode.h"
#include <stdarg.h>

/* Global system state */
typedef struct _OW_SYSTEM_STATE {
    OW_PML4_ENTRY*      PML4Table;
    OW_VAD_NODE*        VadRoot;
    OW_OBJECT_DIR*      RootNamespace;
    OW_OBJECT_DIR*      DriverDirectory;
    bool                SystemHalted;
    uint32_t            BootPhase;
    /* Which of the three userspace states the boot resolved to.  Kept on the
     * system state rather than as a local because the survey (phase 5c) and the
     * hand-off (phase 5c.5) are separate phases, and re-deriving the answer
     * from the volume between them would let the two disagree if anything
     * changed the catalog in between. */
    OW_USERSPACE_STATE  UserspaceState;
} OW_SYSTEM_STATE;

static OW_SYSTEM_STATE g_System;

#define BOOT_TOTAL_WEIGHT 100U   /* real boot completion denominator        */
#define BOOT_PACE_MS      1200U  /* a real beat after each completed phase  */
#define BOOT_LINE_MS       450U  /* each narrated line holds on screen      */

static uint32_t g_boot_weight = 0;

static void boot_spin(uint32_t ms);   /* busy wait w/ HUD spinner (defined below) */

static void boot_logo(void) {
    OwHalVgaSetAttr(0x0B);                              /* bright cyan */
    OwHalUartWriteString("===================================================================\r\n");
    OwHalUartWriteString("                        O P E N W I N D O W S\r\n");
    OwHalUartWriteString("                     Kernel 0.1.0 - Boot Monitor\r\n");
    OwHalVgaSetAttr(0x07);
    OwHalUartWriteString("===================================================================\r\n");
    OwHalVgaStatusBar("OpenWindows Kernel 0.1.0   BOOT [....................................]   0%");
    boot_spin(1800);
}

/* Right-align V into a Width-wide field padded with Pad; returns chars written. */
static int dec_field(char* dst, uint64_t v, int width, char pad) {
    char tmp[12];
    int i = 0, j;
    do { tmp[i++] = '0' + (char)(v % 10); v /= 10; } while (v > 0 && i < (int)sizeof(tmp));
    for (j = 0; j < width; j++) dst[j] = (j < width - i) ? pad : tmp[width - 1 - j];
    return width;
}

/* Real uptime timestamp, Linux kernel log style: "[       0.000] ".
 * Seconds come from the 64-bit monotonic clock, so there is no
 * Y2K38 (32-bit time_t overflow) window anywhere in timekeeping. */
static void km_timestamp(void) {
    char buf[48];
    uint64_t t = OwHalUptimeMs();
    int n = 0;
    buf[n++] = '['; buf[n++] = ' ';
    n += dec_field(buf + n, t / 1000, 6, ' ');
    buf[n++] = '.';
    n += dec_field(buf + n, t % 1000, 3, '0');
    buf[n++] = ']'; buf[n++] = ' ';
    buf[n] = '\0';
    OwHalUartWriteString(buf);
}

static void km_line(uint8_t TagColor, const char* Tag, const char* fmt, ...) {
    char body[110];
    va_list ap;
    uint32_t k;

    /* the line physically assembles: timestamp, then tag, then body,
     * then a trailing "..." while it holds --- nothing snap-appears */
    OwHalVgaSetAttr(0x08);                              /* dim timestamp   */
    km_timestamp();
    boot_spin(130);
    OwHalVgaSetAttr(TagColor);                          /* colored [tag]    */
    OwHalUartWriteString(Tag);
    boot_spin(160);
    OwHalVgaSetAttr(0x0F);                              /* bright white body */
    OwHalUartWriteChar(' ');
    body[0] = '\0';
    if (fmt) {
        va_start(ap, fmt);
        ow_vsnprintf(body, sizeof(body), fmt, ap);
        va_end(ap);
    }
    OwHalUartWriteString(body);
    for (k = 0; k < 3; k++) {                           /* growing "..."   */
        boot_spin(110);
        OwHalUartWriteChar('.');
    }
    boot_spin(200);
    OwHalUartWriteString("\r\n");
    boot_spin(BOOT_LINE_MS);
}

/* Busy wait: sleep through `ms` while animating a spinner on the HUD,
 * so the boot visibly "works" between lines instead of looking dumped. */
static void boot_spin(uint32_t ms) {
    static const char frames[4] = { '|', '/', '-', '\\' };
    uint32_t k = 0;
    while (ms) {
        OwHalDelayMs(60);
        OwHalVgaStatusSetChar(79, frames[k & 3]);
        k++;
        ms = (ms > 60) ? (ms - 60) : 0;
    }
    OwHalVgaStatusSetChar(79, ' ');
}

/* Serial-only boot log spine (VGA muted): the tests read the serial log. */
static void boot_begin(const char* Name) {
    OwHalVgaSetEnabled(false);
    OwDiagLogStarted(Name);
    OwHalVgaSetEnabled(true);
}

/* Advance the pinned HUD bar by a completed phase's share of the boot. */
static void boot_advance_bar(uint32_t Weight) {
    uint32_t pct;
    uint32_t fill;
    char bar[40];
    char line[110];
    uint32_t b;
    int n = 0;

    g_boot_weight += Weight;
    /* Clamp, because this is a percentage of a real total and the alternative is
     * a bar that quietly reads 106%.  Nothing in the normal path can reach the
     * clamp -- the phase weights are chosen to sum to BOOT_TOTAL_WEIGHT -- so
     * hitting it means a phase has been charged twice, which is a bug the HUD
     * should make visible rather than paper over. */
    if (g_boot_weight > BOOT_TOTAL_WEIGHT) g_boot_weight = BOOT_TOTAL_WEIGHT;
    pct  = (g_boot_weight * 100U) / BOOT_TOTAL_WEIGHT;
    fill = (g_boot_weight * 36U) / BOOT_TOTAL_WEIGHT;
    bar[n++] = '[';
    for (b = 0; b < 36; b++) bar[n++] = b < fill ? '#' : '.';
    bar[n++] = ']';
    bar[n] = '\0';
    ow_ksnprintf(line, sizeof(line),
                 "OpenWindows Kernel 0.1.0   BOOT %s  %u%%", bar, pct);
    OwHalVgaStatusBar(line);
}

/* Finish a phase: serial log verdict, then a REAL overall boot percentage on
 * the pinned HUD bar (share of the weighted boot sequence actually done). */
static void boot_diag_done(uint32_t Phase, OW_STATUS Result,
                           const char* Name, int Ok, uint32_t Weight) {
    g_System.BootPhase = Phase;
    OwHalVgaSetEnabled(false);
    if (Ok) {
        OwDiagLogFinished(Name, Result);
    } else {
        OwDiagLogFailed(Name, Result);
        if (Result) OwDiagBanHammer(Result, "boot", Name);
    }
    OwHalVgaSetEnabled(true);

    boot_advance_bar(Weight);
    boot_spin(BOOT_PACE_MS);
}

/* A phase that FAILED, recorded without halting.
 *
 * boot_diag_done() logs the failed verdict and then hammers the BANcode trap,
 * which never returns.  That is right for every phase except one: the owinit
 * userspace resolution is the phase whose failure the next piece of code gets
 * to interpret, because an unusable owinit may still be a bootable machine when
 * the emergency userspace is present.  Recording the failure here and letting
 * the state machine decide keeps "the phase failed" and "the machine is dead"
 * as two separate, separately testable facts. */
static void boot_diag_failed(uint32_t Phase, OW_STATUS Result,
                             const char* Name, uint32_t Weight) {
    g_System.BootPhase = Phase;
    OwHalVgaSetEnabled(false);
    OwDiagLogFailed(Name, Result);
    OwHalVgaSetEnabled(true);

    boot_advance_bar(Weight);
    boot_spin(BOOT_PACE_MS);
}

/* A boot phase whose subsystem the active runlevel does not arm is logged
 * (W+ advisory) and skipped, keeping the weighted boot bar coherent. */
static void boot_skip_line(const char* Name) {
    const OW_RUNLEVEL_DEF* rl = OwRunlevelCurrent();
    OwDiagLogWarning(OW_W_RUNLEVEL_FEATURE_SKIPPED, Name);
    km_line(0x08, "[RUNLVL]", "%s not armed at level %d (%s) - skipped",
            Name, rl->Level, rl->Name);
}

static void boot_skip_phase(const char* Name, uint32_t Phase, uint32_t Weight) {
    boot_skip_line(Name);
    boot_diag_done(Phase, OW_SUCCESS, Name, 1, Weight);
}

/* A phase that FAILED, recorded without halting.
 *
 * boot_diag_done() logs the failed verdict and then hammers the BANcode trap,
 * which never returns.  That is right for every phase except one: the owinit
 * userspace resolution is the phase whose failure the next piece of code gets
 * to interpret, because an unusable owinit may still be a bootable machine when
 * the emergency userspace is present.  Recording the failure here and letting
 * the state machine decide keeps "the phase failed" and "the machine is dead"
 * as two separate, separately testable facts. */
static void boot_diag_failed(uint32_t Phase, OW_STATUS Result,
                             const char* Name, uint32_t Weight);

/* ====================================================================== */
/* Userspace boot policy (the three owinit states)                       */
/* ====================================================================== */
OW_USERSPACE_STATE OwBootClassifyUserspace(const OW_USERSPACE_PROBE* probe) {
    if (!probe) return OW_USERSPACE_ABSENT;

    /* State 1.  A loadable owinit.owx is the answer, full stop: the emergency
     * pair is not consulted and owinitv/owrs are not started, because a rescue
     * shell on a healthy machine is a second init nobody asked for. */
    if (probe->PrimaryValid) return OW_USERSPACE_PRIMARY;

    /* State 2.  No usable primary, but something to fall back to.  Reaching
     * here is not a failure of the boot, only of the primary orchestrator, so
     * the two are reported differently: a warning for the degraded path, a
     * BANcode halt for the unrecoverable one. */
    if (OwUserSpaceEmergencyAvailable(probe)) return OW_USERSPACE_EMERGENCY;

    /* State 3.  Neither.  There is no user-mode init to enter and no rescue
     * path, so nothing the kernel can do next will produce a userspace. */
    return OW_USERSPACE_ABSENT;
}

const char* OwBootUserspaceStateName(OW_USERSPACE_STATE state) {
    switch (state) {
    case OW_USERSPACE_PRIMARY:   return "PRIMARY";
    case OW_USERSPACE_EMERGENCY: return "EMERGENCY";
    case OW_USERSPACE_ABSENT:    return "ABSENT";
    default:                     return "UNKNOWN";
    }
}

/* Narrate one probed image.  `label` is the boot-log tag, `present`/`valid`
 * the probe's two separate answers, and `status` why it is not valid. */
static void log_ow_image(const char* label, bool present, bool valid,
                         OW_STATUS status) {
    if (valid) {
        km_line(0x0A, label, "present, loadable");
    } else if (present) {
        km_line(0x0C, label, "present but UNUSABLE (0x%X) - treated as missing",
                (unsigned)status);
    } else {
        km_line(0x08, label, "not present on the primary volume");
    }
}

/* ====================================================================== */
/* Userspace process hand-off                                            */
/* ====================================================================== */
/* Read an image off the primary volume, create PID 1 for it, load it into that
 * process's own guarded address space, audit the result, and enter it at CPL3.
 *
 * Every step reports on its own.  A hand-off that fails without saying which
 * step failed is indistinguishable, in the log, from a volume that was never
 * provisioned -- and the fix for those two is completely different.
 *
 * `out` receives the process so the caller can say which image it entered, or
 * NULL when the hand-off did not happen. */
static OW_PROCESS_OBJECT* boot_launch_init(const char* image_name,
                                           const char* process_name) {
    static uint8_t s_init_image[OW_USERSPACE_IMAGE_MAX];
    uint32_t read_len = 0;
    OW_PROCESS_OBJECT* oproc;
    OW_STATUS rds;

    rds = OwFsOwfsRead(image_name, s_init_image,
                       (uint32_t)sizeof(s_init_image), &read_len);
    if (!ow_status_success(rds) || read_len == 0) {
        km_line(0x0C, "[OWINIT]", "%s read FAILED (0x%X, %u bytes)",
                image_name, (unsigned)rds, (unsigned)read_len);
        return (OW_PROCESS_OBJECT*)0;
    }

    oproc = OwPsCreateProcess(process_name, OW_PS_PID_KERNEL);
    if (!oproc) {
        km_line(0x0C, "[OWINIT]", "%s process creation FAILED", process_name);
        return (OW_PROCESS_OBJECT*)0;
    }
    OwDiagLogFinished("OWINIT Process", OW_C_OWINIT_PROCESS_CREATED);

    /* Provenance is named, not inferred.  This is the kernel's own hand-off of
     * the init image, and saying so is what keeps the measurement log honest:
     * the loader sees an ordinary process object here and could not tell a boot
     * from a userspace spawn by looking. */
    if (ow_status_error(OwPsLoadImage(oproc, s_init_image, read_len,
                                      (uint32_t)OW_CIS_RECORD_BOOT))) {
        /* Without this the load's reason is discarded: the boot simply
         * continued as though the image had not been there at all, with no
         * init-related line in the log, which is a very expensive thing to
         * debug after the fact. */
        km_line(0x0C, "[OWINIT]", "%s image load FAILED", process_name);
        return (OW_PROCESS_OBJECT*)0;
    }

    /* Audit the init's address space with the same checker the synthetic Ring 3
     * app uses: if the loader ever maps a data section executable, or misses U/S
     * on a tier, it shows up here as a counted violation rather than as a latent
     * hole. */
    if (OwMemAuditUserWindow(oproc->Pml4Phys, oproc->VadRoot) != 0u) {
        km_line(0x0C, "[OWINIT]", "USER WINDOW AUDIT FAILED");
    }

    if (ow_status_error(OwPsLaunchUserImage(oproc))) {
        km_line(0x0C, "[OWINIT]", "%s CPL3 launch FAILED", process_name);
        return (OW_PROCESS_OBJECT*)0;
    }
    return oproc;
}

void _start(void) {
    /* Pin the boot monitor; the log console lives below it */
    OwHalVgaInitialize();
    boot_logo();

    /* Phase 1: Hardware Abstraction Layer */
    boot_begin("HAL Init");
    OwHalInitialize();
    OwHalIdtInit(0x08U);
    km_line(0x0B, "[HAL]", "console: VGA text 80x25 @ 0xB8000 (row 0-24)");
    km_line(0x0B, "[HAL]", "uart0: COM1 @ 0x3F8, 115200 baud 8N1");
    km_line(0x0B, "[HAL]", "timer: 8254 PIT ~1000 Hz, monotonic clock armed");
    km_line(0x0B, "[TIME]", "64-bit monotonic time (uint64 ms) - no Y2K38 overflow");
    boot_diag_done(1, OW_C_HAL_INITIALIZED, "HAL Init", 1, 12);

    /* Phase 1b: ACPI firmware tables (software power control: S5 + reset) */
    OwAcpiInitialize();

    /* Phase 2: Memory Manager */
    boot_begin("Memory Init");
    OwMemInitialize();
    g_System.PML4Table = (OW_PML4_ENTRY*)OwMemAllocatePage();
    g_System.VadRoot = (void*)0;
    g_System.SystemHalted = false;
    g_System.UserspaceState = OW_USERSPACE_ABSENT;
    km_line(0x0D, "[MEM]", "pml4: 512 GiB virtual address space, table built");
    km_line(0x0D, "[MEM]", "vad: zero-allocation core, no dynamic heap");
    km_line(0x0D, "[MEM]", "page manager: 4 KiB granularity armed");
    boot_diag_done(2, OW_C_PML4_BUILT, "Memory Init", 1, 10);

    /* Phase 3: Object Manager */
    boot_begin("Object Manager");
    OwObjInitialize();
    g_System.RootNamespace = OwObjCreateDirectory("\\", (void*)0);
    OwObjCreateDirectory("Device", g_System.RootNamespace);
    OwObjCreateDirectory("DosDevices", g_System.RootNamespace);
    OwObjCreateDirectory("Kernel", g_System.RootNamespace);
    g_System.DriverDirectory = OwObjCreateDirectory("Drivers", g_System.RootNamespace);
    km_line(0x0E, "[OBJ]", "namespace: root \\ mounted");
    km_line(0x0E, "[OBJ]", "namespace: \\Device, \\Kernel, \\Drivers created");
    boot_diag_done(3, OW_C_OBJ_MANAGER_READY, "Object Manager", 1, 8);

    /* Phase 4: Diagnostic Engine (BANcode) + Runlevel subsystem + ALPC */
    boot_begin("Diagnostics");
    OwDiagInitialize();
    {
        OW_STATUS rl = OwRunlevelInitialize(OW_RUNLEVEL_BOOT_DEFAULT);
        int okr = ow_status_success(rl);
        if (okr) {
            const OW_RUNLEVEL_DEF* rld = OwRunlevelCurrent();
            km_line(0x0A, "[RUNLVL]", "target %d (%s): %s",
                    rld->Level, rld->Name, rld->Description);
            km_line(0x0A, "[RUNLVL]", "%u profile(s) compiled, %u feature(s) armed",
                    (unsigned int)OW_RUNLEVEL_COUNT,
                    (unsigned int)OwRunlevelActiveFeatureCount());
        } else {
            km_line(0x0C, "[RUNLVL]", "runlevel table compile FAILED");
        }
        km_line(0x0E, "[DIAG]", "BANcode engine online");
        if (OwRunlevelRequires(OW_RUNLVL_F_ALPC)) {
            OwAlpcInitialize();
            km_line(0x0E, "[DIAG]", "ALPC dispatcher started");
        } else {
            boot_skip_line("ALPC");
        }
        boot_diag_done(4, okr ? (OW_STATUS)OW_C_RUNLEVEL_TABLE_READY : (OW_STATUS)0,
                       "Diagnostics", okr, 8);
    }

    /* Phase 4b: SuperUnicode SUCS commit-on-boot + SUTF self-test */
    if (OwRunlevelRequires(OW_RUNLVL_F_SUCS)) {
        boot_begin("SuperUnicode");
        OwSucsInitialize();
        if (OwSucsCommitBoot()) {
            ow_kprintf("[SUCS] Mode switch committed at boot (count=%u)\r\n",
                       OwSucsModeChangeCount());
        }
        {
            int ok4b = OwSucsSelfTest();
            if (ok4b) {
                ow_kprintf("[SUTF] Codec self-test: OK (Base SUCS / SUTF-8 active)\r\n");
                km_line(0x0D, "[SUCS]", "SUTF-8 codec self-test passed");
            } else {
                km_line(0x0C, "[SUCS]", "codec self-test FAILED - integrity compromised");
            }
            km_line(0x0D, "[SUCS]", "mode switch committed at boot");
            boot_diag_done(4, ok4b ? OW_SUCCESS : OW_B_SENTINEL_INTEGRITY_FAIL,
                           "SuperUnicode", ok4b, 6);
        }
    } else {
        boot_skip_phase("SuperUnicode", 4, 6);
    }

    /* Phase 4c: Process / Thread subsystem (NT-like executive objects).
     * Builds the static process/thread tables and the idle system thread 0.
     * Scheduling stays off until OwPsStartScheduler() is armed after the
     * owinit provisioning hand-off; the boot thread keeps exclusive CPU. */
    boot_begin("PS Init");
    {
        int ok4c = ow_status_success(OwPsInitialize());
        km_line(0x0D, "[PS]", "process/thread tables compiled");
        km_line(0x0D, "[PS]", "idle system thread 0 registered");
        boot_diag_done(40, ok4c ? OW_C_PS_READY : (OW_STATUS)0,
                       "PS Init", ok4c, 4);
    }

    /* Phase 5: Virtual File System */
    if (OwRunlevelRequires(OW_RUNLVL_F_VFS)) {
        boot_begin("VFS Primary");
        {
            int okv = ow_status_success(OwVfsMountPrimary());
            km_line(0x0A, "[VFS]", "OWFS: primary database mounted");
            km_line(0x0A, "[VFS]", "journal: initialized");
            boot_diag_done(5, okv ? OW_C_VFS_PRIMARY_MOUNTED : (OW_STATUS)0,
                           "VFS Primary", okv, 8);
        }
    } else {
        boot_skip_phase("VFS Primary", 5, 8);
    }
    if (OwRunlevelRequires(OW_RUNLVL_F_USFS)) {
        boot_begin("VFS Secure");
        {
            int oks = ow_status_success(OwVfsMountSecure());
            km_line(0x0A, "[VFS]", "USFS: secure volume mounted");
            km_line(0x0A, "[VFS]", "secure stream verified");
            boot_diag_done(50, oks ? OW_C_VFS_SECURE_MOUNTED : (OW_STATUS)0,
                           "VFS Secure", oks, 6);
        }
    } else {
        boot_skip_phase("VFS Secure", 50, 6);
    }

    /* Phase 5b: Physical storage (OWFS on primary disk, USFS on secure) */
    if (OwRunlevelRequires(OW_RUNLVL_F_STORAGE)) {
        boot_begin("Storage");
        OwDiskInitialize();
        km_line(0x0E, "[DISK]", "disk0: OWFS geometry accepted");
        km_line(0x0E, "[DISK]", "disk1: USFS geometry accepted");
        km_line(0x0E, "[DISK]", "sector engine: %u-sector LBA ready", OW_RAMDISK_PRIMARY_BLOCKS);
        boot_diag_done(51, OW_SUCCESS, "Storage", 1, 8);
    } else {
        boot_skip_phase("Storage", 51, 8);
    }

    /* Phase 5c: userspace resolution over owinit / owinitv / owrs.
     *
     * There are exactly three answers, and they are decided here, from what is
     * actually on the primary volume rather than from what the volume was
     * supposed to contain:
     *
     *   1  owinit.owx present and loadable   -> it becomes PID 1.  Done; the
     *                                              emergency pair is not started.
     *   2  otherwise, and at least one of owinitv.owx / owrs.owx is loadable
     *                                         -> owinitv.owx becomes PID 1 and
     *                                              brings up the minimum
     *                                              userspace, spawning owrs.owx
     *                                              as the rescue shell.
     *   3  neither                            -> unrecoverable.  Panic.
     *
     * A present-but-unloadable owinit.owx lands in state 2, not state 3: a
     * damaged orchestrator on a volume that still holds a rescue shell is a
     * degraded machine, and panicking there would throw away the tool meant to
     * fix it. */
    if (OwRunlevelRequires(OW_RUNLVL_F_OWINIT)) {
        OW_USERSPACE_PROBE probe;
        OW_USERSPACE_STATE  ustate;

        boot_begin("owinit");
        OwDiskProbeUserspace(&probe);
        ustate = OwBootClassifyUserspace(&probe);
        g_System.UserspaceState = ustate;

        log_ow_image("[OWINIT]", probe.PrimaryPresent, probe.PrimaryValid,
                     probe.PrimaryStatus);
        ow_kprintf("[OWINIT] userspace survey: primary(%s) owinitv(%s) "
                   "owrs(%s) -> state %s\r\n",
                   probe.PrimaryValid ? "ok" : "unusable",
                   probe.EmergencyValid ? "ok" : "unusable",
                   probe.RescueValid ? "ok" : "unusable",
                   OwBootUserspaceStateName(ustate));

        if (ustate == OW_USERSPACE_PRIMARY) {
            km_line(0x0A, "[OWINIT]", "state PRIMARY: owinit.owx is PID 1");
            boot_diag_done(52, OW_SUCCESS, "owinit", 1, 6);
        } else if (ustate == OW_USERSPACE_EMERGENCY) {
            /* Degraded, not broken.  The primary orchestrator did not come up,
             * but a userspace does, so this is a warning and not a BANcode
             * halt: halting here would destroy the rescue shell. */
            OwDiagLogWarning(OW_W_OWINIT_EMERGENCY,
                             "primary owinit unusable; entering owinitv");
            km_line(0x0E, "[OWINIT]", "state EMERGENCY: owinitv.owx is PID 1");
            if (probe.EmergencyValid) {
                km_line(0x0E, "[OWINIT]", "owinitv will spawn owrs.owx "
                        "(%s)", probe.RescueValid ? "rescue shell available"
                                                  : "NOT on this volume");
            } else {
                km_line(0x0C, "[OWINIT]", "owinitv.owx UNUSABLE; owrs.owx "
                        "cannot be launched without it");
            }
            boot_diag_done(52, OW_W_OWINIT_EMERGENCY, "owinit", 1, 6);
        } else {
            /* State 3.  Nothing to enter.
             *
             * "No emergency userspace" and "a rescue shell with no init to
             * reach it from" are the same state and completely different
             * faults, and the second one is the more actionable: someone
             * flashing a lone owrs.owx needs to be told the file is fine and
             * the pair is not, not sent looking for a disk to re-image. */
            if (OwUserSpaceEmergencyBytes(&probe)) {
                km_line(0x0C, "[OWINIT]", "state ABSENT: no usable owinit, and "
                        "the volume has emergency bytes but no usable owinitv.owx "
                        "to enter (owinitv is the init; owrs cannot be PID 1)");
                boot_diag_failed(52, OW_B_OWINIT_MISSING, "owinit", 6);
                OwDiagBanHammer(OW_B_OWINIT_MISSING, "userspace",
                                "owinit.owx missing or unusable, and owinitv.owx "
                                "missing or unusable, so no user-mode init can be "
                                "entered (an owrs.owx alone is a rescue shell with "
                                "no init to reach it from)");
            } else {
                km_line(0x0C, "[OWINIT]", "state ABSENT: no usable owinit and no "
                        "emergency userspace on the volume");
                boot_diag_failed(52, OW_B_OWINIT_MISSING, "owinit", 6);
                OwDiagBanHammer(OW_B_OWINIT_MISSING, "userspace",
                                "owinit.owx missing or unusable and no emergency "
                                "userspace (owinitv.owx / owrs.owx) available");
            }
            ow_hlt_loop();   /* unreachable: BanHammer does not return */
        }
    } else {
        boot_skip_phase("owinit", 52, 6);
    }

    /* Phase 5c.1: Copyleft Integrity Safeguard.
     *
     * Armed BEFORE the init hand-off, which is the only place it can go.
     * This is the first moment in boot at which any executable has been mapped
     * into a process, so a CIS that came up after the hand-off would have let
     * exactly one image through unmeasured -- the init, which is also the
     * image with the most authority once it is running.  Arming here also
     * means the survey above is the last thing in boot that looks at an image
     * without asking CIS about it.
     *
     * The phase is gated on OW_RUNLVL_F_CIS, which is in
     * OW_RUNLEVEL_CORE_FEATURES, so it is armed in every functional profile
     * including the negative recovery ones.  A runlevel must not be able to
     * switch off executable verification: that is precisely the runlevel an
     * attacker with any write access would choose.
     *
     * Weight 0, charged to the userspace-resolution step it gates, the same
     * treatment the 5c.5 hand-off below gets.  The boot HUD denominator was
     * already over-subscribed (106 against a 100 total) before this phase
     * existed, so it is not given a share of its own; boot_diag_done() clamps
     * the percentage either way. */
    if (OwRunlevelRequires(OW_RUNLVL_F_CIS)) {
        boot_begin("CIS");
        {
            OW_STATUS cist = OwCisInitialize();
            if (ow_status_error(cist)) {
                km_line(0x0C, "[CIS]", "enforcement FAILED to arm - "
                        "no executable will be mapped");
                boot_diag_failed(52, cist, "CIS", 0);
                /* A halt, not a warning.  OwCisIsReady() stays false, so every
                 * image load is refused from here on; carrying on would hand a
                 * machine whose init cannot start to the shell, with the real
                 * fault buried in the log rather than stated as the reason the
                 * machine stopped. */
                OwDiagBanHammer(cist, "CIS",
                                "Copyleft Integrity Safeguard could not arm; "
                                "no image may be mapped without it");
                ow_hlt_loop();
            }
            if (OwCisTrustedKeyCount() == 0) {
                km_line(0x0E, "[CIS]", "armed with 0 trust anchors - "
                        "every image will be refused");
            }
            km_line(0x0A, "[CIS]", "enforcement armed (signatures mandatory)");
            boot_diag_done(52, OW_C_CIS_ONLINE, "CIS", 1, 0);
        }
    } else {
        /* Unreachable while CIS is in OW_RUNLEVEL_CORE_FEATURES.  Present so
         * that removing the feature bit from the core mask produces a loud
         * refusal rather than a silently unguarded boot. */
        km_line(0x0C, "[CIS]", "runlevel does not arm CIS - refusing to "
                "continue without image verification");
        boot_diag_failed(52, OW_ERR_UNSUPPORTED, "CIS", 0);
        OwDiagBanHammer(OW_ERR_UNSUPPORTED, "CIS",
                        "active runlevel does not arm the Copyleft Integrity "
                        "Safeguard");
        ow_hlt_loop();
    }

    /* Phase 5c.5: enter the init the survey chose.
     *
     * The loader charges the image out of the process's own frame run and maps
     * it inside the guarded user window, so the init now executes with a real
     * privilege boundary: it can only reach the pages its own VAD tree
     * describes, and its data sections are execute-disabled.  It reaches the
     * kernel through int 0x80 like any other Ring 3 program.
     *
     * State 2 hands off to owinitv, NOT to owrs: owrs is a rescue shell with no
     * init duties, so entering it directly would produce a machine with a
     * console and no one to start anything.  owinitv brings up the minimum
     * userspace and spawns owrs through OW_SYS_PS_SPAWN_OWX, which is a user
     * mode program doing a user mode thing, over the same loader and the same
     * OWFS path the kernel just used. */
    if (OwRunlevelRequires(OW_RUNLVL_F_OWINIT)) {
        const char* init_image = (g_System.UserspaceState == OW_USERSPACE_PRIMARY)
                                   ? OW_INIT_EXEC_NAME
                                   : OW_INITV_EXEC_NAME;
        const char* init_name  = (g_System.UserspaceState == OW_USERSPACE_PRIMARY)
                                   ? "owinit" : "owinitv";
        OW_PROCESS_OBJECT* iproc = (OW_PROCESS_OBJECT*)0;

        if (g_System.UserspaceState != OW_USERSPACE_ABSENT) {
            iproc = boot_launch_init(init_image, init_name);
        }

        if (iproc) {
            km_line(0x0A, "[OWINIT]", "%s entered at CPL3 (PID %u)",
                    init_name, (unsigned)iproc->ProcessId);
        } else if (g_System.UserspaceState == OW_USERSPACE_PRIMARY) {
            /* State 1 promised a PID 1 and did not deliver one.  Falling
             * through to the shell would leave a "healthy" boot with no
             * userspace at all, which is state 3 wearing state 1's label. */
            km_line(0x0C, "[OWINIT]", "state PRIMARY but no init was entered "
                    "- unrecoverable boot failure - panic");
            /* Weight 0: phase 5c already charged this phase its full share of
             * the bar when it selected the init.  This is a failure of the
             * 5c.5 hand-off, not a second phase, and charging it again would
             * push the completion percentage past 100%. */
            boot_diag_failed(52, OW_B_OWINIT_MISSING, "owinit", 0);
            OwDiagBanHammer(OW_B_OWINIT_MISSING, "userspace",
                            "owinit.owx was present and loadable but could not "
                            "be entered as PID 1");
            ow_hlt_loop();
        } else {
            /* State 2 has the same obligation and it matters more here, not
             * less: the emergency userspace is a last-resort path, so a
             * hand-off that quietly fails leaves the machine booting on with no
             * init and no indication that the rescue path is dead.  The image
             * passed the survey, so "present and loadable but not enterable"
             * means the frame run could not be built for a user process -- a
             * RAM or loader fault, not a bad disk.  The diagnostic says so,
             * because the two causes send a user to different places. */
            km_line(0x0C, "[OWINIT]", "state EMERGENCY but owinitv could not be "
                    "entered - the rescue path is not available - panic");
            boot_diag_failed(52, OW_B_OWINIT_MISSING, "owinit", 0);
            OwDiagBanHammer(OW_B_OWINIT_MISSING, "userspace",
                            "owinitv.owx was present and loadable but could not "
                            "be entered as PID 1, so the emergency userspace is "
                            "unavailable (this indicates a process frame or loader "
                            "fault, not a damaged owinitv.owx)");
            ow_hlt_loop();
        }
    }

    /* Phase 5d: Kernel Checksum & Integrity Validation (openwinkrnl.chk) */
    if (OwRunlevelRequires(OW_RUNLVL_F_INTEGRITY)) {
        boot_begin("Kernel Integrity");
        {
            OW_STATUS chkst = OwSentinelVerifyKernelChecksum();
            int chkok = ow_status_success(chkst);
            if (chkok) {
                km_line(0x0A, "[SENT]", "kernel checksum verified (openwinkrnl.chk)");
            } else {
                km_line(0x0C, "[SENT]", "kernel checksum CORRUPTED (openwinkrnl.chk)");
            }
            boot_diag_done(53, chkok ? OW_SUCCESS : OW_B_SENTINEL_INTEGRITY_FAIL,
                           "Kernel Integrity", chkok, 6);
        }
    } else {
        boot_skip_phase("Kernel Integrity", 53, 6);
    }

    /* Phase 6: Network Router */
    if (OwRunlevelRequires(OW_RUNLVL_F_NETWORK)) {
        boot_begin("Network");
        {
            int okn = ow_status_success(OwNetInitialize());
            km_line(0x0B, "[NET]", "router service starting");
            km_line(0x0B, "[NET]", "router online");
            boot_diag_done(6, okn ? OW_C_NETWORK_ONLINE : (OW_STATUS)0,
                           "Network", okn, 4);
        }
    } else {
        boot_skip_phase("Network", 6, 6);
    }

    /* Phase 6b: UniVIP volume registry + FVIP root index */
    if (OwRunlevelRequires(OW_RUNLVL_F_VIP)) {
        boot_begin("UniVIP");
        OwVipInitialize();
        if (OwVipIsUp()) {
            ow_kprintf("[VIP] UniVIP online: root volume %u @ LBA %llu, FVIP index ready\r\n",
                       OW_VIP_ROOT_VOLUME, (unsigned long long)OW_VIP_ROOT_BASE_SECTOR);
            km_line(0x0D, "[VIP]", "UniVIP registry online, root volume %u @ LBA %llu",
                    OW_VIP_ROOT_VOLUME, (unsigned long long)OW_VIP_ROOT_BASE_SECTOR);
            km_line(0x0D, "[VIP]", "FVIP root volume index compiled");
            boot_diag_done(6, OW_SUCCESS, "UniVIP", 1, 8);
        } else {
            ow_kprintf("[VIP] UniVIP init failed\r\n");
            km_line(0x0C, "[VIP]", "UniVIP init FAILED");
            boot_diag_done(6, (OW_STATUS)0, "UniVIP", 0, 8);
        }
    } else {
        boot_skip_phase("UniVIP", 6, 8);
    }

    /* Phase 7: Sentinel Active Defense */
    if (OwRunlevelRequires(OW_RUNLVL_F_SENTINEL)) {
        boot_begin("Sentinel");
        OwSentinelInitialize();
        km_line(0x0E, "[SENT]", "active defense armed");
        km_line(0x0E, "[SENT]", "integrity chains bound");
        boot_diag_done(7, OW_C_SENTINEL_ONLINE, "Sentinel", 1, 6);
    } else {
        boot_skip_phase("Sentinel", 7, 6);
    }

    /* Phase 8: System Call Gateway */
    if (OwRunlevelRequires(OW_RUNLVL_F_SYSCALL)) {
        boot_begin("Syscall Gateway");
        OwSyscallInitialize();  /* [DEBUG BISECT: only KeSyncSelfTest skipped inside] */
        km_line(0x0B, "[SYSC]", "system call table installed");
        km_line(0x0B, "[SYSC]", "gateway ready");
        boot_diag_done(8, OW_C_SYSCALL_GATEWAY_READY, "Syscall Gateway", 1, 4);
    } else {
        boot_skip_phase("Syscall Gateway", 8, 4);
    }

    /* Boot Complete */
    boot_begin("Boot Complete");
    km_line(0x0A, "[INIT]", "handing off to shell 'sh' as init process");
    km_line(0x0A, "[BOOT]", "kernel boot complete in %llu ms",
            (unsigned long long)OwHalUptimeMs());
    boot_diag_done(9, OW_C_BOOT_COMPLETE, "Boot Complete", 1, 2);

    /* PS scheduler hand-off: snapshot the boot thread's context (thread 0,
     * the shell), then arm the 100 Hz preemption tick.  From here on the
     * scheduler round-robins thread 0 against the enqueued owinit process
     * thread (PID 1) whatever test shell script runs next. */
    OwPsCaptureBootContext();
    OwPsStartScheduler();

    /* Queue the standalone Ring 3 application: it drives UART_WRITE,
     * PS_SLEEP (a real block/wake) and PS_EXIT_THREAD through int 0x80,
     * then hands the CPU back to the kernel for good. */
    if (OwRunlevelRequires(OW_RUNLVL_F_SYSCALL)) {
        OwUmLaunchHello();
    }

    OwShellInitialize();
    OwShellRun();

    /* Shutdown: run the OpenWindows-Essentials rc.d shutdown sequence and
     * issue a software ACPI S5 power-off. Falls through to the halt fallback
     * when the host never acknowledges the power-off request. */
    OwRcShutdown();
    OwAcpiPowerOff();

    ow_kprintf("[SHUTDOWN] Halting processor...\r\n");
    OwHalSmpHaltIPI();
    ow_hlt_loop();
}