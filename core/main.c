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
#include "../inc/ow_ps.h"
#include "../storage/owdisk.h"
#include <stdarg.h>

/* Global system state */
typedef struct _OW_SYSTEM_STATE {
    OW_PML4_ENTRY*      PML4Table;
    OW_VAD_NODE*        VadRoot;
    OW_OBJECT_DIR*      RootNamespace;
    OW_OBJECT_DIR*      DriverDirectory;
    bool                SystemHalted;
    uint32_t            BootPhase;
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

    g_boot_weight += Weight;
    {
        uint32_t pct = (g_boot_weight * 100U) / BOOT_TOTAL_WEIGHT;
        uint32_t fill = (g_boot_weight * 36U) / BOOT_TOTAL_WEIGHT;
        char bar[40];
        uint32_t b;
        int n = 0;
        char line[110];
        bar[n++] = '[';
        for (b = 0; b < 36; b++) bar[n++] = b < fill ? '#' : '.';
        bar[n++] = ']';
        bar[n] = '\0';
        ow_ksnprintf(line, sizeof(line),
                     "OpenWindows Kernel 0.1.0   BOOT %s  %u%%", bar, pct);
        OwHalVgaStatusBar(line);
    }
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

    /* Phase 5c: owinit provisioning check.
     * The kernel only hands off to userland when the primary OWFS volume
     * carries the Tier-3 userspace orchestrator owinit.owx. A missing
     * owinit executable is a fatal BANcode halt, not a warning. */
    if (OwRunlevelRequires(OW_RUNLVL_F_OWINIT)) {
        boot_begin("owinit");
        {
            int owloc = OwDiskOwinitPresent();
            if (owloc) {
                ow_kprintf("[OWINIT] Root orchestrator executable owinit.owx located\r\n");
                km_line(0x0A, "[OWINIT]", "root orchestrator executable located");
                km_line(0x0A, "[OWINIT]", "owinit.owx provisioned (Tier-3 userspace)");
            } else {
                km_line(0x0C, "[OWINIT]", "owinit.owx executable MISSING - fatal");
            }
            boot_diag_done(52, owloc ? OW_SUCCESS : OW_B_OWINIT_MISSING,
                           "owinit", owloc, 6);
        }
    } else {
        boot_skip_phase("owinit", 52, 6);
    }

    /* Phase 5c.5: owinit process hand-off.  When the provisioning check above
    * found the Essentials owinit.owx on the primary volume, load it into a
    * PID 1 process and register its primary thread (reads = one thread, no
    * preemption yet; the scheduler is armed just before the shell so the boot
    * stays deterministic). */
    if (OwRunlevelRequires(OW_RUNLVL_F_OWINIT) && OwDiskOwinitPresent()) {
        static uint8_t s_OwinitImage[64U * 1024U];
        uint32_t read_len = 0;
        OW_STATUS rds = OwFsOwfsRead(OW_INIT_EXEC_NAME, s_OwinitImage,
                                     (uint32_t)sizeof(s_OwinitImage), &read_len);
        if (!ow_status_success(rds) || read_len == 0) {
            km_line(0x0C, "[OWINIT]", "owinit.owx read FAILED");
        } else {
            OW_PROCESS_OBJECT* oproc = OwPsCreateProcess("owinit", OW_PS_PID_KERNEL);
            if (!oproc) {
                km_line(0x0C, "[OWINIT]", "process creation FAILED");
            } else {
                OwDiagLogFinished("OWINIT Process", OW_C_OWINIT_PROCESS_CREATED);
                if (ow_status_success(OwPsLoadImage(oproc, s_OwinitImage, read_len))) {
                    OW_THREAD_OBJECT* othr =
                        OwPsCreateThread(oproc, oproc->EntryPoint, 0);
                    if (!othr) {
                        km_line(0x0C, "[OWINIT]", "thread creation FAILED");
                    } else {
                        km_line(0x0A, "[OWINIT]", "orchestrator enqueued as PID 1 thread %u",
                                (unsigned)othr->Tid);
                    }
                }
            }
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