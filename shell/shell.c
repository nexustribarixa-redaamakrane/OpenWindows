/* shell.c - OpenWindows Debug Shell (Ring 0) */
#include "../inc/ow_acpi.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_ecosys.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_net.h"
#include "../inc/ow_rc.h"
#include "../inc/ow_runlevel.h"
#include "../inc/ow_sentinel.h"
#include "../inc/ow_shell.h"
#include "../inc/ow_string.h"
#include "../inc/ow_syscall.h"
#include "../inc/ow_vfs.h"
#include "../storage/owdisk.h"

static char g_CmdLine[512];
static bool g_ShellRunning = false;
static uint32_t g_AutoIdx = 0;

/* The diagnostics started with the existing test scripts -- help, SUCS mode
 * switches, the UniVIP volume registry, and the OWFS store bring-up -- are now
 * part of the kernel itself: right after boot the shell (as init) runs them
 * automatically. Nothing has to be typed in from outside; the transcript below
 * is produced by the kernel source alone. */
static const char *const k_InitScript[] = {
    "help",
    "status",
    "runlevel",
    "runlevel list",
    "runlevel features",
    "alloc 4096",
    "sucs",
    "sucs ext",
    "sucs",
    "vip mount 1 131200 kernel",
    "vip resolve 1",
    "vip index /boot/bootvid.owd 12 3",
    "vip lookup /boot/bootvid.owd",
    "vip lookup /nope",
    "vip verify",
    "fs format OWINIT",
    "fs mount",
    "fs mkdir System",
    "fs create bootvid.owd",
    "fs write bootvid.owd OpenWindows storage live",
    "fs read bootvid.owd",
    "fs list",
    "fs status",
    "fs umount",
    "fs mount",
    "fs read bootvid.owd"};

static const uint32_t k_InitScriptCount =
    (uint32_t)(sizeof(k_InitScript) / sizeof(k_InitScript[0]));

/* Return the raw remainder of the line after a token (spaces intact). */
static char *shell_tail_after(const char *token) {
  const char *end;
  if (!token)
    return (void *)0;
  end = token + ow_strlen(token);
  if (end < &g_CmdLine[sizeof(g_CmdLine) - 1] && *end == '\0')
    end++;
  return (char *)end;
}

static void shell_read_line(void) {
  uint32_t pos = 0;
  while (1) {
    char c;
    if (OwHalUartCanRead()) {
      c = OwHalUartReadChar();
    } else if (OwHalKbdCanRead()) {
      c = OwHalKbdReadChar();
    } else {
      continue;
    }
    if (c == '\r' || c == '\n') {
      OwHalUartWriteChar('\r');
      OwHalUartWriteChar('\n');
      break;
    }
    if (c == 0x08 || c == 0x7F) {
      if (pos > 0) {
        pos--;
        OwHalUartWriteChar('\b');
        OwHalUartWriteChar(' ');
        OwHalUartWriteChar('\b');
      }
      continue;
    }
    if (pos < sizeof(g_CmdLine) - 1) {
      g_CmdLine[pos++] = c;
      OwHalUartWriteChar(c);
    }
  }
  g_CmdLine[pos] = '\0';
}

OW_STATUS OwShellInitialize(void) {
  /* Auto-detect the PS/2 keyboard; UART remains the fallback input. */
  (void)OwHalKbdInitialize();
  return OW_SUCCESS;
}

void OwShellPrintBanner(void) {
  ow_kprintf("\r\n");
  ow_kprintf("================================================================="
             "=======\r\n");
  ow_kprintf("            OpenWindows DEBUG SYSTEM CONTROL SHELL\r\n");
  ow_kprintf("================================================================="
             "=======\r\n");
}

void OwShellPrintHelp(void) {
  ow_kprintf("Commands:\r\n");
  ow_kprintf("  help              - Display this menu\r\n");
  ow_kprintf("  status            - Dump system state\r\n");
  ow_kprintf("  runlevel          - Show current runlevel & config\r\n");
  ow_kprintf("  runlevel list     - List all runlevel profiles (-6..6)\r\n");
  ow_kprintf("  runlevel features - Show armed feature set\r\n");
  ow_kprintf("  runlevel set <n>  - Switch runlevel (-6..6)\r\n");
  ow_kprintf("  alloc <size>      - Allocate virtual memory\r\n");
  ow_kprintf("  load <path> <tier>- Load driver (1/2/3)\r\n");
  ow_kprintf("  write <name> <txt>- Create file on VFS\r\n");
  ow_kprintf("  read <name>       - Read file from VFS\r\n");
  ow_kprintf("  route <hex>       - Query route table\r\n");
  ow_kprintf("  sucs              - Show SUCS mode\r\n");
  ow_kprintf("  sucs <base|ext>   - Stage SUCS mode switch\r\n");
  ow_kprintf("  vip mount <vol> <sector> <label> - Register volume\r\n");
  ow_kprintf("  vip resolve <vol> - Resolve volume base LBA\r\n");
  ow_kprintf("  vip index <path> <sector> <flags> - Insert FVIP entry\r\n");
  ow_kprintf("  vip lookup <path> - Lookup FVIP entry\r\n");
  ow_kprintf("  vip verify        - Verify FVIP index integrity\r\n");
  ow_kprintf("  fs format [label] - Format OWFS primary volume\r\n");
  ow_kprintf("  fs mount          - Mount OWFS primary volume\r\n");
  ow_kprintf("  fs umount         - Unmount OWFS primary volume\r\n");
  ow_kprintf("  fs mkdir <name>   - Create catalog in root\r\n");
  ow_kprintf("  fs create <name>  - Create file in root\r\n");
  ow_kprintf("  fs write <name> <txt> - Write file in root\r\n");
  ow_kprintf("  fs read <name>    - Read root file\r\n");
  ow_kprintf("  fs list           - List root catalog (OWFS)\r\n");
  ow_kprintf("  fs status         - OWFS/USFS volume status\r\n");
  ow_kprintf("  trap <vector>     - CPU exception trap "
             "(#DE/#GP/#PF/#UD/#SS/#DF/#BP)\r\n");
  ow_kprintf("  nuke <hex>        - Manual KeDropBanHammer\r\n");
  ow_kprintf(
      "  shutdown/poweroff - RC shutdown sequence then ACPI S5 power-off\r\n");
  ow_kprintf(
      "  reboot            - RC shutdown sequence then software reset\r\n");
  ow_kprintf("  acpi              - Show ACPI firmware-table status\r\n");
  ow_kprintf("  exit              - Shutdown kernel (RC sequence + ACPI "
             "power-off)\r\n");
  ow_kprintf("================================================================="
             "=======\r\n\r\n");
}

static void execute_trap(const char *name, uint32_t vector, const char *desc) {
  ow_kprintf("[TRAP] CPU Hardware Exception Vector %u (%s): %s\r\n", vector,
             name, desc);
  OwHalCrashScreen(name, vector);
  ow_kprintf("\r\nCRITICAL ERROR CODE: U+%08X (%s)\r\n", (unsigned)vector,
             name);
  ow_kprintf("COMPONENT: CPU Interrupt & Trap Gateway\r\n");
  ow_kprintf("REASON: %s\r\n", desc);
  ow_kprintf("STATE DUMP: Registers frozen. SMP cores halted via IPI.\r\n");
  OwHalSmpHaltIPI();
  g_ShellRunning = false;
}

OW_STATUS OwShellRun(void) {
  g_ShellRunning = true;
  g_AutoIdx = 0;

  OwShellPrintBanner();
  OwShellPrintHelp();

  while (g_ShellRunning) {
    /* Kernel auto-init: at full-feature runlevels the init script
     * ("ow-krnl> ..." echoed straight from source) runs the boot
     * diagnostics themselves. Recovery levels skip it and drop
     * straight to the interactive prompt. */
    if (g_AutoIdx < k_InitScriptCount) {
      int full = OwRunlevelRequires(OW_RUNLVL_F_VFS) &&
                 OwRunlevelRequires(OW_RUNLVL_F_VIP) &&
                 OwRunlevelRequires(OW_RUNLVL_F_NETWORK);
      if (!full) {
        g_AutoIdx = k_InitScriptCount;
        continue;
      }
      ow_kprintf("ow-krnl> %s\r\n", k_InitScript[g_AutoIdx]);
      if (ow_strlen(k_InitScript[g_AutoIdx]) < sizeof(g_CmdLine)) {
        ow_memcpy(g_CmdLine, k_InitScript[g_AutoIdx],
                  ow_strlen(k_InitScript[g_AutoIdx]) + 1);
      }
      g_AutoIdx++;
    } else {
      ow_kprintf("ow-krnl> ");
      shell_read_line();
    }

    if (ow_strlen(g_CmdLine) == 0)
      continue;

    {
      char *cmd = ow_strtok(g_CmdLine, " ");
      if (!cmd)
        continue;

      if (ow_strcmp(cmd, "help") == 0) {
        OwShellPrintHelp();
      } else if (ow_strcmp(cmd, "exit") == 0) {
        ow_kprintf("[SHUTDOWN] Exiting...\r\n");
        g_ShellRunning = false;
      } else if (ow_strcmp(cmd, "status") == 0) {
        ow_kprintf("--- SYSTEM STATUS ---\r\n");
        ow_kprintf("Memory Pages: %u / %u used\r\n", OwMemPagesUsed(),
                   OwMemPagesTotal());
        ow_kprintf("VFS Primary:   %s\r\n",
                   OwVfsIsPrimaryMounted() ? "MOUNTED" : "NOT MOUNTED");
        ow_kprintf("VFS Secure:    %s\r\n",
                   OwVfsIsSecureMounted() ? "MOUNTED" : "NOT MOUNTED");
      } else if (ow_strcmp(cmd, "runlevel") == 0) {
        char *sub = ow_strtok((void *)0, " ");
        const OW_RUNLEVEL_DEF *rl = OwRunlevelCurrent();
        if (!sub || ow_strcmp(sub, "status") == 0) {
          if (rl) {
            ow_kprintf("[RUNLVL] current=%d (%s) target=%d transitions=%u\r\n",
                       rl->Level, rl->Name, OwRunlevelGetTarget(),
                       OwRunlevelTransitions());
            ow_kprintf("[RUNLVL] config: verbosity=%u watchdogMs=%u heapKB=%u "
                       "maxHandles=%u\r\n",
                       rl->LogVerbosity, rl->WatchdogMs, rl->HeapBudgetKB,
                       rl->MaxHandles);
          }
          OwRunlevelPrintFeatures();
        } else if (ow_strcmp(sub, "list") == 0) {
          OwRunlevelPrintTable();
        } else if (ow_strcmp(sub, "features") == 0) {
          OwRunlevelPrintFeatures();
        } else if (ow_strcmp(sub, "set") == 0) {
          char *n = ow_strtok((void *)0, " ");
          int32_t level;
          OW_STATUS rst;
          if (!n) {
            ow_kprintf("Usage: runlevel set <-6..6>\r\n");
            continue;
          }
          level = (int32_t)ow_atoi(n);
          rst = OwRunlevelSet(level);
          ow_kprintf("[RUNLVL] set %d: %s\r\n", level,
                     ow_status_success(rst) ? "accepted" : "rejected");
        } else {
          ow_kprintf("Usage: runlevel [status|list|features|set <level>]\r\n");
        }
      } else if (ow_strcmp(cmd, "alloc") == 0) {
        char *size_str = ow_strtok((void *)0, " ");
        uint64_t size;
        int64_t addr;
        if (!size_str) {
          ow_kprintf("Error: Missing size.\r\n");
          continue;
        }
        size = ow_strtoull(size_str, (void *)0, 10);
        addr = OwSyscallDispatch(OW_SYS_ALLOC, size, 0, 0);
        if (addr != -1) {
          ow_kprintf("[OK] Allocated at 0x%llX\r\n", (unsigned long long)addr);
        } else {
          ow_kprintf("[FAIL] Allocation rejected.\r\n");
        }
      } else if (ow_strcmp(cmd, "load") == 0) {
        char *path = ow_strtok((void *)0, " ");
        char *tier_str = ow_strtok((void *)0, " ");
        uint32_t tier;
        if (!path || !tier_str) {
          ow_kprintf("Usage: load <path> <tier>\r\n");
          continue;
        }
        tier = ow_atoi(tier_str);
        if (tier < 1 || tier > 3) {
          ow_kprintf("Error: Tier must be 1, 2, or 3.\r\n");
          continue;
        }
        if (ow_status_success(
                OwSentinelValidateDriver(path, (OW_DRIVER_TIER)tier))) {
          ow_kprintf("[OK] Driver '%s' loaded into Tier %u.\r\n", path, tier);
        } else {
          OwDiagBanHammer(OW_B_TIER_EXTENSION_VIOLATION, "fltrmgr",
                          "Unauthorized driver");
        }
      } else if (ow_strcmp(cmd, "write") == 0) {
        char *name = ow_strtok((void *)0, " ");
        char *text = shell_tail_after(name);
        if (!name || !text) {
          ow_kprintf("Usage: write <name> <text>\r\n");
          continue;
        }
        if (ow_status_success(OwVfsCreateFile(name, 0))) {
          if (ow_status_success(OwVfsWriteFile(name, (const uint8_t *)text,
                                               (uint32_t)ow_strlen(text)))) {
            ow_kprintf("[OK] Written to '%s'.\r\n", name);
          } else {
            ow_kprintf("[ERROR] Write failed.\r\n");
          }
        } else {
          ow_kprintf("[ERROR] Create failed.\r\n");
        }
      } else if (ow_strcmp(cmd, "read") == 0) {
        char *name = ow_strtok((void *)0, " ");
        uint8_t buf[1024];
        uint32_t n;
        if (!name) {
          ow_kprintf("Usage: read <name>\r\n");
          continue;
        }
        ow_memset(buf, 0, sizeof(buf));
        n = OwVfsReadFile(name, buf, sizeof(buf) - 1);
        if (n > 0) {
          ow_kprintf("[OK] Read %u bytes:\r\n", n);
          ow_kprintf("---\r\n%s\r\n---\r\n", (char *)buf);
        } else {
          ow_kprintf("[ERROR] File not found.\r\n");
        }
      } else if (ow_strcmp(cmd, "route") == 0) {
        char *addr_str = ow_strtok((void *)0, " ");
        uint64_t addr;
        uint32_t iface = 0;
        uint64_t next_hop = 0;
        if (!addr_str) {
          ow_kprintf("Usage: route <44bit_hex>\r\n");
          continue;
        }
        addr = ow_strtoull(addr_str, (void *)0, 16);
        if (ow_status_success(OwNetLookupRoute(addr, &iface, &next_hop))) {
          ow_kprintf("[ROUTE] Interface: %u, NextHop: 0x%llX\r\n", iface,
                     (unsigned long long)next_hop);
        } else {
          ow_kprintf("[ROUTE] No match for 0x%llX\r\n",
                     (unsigned long long)addr);
        }
      } else if (ow_strcmp(cmd, "sucs") == 0) {
        char *arg = ow_strtok((void *)0, " ");
        int mode;
        if (!arg || ow_strcmp(arg, "status") == 0) {
          ow_kprintf("[SUCS] active=%s pending=%s reboot=%u changes=%u\r\n",
                     OwSucsActiveMode() == 0
                         ? "BASE"
                         : (OwSucsActiveMode() == 1 ? "EXTENDED" : "?"),
                     OwSucsPendingMode() == 0
                         ? "BASE"
                         : (OwSucsPendingMode() == 1 ? "EXTENDED" : "?"),
                     OwSucsIsRebootRequired() ? 1 : 0, OwSucsModeChangeCount());
        } else if (ow_strcmp(arg, "base") == 0) {
          mode = OwSucsRequestModeSwitch(0);
          ow_kprintf("[SUCS] request: %s\r\n", mode == 3
                                                   ? "staged, reboot required"
                                               : mode == 2 ? "already active"
                                               : mode == 1 ? "invalid mode"
                                                           : "error");
        } else if (ow_strcmp(arg, "ext") == 0) {
          mode = OwSucsRequestModeSwitch(1);
          ow_kprintf("[SUCS] request: %s\r\n", mode == 3
                                                   ? "staged, reboot required"
                                               : mode == 2 ? "already active"
                                               : mode == 1 ? "invalid mode"
                                                           : "error");
        } else {
          ow_kprintf("Usage: sucs [status|base|ext]\r\n");
        }
      } else if (ow_strcmp(cmd, "vip") == 0) {
        char *sub = ow_strtok((void *)0, " ");
        uint32_t code;
        if (!sub) {
          ow_kprintf("Usage: vip <mount|resolve|index|lookup|verify>\r\n");
          continue;
        }
        if (ow_strcmp(sub, "mount") == 0) {
          char *v = ow_strtok((void *)0, " ");
          char *s = ow_strtok((void *)0, " ");
          char *l = ow_strtok((void *)0, " ");
          if (!v || !s || !l) {
            ow_kprintf("Usage: vip mount <vol> <sector> <label>\r\n");
            continue;
          }
          code = OwVipRegisterVolume((uint32_t)ow_strtoull(v, (void *)0, 10),
                                     ow_strtoull(s, (void *)0, 10), l);
          ow_kprintf("[VIP] mount code 0x%X\r\n", code);
        } else if (ow_strcmp(sub, "resolve") == 0) {
          char *v = ow_strtok((void *)0, " ");
          uint64_t base = 0;
          if (!v) {
            ow_kprintf("Usage: vip resolve <vol>\r\n");
            continue;
          }
          code = OwVipResolveVolume((uint32_t)ow_strtoull(v, (void *)0, 10),
                                    &base);
          if (OwVipIsSuccessCode(code)) {
            ow_kprintf("[VIP] volume %u base LBA %llu\r\n",
                       (unsigned int)ow_strtoull(v, (void *)0, 10),
                       (unsigned long long)base);
          } else {
            ow_kprintf("[VIP] resolve failed code 0x%X\r\n", code);
          }
        } else if (ow_strcmp(sub, "index") == 0) {
          char *p = ow_strtok((void *)0, " ");
          char *so = ow_strtok((void *)0, " ");
          char *fl = ow_strtok((void *)0, " ");
          if (!p || !so || !fl) {
            ow_kprintf("Usage: vip index <path> <sector> <flags>\r\n");
            continue;
          }
          code = OwVipIndexInsert(p, ow_strtoull(so, (void *)0, 10),
                                  (uint32_t)ow_strtoull(fl, (void *)0, 16));
          ow_kprintf("[VIP] index code 0x%X (entries=%d)\r\n", code,
                     OwVipIndexEntryCount());
        } else if (ow_strcmp(sub, "lookup") == 0) {
          char *p = ow_strtok((void *)0, " ");
          uint64_t so = 0;
          uint32_t fl = 0;
          if (!p) {
            ow_kprintf("Usage: vip lookup <path>\r\n");
            continue;
          }
          code = OwVipIndexLookup(p, &so, &fl);
          if (OwVipIsSuccessCode(code)) {
            ow_kprintf("[VIP] '%s' sector_offset=%llu flags=0x%X\r\n", p,
                       (unsigned long long)so, fl);
          } else {
            ow_kprintf("[VIP] lookup miss code 0x%X\r\n", code);
          }
        } else if (ow_strcmp(sub, "verify") == 0) {
          code = OwVipVerifyIndex();
          ow_kprintf("[VIP] integrity code 0x%X (entries=%d)\r\n", code,
                     OwVipIndexEntryCount());
        } else {
          ow_kprintf("Unknown vip subcommand.\r\n");
        }
      } else if (ow_strcmp(cmd, "fs") == 0) {
        char *sub = ow_strtok((void *)0, " ");
        OW_STATUS st;
        if (!sub) {
          ow_kprintf(
              "Usage: fs "
              "<format|mount|umount|mkdir|create|write|read|list|status>\r\n");
          continue;
        }
        if (ow_strcmp(sub, "format") == 0) {
          char *label = ow_strtok((void *)0, " ");
          if (!label)
            label = (char *)"OWINIT";
          st = OwFsOwfsFormat((const uint8_t *)label,
                              (uint32_t)ow_strlen(label));
          ow_kprintf("[FS] format: %s (code 0x%X)\r\n",
                     ow_status_success(st) ? "OK" : "FAILED", (unsigned int)st);
        } else if (ow_strcmp(sub, "mount") == 0) {
          st = OwFsOwfsMount();
          ow_kprintf("[FS] owfs mount: %s (code 0x%X)\r\n",
                     ow_status_success(st) ? "OK" : "FAILED", (unsigned int)st);
        } else if (ow_strcmp(sub, "umount") == 0) {
          st = OwFsOwfsUnmount();
          ow_kprintf("[FS] owfs umount: %s (code 0x%X)\r\n",
                     ow_status_success(st) ? "OK" : "FAILED", (unsigned int)st);
        } else if (ow_strcmp(sub, "mkdir") == 0) {
          char *n = ow_strtok((void *)0, " ");
          uint32_t ino = 0;
          if (!n) {
            ow_kprintf("Usage: fs mkdir <name>\r\n");
            continue;
          }
          st = OwFsOwfsMkdir(n, &ino);
          ow_kprintf("[FS] mkdir '%s': %s (ino %u, code 0x%X)\r\n", n,
                     ow_status_success(st) ? "OK" : "FAILED", ino,
                     (unsigned int)st);
        } else if (ow_strcmp(sub, "create") == 0) {
          char *n = ow_strtok((void *)0, " ");
          uint32_t ino = 0;
          if (!n) {
            ow_kprintf("Usage: fs create <name>\r\n");
            continue;
          }
          st = OwFsOwfsCreate(n, &ino);
          ow_kprintf("[FS] create '%s': %s (ino %u, code 0x%X)\r\n", n,
                     ow_status_success(st) ? "OK" : "FAILED", ino,
                     (unsigned int)st);
        } else if (ow_strcmp(sub, "write") == 0) {
          char *n = ow_strtok((void *)0, " ");
          char *t = shell_tail_after(n);
          if (!n || !t) {
            ow_kprintf("Usage: fs write <name> <text>\r\n");
            continue;
          }
          st = OwFsOwfsWrite(n, (const uint8_t *)t, (uint32_t)ow_strlen(t));
          ow_kprintf("[FS] write '%s': %s (code 0x%X)\r\n", n,
                     ow_status_success(st) ? "OK" : "FAILED", (unsigned int)st);
        } else if (ow_strcmp(sub, "read") == 0) {
          char *n = ow_strtok((void *)0, " ");
          uint8_t buf[512];
          uint32_t got = 0;
          if (!n) {
            ow_kprintf("Usage: fs read <name>\r\n");
            continue;
          }
          ow_memset(buf, 0, sizeof(buf));
          st = OwFsOwfsRead(n, buf, sizeof(buf) - 1, &got);
          if (ow_status_success(st)) {
            ow_kprintf("[FS] read '%s' (%u bytes):\r\n---\r\n%s\r\n---\r\n", n,
                       got, (char *)buf);
          } else {
            ow_kprintf("[FS] read '%s': FAILED (code 0x%X)\r\n", n,
                       (unsigned int)st);
          }
        } else if (ow_strcmp(sub, "list") == 0) {
          uint32_t count = 0;
          st = OwFsOwfsList(&count);
          ow_kprintf("[FS] list root: %s (%u entries)\r\n",
                     ow_status_success(st) ? "OK" : "FAILED", count);
        } else if (ow_strcmp(sub, "status") == 0) {
          ow_kprintf("[FS] OWFS: %s  free blocks: %u\r\n",
                     OwDiskOwfsMounted() ? "MOUNTED" : "DETACHED",
                     (unsigned int)OwFsOwfsFreeBlocks());
          ow_kprintf("[FS] USFS: %s  free blocks: %u\r\n",
                     OwDiskUsfsMounted() ? "MOUNTED" : "DETACHED",
                     (unsigned int)OwFsUsfsFreeBlocks());
        } else {
          ow_kprintf("Unknown fs subcommand.\r\n");
        }
      } else if (ow_strcmp(cmd, "trap") == 0) {
        char *type = ow_strtok((void *)0, " ");
        if (!type) {
          ow_kprintf("Usage: trap <div0|gp|pf|ud|ss|df|bp>\r\n");
          ow_kprintf("  div0 - #DE (Vector 0: Divide Error)\r\n");
          ow_kprintf("  bp   - #BP (Vector 3: Breakpoint)\r\n");
          ow_kprintf("  ud   - #UD (Vector 6: Invalid Opcode)\r\n");
          ow_kprintf("  df   - #DF (Vector 8: Double Fault)\r\n");
          ow_kprintf("  ss   - #SS (Vector 12: Stack-Segment Fault)\r\n");
          ow_kprintf("  gp   - #GP (Vector 13: General Protection Fault)\r\n");
          ow_kprintf("  pf   - #PF (Vector 14: Page Fault)\r\n");
          continue;
        }
        if (ow_strcmp(type, "div0") == 0 || ow_strcmp(type, "de") == 0) {
          execute_trap("Divide Error", 0x00000000U,
                       "Divide by zero fault (#DE)");
        } else if (ow_strcmp(type, "gp") == 0 || ow_strcmp(type, "gpf") == 0) {
          execute_trap("General Protection", 0x0000000DU,
                       "General protection fault (#GP)");
        } else if (ow_strcmp(type, "pf") == 0 ||
                   ow_strcmp(type, "pagefault") == 0) {
          execute_trap("Page Fault", 0x0000000EU,
                       "Unmapped page translation fault (#PF)");
        } else if (ow_strcmp(type, "ud") == 0 || ow_strcmp(type, "ud2") == 0 ||
                   ow_strcmp(type, "invalid") == 0) {
          execute_trap("Invalid Opcode", 0x00000006U,
                       "Undefined instruction (#UD / ud2)");
        } else if (ow_strcmp(type, "ss") == 0 ||
                   ow_strcmp(type, "stack") == 0) {
          execute_trap("Stack-Segment Fault", 0x0000000CU,
                       "Stack-segment or alignment violation (#SS)");
        } else if (ow_strcmp(type, "df") == 0 ||
                   ow_strcmp(type, "doublefault") == 0) {
          execute_trap("Double Fault", 0x00000008U,
                       "Double fault exception (#DF)");
        } else if (ow_strcmp(type, "bp") == 0 || ow_strcmp(type, "int3") == 0) {
          execute_trap("Breakpoint", 0x00000003U,
                       "Breakpoint trap (#BP / int3)");
        } else if (ow_strcmp(type, "of") == 0 || ow_strcmp(type, "into") == 0) {
          execute_trap("Overflow", 0x00000004U, "Overflow trap (#OF / into)");
        } else {
          ow_kprintf(
              "Unknown trap type '%s'. Type 'trap' for available vectors.\r\n",
              type);
        }
      } else if (ow_strcmp(cmd, "nuke") == 0) {
        char *code_str = ow_strtok((void *)0, " ");
        uint32_t code;
        if (!code_str) {
          ow_kprintf("Usage: nuke <bancode_hex>\r\n");
          continue;
        }
        code = (uint32_t)ow_strtoull(code_str, (void *)0, 16);
        OwDiagBanHammer(code, "shell", "Manual nuke");
      } else if (ow_strcmp(cmd, "shutdown") == 0 ||
                 ow_strcmp(cmd, "poweroff") == 0 ||
                 ow_strcmp(cmd, "power") == 0) {
        ow_kprintf("[SHUTDOWN] poweroff requested\r\n");
        OwRcShutdown();
        OwAcpiPowerOff();
      } else if (ow_strcmp(cmd, "reboot") == 0 ||
                 ow_strcmp(cmd, "reset") == 0) {
        ow_kprintf("[SHUTDOWN] restart requested\r\n");
        OwRcRestart();
        OwAcpiReset();
      } else if (ow_strcmp(cmd, "acpi") == 0) {
        OwAcpiStatus();
      } else if (ow_strcmp(cmd, "safeoff") == 0) {
        /* Secret command: not listed in help. The switch is only
         * usable through the Ring 3 system-call gateway; the kernel
         * never arms the soft power-off screen on its own. */
        char *state = ow_strtok((void *)0, " ");
        bool enable;
        if (!state) {
          ow_kprintf("Usage: safeoff <on|off>\r\n");
          continue;
        }
        enable = (ow_strcmp(state, "on") == 0);
        if (ow_status_success(OwApiSetSafePowerOffScreen(enable))) {
          ow_kprintf("[ACPI] safe power-off screen: %s\r\n",
                     enable ? "armed" : "disarmed");
        } else {
          ow_kprintf(
              "[ACPI] gateway rejected safe power-off screen request\r\n");
        }
      } else if (ow_strcmp(cmd, "autoreboot") == 0) {
        /* Usermode-only crash screen autoreboot control. */
        char *state = ow_strtok((void *)0, " ");
        bool enable;
        if (!state) {
          ow_kprintf("Usage: autoreboot <on|off>\r\n");
          continue;
        }
        enable = (ow_strcmp(state, "on") == 0 || ow_strcmp(state, "1") == 0 ||
                  ow_strcmp(state, "enable") == 0 || ow_strcmp(state, "true") == 0);
        if (ow_status_success(OwApiSetAutoReboot(enable))) {
          ow_kprintf("[CRASH] autoreboot: %s\r\n", enable ? "enabled" : "disabled");
        } else {
          ow_kprintf("[CRASH] gateway rejected autoreboot request\r\n");
        }
      } else if (ow_strcmp(cmd, "kdump") == 0) {
        /* Usermode-only crash screen kdump control. */
        char *state = ow_strtok((void *)0, " ");
        bool enable;
        if (!state) {
          ow_kprintf("Usage: kdump <on|off>\r\n");
          continue;
        }
        enable = (ow_strcmp(state, "on") == 0 || ow_strcmp(state, "1") == 0 ||
                  ow_strcmp(state, "enable") == 0 || ow_strcmp(state, "true") == 0);
        if (ow_status_success(OwApiSetKdump(enable))) {
          ow_kprintf("[CRASH] kdump: %s\r\n", enable ? "enabled" : "disabled");
        } else {
          ow_kprintf("[CRASH] gateway rejected kdump request\r\n");
        }
      } else {
        ow_kprintf("Unknown command. Type 'help'.\r\n");
      }
    }
  }
  return OW_SUCCESS;
}
