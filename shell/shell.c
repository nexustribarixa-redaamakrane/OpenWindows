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

/* Current working directory for the navigation commands (pwd/cd/ls/dir).  The
 * shell is one Ring 0 context, so a single inode and its rendered path are
 * enough; there is no per-process CWD.  Root is OWFS inode 0, set explicitly in
 * OwShellInitialize so the value never depends on zero-initialised BSS
 * coincidentally matching the root inode. */
static uint32_t g_CwdInode = 0;
static char     g_CwdPath[256] = "/";

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
    "fs read bootvid.owd",
    /* Regression cover for the testing report's findings.  Every line below is
     * asserted by tools/qemu_run.ps1, so a regression in any of them fails
     * `make qemu` instead of only turning up in a manual session:
     *   pwd/cd/ls     navigation commands, which did not exist before;
     *   ls <dir>      lists the named directory and reports a missing one,
     *                 instead of silently printing the CWD;
     *   write/read    the VFS facade, now the same on-disk truth as `fs`;
     *   fs read       cross-check that a file written through the VFS facade is
     *                 visible to the OWFS path (the original two-stack
     *                 divergence: `write` and `fs` could not see each other);
     *   sucs commit   applies the mode staged by `sucs ext` with no reboot;
     *   alloc         succeeds for a real size, refuses an oversized one, and
     *                 rejects a near-UINT64_MAX size instead of wrapping the
     *                 page count to zero;
     *   status        reports the managed arena and firmware RAM separately. */
    "pwd",
    "cd System",
    "pwd",
    "ls",
    "ls /",          /* the path argument lists the named dir, not the CWD */
    "cd ..",
    "pwd",
    "ls /nope",      /* a missing path is reported, not silently the CWD */
    "write interop.txt via-vfs-facade",
    "read interop.txt",
    "fs read interop.txt",
    "sucs commit",
    "sucs",
    "alloc 33554432",
    "alloc 18446744073709551615", /* near-UINT64_MAX must not wrap to 0 pages */
    "status"};

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
  g_CwdInode = OwFsOwfsRootInode();
  ow_memcpy(g_CwdPath, "/", 2);
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
  ow_kprintf("  alloc <size>      - Allocate kernel frame pages (4 KiB each)\r\n");
  ow_kprintf("  load <path> <tier>- Load driver (1/2/3)\r\n");
  ow_kprintf("  pwd / cwd         - Print the current working directory\r\n");
  ow_kprintf("  cd <dir|..|/>     - Change the current working directory\r\n");
  ow_kprintf("  ls / dir [dir]    - List the current or named directory\r\n");
  ow_kprintf("  write <name> <txt>- Create file in the root VFS catalog\r\n");
  ow_kprintf("  read <name>       - Read file from the root VFS catalog\r\n");
  ow_kprintf("  route <hex>       - Query route table\r\n");
  ow_kprintf("  sucs              - Show SUCS mode\r\n");
  ow_kprintf("  sucs <base|ext>   - Stage SUCS mode switch\r\n");
  ow_kprintf("  sucs commit       - Apply the staged SUCS mode now (no reboot)\r\n");
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
  /* This command exists to *drive* the fatal-fault path on demand so the crash
   * screen, the SMP IPI halt and the halt record can be inspected.  It is a
   * simulation, not evidence that the kernel cannot survive a fault: faults
   * raised by CPL3 code are demand-paged and resumed (see the "[PF] RESOLVED"
   * lines), and this command says so before it halts the shell. */
  ow_kprintf("[TRAP] diagnostic only - injecting Vector %u on purpose to show "
             "the fatal-fault path\r\n", vector);
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

/* Resolve a '/'-separated path against a base directory (or from root when it
 * starts with '/'), walking each component through the OWFS catalog.  The result
 * is written to the caller's out parameters and the shell's current directory is
 * left untouched, so `cd` (which commits the result) and `ls <dir>` (which only
 * reads it) share one resolver.  ".." uses the inode's recorded parent.  Returns
 * false when any component is missing or is not a catalog. */
static bool shell_resolve_path(uint32_t base_inode, const char *base_path,
                               const char *path, uint32_t *out_inode,
                               char *out_path, size_t out_cap) {
  uint32_t inode = base_inode;
  char newpath[sizeof(g_CwdPath)];
  const char *p = path;

  if (!path || *path == '\0' || !out_inode || !out_path || out_cap == 0u)
    return false;

  ow_strncpy(newpath, base_path ? base_path : "/", sizeof(newpath));
  newpath[sizeof(newpath) - 1] = '\0';

  if (*p == '/') {
    inode = OwFsOwfsRootInode();
    ow_strncpy(newpath, "/", sizeof(newpath));
    while (*p == '/')
      p++;
  }

  while (*p) {
    const char *slash = ow_strchr(p, '/');
    size_t len = slash ? (size_t)(slash - p) : ow_strlen(p);
    char comp[128];
    uint32_t next = 0;
    bool is_dir = false;

    if (len == 0) { /* collapse runs of '/' */
      p++;
      continue;
    }
    if (len >= sizeof(comp))
      return false;

    ow_memcpy(comp, p, len);
    comp[len] = '\0';

    if (ow_strcmp(comp, ".") == 0) {
      /* no-op */
    } else if (ow_strcmp(comp, "..") == 0) {
      uint32_t parent = inode;
      if (ow_status_success(OwFsOwfsGetParent(inode, &parent)) &&
          parent != inode) {
        inode = parent;
      } else {
        inode = OwFsOwfsRootInode();
      }
      /* Trim the last component from the rendered path. */
      {
        char *last = newpath + ow_strlen(newpath);
        while (last > newpath && *(last - 1) != '/')
          last--;
        if (last > newpath)
          last--;
        *last = '\0';
        if (newpath[0] == '\0')
          ow_strncpy(newpath, "/", sizeof(newpath));
      }
    } else {
      if (!ow_status_success(OwFsOwfsLookupIn(inode, comp, &next, &is_dir)) ||
          !is_dir)
        return false;
      if (ow_strcmp(newpath, "/") == 0) {
        if (ow_strlen(comp) + 2 > sizeof(newpath))
          return false;
        ow_memcpy(newpath + 1, comp, ow_strlen(comp) + 1);
      } else {
        size_t cur = ow_strlen(newpath);
        size_t n = ow_strlen(comp);
        if (cur + 1 + n + 1 > sizeof(newpath))
          return false;
        newpath[cur] = '/';
        ow_memcpy(newpath + cur + 1, comp, n + 1);
      }
      inode = next;
    }
    p += len;
  }

  ow_strncpy(out_path, newpath, out_cap);
  out_path[out_cap - 1] = '\0';
  *out_inode = inode;
  return true;
}

/* Change the shell's current directory by resolving `path` against it.  Leaves
 * the CWD untouched when the path does not resolve. */
static bool shell_cd_apply(const char *path) {
  uint32_t inode;
  char newpath[sizeof(g_CwdPath)];

  if (!shell_resolve_path(g_CwdInode, g_CwdPath, path, &inode, newpath,
                          sizeof(newpath)))
    return false;

  g_CwdInode = inode;
  ow_strncpy(g_CwdPath, newpath, sizeof(g_CwdPath));
  g_CwdPath[sizeof(g_CwdPath) - 1] = '\0';
  return true;
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
        uint64_t fwb = OwMemFirmwareBytes();
        ow_kprintf("--- SYSTEM STATUS ---\r\n");
        ow_kprintf("Memory (kernel pool): %u / %u pages used (%u MiB 4-KiB "
                   "arena)\r\n",
                   OwMemPagesUsed(), OwMemPagesTotal(),
                   (unsigned)(((uint64_t)OwMemPagesTotal() * OW_PAGE_SIZE) /
                              (1024ULL * 1024ULL)));
        if (fwb != 0u) {
          ow_kprintf("Memory (firmware):    %llu MiB reported by the "
                     "bootloader (%u 4-KiB pages, not managed)\r\n",
                     (unsigned long long)(fwb / (1024ULL * 1024ULL)),
                     OwMemFirmwarePages());
        } else {
          ow_kprintf("Memory (firmware):    unknown (no bootloader memory "
                     "map)\r\n");
        }
        ow_kprintf("VFS Primary:   %s (OWFS)\r\n",
                   OwVfsIsPrimaryMounted() ? "MOUNTED" : "NOT MOUNTED");
        ow_kprintf("VFS Secure:    %s (USFS)\r\n",
                   OwVfsIsSecureMounted() ? "MOUNTED" : "NOT MOUNTED");
        ow_kprintf("CWD:           %s\r\n", g_CwdPath);
      } else if (ow_strcmp(cmd, "pwd") == 0 || ow_strcmp(cmd, "cwd") == 0) {
        ow_kprintf("%s\r\n", g_CwdPath);
      } else if (ow_strcmp(cmd, "ls") == 0 || ow_strcmp(cmd, "dir") == 0) {
        /* Optional directory argument: `ls` lists the CWD, `ls <dir>` lists the
         * named directory.  The argument used to be parsed and then ignored, so
         * `ls /missing` silently printed the CWD; now it resolves the path and
         * reports a miss instead. */
        char *target = ow_strtok((void *)0, " ");
        uint32_t inode = g_CwdInode;
        char path[sizeof(g_CwdPath)];
        ow_strncpy(path, g_CwdPath, sizeof(path));
        path[sizeof(path) - 1] = '\0';
        if (target &&
            !shell_resolve_path(g_CwdInode, g_CwdPath, target, &inode, path,
                                sizeof(path))) {
          ow_kprintf("[FS] ls '%s': no such directory\r\n", target);
        } else {
          uint32_t count = 0;
          OW_STATUS lst = OwFsOwfsListIn(inode, &count);
          if (ow_status_success(lst)) {
            ow_kprintf("[FS] %s: %u entr%s\r\n", path, count,
                       count == 1u ? "y" : "ies");
          } else {
            ow_kprintf("[FS] ls %s: FAILED (code 0x%X)\r\n", path,
                       (unsigned int)lst);
          }
        }
      } else if (ow_strcmp(cmd, "cd") == 0) {
        char *target = ow_strtok((void *)0, " ");
        if (!target) {
          ow_kprintf("%s\r\n", g_CwdPath);
        } else if (shell_cd_apply(target)) {
          ow_kprintf("[FS] cd: %s\r\n", g_CwdPath);
        } else {
          ow_kprintf("[FS] cd: '%s': no such directory\r\n", target);
        }
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
        uint64_t want;
        uint32_t pages;
        uint32_t used;
        uint32_t total;
        uint32_t free_pages;
        uint64_t addr;
        if (!size_str) {
          ow_kprintf("Usage: alloc <bytes>\r\n");
          continue;
        }
        size = ow_strtoull(size_str, (void *)0, 10);
        if (size == 0u) {
          ow_kprintf("[FAIL] alloc: size must be greater than zero\r\n");
          continue;
        }
        /* Rounding up adds (OW_PAGE_SIZE - 1).  Reject sizes where that would
         * wrap before computing the page count: for a near-UINT64_MAX request
         * `size + 4095` wraps to a tiny value, `want` becomes zero, and the
         * allocator reports a bogus zero-page "frame allocator refused" instead
         * of the honest "too large". */
        if (size > (uint64_t)-1 - (uint64_t)(OW_PAGE_SIZE - 1u)) {
          ow_kprintf("[FAIL] alloc %llu bytes: request is too large to size\r\n",
                     (unsigned long long)size);
          continue;
        }
        /* The shell runs at Ring 0, so it takes frames straight from the
         * kernel's own frame arena.  It deliberately does NOT go through
         * OW_SYS_ALLOC: that syscall allocates a private page inside a CPL3
         * process's address space and has no meaning for a caller with no
         * process (which is why every `alloc` used to be rejected). */
        want = (size + (OW_PAGE_SIZE - 1u)) / OW_PAGE_SIZE;
        used = OwMemPagesUsed();
        total = OwMemPagesTotal();
        free_pages = (used < total) ? (total - used) : 0u;
        if (want > (uint64_t)total || want > (uint64_t)free_pages) {
          ow_kprintf("[FAIL] alloc %llu bytes (%llu page(s)): kernel pool "
                     "exhausted (%u of %u 4-KiB pages free)\r\n",
                     (unsigned long long)size, (unsigned long long)want,
                     free_pages, total);
          continue;
        }
        pages = (uint32_t)want;
        addr = OwMemAllocatePages(pages);
        if (addr == 0u) {
          ow_kprintf("[FAIL] alloc %llu bytes (%u page(s)): frame allocator "
                     "refused the request\r\n",
                     (unsigned long long)size, pages);
        } else {
          ow_kprintf("[OK] Allocated %u page(s) (%llu bytes) at 0x%llX; pool "
                     "%u/%u pages used\r\n",
                     pages, (unsigned long long)size,
                     (unsigned long long)addr, OwMemPagesUsed(),
                     OwMemPagesTotal());
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
        OW_STATUS cs;
        if (!name || !text) {
          ow_kprintf("Usage: write <name> <text>\r\n");
          continue;
        }
        cs = OwVfsCreateFile(name, 0);
        if (ow_status_success(cs) || cs == OW_ERR_ALREADY_EXISTS) {
          if (ow_status_success(OwVfsWriteFile(name, (const uint8_t *)text,
                                               (uint32_t)ow_strlen(text)))) {
            ow_kprintf("[OK] Written to '%s'.\r\n", name);
          } else {
            ow_kprintf("[ERROR] Write failed.\r\n");
          }
        } else {
          ow_kprintf("[ERROR] Create failed (code 0x%X).\r\n",
                     (unsigned int)cs);
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
          ow_kprintf("[ERROR] Read failed (missing or empty file).\r\n");
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
          ow_kprintf("[SUCS] request: %s\r\n",
                     mode == 3 ? "staged, reboot required (or 'sucs commit')"
                               : mode == 2 ? "already active"
                                           : mode == 1 ? "invalid mode"
                                                       : "error");
        } else if (ow_strcmp(arg, "ext") == 0) {
          mode = OwSucsRequestModeSwitch(1);
          ow_kprintf("[SUCS] request: %s\r\n",
                     mode == 3 ? "staged, reboot required (or 'sucs commit')"
                               : mode == 2 ? "already active"
                                           : mode == 1 ? "invalid mode"
                                                       : "error");
        } else if (ow_strcmp(arg, "commit") == 0 ||
                   ow_strcmp(arg, "apply") == 0) {
          /* The mode-change library stages a switch and asks for a reboot,
           * because a deployed system applies it from persistent storage on
           * the next boot.  This live test volume is a RAM disk, so a reboot
           * would discard the request (and all other state) before it could be
           * committed.  Committing here applies the staged mode to the running
           * kernel, which is the only way to actually exercise EXTENDED. */
          if (OwSucsCommitNow()) {
            ow_kprintf("[SUCS] committed: active=%s pending=%s reboot=0 "
                       "changes=%u\r\n",
                       OwSucsActiveMode() == 1 ? "EXTENDED" : "BASE",
                       OwSucsPendingMode() == 1 ? "EXTENDED" : "BASE",
                       OwSucsModeChangeCount());
          } else {
            ow_kprintf("[SUCS] nothing to commit (active=%s pending=%s)\r\n",
                       OwSucsActiveMode() == 0 ? "BASE" : "EXTENDED",
                       OwSucsPendingMode() == 0 ? "BASE" : "EXTENDED");
          }
        } else {
          ow_kprintf("Usage: sucs [status|base|ext|commit]\r\n");
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
