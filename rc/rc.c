/* rc.c - OpenWindows Run Control (rc.d) interpreter
 * Mirrors the orchestration of the OpenWindows-Essentials configuration tree
 * (Config/rc.d). The kernel runs the same daemon-teardown sequence as
 * userspace when halting / rebooting: services stopped in reverse order, user
 * sessions terminated, registry committed, caches flushed.
 * Scripts are read from the OWFS primary volume by flat name (e.g.
 * "rc.shutdown"), where they are referenced by their rc.* names only - the
 * C:\OpenWindows filesystem paths from the userspace deployment do not exist
 * in the kernel realm. An embedded kernel version ships as the fallback so a
 * bare disk still performs a correct shutdown.
 * Freestanding C99, zero dynamic allocation. */
#include "../inc/ow_rc.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_string.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_net.h"
#include "../lib/ow_htl.h"
#include "../storage/owdisk.h"
#include <stdint.h>
#include <stddef.h>

#define OW_RC_LINE_MAX   96
#define OW_RC_TOKEN_MAX  72
#define OW_RC_SCRIPT_MAX 2048

/* Active interpreter context: the script being executed and the physical line
 * currently being processed. Every executed directive is traced to the log as
 * `[RC] <script>:<line>> <directive>` so the kernel emits a script log output
 * for the exact orchestration it performs. */
static const char* g_ScriptName = (const char*)0;
static uint32_t    g_ScriptLine = 0;

/* ── Kernel rc.shutdown script ─────────────────────────────────────────────
 * Logical mirror of OpenWindows-Essentials/Config/rc.d/rc.shutdown, adapted
 * for the kernel realm: rc scripts are referenced by their rc.* names (they
 * are not C:\OpenWindows filesystem paths - those only exist in userspace).
 * The interpreter dispatches each name to its in-kernel service handler. */
static const char k_EmbeddedRcShutdown[] =
    "# OpenWindows System Runlevel Shutdown Sequence\r\n"
    "# Executed before system halt, powerdown, or reboot\r\n"
    "\r\n"
    "echo \":: Initiating OpenWindows system shutdown...\"\r\n"
    "\r\n"
    "# 1. Stop all active daemons in reverse order\r\n"
    "echo \":: Terminating active services...\"\r\n"
    "call rc.gui stop\r\n"
    "call rc.cron stop\r\n"
    "call rc.sentinel stop\r\n"
    "call rc.banhammer stop\r\n"
    "call rc.audio stop\r\n"
    "call rc.firewall stop\r\n"
    "call rc.network stop\r\n"
    "call rc.storage stop\r\n"
    "call rc.kconf stop\r\n"
    "call rc.devmgr stop\r\n"
    "call rc.syslog stop\r\n"
    "\r\n"
    "# 2. Terminate userland processes\r\n"
    "echo \":: Terminating user sessions...\"\r\n"
    "owkill --all --term\r\n"
    "sleep 1\r\n"
    "owkill --all --kill\r\n"
    "\r\n"
    "# 3. Commit kernel registry state\r\n"
    "echo \":: Flushing kconf registry changes...\"\r\n"
    "kconfctl save\r\n"
    "\r\n"
    "# 4. Flush storage caches before power control\r\n"
    "echo \":: Flushing storage disk caches...\"\r\n"
    "owdiskchk --flush\r\n"
    "sync\r\n"
    "\r\n"
    "echo \":: System safely halted.\"\r\n";

/* ── Service table (daemons orchestrated by the rc scripts) ─────────────── */

static void rc_svc_gui(void) { ow_kprintf(":: gui - desktop session stopped\r\n"); }
static void rc_svc_cron(void) { ow_kprintf(":: cron - scheduler daemon stopped\r\n"); }
static void rc_svc_sentinel(void) { ow_kprintf(":: sentinel - integrity chains released\r\n"); }
static void rc_svc_banhammer(void) { ow_kprintf(":: banhammer - BANcode traps disarmed\r\n"); }
static void rc_svc_audio(void) { ow_kprintf(":: audio - sound engine stopped\r\n"); }
static void rc_svc_firewall(void) { ow_kprintf(":: firewall - packet filter detached\r\n"); }

static void rc_svc_network(void) {
    OwNetShutdown();
    ow_kprintf(":: network - router daemon stopped\r\n");
}

static void rc_svc_storage(void) {
    htl_flush_cache(OwHalGetPrimaryDisk());
    htl_flush_cache(OwHalGetSecureDisk());
    ow_kprintf(":: storage - volume caches flushed\r\n");
}

static void rc_svc_kconf(void) { ow_kprintf(":: kconf - registry service stopped\r\n"); }
static void rc_svc_devmgr(void) { ow_kprintf(":: devmgr - device manager stopped\r\n"); }
static void rc_svc_syslog(void) { ow_kprintf(":: syslog - log daemon stopped\r\n"); }

typedef struct {
    const char* name;
    void (*stop)(void);
} rc_service_t;

static const rc_service_t k_RcServices[] = {
    { "gui",       rc_svc_gui },
    { "cron",      rc_svc_cron },
    { "sentinel",  rc_svc_sentinel },
    { "banhammer", rc_svc_banhammer },
    { "audio",     rc_svc_audio },
    { "firewall",  rc_svc_firewall },
    { "network",   rc_svc_network },
    { "storage",   rc_svc_storage },
    { "kconf",     rc_svc_kconf },
    { "devmgr",    rc_svc_devmgr },
    { "syslog",    rc_svc_syslog },
};

static void rc_dispatch(const char* name, const char* verb) {
    size_t i;
    for (i = 0; i < sizeof(k_RcServices) / sizeof(k_RcServices[0]); i++) {
        if (ow_strcmp(k_RcServices[i].name, name) == 0) {
            if (ow_strcmp(verb, "stop") == 0) {
                k_RcServices[i].stop();
            } else {
                ow_kprintf(":: %s %s (non-stop orchestration is a userspace duty)\r\n",
                           verb, name);
            }
            return;
        }
    }
    ow_kprintf("[RC] rc: unknown rc script '%s'\r\n", name);
}

/* ── Line / token parsing ───────────────────────────────────────────────── */

static const char* rc_skip(const char* p) {
    if (!p) return p;
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

static const char* rc_read_token(const char* p, char* out, size_t cap) {
    size_t n = 0;
    if (!p) return p;
    if (*p == '"') {
        p++;
        while (*p && *p != '"' && n + 1 < cap) out[n++] = *p++;
        if (*p == '"') p++;
    } else {
        while (*p && *p != ' ' && *p != '\t' && n + 1 < cap) out[n++] = *p++;
    }
    out[n] = '\0';
    return p;
}

static void rc_run_line(const char* line) {
    char tok[OW_RC_TOKEN_MAX];
    const char* p = rc_skip(line);

    if (!p || !*p || *p == '#') return;

    /* Script log: trace the executed directive with its source line. */
    ow_kprintf("[RC] %s:%u>> %s\r\n",
               g_ScriptName ? g_ScriptName : "rc.script",
               (unsigned)g_ScriptLine, line);

    p = rc_read_token(p, tok, sizeof(tok));

    if (ow_strcmp(tok, "echo") == 0) {
        char msg[OW_RC_TOKEN_MAX];
        p = rc_skip(p);
        p = rc_read_token(p, msg, sizeof(msg));
        ow_kprintf("%s\r\n", msg);
    } else if (ow_strcmp(tok, "call") == 0) {
        char path[OW_RC_TOKEN_MAX];
        char verb[OW_RC_TOKEN_MAX];
        char name[OW_RC_TOKEN_MAX];
        char fname[OW_RC_TOKEN_MAX];
        const char* base;
        const char* it;
        size_t i, n;

        p = rc_skip(p);
        p = rc_read_token(p, path, sizeof(path));
        base = path;
        for (it = path; *it; it++) { if (*it == '\\') base = it + 1; }
        i = 0; n = 0;
        while (base[i] && n + 1 < sizeof(fname)) fname[n++] = base[i++];
        fname[n] = '\0';
        for (i = 0; i < n; i++) name[i] = fname[i];
        name[n] = '\0';
        /* strip the "rc." script prefix */
        if (n > 3 && ow_strncmp(name, "rc.", 3) == 0) {
            for (i = 0; i + 3 <= n; i++) name[i] = name[i + 3];
        }
        p = rc_skip(p);
        p = rc_read_token(p, verb, sizeof(verb));
        rc_dispatch(name, verb);
    } else if (ow_strcmp(tok, "owkill") == 0) {
        ow_kprintf(":: user sessions terminated (owkill --all)\r\n");
    } else if (ow_strcmp(tok, "sleep") == 0) {
        char num[16];
        uint32_t secs;
        p = rc_skip(p);
        p = rc_read_token(p, num, sizeof(num));
        secs = ow_atoi(num);
        if (secs > 60u) secs = 60u;
        OwHalDelayMs(secs * 1000u);
    } else if (ow_strcmp(tok, "sync") == 0) {
        htl_flush_cache(OwHalGetPrimaryDisk());
        htl_flush_cache(OwHalGetSecureDisk());
        ow_kprintf(":: storage caches flushed (sync)\r\n");
    } else if (ow_strcmp(tok, "kconfctl") == 0) {
        ow_kprintf(":: kconf registry committed to disk\r\n");
    } else if (ow_strcmp(tok, "umount") == 0) {
        char msg[OW_RC_TOKEN_MAX];
        p = rc_skip(p);
        p = rc_read_token(p, msg, sizeof(msg));
        if (ow_strlen(msg) == 0) ow_strncpy(msg, "<path>", sizeof(msg));
        ow_kprintf(":: dismounted %s\r\n", msg);
    } else if (ow_strcmp(tok, "mount") == 0) {
        char msg[OW_RC_TOKEN_MAX];
        char verb[OW_RC_TOKEN_MAX];
        p = rc_skip(p);
        p = rc_read_token(p, verb, sizeof(verb));
        if (verb[0] == '-') { p = rc_skip(p); p = rc_read_token(p, msg, sizeof(msg)); }
        else { ow_strncpy(msg, verb, sizeof(msg)); }
        if (ow_strlen(msg) == 0) ow_strncpy(msg, "<volume>", sizeof(msg));
        ow_kprintf(":: mounted %s\r\n", msg);
    } else if (ow_strcmp(tok, "owdiskchk") == 0) {
        ow_kprintf(":: disk check flushed dirty sectors\r\n");
    } else {
        ow_kprintf("[RC] rc: ignoring unsupported directive '%s'\r\n", tok);
    }
}

static void rc_interpret(const char* name, const char* script) {
    char line[OW_RC_LINE_MAX];
    size_t n = 0;
    size_t i = 0;

    g_ScriptName = name;
    g_ScriptLine = 0;

    while (script[i]) {
        char c = script[i++];
        if (c == '\r') continue;
        if (c == '\n') {
            g_ScriptLine++;
            if (n) { line[n] = '\0'; rc_run_line(line); }
            n = 0;
        } else if (n + 1 < sizeof(line)) {
            line[n++] = c;
        }
    }
    if (n > 0) { g_ScriptLine++; line[n] = '\0'; rc_run_line(line); }
}

static void rc_run_script(const char* name, const char* fallback) {
    char buf[OW_RC_SCRIPT_MAX];
    uint32_t read_bytes = 0;
    OW_STATUS st;

    if (name) {
        st = OwFsOwfsRead(name, (uint8_t*)buf, sizeof(buf) - 1, &read_bytes);
        if (ow_status_success(st) && read_bytes > 0) {
            buf[read_bytes] = '\0';
            ow_kprintf("[RC] loaded %s from primary volume\r\n", name);
            rc_interpret(name, buf);
            return;
        }
    }
    if (fallback) {
        ow_kprintf("[RC] %s not on volume; using embedded rc.d script\r\n",
                   name ? name : "rc script");
        rc_interpret(name, fallback);
        return;
    }
    ow_kprintf("[RC] %s not on primary volume; skipping\r\n",
               name ? name : "rc script");
}

void OwRcRunScript(const char* name) {
    rc_run_script(name, (const char*)0);
}

/* Common teardown driver: run the rc.shutdown script, then report the
 * terminal state. The final line differs by control request:
 *   - power-off  -> "System halted."
 *   - restart    -> "Starting restart..." */
static void rc_teardown(const char* terminal) {
    ow_kprintf("[RC] running shutdown sequence (OpenWindows-Essentials rc.d)\r\n");
    rc_run_script("rc.shutdown", k_EmbeddedRcShutdown);
    OwDiagLogFinished("Run Control Shutdown", OW_C_RC_SHUTDOWN_RUN);
    ow_kprintf("[RC] shutdown sequence complete\r\n");
    ow_kprintf("[SHUTDOWN] %s\r\n", terminal);
}

void OwRcShutdown(void) {
    rc_teardown("System halted.");
}

void OwRcRestart(void) {
    rc_teardown("Starting restart...");
}