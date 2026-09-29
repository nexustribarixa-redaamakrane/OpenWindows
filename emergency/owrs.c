/* owrs.c - OpenWindows rescue shell (.owx)
 *
 * The interactive half of the emergency userspace.  owinitv.owx starts this
 * image; from here on it is a plain user-mode program on a plain user-mode
 * kernel gateway, and everything it can do, any .owx on the volume can do.
 *
 * Its job is to be useful on a machine whose primary orchestrator is missing or
 * corrupt.  That constrains the command set more than it sounds like it should:
 * almost every diagnostic an operator would reach for -- drivers, services, the
 * window manager, the filesystem driver -- did not come up, because none of them
 * run in a degraded boot.  So the shell does not pretend.  It can report what it
 * is, report the PIDs alive, load another image from the volume, and get out of
 * the way.  A `ps` that lists nothing would be worse than no `ps`, because it
 * looks like an answer.
 *
 * C99 freestanding.  Zero heap, zero imports, zero libc. */

#include "ow_gate.h"

void* memcpy(void* dst, const void* src, unsigned long n);
void* memset(void* s, int c, unsigned long n);

void* memcpy(void* dst, const void* src, unsigned long n) {
    unsigned char*       d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    unsigned long        i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void* memset(void* s, int c, unsigned long n) {
    unsigned char* p = (unsigned char*)s;
    unsigned long  i;
    for (i = 0; i < n; i++) p[i] = (unsigned char)c;
    return s;
}

/* ---- line buffer --------------------------------------------------------- */

#define LINE_MAX 64

static char g_line[LINE_MAX];
static int  g_len;

/* Ticks owrs has been alive.  Counted in ow_gate_sleep units, so it is 10 ms per
 * tick; the uptime command multiplies rather than storing a clock, because the
 * only time source a CPL3 program can see is the one it asks the scheduler for. */
static uint64_t g_ticks;

static void put_num(uint64_t v) {
    char digits[20];
    int  n = 0;

    if (v == 0) {
        ow_gate_putc('0');
        return;
    }
    while (v != 0 && n < (int)sizeof(digits)) {
        digits[n++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    while (n-- > 0) ow_gate_putc(digits[n]);
}

/* Case-insensitive compare, ASCII only.  The shell's vocabulary is lower case
 * and there is no locale, so anything else would be a dependency this image
 * cannot have. */
static int streq(const char* a, const char* b) {
    while (*a && *b) {
        char ca = *a++;
        char cb = *b++;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return *a == *b;
}

static int starts_with(const char* s, const char* prefix) {
    while (*prefix) {
        if (*s++ != *prefix) return 0;
        prefix++;
    }
    return 1;
}

static void print(const char* s) {
    ow_gate_puts(s);
}

/* ---- commands ------------------------------------------------------------ */

static void cmd_help(void) {
    print(" Commands:\r\n");
    print("   help          this list\r\n");
    print("   who           what is running on this machine\r\n");
    print("   uptime        seconds since the rescue shell started\r\n");
    print("   spawn <image> load <image>.owx from the boot volume, e.g.\r\n");
    print("                 'spawn owinit' -- the loader will refuse it if\r\n");
    print("                 the file is missing or fails its checksums\r\n");
    print("   exit          leave the rescue shell\r\n");
    print("\r\n");
    print(" Not available, and not faked: driver, service and filesystem\r\n");
    print(" diagnostics. None of those subsystems came up in a degraded boot.\r\n");
}

static void cmd_who(void) {
    print(" OpenWindows emergency userspace\r\n");
    print("   PID 1  owinitv   volatile init (entered by the kernel)\r\n");
    print("   PID ");
    put_num((uint64_t)ow_gate_getpid());
    print("  owrs      this rescue shell\r\n");
    print(" Boot state: DEGRADED -- no orchestrator, no services.\r\n");
}

static void cmd_uptime(void) {
    /* 100 Hz tick, so 100 ticks is one second. */
    put_num(g_ticks / 100u);
    print(" second");
    if (g_ticks / 100u != 1u) print("s");
    print(" since the rescue shell started.\r\n");
}

/* Does `s` end with `suffix`? */
static int ends_with(const char* s, const char* suffix) {
    int sl = 0;
    int xl = 0;

    while (s[sl]) sl++;
    while (suffix[xl]) xl++;
    if (sl < xl) return 0;
    s += sl - xl;
    while (xl--) {
        if (*s++ != *suffix++) return 0;
    }
    return 1;
}

/* spawn <image>
 *
 * The most useful thing a rescue shell can do, because it is the one operation
 * that needs no subsystem: the kernel's loader and the OWFS read are both always
 * present, so any image on the volume can be entered without having brought
 * anything else up first.
 *
 * The name is taken as given and ".owx" is appended if the caller left it off,
 * since the catalog lookup is by full filename and a half-typed name that returns
 * -1 is indistinguishable from a corrupt image. */
static void cmd_spawn(const char* arg) {
    char        name[LINE_MAX];
    int         n = 0;
    const char* p = arg;
    int64_t     pid;

    while (*p == ' ') p++;
    if (*p == '\0') {
        print(" usage: spawn <image>\r\n");
        return;
    }

    while (*p && *p != ' ' && n < (int)sizeof(name) - 1) name[n++] = *p++;
    name[n] = '\0';

    if (!ends_with(name, ".owx")) {
        if (n + 4 >= (int)sizeof(name)) {
            print(" image name too long\r\n");
            return;
        }
        name[n++] = '.';
        name[n++] = 'o';
        name[n++] = 'w';
        name[n++] = 'x';
        name[n] = '\0';
    }

    pid = ow_gate_spawn(name);
    if (pid < 0) {
        print(" could not start ");
        print(name);
        print(": no such image on the volume, or it failed its checksums.\r\n");
        return;
    }
    print(" started ");
    print(name);
    print(" as PID ");
    put_num((uint64_t)pid);
    print("\r\n");
}

static void dispatch(void) {
    if (g_len == 0) return;
    if (streq(g_line, "help") || streq(g_line, "?")) {
        cmd_help();
    } else if (streq(g_line, "who")) {
        cmd_who();
    } else if (streq(g_line, "uptime")) {
        cmd_uptime();
    } else if (streq(g_line, "exit") || streq(g_line, "quit")) {
        print(" leaving the rescue shell\r\n");
        ow_gate_exit();
        /* OW_SYS_PS_EXIT_THREAD does not return.  If it somehow did, continuing
         * to the prompt would be the worst outcome: an exited process with a
         * live console. */
        for (;;) ow_gate_yield();
    } else if (starts_with(g_line, "spawn")) {
        cmd_spawn(g_line + 5);
    } else {
        print(" unknown command: ");
        print(g_line);
        print("\r\n type 'help'.\r\n");
    }
}

static void prompt(void) {
    print("owrs> ");
}

/* Read one line.  Returns 0 when the shell should exit.
 *
 * The loop is written around the non-blocking UART read rather than a blocking
 * one, with a sleep in the gap, for two reasons that point the same way.  The
 * kernel's read is non-blocking by contract because the register-level read
 * spins, so blocking here would mean either spinning in user mode -- which the
 * scheduler cannot preempt, because there is no interrupt in the picture -- or
 * a kernel call that never returns.  Polling and sleeping is the only shape the
 * gateway actually supports, and it is also what lets owrs share the CPU with
 * owinitv. */
static int read_line(void) {
    g_len = 0;
    prompt();

    for (;;) {
        int c = ow_gate_getc();

        if (c < 0) {
            g_ticks++;
            ow_gate_sleep(1);
            continue;
        }

        if (c == '\r' || c == '\n') {
            ow_gate_puts("\r\n");
            g_line[g_len] = '\0';
            return 1;
        }
        if (c == 0x08 || c == 0x7F) {           /* backspace */
            if (g_len > 0) {
                g_len--;
                print("\b \b");
            }
            continue;
        }
        if (c == 0x03) {                         /* Ctrl-C */
            print("^C\r\n");
            g_len = 0;
            g_line[0] = '\0';
            return 1;
        }
        if (c < 0x20) continue;                  /* drop other control bytes */

        if (g_len < LINE_MAX - 1) {
            g_line[g_len++] = (char)c;
            ow_gate_putc((char)c);
        } else {
            /* Echo a rejection once rather than silently truncating: a line
             * that quietly loses its tail is how you end up believing you typed
             * a filename you did not. */
            ow_gate_puts("^?");
        }
    }
}

int owrs_main(void);

int owrs_main(void) {
    print("\r\n OpenWindows rescue shell (owrs.owx)\r\n");
    print(" This machine booted in its degraded state. Type 'help'.\r\n");

    for (;;) {
        if (read_line()) dispatch();
    }

    return 0;
}
