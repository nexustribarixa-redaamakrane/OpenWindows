/* owinitv.c - OpenWindows emergency session initializer (.owx)
 *
 * The volatile init.  In state 2 the kernel finds no usable owinit.owx, enters
 * THIS image as PID 1 instead, and this program's whole job is to bring up the
 * minimum userspace: announce that the machine is degraded and why, start the
 * rescue shell, and then stay out of the way.
 *
 * What this deliberately does NOT do:
 *
 *   - It does not try to be owinit.  owinit parses boot directives, mounts root
 *     storage and launches a window manager; none of that is meaningful on a
 *     volume whose orchestrator is missing or corrupt, and attempting it would
 *     turn a degraded boot into a second cascade of failures on top of the first.
 *
 *   - It does not touch the kernel directly.  There is no "emergency mode", no
 *     relaxed gate, no second loader.  The kernel hands off exactly as it does
 *     for owinit.owx; everything below the hand-off is ordinary user-mode code
 *     making ordinary user-mode calls.  That is the reason the rescue path is
 *     trustworthy: it has no privileged step that ordinary boots do not also
 *     have.
 *
 *   - It does not exit.  See owinitv_main's closing note.
 *
 * C99 freestanding.  Zero heap, zero imports, zero libc. */

#include "ow_gate.h"

/* GCC emits calls to these from perfectly ordinary code -- a struct assignment
 * or an array initialiser is enough -- and in a freestanding image with no CRT
 * an unresolved one becomes an unbound IAT slot, which tools/owx_pack.py then
 * refuses to pack.  Defining them here is what keeps the image import-free. */
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

/* The image the kernel asked us to bring up.  A name, not a handle: the rescue
 * shell is an ordinary file on the ordinary volume, reached through the ordinary
 * OWFS name lookup, and it is the same name the boot survey reported on. */
static const char k_rescue_image[] = "owrs.owx";

/* The primary orchestrator, named so that a human reading the serial log can
 * tell which image was rejected without cross-referencing the kernel log. */
static const char k_primary_image[] = "owinit.owx";

static void announce(void) {
    ow_gate_puts("\r\n");
    ow_gate_puts("===============================================================\r\n");
    ow_gate_puts(" OpenWindows EMERGENCY USERSpace\r\n");
    ow_gate_puts("===============================================================\r\n");
    ow_gate_puts(" The primary orchestrator (" );
    ow_gate_puts(k_primary_image);
    ow_gate_puts(") was missing or unusable on the boot volume.\r\n");
    ow_gate_puts(" owinitv.owx has been entered as PID 1 instead.\r\n");
    ow_gate_puts(" This is a DEGRADED boot: storage, drivers and services have\r\n");
    ow_gate_puts(" NOT been started. Diagnostics only.\r\n");
    ow_gate_puts("===============================================================\r\n");
}

/* Decimal, most significant digit first.
 *
 * Written out rather than using any formatting library because there is no
 * formatting library: OW_SYS_UART_WRITE takes a NUL-terminated string, so a
 * number has to become text by hand.  Digits are emitted into a fixed buffer in
 * reverse and then walked backwards, which needs no allocation. */
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

/* Bring up the rescue shell.
 *
 * The one thing that can fail here is owrs.owx being absent, and it fails
 * VISIBLY: a spawn that returns -1 leaves the machine with an init and no shell,
 * which would look like a hung boot rather than a missing file. */
static void start_rescue(void) {
    int64_t pid = ow_gate_spawn(k_rescue_image);

    if (pid < 0) {
        ow_gate_puts(" owinitv: could NOT start the rescue shell (");
        ow_gate_puts(k_rescue_image);
        ow_gate_puts(").\r\n");
        ow_gate_puts(" The volume has no usable ");
        ow_gate_puts(k_rescue_image);
        ow_gate_puts(", or the kernel refused to load it.\r\n");
        ow_gate_puts(" There is no interactive shell on this machine.\r\n");
        return;
    }

    ow_gate_puts(" owinitv: rescue shell (");
    ow_gate_puts(k_rescue_image);
    ow_gate_puts(") started as PID ");
    put_num((uint64_t)pid);
    ow_gate_puts(".\r\n");
    ow_gate_puts(" Type 'help' for the command list.\r\n");
}

int owinitv_main(void);

int owinitv_main(void) {
    announce();
    start_rescue();

    /* Park, and this is not optional.
     *
     * The loader seeds an entry return so a C main that finishes is a normal way
     * for an image to end; returning from here lands on a trampoline that issues
     * OW_SYS_PS_EXIT_THREAD, and PID 1 would exit.  A machine whose init has
     * exited is not degraded, it is broken -- there would be nothing left to
     * reap the rescue shell, respawn it, or answer any request the user mode
     * makes.  So the init stays alive and yields the CPU instead, which is also
     * the whole job: owrs does the work, owinitv keeps the userspace existing.
     *
     * Yielding rather than sleeping is deliberate.  OW_SYS_PS_SLEEP would put
     * this thread on a wait queue that nothing will ever wake, which is a
     * subtler way to die than exiting.
     *
     * But a BARE yield loop is its own kind of wrong, and this is where the two
     * constraints above have to be balanced rather than just picked between.
     * An unthrottled `int $0x80` yield loop is a busy-wait: it issues a full
     * trap frame save, a syscall dispatch and a scheduler scan, then does it
     * again immediately, and PID 1 doing that outruns everything else on the
     * machine -- including the Ring 0 debug shell the operator is trying to use
     * to diagnose why the boot is degraded.  Three such threads (this one, owrs,
     * and user-hello) on a 100 Hz tick is enough to make the console unusable.
     *
     * So the loop yields, and then gives the CPU back for a tick.  The yield is
     * what keeps PID 1 runnable, so it is never parked on a queue nothing wakes;
     * the sleep is what stops it from eating the machine between yields.  One
     * tick is short enough that the shell stays responsive and long enough that
     * PID 1 is not the reason the console stutters. */
    for (;;) {
        int i;
        for (i = 0; i < 8; i++) {
            ow_gate_yield();
        }
        ow_gate_sleep(1);
    }

    /* No return.  Kept so that the compiler accepts a non-void function without
     * assuming a code path that should not exist. */
    return 0;
}
