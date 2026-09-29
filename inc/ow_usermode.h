/* ow_usermode.h - Standalone Ring 3 application launchers */
#ifndef OW_USERMODE_H
#define OW_USERMODE_H

/* Launch the simple user-mode hello-world application.
 * This is separate from the required owinit orchestrator.
 *
 * The payload runs entirely at CPL3, so it must not execute privileged
 * instructions (cli/hlt/in/out); it yields control back to the kernel only
 * through int 0x80 syscalls.  Its pages are mapped user-accessible inside
 * the process's own CR3 root (see core/memory.c) and recorded as VADs. */
void OwUmLaunchHello(void);

#endif /* OW_USERMODE_H */