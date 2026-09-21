/* ow_rc.h - OpenWindows Run Control (rc.d) engine
 * Executes the rc scripts from the OpenWindows-Essentials configuration tree
 * (Config under rc.d) so kernel shutdown / restart follow the same
 * orchestrated daemon-teardown sequence as userspace. Scripts are loaded from
 * the OWFS primary volume when present (flat root names, e.g. "rc.shutdown");
 * they reference rc.* script names only (the C:\OpenWindows userspace paths
 * do not exist in the kernel realm). An embedded kernel version ships as the
 * fallback. */
#ifndef OW_RC_H
#define OW_RC_H

/* Interpret a single rc script by name ("rc.shutdown", "rc.sysinit", ...).
 * Loads the file from the OWFS primary volume if present, otherwise uses the
 * embedded kernel version of the script. */
void OwRcRunScript(const char *name);

/* Full shutdown sequence (power-off): run rc.shutdown (daemon teardown in
 * reverse order, userland termination, registry commit, cache flush), then
 * report the halt state. Only called on halt / poweroff. */
void OwRcShutdown(void);

/* Full shutdown sequence (restart): run rc.shutdown as above, then report
 * the restart hand-off. Only called on reboot / reset. */
void OwRcRestart(void);

#endif /* OW_RC_H */