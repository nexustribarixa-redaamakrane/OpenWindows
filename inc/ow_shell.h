/* ow_shell.h - Debug Shell (Ring 0 Interactive Console) */
#ifndef OW_SHELL_H
#define OW_SHELL_H

#include "ow_types.h"

OW_STATUS    OwShellInitialize(void);
OW_STATUS    OwShellRun(void);
void         OwShellPrintBanner(void);
void         OwShellPrintHelp(void);

#endif /* OW_SHELL_H */
