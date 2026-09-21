/* owdisk.h - OpenWindows-Storage integration (OWFS on primary, USFS on secure) */
#ifndef OWDISK_H
#define OWDISK_H

#include "../inc/ow_types.h"
#include <stdint.h>
#include <stdbool.h>

/* Tier-3 userspace root orchestrator executable required on the primary
 * OWFS volume. The kernel only hands off to userland when this .owx image
 * is present; a missing owinit is a fatal BANcode halt, not a warning. */
#define OW_INIT_EXEC_NAME "owinit.owx"

OW_STATUS OwDiskInitialize(void);        /* auto format+mount OWFS & USFS */

bool OwDiskOwfsMounted(void);
bool OwDiskUsfsMounted(void);
bool OwDiskOwinitPresent(void);

OW_STATUS OwFsOwfsFormat(const uint8_t* label, uint32_t label_len);
OW_STATUS OwFsOwfsMount(void);
OW_STATUS OwFsOwfsUnmount(void);
OW_STATUS OwFsOwfsMkdir(const char* name, uint32_t* out_inode);
OW_STATUS OwFsOwfsCreate(const char* name, uint32_t* out_inode);
OW_STATUS OwFsOwfsWrite(const char* name, const uint8_t* data, uint32_t len);
OW_STATUS OwFsOwfsRead(const char* name, uint8_t* buf, uint32_t cap,
                       uint32_t* out_read);
OW_STATUS OwFsOwfsReadOffset(const char* name, uint8_t* buf, uint32_t offset,
                             uint32_t cap, uint32_t* out_read);
OW_STATUS OwFsOwfsList(uint32_t* out_count);
uint32_t  OwFsOwfsFreeBlocks(void);

OW_STATUS OwFsUsfsFormat(const uint8_t* label, uint32_t label_len);
OW_STATUS OwFsUsfsMount(void);
OW_STATUS OwFsUsfsUnmount(void);
uint32_t  OwFsUsfsFreeBlocks(void);

#endif /* OWDISK_H */