/* ow_sentinel.h - Guard Agent (Active Defense) */
#ifndef OW_SENTINEL_H
#define OW_SENTINEL_H

#include "ow_types.h"

typedef enum _OW_DRIVER_TIER {
    OW_DRIVER_TIER_1_CORE     = 1,
    OW_DRIVER_TIER_2_SYSTEM   = 2,
    OW_DRIVER_TIER_3_USER     = 3
} OW_DRIVER_TIER;

typedef bool (*OW_FLT_CALLBACK)(uint32_t RequestType, void* Params);

OW_STATUS    OwSentinelInitialize(void);
OW_STATUS    OwSentinelInterceptUD(uint64_t Rip, const uint8_t* Opcode);
OW_STATUS    OwSentinelInterceptSS(uint64_t Rsp);
OW_STATUS    OwSentinelValidateDriver(const char* DriverPath, OW_DRIVER_TIER Tier);
OW_STATUS    OwFltRegisterCallback(uint32_t RequestType, OW_FLT_CALLBACK Callback);

/* Kernel Checksum Integrity (openwinkrnl.chk)
 * openwinkrnl.chk is a plain text file containing the SHA-256 hex checksum
 * of openwinkrnl.owx. At boot, Sentinel verifies the kernel checksum and crashes/panics
 * if invalid or corrupted. */
#define OW_KERNEL_CHK_NAME     "openwinkrnl.chk"
#define OW_KERNEL_IMG_NAME     "openwinkrnl.owx"

OW_STATUS    OwSentinelVerifyKernelChecksum(void);

#endif /* OW_SENTINEL_H */

