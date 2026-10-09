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

/* Ceiling on the on-volume kernel image read for provenance verification.
 *
 * Bootable images (the multiboot / VDI kernel) are a raw objcopy of the linked
 * PE and carry no CIS block, so the running kernel cannot attest to itself.
 * Provenance is therefore checked against openwinkrnl.owx on the primary
 * volume -- the same artifact the checksum verifier hashes.  It needs a full
 * staging buffer because OwCisVerifyImage hashes and signature-checks the whole
 * image in place; there is no streaming variant.  Sized like the host harness's
 * kernel-image buffer and well above the ~256 KiB release image. */
#define OW_KERNEL_IMAGE_MAX    (1024U * 1024U)

OW_STATUS    OwSentinelVerifyKernelChecksum(void);
OW_STATUS    OwSentinelVerifyKernelProvenance(const void* Image, uint32_t ImageSize, uint32_t Available);
OW_STATUS    OwSentinelVerifyKernelProvenanceFromVolume(void);
OW_STATUS    OwSentinelVerifyRecoveryKernel(const void* Image, uint32_t FileSize);

#endif /* OW_SENTINEL_H */

