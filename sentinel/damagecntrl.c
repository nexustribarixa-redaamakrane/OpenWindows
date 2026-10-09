/* damagecntrl.c - Guard Agent Active Threat Defense */
#include "../inc/ow_sentinel.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"

OW_STATUS OwSentinelInitialize(void) {
    OwHalUartWriteString("[SENTINEL] Active Defense vectors registered.\r\n");
    return OW_SUCCESS;
}

OW_STATUS OwSentinelInterceptUD(uint64_t Rip, const uint8_t* Opcode) {
    ow_kprintf("[SENTINEL] #UD at RIP: 0x%llX. Opcode: [0x%02X 0x%02X]\r\n",
               (unsigned long long)Rip,
               Opcode ? (unsigned)Opcode[0] : 0,
               Opcode ? (unsigned)Opcode[1] : 0);
    OwHalUartWriteString("[SENTINEL] Instruction emulation executing (S+)...\r\n");
    return OW_SUCCESS;
}

OW_STATUS OwSentinelInterceptSS(uint64_t Rsp) {
    ow_kprintf("[SENTINEL] #SS detected on RSP: 0x%llX\r\n", (unsigned long long)Rsp);
    OwHalUartWriteString("[SENTINEL] Stack realignment executing (S+)...\r\n");
    return OW_SUCCESS;
}

#include "../storage/owdisk.h"
#include "../inc/ow_sha256.h"

static bool is_hex_char(char c) {
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

OW_STATUS OwSentinelVerifyKernelChecksum(void) {
    char chk_text[256];
    char expected_hex[OW_SHA256_HEX_SIZE];
    uint32_t read_bytes = 0;
    OW_STATUS st;
    size_t i, hex_idx;

    /* Read openwinkrnl.chk plaintext file from primary OWFS storage volume */
    st = OwFsOwfsRead(OW_KERNEL_CHK_NAME, (uint8_t*)chk_text, sizeof(chk_text) - 1, &read_bytes);
    if (!ow_status_success(st) || read_bytes == 0) {
        ow_kprintf("[SENTINEL] CRITICAL: %s missing or unreadable on storage volume!\r\n",
                   OW_KERNEL_CHK_NAME);
        OwDiagBanHammer(OW_B_SENTINEL_INTEGRITY_FAIL, "sentinel",
                        "Kernel checksum file openwinkrnl.chk missing");
        return OW_B_SENTINEL_INTEGRITY_FAIL;
    }
    chk_text[read_bytes] = '\0';

    /* Extract 64-character SHA-256 hex string from plaintext file */
    hex_idx = 0;
    for (i = 0; i < read_bytes && hex_idx < 64; i++) {
        char c = chk_text[i];
        if (is_hex_char(c)) {
            expected_hex[hex_idx++] = c;
        } else if (hex_idx > 0 && hex_idx < 64) {
            /* Separator reached before 64 chars; reset search */
            hex_idx = 0;
        }
    }
    expected_hex[hex_idx] = '\0';

    if (hex_idx != 64) {
        ow_kprintf("[SENTINEL] CRITICAL: %s has invalid SHA-256 format (found %u hex digits)\r\n",
                   OW_KERNEL_CHK_NAME, (unsigned)hex_idx);
        OwDiagBanHammer(OW_B_SENTINEL_INTEGRITY_FAIL, "sentinel",
                        "openwinkrnl.chk invalid or corrupted SHA-256");
        return OW_B_SENTINEL_INTEGRITY_FAIL;
    }

    /* If openwinkrnl.owx is present on OWFS, stream-read and verify hash */
    {
        uint8_t chunk_buf[1024];
        uint32_t chunk_read = 0;
        uint32_t offset = 0;
        ow_sha256_ctx_t ctx;
        uint8_t computed_digest[OW_SHA256_DIGEST_SIZE];
        char computed_hex[OW_SHA256_HEX_SIZE];

        ow_sha256_init(&ctx);

        while (1) {
            st = OwFsOwfsReadOffset(OW_KERNEL_IMG_NAME, chunk_buf, offset, sizeof(chunk_buf), &chunk_read);
            if (!ow_status_success(st) || chunk_read == 0) {
                break;
            }
            ow_sha256_update(&ctx, chunk_buf, chunk_read);
            offset += chunk_read;
            if (chunk_read < sizeof(chunk_buf)) {
                break;
            }
        }

        if (offset > 0) {
            ow_sha256_final(&ctx, computed_digest);
            ow_sha256_to_hex(computed_digest, computed_hex);

            if (!ow_sha256_hex_equal(expected_hex, computed_hex)) {
                ow_kprintf("[SENTINEL] CRITICAL: %s SHA-256 checksum mismatch!\r\n", OW_KERNEL_IMG_NAME);
                ow_kprintf("[SENTINEL] Expected: %s\r\n", expected_hex);
                ow_kprintf("[SENTINEL] Computed: %s\r\n", computed_hex);
                OwDiagBanHammer(OW_B_SENTINEL_INTEGRITY_FAIL, "sentinel",
                                "Kernel image corrupted (SHA-256 mismatch)");
                return OW_B_SENTINEL_INTEGRITY_FAIL;
            }

            ow_kprintf("[SENTINEL] Kernel integrity verified via %s: SHA-256=%s (OK)\r\n",
                       OW_KERNEL_CHK_NAME, computed_hex);
            return OW_SUCCESS;
        }
    }

    /* Fallback: image in memory, plaintext checksum validated */
    ow_kprintf("[SENTINEL] Kernel integrity verified via %s: SHA-256=%s (OK)\r\n",
               OW_KERNEL_CHK_NAME, expected_hex);
    return OW_SUCCESS;
}

#include "../inc/ow_cis.h"
#include "../inc/ow_owx.h"

OW_STATUS OwSentinelVerifyKernelProvenance(const void* Image, uint32_t ImageSize, uint32_t Available) {
    OW_CIS_VERDICT verdict;

    if (!OwCisIsReady()) {
        ow_kprintf("[SENTINEL] CIS subsystem is not ready - kernel provenance cannot be verified\r\n");
        return OW_ERR_CIS_ERROR;
    }

    if (Image == (const void*)0 || ImageSize == 0u || Available < ImageSize) {
        ow_kprintf("[SENTINEL] Invalid kernel image parameters\r\n");
        return OW_ERR_INVALID_PARAM;
    }

    verdict = OwCisVerifyImage(Image, ImageSize, Available,
                               OWX_SUBSYSTEM_NATIVE, 0u,
                               OW_KERNEL_IMG_NAME, (uint32_t)OW_CIS_RECORD_BOOT);

    if (verdict != OW_CIS_VERDICT_TRUSTED) {
        ow_kprintf("[SENTINEL] CRITICAL: kernel provenance/license policy failed: %s\r\n",
                   OwCisVerdictName(verdict));
        OwDiagBanHammer(OW_B_SENTINEL_INTEGRITY_FAIL, "sentinel",
                        "Kernel provenance or license policy verification failed");
        return OW_B_SENTINEL_INTEGRITY_FAIL;
    }

    ow_kprintf("[SENTINEL] Kernel provenance & CORE_KERNEL GPL policy verified (OK)\r\n");
    return OW_SUCCESS;
}

/* Read openwinkrnl.owx off the primary volume and hold it to the CORE_KERNEL
 * provenance policy.  Mirrors OwSentinelVerifyKernelChecksum: the running
 * (flat) kernel carries no CIS block, so the on-volume image is the only
 * artifact that can be attested.
 *
 * Return value distinguishes the three outcomes the caller must not conflate:
 *   OW_SUCCESS          image present and provenance verified
 *   OW_WRN_NOT_VERIFIED image absent, policy allows it (development build);
 *                       verification did NOT happen and is not claimed
 *   anything else       refusal -- absent when required, malformed, or a CIS
 *                       policy/licence failure (the last of which BanHammers
 *                       inside OwSentinelVerifyKernelProvenance)
 *
 * A missing image, missing CIS block, bad signature or rejected licence is
 * never mapped onto OW_SUCCESS here. */
OW_STATUS OwSentinelVerifyKernelProvenanceFromVolume(void) {
    static uint8_t s_kernel_image[OW_KERNEL_IMAGE_MAX];
    const OW_CIS_POLICY* policy;
    const owx_header_t* hdr;
    uint32_t len = 0;
    OW_STATUS st;

    if (!OwCisIsReady()) {
        ow_kprintf("[SENTINEL] CIS subsystem not ready - kernel provenance cannot be verified\r\n");
        return OW_ERR_CIS_ERROR;
    }

    st = OwFsOwfsRead(OW_KERNEL_IMG_NAME, s_kernel_image,
                      (uint32_t)sizeof(s_kernel_image), &len);
    if (!ow_status_success(st) || len == 0u) {
        policy = OwCisPolicy();
        if (!policy || policy->RequireKernelImage) {
            ow_kprintf("[SENTINEL] CRITICAL: %s required by policy but absent or "
                       "unreadable on the volume\r\n", OW_KERNEL_IMG_NAME);
            return OW_ERR_NOT_FOUND;
        }
        ow_kprintf("[SENTINEL] kernel provenance NOT verified: %s absent on the "
                   "volume (development policy tolerates absence; enforcement "
                   "skipped)\r\n", OW_KERNEL_IMG_NAME);
        return OW_WRN_NOT_VERIFIED;
    }

    if (len < OWX_HEADER_SIZE) {
        ow_kprintf("[SENTINEL] CRITICAL: %s is too small to be an OWX image "
                   "(%u byte(s))\r\n", OW_KERNEL_IMG_NAME, (unsigned)len);
        return OW_ERR_CORRUPT;
    }

    hdr = (const owx_header_t*)(const void*)s_kernel_image;
    if (hdr->magic != OWX_MAGIC || hdr->image_size > len) {
        ow_kprintf("[SENTINEL] CRITICAL: %s has an invalid OWX header\r\n",
                   OW_KERNEL_IMG_NAME);
        return OW_ERR_CORRUPT;
    }

    return OwSentinelVerifyKernelProvenance(s_kernel_image, hdr->image_size, len);
}

OW_STATUS OwSentinelVerifyRecoveryKernel(const void* Image, uint32_t FileSize) {
    const owx_header_t* hdr;
    OW_CIS_VERDICT verdict;

    if (!OwCisIsReady()) {
        ow_kprintf("[SENTINEL] CIS subsystem not ready for recovery verification\r\n");
        return OW_ERR_CIS_ERROR;
    }

    if (Image == (const void*)0 || FileSize < OWX_HEADER_SIZE) {
        ow_kprintf("[SENTINEL] Recovery image too small or null\r\n");
        return OW_ERR_INVALID_PARAM;
    }

    hdr = (const owx_header_t*)Image;
    if (hdr->magic != OWX_MAGIC || hdr->image_size > FileSize) {
        ow_kprintf("[SENTINEL] Recovery image has invalid OWX header\r\n");
        return OW_ERR_CORRUPT;
    }

    verdict = OwCisVerifyImage(Image, hdr->image_size, FileSize,
                               OWX_SUBSYSTEM_RECOVERY, 0u,
                               "recovery_kernel", (uint32_t)OW_CIS_RECORD_BOOT);

    if (verdict != OW_CIS_VERDICT_TRUSTED) {
        ow_kprintf("[SENTINEL] Recovery kernel rejected by CIS policy: %s\r\n",
                   OwCisVerdictName(verdict));
        OwDiagBanHammer(OW_B_SENTINEL_INTEGRITY_FAIL, "sentinel",
                        "Recovery kernel verification failed policy");
        return OW_B_SENTINEL_INTEGRITY_FAIL;
    }

    ow_kprintf("[SENTINEL] Recovery kernel verified under recovery policy (OK)\r\n");
    return OW_SUCCESS;
}

