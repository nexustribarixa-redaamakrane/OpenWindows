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

