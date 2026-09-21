/* fltrmgr.c - Driver Tier Validation */
#include "../inc/ow_sentinel.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_string.h"

#define OW_MAX_FLT_HOOKS 16U

static OW_FLT_CALLBACK g_Callbacks[OW_MAX_FLT_HOOKS];
static uint32_t g_CallbackTypes[OW_MAX_FLT_HOOKS];
static uint32_t g_CallbackCount = 0;

OW_STATUS OwFltRegisterCallback(uint32_t RequestType, OW_FLT_CALLBACK Callback) {
    if (g_CallbackCount >= OW_MAX_FLT_HOOKS) return OW_ERR_INSUFFICIENT;
    if (!Callback) return OW_ERR_NULL_POINTER;

    g_CallbackTypes[g_CallbackCount] = RequestType;
    g_Callbacks[g_CallbackCount] = Callback;
    g_CallbackCount++;
    return OW_SUCCESS;
}

OW_STATUS OwSentinelValidateDriver(const char* DriverPath, OW_DRIVER_TIER Tier) {
    size_t len;

    if (!DriverPath) return OW_ERR_NULL_POINTER;

    len = ow_strlen(DriverPath);
    ow_kprintf("[FLTRMGR] Auditing: '%s' for Tier %u\r\n", DriverPath, (unsigned)Tier);

    switch (Tier) {
        case OW_DRIVER_TIER_1_CORE: {
            const char* ext = ".owc";
            size_t ext_len = ow_strlen(ext);
            if (len < ext_len) return OW_ERR_INVALID_PARAM;
            if (ow_strcmp(DriverPath + len - ext_len, ext) != 0) {
                OwHalUartWriteString("[FLTRMGR] Tier 1 FAILED: not *.owc driver image\r\n");
                return OW_ERR_INVALID_PARAM;
            }
            break;
        }
        case OW_DRIVER_TIER_2_SYSTEM: {
            const char* ext = ".owd";
            size_t ext_len = ow_strlen(ext);
            if (len < ext_len) return OW_ERR_INVALID_PARAM;
            if (ow_strcmp(DriverPath + len - ext_len, ext) != 0) {
                OwHalUartWriteString("[FLTRMGR] Tier 2 FAILED: not *.owd library image\r\n");
                return OW_ERR_INVALID_PARAM;
            }
            break;
        }
        case OW_DRIVER_TIER_3_USER: {
            const char* ext = ".owx";
            size_t ext_len = ow_strlen(ext);
            if (len < ext_len) return OW_ERR_INVALID_PARAM;
            if (ow_strcmp(DriverPath + len - ext_len, ext) != 0) {
                OwHalUartWriteString("[FLTRMGR] Tier 3 FAILED: not *.owx executable image\r\n");
                return OW_ERR_INVALID_PARAM;
            }
            break;
        }
    }

    OwHalUartWriteString("[FLTRMGR] Extension validation passed.\r\n");
    return OW_SUCCESS;
}
