/* sucs.c - SuperUnicode SUTF codec & SUCS kernel mode integration */
#include "../inc/ow_ecosys.h"
#include "sucs_mode.h"
#include "sutf8.h"
#include <stdbool.h>
#include <stdint.h>

static sucs_kernel_boot_config_t g_SucsBoot;
static bool g_SucsInitialized;

void OwSucsInitialize(void) {
  if (g_SucsInitialized)
    return;
  sucs_init_boot_config(&g_SucsBoot, SUCS_MODE_BASE);
  g_SucsInitialized = true;
}

bool OwSucsCommitBoot(void) {
  if (!g_SucsInitialized)
    return false;
  return sucs_commit_mode_on_boot(&g_SucsBoot);
}

int OwSucsActiveMode(void) {
  return g_SucsInitialized ? (int)g_SucsBoot.active_mode : -1;
}

int OwSucsPendingMode(void) {
  return g_SucsInitialized ? (int)g_SucsBoot.pending_mode : -1;
}

bool OwSucsIsRebootRequired(void) {
  return g_SucsInitialized ? g_SucsBoot.reboot_required : false;
}

int OwSucsRequestModeSwitch(int new_mode) {
  sucs_switch_status_t st;
  if (new_mode != SUCS_MODE_BASE && new_mode != SUCS_MODE_EXTENDED) {
    return SUCS_SWITCH_ERR_INVALID_MODE;
  }
  st = sucs_request_mode_switch((sucs_kernel_mode_t)new_mode);
  if (st == SUCS_SWITCH_REBOOT_REQUIRED) {
    g_SucsBoot.pending_mode = (sucs_kernel_mode_t)new_mode;
    g_SucsBoot.reboot_required = true;
  }
  return (int)st;
}

uint32_t OwSucsModeChangeCount(void) {
  return g_SucsInitialized ? g_SucsBoot.mode_change_count : 0u;
}

bool OwSucsSelfTest(void) {
  uint8_t buf[8];
  sucs_char_t cp, out;
  size_t n1, n2;

  OwSucsInitialize();

  if (sutf8_encode_char(0x41U, buf, sizeof(buf)) != 1)
    return false;
  if (sutf8_decode_char(buf, sizeof(buf), &out) != 1)
    return false;
  if (out != 0x41U)
    return false;

  cp = 0x1F600U;
  n1 = sutf8_encode_char(cp, buf, sizeof(buf));
  n2 = sutf8_decode_char(buf, sizeof(buf), &out);
  if (n1 != n2 || n1 == 0 || out != cp)
    return false;

  if (sutf8_encode_char(SUCS_INVALID_CODEPOINT, buf, sizeof(buf)) != 0) {
    return false;
  }
  return true;
}