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

/* Apply a staged mode switch immediately.
 *
 * The library stages `sucs_request_mode_switch` as pending and defers the
 * transition to the next boot.  On a live test volume there is no persistent
 * backing store, so a "next boot" never carries the request and EXTENDED mode
 * is unreachable.  This commits the pending mode now using the same routine the
 * boot path uses, so the diagnostic shell can actually exercise the mode. */
bool OwSucsCommitNow(void) {
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
  if (!g_SucsInitialized) {
    return SUCS_SWITCH_ERR_INVALID_MODE;
  }
  /* Decide against the KERNEL's committed mode, not the library's private copy.
   * sucs_commit_mode_on_boot() is applied to g_SucsBoot, so the library's own
   * active_mode never advances; keying off it would report "already active"
   * forever once a live commit had moved the kernel to EXTENDED, making it
   * impossible to stage a switch back to BASE. */
  if ((sucs_kernel_mode_t)new_mode == g_SucsBoot.active_mode) {
    g_SucsBoot.pending_mode = g_SucsBoot.active_mode;
    g_SucsBoot.reboot_required = false;
    return SUCS_SWITCH_ERR_ALREADY_ACTIVE;
  }
  /* Keep the library's own view in step so any other consumer sees the request,
   * but the status we return reflects the kernel's real state above. */
  st = sucs_request_mode_switch((sucs_kernel_mode_t)new_mode);
  if (st == SUCS_SWITCH_ERR_INVALID_MODE) {
    return (int)st;
  }
  g_SucsBoot.pending_mode = (sucs_kernel_mode_t)new_mode;
  g_SucsBoot.reboot_required = true;
  return SUCS_SWITCH_REBOOT_REQUIRED;
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