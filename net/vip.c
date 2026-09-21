/* vip.c - UniVIP / FVIP volume indexing integration */
#include "../inc/ow_ecosys.h"
#include "../inc/ow_types.h"
#include "univip_fvip.h"
#include <stdbool.h>
#include <stdint.h>

static fvip_table_t g_VolumeIndex;
static bool g_VipInitialized;

uint32_t OwVipInitialize(void) {
  uint32_t code;
  uint64_t base = 0;

  if (g_VipInitialized)
    return OW_SUCCESS;

  code = univip_init_system();
  if (!vip_code_is_success(code))
    return code;

  code = univip_register_volume(OW_VIP_ROOT_VOLUME, OW_VIP_ROOT_BASE_SECTOR,
                                "kernel");
  if (!vip_code_is_success(code))
    return code;

  code = univip_resolve_volume(OW_VIP_ROOT_VOLUME, &base);
  if (!vip_code_is_success(code))
    return code;
  if (base != OW_VIP_ROOT_BASE_SECTOR)
    return (uint32_t)OW_ERR_IO;

  code = fvip_init_volume_index(OW_VIP_ROOT_VOLUME, &g_VolumeIndex);
  if (!vip_code_is_success(code))
    return code;

  g_VipInitialized = true;
  return code;
}

bool OwVipIsUp(void) { return g_VipInitialized; }

bool OwVipIsSuccessCode(uint32_t code) { return vip_code_is_success(code); }

uint32_t OwVipRegisterVolume(uint32_t volume_id, uint64_t base_sector,
                             const char *label) {
  if (!g_VipInitialized)
    return (uint32_t)OW_ERR_NOT_INITIALIZED;
  return univip_register_volume(volume_id, base_sector, label);
}

uint32_t OwVipResolveVolume(uint32_t volume_id, uint64_t *out_base_sector) {
  if (!g_VipInitialized)
    return (uint32_t)OW_ERR_NOT_INITIALIZED;
  return univip_resolve_volume(volume_id, out_base_sector);
}

uint32_t OwVipIndexInsert(const char *path, uint64_t sector_offset,
                          uint32_t flags) {
  if (!g_VipInitialized)
    return (uint32_t)OW_ERR_NOT_INITIALIZED;
  return fvip_insert_entry(&g_VolumeIndex, path, sector_offset, flags);
}

uint32_t OwVipIndexLookup(const char *path, uint64_t *out_sector_offset,
                          uint32_t *out_flags) {
  fvip_entry_t e;
  uint32_t code;

  if (!g_VipInitialized)
    return (uint32_t)OW_ERR_NOT_INITIALIZED;
  code = fvip_lookup_entry(&g_VolumeIndex, path, &e);
  if (vip_code_is_success(code)) {
    if (out_sector_offset)
      *out_sector_offset = e.sector_offset;
    if (out_flags)
      *out_flags = e.flags;
  }
  return code;
}

int OwVipIndexEntryCount(void) {
  return g_VipInitialized ? (int)g_VolumeIndex.count : 0;
}

uint32_t OwVipVerifyIndex(void) {
  if (!g_VipInitialized)
    return (uint32_t)OW_ERR_NOT_INITIALIZED;
  return fvip_verify_integrity(&g_VolumeIndex);
}