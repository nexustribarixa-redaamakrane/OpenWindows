/* ow_ecosys.h - OpenWindows Ecosystem Integration
 * superunicode (SUTF / SUCS kernel mode) + vip (UniVIP / FVIP indexing) */
#ifndef OW_ECOSYS_H
#define OW_ECOSYS_H

#include <stdbool.h>
#include <stdint.h>

/* =========================================================================
 * SuperUnicode SUTF codec & SUCS kernel mode
 * ========================================================================= */
void OwSucsInitialize(void); /* init boot config, commit-on-boot */
bool OwSucsCommitBoot(void); /* true if a mode transition committed */
int OwSucsActiveMode(void);  /* SUCS_MODE_BASE (0) / EXTENDED (1) */
int OwSucsPendingMode(void);
bool OwSucsIsRebootRequired(void);
int OwSucsRequestModeSwitch(int new_mode);
uint32_t OwSucsModeChangeCount(void);
bool OwSucsSelfTest(void); /* SUTF-8 encode/decode round-trip */

/* =========================================================================
 * UniVIP volume registry + FVIP file index (root volume)
 * ========================================================================= */
#define OW_VIP_ROOT_VOLUME 0U
#define OW_VIP_ROOT_BASE_SECTOR 131200ULL /* MBL OWFS partition LBA */

uint32_t OwVipInitialize(void);         /* raw VIP code (C+ on success) */
bool OwVipIsUp(void);                   /* true after successful init */
bool OwVipIsSuccessCode(uint32_t code); /* C+ block success classification */
uint32_t OwVipRegisterVolume(uint32_t volume_id, uint64_t base_sector,
                             const char *label);
uint32_t OwVipResolveVolume(uint32_t volume_id, uint64_t *out_base_sector);
uint32_t OwVipIndexInsert(const char *path, uint64_t sector_offset,
                          uint32_t flags);
uint32_t OwVipIndexLookup(const char *path, uint64_t *out_sector_offset,
                          uint32_t *out_flags);
int OwVipIndexEntryCount(void);
uint32_t OwVipVerifyIndex(void);

#endif /* OW_ECOSYS_H */