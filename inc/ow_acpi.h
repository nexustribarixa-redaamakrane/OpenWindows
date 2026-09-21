/* ow_acpi.h - ACPI software power control (S5 power-off / reset) */
#ifndef OW_ACPI_H
#define OW_ACPI_H

#include <stdbool.h>
#include <stdint.h>

/* Low-memory RSDP search window (EBDA + F0000..FFFFF). */
#define OW_ACPI_RSDP_SEARCH_START 0x000E0000u
#define OW_ACPI_RSDP_SEARCH_END 0x000FFFFFu

/* Locate the ACPI firmware tables (RSDP -> RSDT/XSDT -> FADT) and cache the
 * power-management registers used for software shutdown/restart. Returns true
 * when a usable FADT was found. On the host boot harness (OW_HOST_HAL) this
 * is a no-op stub. */
bool OwAcpiInitialize(void);
bool OwAcpiIsAvailable(void);

/* Print the ACPI discovery status (PM1a_CNT_BLK, S5 sleep type, OEM, SCI_EN).
 */
void OwAcpiStatus(void);

/* Software power-off via ACPI S5 (with emulator APM fallbacks). Only returns
 * on the host harness; on real hardware falls through to a halted CPU.
 * When the soft power-off screen is enabled (userspace-only), this instead
 * refuses to power the hardware down and rather parks the kernel on a
 * "You can safely power off your device now." screen. */
void OwAcpiPowerOff(void);

/* Enable/disable the secret soft power-off screen. This is a userspace-only
 * switch: it must be set through the Ring 3 system-call gateway
 * (OW_SYS_SAFE_POWEROFF_SCREEN / OwApiSetSafePowerOffScreen), never by the
 * kernel itself. While enabled, shutdown stops at the safe-power-off screen
 * instead of actually powering the machine down. */
void OwAcpiSetSafePowerScreen(bool enable);
bool OwAcpiSafePowerScreen(void);

/* Software warm reboot via 8042 / PIIX reset control / ACPI reset register.
 * Only returns on the host harness. */
void OwAcpiReset(void);

#endif /* OW_ACPI_H */