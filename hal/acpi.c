/* acpi.c - Advanced Configuration & Power Interface (software power control)
 * Locates the firmware ACPI tables (RSDP -> RSDT/XSDT -> FADT), caches the
 * PM1a_CNT_BLK / S5 sleep type / reset register, and drives software
 * power-off (ACPI S5) and warm reboot. QEMU (PIIX4 + ICH9) and VirtualBox are
 * the primary targets; emulator legacy-port fallbacks are provided.
 * On the host boot harness (OW_HOST_HAL) everything is a no-op stub so the
 * harness never touches real machine ports. */
#include "../inc/ow_acpi.h"
#include "../inc/ow_io.h"
#include "../inc/ow_hal.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_kprintf.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Userspace-only soft power-off screen flag. Deliberately outside the
 * OW_HOST_HAL guard so the Ring 3 system-call gateway can always flip it.
 * While armed, OwAcpiPowerOff() parks the kernel on a safe-power-off screen
 * instead of actually powering the hardware down. */
static bool        g_safe_power_screen = false;

void OwAcpiSetSafePowerScreen(bool enable) {
    g_safe_power_screen = enable;
}

bool OwAcpiSafePowerScreen(void) {
    return g_safe_power_screen;
}

#ifndef OW_HOST_HAL

/* ── ACPI table structures (packed, v2.0) ───────────────────────────────── */

typedef struct __attribute__((packed)) {
    char     signature[8];
    uint8_t  checksum;
    char     oem_id[6];
    uint8_t  revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t  extended_checksum;
    uint8_t  reserved[3];
} acpi_rsdp_t;

typedef struct __attribute__((packed)) {
    char     signature[4];
    uint32_t length;
    uint8_t  revision;
    uint8_t  checksum;
    char     oem_id[6];
    char     oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} acpi_sdt_t;

typedef struct __attribute__((packed)) {
    acpi_sdt_t hdr;
    uint32_t   firmware_ctrl;
    uint32_t   dsdt;
    uint8_t    reserved0;
    uint8_t    preferred_pm_profile;
    uint16_t   sci_int;
    uint32_t   smi_cmd;
    uint8_t    acpi_enable;
    uint8_t    acpi_disable;
    uint8_t    s4bios_req;
    uint8_t    pstate_ctl;
    uint32_t   pm1a_evt_blk;
    uint32_t   pm1b_evt_blk;
    uint32_t   pm1a_cnt_blk;
    uint32_t   pm1b_cnt_blk;
    uint32_t   pm2_cnt_blk;
    uint32_t   pm_tmr_blk;
    uint32_t   gpe0_blk;
    uint32_t   gpe1_blk;
    uint8_t    pm1_evt_len;
    uint8_t    pm1_cnt_len;
    uint8_t    pm2_cnt_len;
    uint8_t    pm_tmr_len;
    uint8_t    gpe0_blk_len;
    uint8_t    gpe1_blk_len;
    uint8_t    gpe1_base;
    uint8_t    cst_cnt;
    uint16_t   p_lvl2_lat;
    uint16_t   p_lvl3_lat;
    uint16_t   flush_size;
    uint16_t   flush_stride;
    uint8_t    duty_offset;
    uint8_t    duty_width;
    uint8_t    day_alarm;
    uint8_t    month_alarm;
    uint8_t    century;
    uint16_t   iapc_boot_arch;
    uint8_t    reserved1;
    uint32_t   flags;
    /* FACP v2.x (valid when hdr.length >= 132) */
    uint8_t    reset_reg[12];   /* generic address structure */
    uint8_t    reset_value;
} acpi_fadt_t;

typedef struct __attribute__((packed)) {
    uint8_t  address_space_id;
    uint8_t  register_bit_width;
    uint8_t  register_bit_offset;
    uint8_t  access_size;
    uint64_t address;
} acpi_gas_t;

#define ACPI_SIG_RSDP "RSD PTR "
#define ACPI_SIG_FADT "FACP"
#define ACPI_SIG_RSDT "RSDT"
#define ACPI_SIG_XSDT "XSDT"

#define OW_ACPI_PM1A_SLP_EN 0x2000u
#define OW_ACPI_PM1A_SLP_TYP_MASK 0x1C00u

static bool        g_available = false;
static uint16_t    g_pm1a_cnt = 0;
static uint8_t     g_s5_slp_typ = 5;
static uint8_t     g_sci_en = 0;
static uint16_t    g_reset_reg = 0;
static uint8_t     g_reset_value = 0;
static char        g_oem_id[7];

static uint8_t acpi_sum(const uint8_t* data, size_t len) {
    uint8_t sum = 0;
    size_t i;
    for (i = 0; i < len; i++) sum = (uint8_t)(sum + data[i]);
    return sum;
}

static int acpi_sig_cmp(const char* a, const char* b, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    }
    return 0;
}

/* RSDP checksum covers 20 bytes for v1 and the full 36-byte v2 header. */
static bool rsdp_valid(const acpi_rsdp_t* r) {
    if (acpi_sig_cmp(r->signature, ACPI_SIG_RSDP, 8) != 0) return false;
    if (acpi_sum((const uint8_t*)r, 20) != 0) return false;
    if (r->revision >= 2) {
        if (acpi_sum((const uint8_t*)r, sizeof(acpi_rsdp_t)) != 0) return false;
    }
    return true;
}

static const acpi_rsdp_t* acpi_find_rsdp(void) {
    const acpi_rsdp_t* r;
    uint32_t ebda = (uint32_t)(*(uint16_t*)(uintptr_t)0x40E) * 16u;
    uint32_t addr;

    if (ebda >= 0x400 && ebda < 0xA0000u) {
        for (addr = ebda; addr < ebda + 1024u; addr += 16u) {
            r = (const acpi_rsdp_t*)(uintptr_t)addr;
            if (rsdp_valid(r)) return r;
        }
    }
    for (addr = OW_ACPI_RSDP_SEARCH_START; addr < OW_ACPI_RSDP_SEARCH_END;
         addr += 16u) {
        r = (const acpi_rsdp_t*)(uintptr_t)addr;
        if (rsdp_valid(r)) return r;
    }
    return (const acpi_rsdp_t*)0;
}

static const acpi_fadt_t* acpi_locate_fadt(const acpi_sdt_t* root) {
    uint32_t count, i;

    if (acpi_sig_cmp(root->signature, ACPI_SIG_RSDT, 4) == 0) {
        const uint32_t* entries = (const uint32_t*)((const uint8_t*)root + 36);
        count = (root->length - 36u) / 4u;
        for (i = 0; i < count; i++) {
            const acpi_fadt_t* t =
                (const acpi_fadt_t*)(uintptr_t)entries[i];
            if (t && acpi_sig_cmp(t->hdr.signature, ACPI_SIG_FADT, 4) == 0) {
                return t;
            }
        }
    } else if (acpi_sig_cmp(root->signature, ACPI_SIG_XSDT, 4) == 0) {
        const uint64_t* entries = (const uint64_t*)((const uint8_t*)root + 36);
        count = (root->length - 36u) / 8u;
        for (i = 0; i < count; i++) {
            const acpi_fadt_t* t =
                (const acpi_fadt_t*)(uintptr_t)entries[i];
            if (t && acpi_sig_cmp(t->hdr.signature, ACPI_SIG_FADT, 4) == 0) {
                return t;
            }
        }
    }
    return (const acpi_fadt_t*)0;
}

/* The S5 sleep type is defined by the chipset AML (_S5). We cannot evaluate
 * AML, so we select the well-known value for the platforms this kernel
 * targets. */
static uint8_t acpi_pick_s5(const acpi_fadt_t* f) {
    uint32_t pm1 = f->pm1a_cnt_blk;
    if (pm1 == 0x0604u) return 5;   /* ICH9 / QEMU q35 */
    if (pm1 == 0x0404u) return 7;   /* VirtualBox */
    return 7;                       /* PIIX4 (0xB004) / default */
}

#endif /* !OW_HOST_HAL */

bool OwAcpiInitialize(void) {
#ifdef OW_HOST_HAL
    return false;
#else
    const acpi_rsdp_t* rsdp = acpi_find_rsdp();
    const acpi_sdt_t* root;
    const acpi_fadt_t* fadt;

    if (!rsdp) {
        OwDiagLogWarning(OW_W_ACPI_NOT_FOUND, "RSDP not found in low memory");
        return false;
    }

    root = (rsdp->revision >= 2 && rsdp->xsdt_address)
               ? (const acpi_sdt_t*)(uintptr_t)rsdp->xsdt_address
               : (const acpi_sdt_t*)(uintptr_t)rsdp->rsdt_address;
    if (!root) {
        OwDiagLogWarning(OW_W_ACPI_NOT_FOUND, "root system descriptor table missing");
        return false;
    }
    if (root->length < sizeof(acpi_sdt_t) || root->length > 0x10000u) {
        OwDiagLogWarning(OW_W_ACPI_NOT_FOUND, "root SDT length out of range");
        return false;
    }
    /* The ACPI checksum covers the entire table, not just the header. */
    if (acpi_sum((const uint8_t*)root, root->length) != 0) {
        OwDiagLogWarning(OW_W_ACPI_NOT_FOUND, "root SDT checksum mismatch");
        return false;
    }

    fadt = acpi_locate_fadt(root);
    if (!fadt || fadt->pm1a_cnt_blk == 0) {
        OwDiagLogWarning(OW_W_ACPI_NOT_FOUND, "FADT / PM1a control block missing");
        return false;
    }

    {
        uint32_t i;
        for (i = 0; i < 6 && i < sizeof(g_oem_id) - 1; i++) {
            g_oem_id[i] = fadt->hdr.oem_id[i];
        }
        g_oem_id[6] = '\0';
    }

    g_pm1a_cnt = (uint16_t)fadt->pm1a_cnt_blk;
    g_s5_slp_typ = acpi_pick_s5(fadt);
    g_sci_en = (uint8_t)(ow_inw(g_pm1a_cnt) & 1u);

    if (fadt->hdr.length >= 132u) {
        const acpi_gas_t* gas = (const acpi_gas_t*)(const void*)fadt->reset_reg;
        if (gas->address_space_id == 1u &&          /* System I/O */
            gas->register_bit_width == 8u &&
            gas->address != 0) {
            g_reset_reg = (uint16_t)gas->address;
            g_reset_value = fadt->reset_value;
        }
    }

    g_available = true;
    ow_kprintf("[ACPI] firmware tables ready: OEM '%s', PM1a_CNT=0x%X, "
               "S5 typ=%u, SCI_EN=%u\r\n", g_oem_id,
               (unsigned)g_pm1a_cnt, (unsigned)g_s5_slp_typ, (unsigned)g_sci_en);
    if (g_oem_id[0]) OwDiagLogFinished("ACPI Tables", OW_C_ACPI_TABLES_READY);
    return true;
#endif
}

bool OwAcpiIsAvailable(void) {
#ifdef OW_HOST_HAL
    return false;
#else
    return g_available;
#endif
}

void OwAcpiStatus(void) {
#ifdef OW_HOST_HAL
    ow_kprintf("[ACPI] (host harness) status: not available\r\n");
#else
    if (!g_available) {
        ow_kprintf("[ACPI] firmware tables not available\r\n");
        return;
    }
    ow_kprintf("[ACPI] available: OEM '%s', PM1a_CNT=0x%X, "
               "S5 typ=%u, SCI_EN=%u, reset reg=0x%X/0x%X, "
               "safe-power-screen=%s\r\n",
               g_oem_id, (unsigned)g_pm1a_cnt, (unsigned)g_s5_slp_typ,
               (unsigned)g_sci_en, (unsigned)g_reset_reg, (unsigned)g_reset_value,
               g_safe_power_screen ? "on" : "off");
#endif
}

#ifndef OW_HOST_HAL
static void acpi_write_s5_sleep(void) {
    uint16_t v;

    /* Standard ACPI write: preserve current PM1a_CNT, set SLP_TYP + SLP_EN.
     * Only meaningful once ACPI (SCI_EN) is enabled by firmware. */
    v = ow_inw(g_pm1a_cnt);
    v = (uint16_t)((v & ~(uint16_t)OW_ACPI_PM1A_SLP_TYP_MASK) |
                   (uint16_t)((uint16_t)(g_s5_slp_typ & 0x07u) << 10) |
                   OW_ACPI_PM1A_SLP_EN);
    ow_outw(g_pm1a_cnt, v);
}

/* Emulator known-good S5 slots used when the firmware tables disagree. */
static void acpi_legacy_s5_ports(void) {
    ow_outw(0x0604, 0x3400);   /* ICH9 / QEMU q35 */
    ow_outw(0xB004, 0x3C00);   /* PIIX4 / QEMU 'pc' */
    ow_outw(0x0404, 0x3C00);   /* VirtualBox */
}
#endif

void OwAcpiPowerOff(void) {
#ifdef OW_HOST_HAL
    if (g_safe_power_screen) {
        ow_kprintf("[ACPI] (host harness) safe power-off screen\r\n");
        return;
    }
    ow_kprintf("[ACPI] (host harness) software power-off requested\r\n");
    return;
#else
    /* Secret soft off: do NOT pull the power. Park the kernel on the
     * safe-power-off screen and wait for the operator to cut power. */
    if (g_safe_power_screen) {
        ow_kprintf("========================================================\r\n");
        ow_kprintf("  You can safely power off your device now.\r\n");
        ow_kprintf("========================================================\r\n");
        ow_hlt_loop();
        return;
    }

    ow_kprintf("[ACPI] software power-off (S5)\r\n");
    OwDiagLogFinished("Software Power Off", OW_C_ACPI_POWEROFF);

    if (g_available && g_sci_en) {
        acpi_write_s5_sleep();
        OwHalDelayMs(300);
    }

    acpi_legacy_s5_ports();
    OwHalDelayMs(200);

    /* Last-resort legacy APM ports used by QEMU/VirtualBox. */
    ow_outw(0x604, 0x2000);
    ow_outw(0xB004, 0x2000);
    ow_outw(0x600, 0x34);

    ow_kprintf("[ACPI] power-off request complete; halting CPU\r\n");
    ow_hlt_loop();
    return;
#endif
}

void OwAcpiReset(void) {
#ifdef OW_HOST_HAL
    ow_kprintf("[ACPI] (host harness) software reset requested\r\n");
    return;
#else
    ow_kprintf("[ACPI] software reset\r\n");

    /* 8042 keyboard-controller reset. */
    ow_outb(0x64, 0xFE);
    OwHalDelayMs(200);

    /* PIIX / ICH reset-control register. */
    ow_outb(0xCF9, 0x0E);
    OwHalDelayMs(200);

    /* ACPI reset register from FADT (System I/O). */
    if (g_reset_reg) {
        ow_outb(g_reset_reg, g_reset_value);
        OwHalDelayMs(200);
    }

    ow_kprintf("[ACPI] reset request complete; halting CPU\r\n");
    ow_hlt_loop();
    return;
#endif
}