/* host_hal.c - Host-side Hardware Translation Layer for the openwinkrnl.owx
 * boot harness. Mirrors hal/htl.c but routes UART to the console and
 * provides scripted keyboard input, so the real kernel main() -> shell
 * flow can be executed and validated on the build host. */
#include "../../inc/ow_types.h"
#include "../../inc/ow_hal.h"
#include "../../inc/ow_crash_msg.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ---- RAM disks (mirror hal/htl.c: 8 MiB each) --------------------------- */
static uint8_t g_ramdisk_primary[OW_RAMDISK_BLOCK_SIZE * OW_RAMDISK_PRIMARY_BLOCKS];
static uint8_t g_ramdisk_secondary[OW_RAMDISK_BLOCK_SIZE * OW_RAMDISK_SECONDARY_BLOCKS];

typedef struct { uint8_t* data; uint32_t total_blocks; } ramdisk_ctx_t;

static ramdisk_ctx_t g_ctx_primary;
static ramdisk_ctx_t g_ctx_secondary;
static htl_device_t  g_dev_primary;
static htl_device_t  g_dev_secondary;

static htl_status_t ramdisk_read(void* ctx, uint32_t block_num, void* buf, uint32_t block_size) {
    ramdisk_ctx_t* ram = (ramdisk_ctx_t*)ctx;
    if (!ram || !buf) return HTL_ERR_INVALID_PARAM;
    if (block_num >= ram->total_blocks) return HTL_ERR_INVALID_BLOCK;
    memcpy(buf, ram->data + ((size_t)block_num * OW_RAMDISK_BLOCK_SIZE), block_size);
    return HTL_OK;
}

static htl_status_t ramdisk_write(void* ctx, uint32_t block_num, const void* buf, uint32_t block_size) {
    ramdisk_ctx_t* ram = (ramdisk_ctx_t*)ctx;
    if (!ram || !buf) return HTL_ERR_INVALID_PARAM;
    if (block_num >= ram->total_blocks) return HTL_ERR_INVALID_BLOCK;
    memcpy(ram->data + ((size_t)block_num * OW_RAMDISK_BLOCK_SIZE), buf, block_size);
    return HTL_OK;
}

static htl_status_t ramdisk_flush(void* ctx) { (void)ctx; return HTL_OK; }

/* ---- UART: scripted input + captured output ------------------------------ */
#define HOST_OUT_CAP (1u << 20)
static char g_out[HOST_OUT_CAP];
static size_t g_out_len = 0;

static const char* g_in_script = (const char*)0;
static size_t g_in_pos = 0;

char* HostHalOutput(void) { return g_out; }
size_t HostHalOutputLen(void) { return g_out_len; }
void HostHalSetInputScript(const char* script) { g_in_script = script; g_in_pos = 0; }

void OwHalUartInit(void) { }

void OwHalUartWriteChar(char c) {
    if (g_out_len + 1 < HOST_OUT_CAP) {
        g_out[g_out_len++] = c;
        g_out[g_out_len] = '\0';
    }
    putchar(c);
    if (c == '\n') fflush(stdout);
}

void OwHalUartWriteString(const char* str) {
    if (!str) return;
    while (*str) OwHalUartWriteChar(*str++);
}

bool OwHalUartCanRead(void) {
    return g_in_script && g_in_script[g_in_pos] != '\0';
}

char OwHalUartReadChar(void) {
    if (!g_in_script || g_in_script[g_in_pos] == '\0') return '\0';
    return g_in_script[g_in_pos++];
}

uint8_t OwHalPortReadByte(uint16_t Port) { (void)Port; return 0; }
void OwHalPortWriteByte(uint16_t Port, uint8_t Value) { (void)Port; (void)Value; }

/* No real PS/2 hardware on the harness; the shell uses UART script input. */
bool OwHalKbdInitialize(void) { return false; }
bool OwHalKbdCanRead(void) { return false; }
char OwHalKbdReadChar(void) { return '\0'; }

/* ---- VGA: no screen on the harness, everything is serial/console output --- */
static uint64_t g_host_uptime_ms = 0;

void OwHalVgaInitialize(void) { }
void OwHalVgaWriteChar(char c) { (void)c; }
void OwHalVgaSetAttr(uint8_t Attr) { (void)Attr; }
void OwHalVgaSetEnabled(bool Enabled) { (void)Enabled; }
void OwHalVgaStatusBar(const char* Text) { (void)Text; }
void OwHalVgaStatusSetChar(uint32_t col, char c) { (void)col; (void)c; }
void OwHalVgaClearAll(uint8_t Attr) { (void)Attr; }
void OwHalVgaDrawText(uint8_t Row, uint8_t Col, const char* Text, uint8_t Attr) {
    (void)Row; (void)Col; (void)Text; (void)Attr;
}
/* Usermode-only crash screen flags: autoreboot & kdump */
static bool g_crash_autoreboot = false;
static bool g_crash_kdump = false;

void OwHalSetAutoReboot(bool Enable) {
    g_crash_autoreboot = Enable;
}

bool OwHalGetAutoReboot(void) {
    return g_crash_autoreboot;
}

void OwHalSetKdump(bool Enable) {
    g_crash_kdump = Enable;
}

bool OwHalGetKdump(void) {
    return g_crash_kdump;
}

void OwHalCrashScreen(const char* Name, uint32_t Code) {
    OwHalCrashScreenState(Name, Code, OW_CRASH_RECOVERY_NOT_ATTEMPTED,
                          OW_CRASH_RECOVERY_NOT_ATTEMPTED, false);
}

void OwHalCrashScreenState(const char* Name, uint32_t Code,
                           ow_crash_recovery_status_t RecoveryStatus,
                           ow_crash_recovery_status_t TelemetryStatus,
                           bool ResetRequested) {
    const char* msg;
    char line[80];
    char code[16];
    uint32_t v;
    int i;

    static const char* const s_crash_ring[] = {
        "    #######    ",
        "   #### ####   ",
        "   ##/    ##   ",
        "  ### /   ###  ",
        "  ##   /   ##  ",
        "  ###   / ###  ",
        "   ##    /##   ",
        "   #### ####   ",
        "    #######    "
    };
    int rows = (int)(sizeof(s_crash_ring) / sizeof(s_crash_ring[0]));

    msg = OwCrashPickDiagnosticMessage(
        (uint64_t)__builtin_ia32_rdtsc() ^ ((uint64_t)Code << 16),
        g_crash_autoreboot, g_crash_kdump, RecoveryStatus, TelemetryStatus,
        ResetRequested);

    v = Code;
    for (i = 7; i >= 0; i--) { code[i] = "0123456789ABCDEF"[v & 0xF]; v >>= 4; }
    code[8] = '\0';
    snprintf(line, sizeof(line), "B+ U+%s (%s)", code, Name ? Name : "System Fault");

    OwHalUartWriteString("\r\n========================================================================\r\n");
    OwHalUartWriteString(msg);
    OwHalUartWriteString("\r\n\r\n");
    OwHalUartWriteString(line);
    OwHalUartWriteString("\r\n\r\n");
    for (i = 0; i < rows; i++) {
        OwHalUartWriteString("                       ");
        OwHalUartWriteString(s_crash_ring[i]);
        OwHalUartWriteString("\r\n");
    }
    OwHalUartWriteString("\r\n                                SYSTEM HALTED\r\n");
    OwHalUartWriteString("========================================================================\r\n");
}

uint64_t OwHalUptimeMs(void) { return g_host_uptime_ms; }

/* ---- MMIO: bump-allocated scratch ---------------------------------------- */
static uint8_t g_mmio_pool[8u * 1024u * 1024u];
static size_t g_mmio_used = 0;

void* OwHalMapMmio(uint64_t Physical, uint32_t Size) {
    void* p;
    if (g_mmio_used + Size > sizeof(g_mmio_pool)) return (void*)0;
    p = &g_mmio_pool[g_mmio_used];
    g_mmio_used += Size;
    memset(p, 0, Size);
    (void)Physical;
    return p;
}

void OwHalSmpHaltIPI(void) {
    OwHalUartWriteString("[HAL] BROADCASTING IPI_FREEZE_SMP TO ALL CORES\r\n");
}

void OwHalDelayMs(uint32_t ms) {
    g_host_uptime_ms += ms;   /* pacing-only for the hosttest harness */
}

/* OwHalIdtInit + OwHalBootPaceMs - hosttest has no real IDT / PIT; the
 * interlocked interrupt gate table only exists on the long-mode kernel, so
 * the harness keeps no-op stubs so shell/main link cleanly. */
void OwHalIdtInit(uint16_t KernelCodeSelector) { (void)KernelCodeSelector; }
void OwHalBootPaceMs(uint32_t ms) { OwHalDelayMs(ms); }

OW_STATUS OwHalInitialize(void) {
    g_out_len = 0;
    g_in_script = (const char*)0;
    g_in_pos = 0;
    g_mmio_used = 0;

    memset(g_ramdisk_primary, 0, sizeof(g_ramdisk_primary));
    g_ctx_primary.data = g_ramdisk_primary;
    g_ctx_primary.total_blocks = OW_RAMDISK_PRIMARY_BLOCKS;
    memset(&g_dev_primary, 0, sizeof(g_dev_primary));
    g_dev_primary.read_block = ramdisk_read;
    g_dev_primary.write_block = ramdisk_write;
    g_dev_primary.flush_cache = ramdisk_flush;
    g_dev_primary.driver_ctx = &g_ctx_primary;
    g_dev_primary.device_type = HTL_DEV_UNKNOWN;
    g_dev_primary.block_size = OW_RAMDISK_BLOCK_SIZE;
    g_dev_primary.total_blocks = OW_RAMDISK_PRIMARY_BLOCKS;
    g_dev_primary.write_protect = 0;

    memset(g_ramdisk_secondary, 0, sizeof(g_ramdisk_secondary));
    g_ctx_secondary.data = g_ramdisk_secondary;
    g_ctx_secondary.total_blocks = OW_RAMDISK_SECONDARY_BLOCKS;
    memset(&g_dev_secondary, 0, sizeof(g_dev_secondary));
    g_dev_secondary.read_block = ramdisk_read;
    g_dev_secondary.write_block = ramdisk_write;
    g_dev_secondary.flush_cache = ramdisk_flush;
    g_dev_secondary.driver_ctx = &g_ctx_secondary;
    g_dev_secondary.device_type = HTL_DEV_UNKNOWN;
    g_dev_secondary.block_size = OW_RAMDISK_BLOCK_SIZE;
    g_dev_secondary.total_blocks = OW_RAMDISK_SECONDARY_BLOCKS;
    g_dev_secondary.write_protect = 0;

    return OW_SUCCESS;
}

htl_device_t* OwHalGetPrimaryDisk(void) { return &g_dev_primary; }
htl_device_t* OwHalGetSecureDisk(void) { return &g_dev_secondary; }