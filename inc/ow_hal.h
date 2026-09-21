/* ow_hal.h - OpenWindows hardware translation layer (HAL) */
#ifndef OW_HAL_H
#define OW_HAL_H

#include "../inc/ow_types.h"
#include "../lib/ow_htl.h"
#include "ow_crash_msg.h"

#define OW_HAL_BLOCK_SIZE           0x1000U
#define OW_RAMDISK_BLOCK_SIZE       0x1000U
#define OW_RAMDISK_PRIMARY_BLOCKS   2048U
#define OW_RAMDISK_SECONDARY_BLOCKS 2048U
#define OW_HAL_RAMDISK_PRIMARY_BLOCKS   2048U
#define OW_HAL_RAMDISK_SECONDARY_BLOCKS 2048U

#define OW_HAL_MMIO_APIC            0xFEE00000ULL
#define OW_HAL_MMIO_UART            0xFE001000ULL
#define OW_HAL_MMIO_FB              0xFD000000ULL
#define OW_HAL_MMIO_FB_SIZE         (1024U * 768U * 4U)

#define OW_UART_COM1                0x3F8U

typedef struct _OW_HAL_MMIO {
    uint64_t    PhysicalAddress;
    uint64_t    VirtualAddress;
    uint32_t    Size;
    const char* DeviceName;
} OW_HAL_MMIO;

OW_STATUS    OwHalInitialize(void);
void         OwHalSetupUserMode(void);
void         OwHalTssSetRsp0(uint64_t KernelStackTop);
void         OwHalMemSetUserAccessible(uint64_t VirtualAddress);
void         OwHalUartInitialize(void);
void         OwHalUartWriteChar(char c);
void         OwHalUartWriteString(const char* s);
bool         OwHalUartCanRead(void);
char         OwHalUartReadChar(void);
uint8_t      OwHalPortReadByte(uint16_t Port);
void         OwHalPortWriteByte(uint16_t Port, uint8_t Value);
void*        OwHalMapMmio(uint64_t Physical, uint32_t Size);
void         OwHalSmpHaltIPI(void);
htl_device_t* OwHalGetPrimaryDisk(void);
htl_device_t* OwHalGetSecureDisk(void);
void         OwHalVgaInitialize(void);
void         OwHalVgaWriteChar(char c);
void         OwHalVgaSetAttr(uint8_t Attr);
void         OwHalVgaSetEnabled(bool Enabled);
void         OwHalVgaStatusBar(const char* Text);
void         OwHalVgaStatusSetChar(uint32_t col, char c);
void         OwHalVgaClearAll(uint8_t Attr);
void         OwHalVgaDrawText(uint8_t Row, uint8_t Col, const char* Text,
                              uint8_t Attr);
void         OwHalCrashScreen(const char* Name, uint32_t Code);
void         OwHalCrashScreenState(const char* Name, uint32_t Code,
                                   ow_crash_recovery_status_t RecoveryStatus,
                                   ow_crash_recovery_status_t TelemetryStatus,
                                   bool ResetRequested);
void         OwHalSetAutoReboot(bool Enable);
bool         OwHalGetAutoReboot(void);
void         OwHalSetKdump(bool Enable);
bool         OwHalGetKdump(void);
void         OwHalDelayMs(uint32_t ms);
uint64_t     OwHalUptimeMs(void);
bool         OwHalKbdInitialize(void);
bool         OwHalKbdCanRead(void);
char         OwHalKbdReadChar(void);
void         OwHalIdtInit(uint16_t KernelCodeSelector);
void         OwHalBootPaceMs(uint32_t ms);

#endif /* OW_HAL_H */
