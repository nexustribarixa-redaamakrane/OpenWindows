/* htl.c - Hardware Translation Layer (HAL) */
#include "../inc/ow_hal.h"
#include "../inc/ow_io.h"
#include "../inc/ow_mem.h"
#include "../lib/kalloc.h"

/* ---- GDT + TSS (Ring 3 support) -----------------------------------------
 * The boot loaders install a minimal 3-entry GDT (null, kernel code 0x08,
 * kernel data 0x10).  OwHalSetupUserMode() replaces it with a full table:
 * same kernel descriptors at identical selectors, plus DPL3 user code/data
 * (0x18 / 0x20) and a 64-bit TSS (0x28) whose RSP0 the scheduler repoints
 * at the currently-running user thread's kernel stack before each CPL3
 * resume, so every trap/IRQ from user mode lands on a clean stack. */
#define OW_GDT_KCODE   0x08U
#define OW_GDT_KDATA   0x10U
#define OW_GDT_UCODE   0x18U
#define OW_GDT_UDATA   0x20U
#define OW_GDT_TSS     0x28U
#define OW_TSS_LIMIT   0x67U   /* 104-byte TSS minus 1 */
#define OW_TSS_NO_IO   0x68U   /* I/O map base past limit: user I/O is #GP */

typedef struct __attribute__((packed)) {
    uint32_t Reserved1;                 /* +0x00 */
    uint64_t Rsp0;                      /* +0x04 */
    uint64_t Rsp1;                      /* +0x0C */
    uint64_t Rsp2;                      /* +0x14 */
    uint64_t Ist[7];                    /* +0x1C */
    uint64_t Reserved2;                 /* +0x54 */
    uint16_t Reserved3;                 /* +0x5C */
    uint16_t IomapBase;                 /* +0x5E */
} OW_TSS;

static uint64_t ow_gdt[8];
static OW_TSS   ow_tss;

void OwHalSetupUserMode(void) {
    uint64_t tss_base = (uint64_t)(uintptr_t)&ow_tss;
    struct __attribute__((packed)) {
        uint16_t Limit;
        uint64_t Base;
    } gdtr;

    /* Preserve the exact kernel descriptors the loaders established, then
     * append user code/data and the TSS (long-mode TSS descriptor spans two
     * consecutive GDT slots; the base high dword lives in slot 6). */
    ow_gdt[0] = 0x0000000000000000ULL;   /* 0x00 null                */
    ow_gdt[1] = 0x00209A0000000000ULL;   /* 0x08 kernel code (L=1)   */
    ow_gdt[2] = 0x0000920000000000ULL;   /* 0x10 kernel data         */
    ow_gdt[3] = 0x0020FA0000000000ULL;   /* 0x18 user   code (DPL3)  */
    ow_gdt[4] = 0x0000F20000000000ULL;   /* 0x20 user   data (DPL3)  */
    ow_gdt[5] = (uint64_t)(OW_TSS_LIMIT & 0xFFFFu)
             | (((tss_base)      & 0xFFFFu) << 16)
             | (((tss_base >> 16) & 0xFFull) << 32)
             | (0x89ull << 40)             /* present, 64-bit TSS, avail */
             | (((tss_base >> 24) & 0xFFull) << 56);
    ow_gdt[6] = (tss_base >> 32);         /* TSS base[63:32]            */
    ow_gdt[7] = 0x0000000000000000ULL;   /* padding, reserved          */

    /* I/O map disabled: any CPL3 port I/O raises #GP. */
    ow_memset(&ow_tss, 0, sizeof(ow_tss));
    ow_tss.Rsp0 = 0;
    ow_tss.Ist[0] = 0;
    ow_tss.IomapBase = OW_TSS_NO_IO;

    gdtr.Limit = (uint16_t)(sizeof(ow_gdt) - 1u);
    gdtr.Base  = (uint64_t)(uintptr_t)ow_gdt;
    __asm__ volatile("lgdt %0" : : "m"(gdtr) : "memory");

    {
        uint16_t sel = OW_GDT_TSS;
        __asm__ volatile("ltr %0" : : "r"(sel));
    }
}

/* Repoint TSS.RSP0 at the current user thread's kernel stack before it is
 * resumed into CPL3.  A plain memory write suffices: the CPU re-reads RSP0
 * from the TSS structure on every trap that changes privilege. */
void OwHalTssSetRsp0(uint64_t KernelStackTop) {
    ow_tss.Rsp0 = KernelStackTop;
}

/* Give a 2 MB identity-mapped page (huge-page PDE under the current PML4)
 * the User/Supervisor bit so CPL3 code/data/stack can live there.  The boot
 * maps all RAM as supervisor (PDE = 0x83); user space needs U/S set.  The
 * caller must guarantee the page is identity-mapped, physically free (not
 * kernel .bss / stack pool), and backed by RAM.  OW_USER_BASE 0x4000000
 * (64 MiB) sits above the kernel's BSS end (~47 MiB) and within RAM. */
void OwHalMemSetUserAccessible(uint64_t VirtualAddress) {
    uint64_t cr3;
    uint64_t pml4i = (VirtualAddress >> 39) & 0x1FFull;
    uint64_t pdpti = (VirtualAddress >> 30) & 0x1FFull;
    uint64_t pdi   = (VirtualAddress >> 21) & 0x1FFull;
    uint64_t* pml4;
    uint64_t* pdpt;
    uint64_t* pd;
    uint64_t  pde;

    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));
    pml4 = (uint64_t*)cr3;

    /* U/S is checked on EVERY level of the x86-64 page walk, not just the
     * leaf: a CPL3 access only succeeds if the PML4E, the PDPTE AND the PDE
     * all carry the user bit.  The boot identity map stamps RAM supervisor
     * (0x83) at every level, so this helper must raise U/S on every present
     * level of the walked path.  (The leaf PDE still gates: kernel pages
     * keep U/S=0 there, so rising the upper shared levels alone does not
     * expose supervisor RAM to CPL3.) */
    if ((pml4[pml4i] & 1ull) == 0) return;
    pml4[pml4i] |= 4ull;                      /* U/S on PML4E   */
    pdpt = (uint64_t*)(pml4[pml4i] & 0x000FFFFFFFFFF000ull);
    if ((pdpt[pdpti] & 1ull) == 0) return;
    pdpt[pdpti] |= 4ull;                      /* U/S on PDPTE   */
    pd = (uint64_t*)(pdpt[pdpti] & 0x000FFFFFFFFFF000ull);
    pde = pd[pdi];
    pd[pdi] = pde | 4ull;                     /* set U/S on PDE (leaf gate) */
    __asm__ volatile("invlpg (%0)" : : "r"(VirtualAddress) : "memory");
}

#define MAX_MMIO_RANGES 32U

static OW_HAL_MMIO g_Mmio[MAX_MMIO_RANGES];
static uint32_t g_MmioCount = 0;

/* Primary RAM disk: blocks 0-2047 (8 MiB) */
static uint8_t g_ramdisk_primary[OW_RAMDISK_BLOCK_SIZE * OW_RAMDISK_PRIMARY_BLOCKS];
/* Secondary RAM disk: blocks 2048-4095 (8 MiB) */
static uint8_t g_ramdisk_secondary[OW_RAMDISK_BLOCK_SIZE * OW_RAMDISK_SECONDARY_BLOCKS];

typedef struct {
    uint8_t*    data;
    uint32_t    total_blocks;
} ramdisk_ctx_t;

static ramdisk_ctx_t g_ctx_primary;
static ramdisk_ctx_t g_ctx_secondary;
static htl_device_t g_dev_primary;
static htl_device_t g_dev_secondary;

static htl_status_t ramdisk_read(void* ctx, uint32_t block_num, void* buf, uint32_t block_size) {
    ramdisk_ctx_t* ram = (ramdisk_ctx_t*)ctx;
    if (!ram || !buf) return HTL_ERR_INVALID_PARAM;
    if (block_num >= ram->total_blocks) return HTL_ERR_INVALID_BLOCK;
    ow_memcpy(buf, ram->data + ((size_t)block_num * OW_RAMDISK_BLOCK_SIZE), block_size);
    return HTL_OK;
}

static htl_status_t ramdisk_write(void* ctx, uint32_t block_num, const void* buf, uint32_t block_size) {
    ramdisk_ctx_t* ram = (ramdisk_ctx_t*)ctx;
    if (!ram || !buf) return HTL_ERR_INVALID_PARAM;
    if (block_num >= ram->total_blocks) return HTL_ERR_INVALID_BLOCK;
    ow_memcpy(ram->data + ((size_t)block_num * OW_RAMDISK_BLOCK_SIZE), buf, block_size);
    return HTL_OK;
}

static htl_status_t ramdisk_flush(void* ctx) {
    (void)ctx;
    return HTL_OK;
}

/* UART COM1 (16550) */
static uint8_t g_uart_input_ok = 0;

static void uart_init(void) {
    ow_outb(OW_UART_COM1 + 1, 0x00);
    ow_outb(OW_UART_COM1 + 3, 0x80);
    ow_outb(OW_UART_COM1 + 0, 0x03);
    ow_outb(OW_UART_COM1 + 1, 0x00);
    ow_outb(OW_UART_COM1 + 3, 0x03);
    ow_outb(OW_UART_COM1 + 2, 0xC7);
    /* Presence probe: an absent/unwired 16550 (e.g. VirtualBox with no serial
     * port) reads back 0xFF with every LSR bit set, which would make the
     * shell think input is always pending and starve the keyboard. Only
     * trust input if the line status register reads sane at idle (error
     * bits clear, e.g. 0x60 = THRE|TSRE). */
    {
        uint8_t lsr = ow_inb(OW_UART_COM1 + 5);
        g_uart_input_ok = (lsr != 0xFFU) && ((lsr & 0x1EU) == 0U);
    }
}

static void uart_wait_tx(void) {
    while ((ow_inb(OW_UART_COM1 + 5) & 0x20) == 0) {}
}

#define VGA_MEMORY      ((volatile uint16_t*)0xB8000U)
#define VGA_COLS  80
#define VGA_ROWS  25
#define VGA_LOGO_ROWS   4          /* pinned boot logo region (rows 0-3) */
#define VGA_STATUS_ROW  (VGA_ROWS - 1)  /* pinned HUD status region (row 24) */

#define VGA_CRTC_INDEX  0x3D4U
#define VGA_CRTC_DATA   0x3D5U

static uint16_t g_vga_row = 0;
static uint16_t g_vga_col = 0;
static uint8_t  g_vga_attr   = 0x07U;    /* default: light gray on black */
static uint8_t  g_vga_enabled = 1;
static uint64_t g_kernel_uptime_ms = 0;

/* Program the VGA hardware text cursor so the blinking block tracks the
 * console position instead of sitting frozen at the top-left corner. */
static void vga_update_cursor(void) {
    uint16_t off = (uint16_t)((uint32_t)g_vga_row * VGA_COLS + (uint32_t)g_vga_col);
    ow_outb(VGA_CRTC_INDEX, 0x0FU);
    ow_outb(VGA_CRTC_DATA, (uint8_t)(off & 0xFFU));
    ow_outb(VGA_CRTC_INDEX, 0x0EU);
    ow_outb(VGA_CRTC_DATA, (uint8_t)((off >> 8) & 0xFFU));
}

void OwHalVgaInitialize(void) {
    uint32_t i;
    volatile uint16_t* mem = VGA_MEMORY;
    for (i = 0; i < VGA_COLS * VGA_ROWS; i++) mem[i] = 0x0700;
    g_vga_row = 0;
    g_vga_col = 0;
    g_vga_attr = 0x07U;
    g_vga_enabled = 1;
    vga_update_cursor();
}

/* Console scrolling keeps the pinned logo region (rows 0-3) and the HUD
 * status row (row 24) fixed; only the log area between them shifts. */
static void vga_scroll(void) {
    volatile uint16_t* mem = VGA_MEMORY;
    uint32_t i;
    uint32_t first = VGA_LOGO_ROWS * VGA_COLS;
    for (i = first; i < (VGA_STATUS_ROW - 1) * VGA_COLS; i++) mem[i] = mem[i + VGA_COLS];
    for (i = (VGA_STATUS_ROW - 1) * VGA_COLS; i < VGA_STATUS_ROW * VGA_COLS; i++) mem[i] = 0x0700;
    g_vga_row = VGA_STATUS_ROW - 1;
    g_vga_col = 0;
    vga_update_cursor();
}

void OwHalVgaWriteChar(char c) {
    volatile uint16_t* mem = VGA_MEMORY;
    uint32_t off;

    if (!g_vga_enabled) return;

    switch (c) {
    case '\r':
        g_vga_col = 0;
        vga_update_cursor();
        return;
    case '\n':
        g_vga_row++;
        g_vga_col = 0;
        if (g_vga_row >= VGA_STATUS_ROW) vga_scroll();
        vga_update_cursor();
        return;
    case '\b':
        if (g_vga_col > 0) g_vga_col--;
        mem[(uint32_t)g_vga_row * VGA_COLS + (uint32_t)g_vga_col] =
            (uint16_t)((uint16_t)(g_vga_attr << 8) | 0x00U);
        vga_update_cursor();
        return;
    case '\t':
        do { g_vga_col++; } while (g_vga_col & 7U);
        if (g_vga_col >= VGA_COLS) { g_vga_col = 0; g_vga_row++; }
        if (g_vga_row >= VGA_STATUS_ROW) vga_scroll();
        vga_update_cursor();
        return;
    default:
        break;
    }

    if (g_vga_col >= VGA_COLS) {
        g_vga_col = 0;
        g_vga_row++;
        if (g_vga_row >= VGA_STATUS_ROW) vga_scroll();
    }
    off = (uint32_t)g_vga_row * VGA_COLS + (uint32_t)g_vga_col;
    mem[off] = (uint16_t)((uint16_t)(g_vga_attr << 8) | ((uint8_t)c));
    g_vga_col++;
    vga_update_cursor();
}

void OwHalVgaSetAttr(uint8_t Attr) { g_vga_attr = Attr; }

void OwHalVgaSetEnabled(bool Enabled) { g_vga_enabled = Enabled ? 1 : 0; }

/* HUD status row renderer: blue field, bright white text (row 24, pinned). */
void OwHalVgaStatusBar(const char* Text) {
    volatile uint16_t* mem = VGA_MEMORY;
    uint32_t i, base = (uint32_t)VGA_STATUS_ROW * VGA_COLS;
    for (i = 0; i < VGA_COLS; i++) mem[base + i] = 0x1F00;
    if (Text) {
        for (i = 0; Text[i] && i < VGA_COLS; i++) {
            mem[base + i] = (uint16_t)((0x1FU << 8) | (uint8_t)Text[i]);
        }
    }
    vga_update_cursor();
}

/* Update a single HUD cell (e.g. a spinner character in the status row). */
void OwHalVgaStatusSetChar(uint32_t Col, char c) {
    volatile uint16_t* mem = VGA_MEMORY;
    if (Col >= VGA_COLS) return;
    mem[(uint32_t)VGA_STATUS_ROW * VGA_COLS + Col] =
        (uint16_t)((0x1FU << 8) | (uint8_t)c);
    vga_update_cursor();
}

/* Fill the entire text buffer with one attribute (used to clear the screen to
 * a flat background, e.g. black during the BANcode crash banner). */
void OwHalVgaClearAll(uint8_t Attr) {
    volatile uint16_t* mem = VGA_MEMORY;
    uint32_t i;
    for (i = 0; i < VGA_COLS * VGA_ROWS; i++) mem[i] = (uint16_t)((uint16_t)(Attr << 8) | 0x20U);
    vga_update_cursor();
}

/* Paint a literal string at an absolute (row, col) instead of through the
 * rolling console cursor. Used by the crash screen for exact placement. */
void OwHalVgaDrawText(uint8_t Row, uint8_t Col, const char* Text, uint8_t Attr) {
    volatile uint16_t* mem = VGA_MEMORY;
    uint32_t off;
    uint32_t x;
    if (!Text) return;
    if (Row >= VGA_ROWS || Col >= VGA_COLS) return;
    off = (uint32_t)Row * VGA_COLS + (uint32_t)Col;
    for (x = 0; Text[x] != '\0' && (Col + x) < VGA_COLS; x++) {
        mem[off + x] = (uint16_t)((uint16_t)(Attr << 8) | (uint8_t)Text[x]);
    }
    vga_update_cursor();
}

uint64_t OwHalUptimeMs(void) { return g_kernel_uptime_ms; }

OW_STATUS OwHalInitialize(void) {
    uint32_t i;

    /* Install the full GDT (user selectors + TSS) up front so every later
     * boot phase can assume CPL3 machinery is available. */
    OwHalSetupUserMode();

    /* NOTE: VGA is prepared by the boot loader (OwHalVgaInitialize + pinned
     * logo) before phase 1 runs, so we must not wipe the screen here. */

    /* Initialize UART */
    uart_init();

    /* Initialize MMIO tracking */
    g_MmioCount = 0;

    /* Initialize primary RAM disk */
    ow_memset(g_ramdisk_primary, 0, sizeof(g_ramdisk_primary));
    g_ctx_primary.data = g_ramdisk_primary;
    g_ctx_primary.total_blocks = OW_RAMDISK_PRIMARY_BLOCKS;
    ow_memset(&g_dev_primary, 0, sizeof(g_dev_primary));
    g_dev_primary.read_block = ramdisk_read;
    g_dev_primary.write_block = ramdisk_write;
    g_dev_primary.flush_cache = ramdisk_flush;
    g_dev_primary.driver_ctx = &g_ctx_primary;
    g_dev_primary.device_type = HTL_DEV_UNKNOWN;
    g_dev_primary.block_size = OW_RAMDISK_BLOCK_SIZE;
    g_dev_primary.total_blocks = OW_RAMDISK_PRIMARY_BLOCKS;
    g_dev_primary.write_protect = 0;

    /* Initialize secondary RAM disk */
    ow_memset(g_ramdisk_secondary, 0, sizeof(g_ramdisk_secondary));
    g_ctx_secondary.data = g_ramdisk_secondary;
    g_ctx_secondary.total_blocks = OW_RAMDISK_SECONDARY_BLOCKS;
    ow_memset(&g_dev_secondary, 0, sizeof(g_dev_secondary));
    g_dev_secondary.read_block = ramdisk_read;
    g_dev_secondary.write_block = ramdisk_write;
    g_dev_secondary.flush_cache = ramdisk_flush;
    g_dev_secondary.driver_ctx = &g_ctx_secondary;
    g_dev_secondary.device_type = HTL_DEV_UNKNOWN;
    g_dev_secondary.block_size = OW_RAMDISK_BLOCK_SIZE;
    g_dev_secondary.total_blocks = OW_RAMDISK_SECONDARY_BLOCKS;
    g_dev_secondary.write_protect = 0;

    /* Map MMIO regions */
    OwHalMapMmio(OW_HAL_MMIO_APIC, 0x1000);
    OwHalMapMmio(OW_HAL_MMIO_UART, 0x1000);
    OwHalMapMmio(OW_HAL_MMIO_FB, OW_HAL_MMIO_FB_SIZE);

    (void)i;
    return OW_SUCCESS;
}

void OwHalUartInit(void) { uart_init(); }

void OwHalUartWriteChar(char c) {
    uart_wait_tx();
    ow_outb(OW_UART_COM1, (uint8_t)c);
    OwHalVgaWriteChar(c);
}

void OwHalUartWriteString(const char* str) {
    if (!str) return;
    while (*str) { OwHalUartWriteChar(*str); str++; }
}

/* 8254 PIT.  Channel 0 is reprogrammed by OwPsStartScheduler() to PERIODIC
 * mode at 100 Hz (scheduler preemption tick, vector 0x20 = IRQ0, handled in
 * hal/idt.c).  The busy-delay below uses channel 2 exclusively so it never
 * disturbs the periodic tick that the process/thread subsystem depends on. */
#define PIT_CMD_PORT      0x43U
#define PIT_CMD_CH2       0xB6U            /* ch2, lobyte/hibyte, mode 3, binary */
#define PIT_CMD_CH2_LATCH 0x80U            /* ch2, latch count */
#define PIT_DATA_CH0      0x40U
#define PIT_DATA_CH2      0x42U
#define PIT_DIVISOR_1KHZ  1193U

static uint16_t pit_read_count_ch2(void) {
    uint16_t lo, hi;
    ow_outb(PIT_CMD_PORT, PIT_CMD_CH2_LATCH);
    lo = ow_inb(PIT_DATA_CH2);
    hi = ow_inb(PIT_DATA_CH2);
    return (uint16_t)(lo | (uint16_t)(hi << 8));
}

void OwHalDelayMs(uint32_t ms) {
    uint32_t elapsed = 0;
    uint16_t start, now;

    if (ms == 0) return;
    ow_outb(PIT_CMD_PORT, PIT_CMD_CH2);
    ow_outb(PIT_DATA_CH2, (uint8_t)(PIT_DIVISOR_1KHZ & 0xFFU));
    ow_outb(PIT_DATA_CH2, (uint8_t)(PIT_DIVISOR_1KHZ >> 8));

    start = pit_read_count_ch2();
    while (elapsed < ms) {
        now = pit_read_count_ch2();
        elapsed += (uint16_t)(start - now);   /* countdown wraps cleanly in u16 */
        start = now;
    }
    g_kernel_uptime_ms += elapsed;
}

bool OwHalUartCanRead(void) {
    if (!g_uart_input_ok) return false;
    return (ow_inb(OW_UART_COM1 + 5) & 0x01) != 0;
}

char OwHalUartReadChar(void) {
    if (!g_uart_input_ok) return '\0';
    while (!OwHalUartCanRead()) {}
    return (char)ow_inb(OW_UART_COM1);
}

uint8_t OwHalPortReadByte(uint16_t Port) {
    if (Port == OW_UART_COM1 && OwHalUartCanRead()) return ow_inb(Port);
    return 0;
}

void OwHalPortWriteByte(uint16_t Port, uint8_t Value) {
    if (Port == OW_UART_COM1) OwHalUartWriteChar((char)Value);
}

void* OwHalMapMmio(uint64_t Physical, uint32_t Size) {
    void* virt;
    if (g_MmioCount >= MAX_MMIO_RANGES) return (void*)0;
    virt = kcalloc(1, Size);
    if (!virt) return (void*)0;

    g_Mmio[g_MmioCount].PhysicalAddress = Physical;
    g_Mmio[g_MmioCount].VirtualAddress = (uint64_t)(uintptr_t)virt;
    g_Mmio[g_MmioCount].Size = Size;

    if (Physical == OW_HAL_MMIO_APIC) g_Mmio[g_MmioCount].DeviceName = "LocalAPIC";
    else if (Physical == OW_HAL_MMIO_UART) g_Mmio[g_MmioCount].DeviceName = "UART16550";
    else if (Physical == OW_HAL_MMIO_FB) g_Mmio[g_MmioCount].DeviceName = "LinearFrameBuffer";
    else g_Mmio[g_MmioCount].DeviceName = "MMIO-Generic";

    g_MmioCount++;
    return virt;
}

void OwHalSmpHaltIPI(void) {
    OwHalUartWriteString("[HAL] BROADCASTING IPI_FREEZE_SMP TO ALL CORES\r\n");
}

htl_device_t* OwHalGetPrimaryDisk(void) { return &g_dev_primary; }
htl_device_t* OwHalGetSecureDisk(void) { return &g_dev_secondary; }
