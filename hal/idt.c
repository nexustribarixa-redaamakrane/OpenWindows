/* idt.c - OpenWindows long-mode IDT: gate table, lidt, common handler.
 *
 * The 32 ISR stubs in hal/interrupts.S normalise every CPU exception frame
 * (synthetic error code where the CPU supplies none, vector always pushed on
 * top) and fall through the shared 64-bit entry, which pushes the 15 GP
 * registers so RAX lands at offset +0 and R15 at +112 (see the offset map in
 * hal/interrupts.S). The shared entry then calls OwHalCommonInterruptHandler
 * with a pointer to that frame. This file owns the IDT itself: it lays the
 * 256-entry long-mode gate table (gates 0-31 wired to the real stubs, the
 * rest parked on OwIsrTable[0]), loads it with lidt via the packed 10-byte
 * pseudo-descriptor, and provides the C handler that melts the screen into a
 * red crash banner and halts - it never returns, so the iretq path in the
 * assembly stays a correctness contract only.
 */
#include "../inc/ow_hal.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_io.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_syscall.h"
#include "../inc/ow_crash_msg.h"
#include "idt.h"

/* ---- IDT storage ------------------------------------------------------ */

#define OW_IDT_ENTRIES  256U
#define OW_IDT_ATTR     0x8EU          /* present, DPL0, 64-bit intr gate */
#define OW_IDT_SYSCALL_VEC 0x80U
#define OW_IDT_SYSCALL_ATTR 0xEEU      /* present, DPL3, 64-bit intr gate */
#define OW_IDT_CS       0x08U          /* GDT kernel code selector         */
#define OW_GATE_OFFSET(g)  ((int)((const ow_idt_entry_t*)(g) - ow_idt_table))

/* Vector 0x80 is the ring-3 syscall gate; the entry must be callable from
 * CPL3 (DPL3), so idt.c special-cases it rather than baking it into the
 * static stub table. */
extern void OwIsr128(void);

static ow_idt_entry_t  ow_idt_table[OW_IDT_ENTRIES];
static uint8_t         ow_idt_loaded;

/* Externs from hal/interrupts.S (one per vector 0-31). */
extern void OwIsr0(void);
extern void OwIsr1(void);
extern void OwIsr2(void);
extern void OwIsr3(void);
extern void OwIsr4(void);
extern void OwIsr5(void);
extern void OwIsr6(void);
extern void OwIsr7(void);
extern void OwIsr8(void);
extern void OwIsr9(void);
extern void OwIsr10(void);
extern void OwIsr11(void);
extern void OwIsr12(void);
extern void OwIsr13(void);
extern void OwIsr14(void);
extern void OwIsr15(void);
extern void OwIsr16(void);
extern void OwIsr17(void);
extern void OwIsr18(void);
extern void OwIsr19(void);
extern void OwIsr20(void);
extern void OwIsr21(void);
extern void OwIsr22(void);
extern void OwIsr23(void);
extern void OwIsr24(void);
extern void OwIsr25(void);
extern void OwIsr26(void);
extern void OwIsr27(void);
extern void OwIsr28(void);
extern void OwIsr29(void);
extern void OwIsr30(void);
extern void OwIsr31(void);
extern void OwIsr32(void);

static const void* const OwIsrStubs[OW_IDT_ENTRIES] = {
    OwIsr0,  OwIsr1,  OwIsr2,  OwIsr3,  OwIsr4,  OwIsr5,  OwIsr6,  OwIsr7,
    OwIsr8,  OwIsr9,  OwIsr10, OwIsr11, OwIsr12, OwIsr13, OwIsr14, OwIsr15,
    OwIsr16, OwIsr17, OwIsr18, OwIsr19, OwIsr20, OwIsr21, OwIsr22, OwIsr23,
    OwIsr24, OwIsr25, OwIsr26, OwIsr27, OwIsr28, OwIsr29, OwIsr30, OwIsr31,
    OwIsr32, OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,
    OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,
    OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,
    OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0,  OwIsr0
};

static const char* const OwVectorNames[32] = {
    "Divide Error",            /* 0  */
    "Debug",                   /* 1  */
    "Non-Maskable Interrupt",  /* 2  */
    "Breakpoint",              /* 3  */
    "Overflow",                /* 4  */
    "BOUND Range Exceeded",    /* 5  */
    "Invalid Opcode",          /* 6  */
    "Device Not Available",    /* 7  */
    "Double Fault",            /* 8  */
    "Coprocessor Segment",     /* 9  */
    "Invalid TSS",             /* 10 */
    "Segment Not Present",     /* 11 */
    "Stack-Segment Fault",     /* 12 */
    "General Protection",      /* 13 */
    "Page Fault",              /* 14 */
    "Reserved",                /* 15 */
    "x87 Floating-Point",      /* 16 */
    "Alignment Check",         /* 17 */
    "Machine Check",           /* 18 */
    "SIMD Floating-Point",     /* 19 */
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved"
};

const char* OwHalVectorName(uint32_t Vector) {
    return (Vector < 32U) ? OwVectorNames[Vector] : "Unknown Vector";
}

/* ---- BANcode crash banner ------------------------------------------------
 * Draws a Windows-style "stop" screen directly to the VGA text buffer:
 *   black background, red ASCII prohibitory ring centered, white
 *   "You need to restart your device." message in the top corner, then the
 *   stop code + exception reason and a register summary below the ring. */

#define OW_CRASH_ATTR_BLACK      0x00U   /* black on black               */
#define OW_CRASH_ATTR_WHITE      0x0FU   /* bright white on black        */
#define OW_CRASH_ATTR_DIM        0x07U   /* light gray on black          */
#define OW_CRASH_ATTR_RED        0x0CU   /* bright red on black          */

static const char* const ow_crash_ring[] = {
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
#define OW_CRASH_RING_ROWS  ((int)(sizeof(ow_crash_ring) / sizeof(ow_crash_ring[0])))
#define OW_CRASH_RING_TOP   ((uint8_t)7)
#define OW_CRASH_RING_COL   ((uint8_t)32)

static const char* const ow_hex_upper = "0123456789ABCDEF";

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
    uint32_t lo, hi;

    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    msg = OwCrashPickDiagnosticMessage(
        (((uint64_t)hi << 32) | (uint64_t)lo) ^ ((uint64_t)Code << 16),
        g_crash_autoreboot, g_crash_kdump, RecoveryStatus, TelemetryStatus,
        ResetRequested);

    OwHalVgaClearAll(OW_CRASH_ATTR_BLACK);

    {
        int len = 0;
        while (msg[len] != '\0') len++;
        if (len > 78) {
            int split = 78;
            while (split > 0 && msg[split] != ' ') split--;
            if (split == 0) split = 78;
            char part1[80], part2[80];
            int j;
            for (j = 0; j < split && j < 79; j++) part1[j] = msg[j];
            part1[j] = '\0';
            int start2 = (msg[split] == ' ') ? split + 1 : split;
            for (j = 0; msg[start2 + j] != '\0' && j < 79; j++) part2[j] = msg[start2 + j];
            part2[j] = '\0';
            OwHalVgaDrawText(0, 1, part1, OW_CRASH_ATTR_WHITE);
            OwHalVgaDrawText(1, 1, part2, OW_CRASH_ATTR_WHITE);
        } else {
            OwHalVgaDrawText(0, 1, msg, OW_CRASH_ATTR_WHITE);
        }
    }
    v = Code;
    for (i = 7; i >= 0; i--) { code[i] = ow_hex_upper[v & 0xF]; v >>= 4; }
    code[8] = '\0';
    ow_ksnprintf(line, sizeof(line), "B+ U+%s (%s)", code, Name ? Name : "System Fault");
    OwHalVgaDrawText(2, 1, line, OW_CRASH_ATTR_WHITE);

    for (i = 0; i < OW_CRASH_RING_ROWS; i++) {
        OwHalVgaDrawText((uint8_t)(OW_CRASH_RING_TOP + i), OW_CRASH_RING_COL,
                         ow_crash_ring[i], OW_CRASH_ATTR_RED);
    }

    OwHalVgaDrawText(21, 34, "SYSTEM HALTED", OW_CRASH_ATTR_WHITE);

    /* Also emit crash screen banner to UART serial terminal */
    OwHalUartWriteString("\r\n========================================================================\r\n");
    OwHalUartWriteString(msg);
    OwHalUartWriteString("\r\n\r\n");
    OwHalUartWriteString(line);
    OwHalUartWriteString("\r\n\r\n");
    for (i = 0; i < OW_CRASH_RING_ROWS; i++) {
        OwHalUartWriteString("                       ");
        OwHalUartWriteString(ow_crash_ring[i]);
        OwHalUartWriteString("\r\n");
    }
    OwHalUartWriteString("\r\n                                SYSTEM HALTED\r\n");
    OwHalUartWriteString("========================================================================\r\n");
}

/* ---- Common interrupt handler --------------------------------------------
 * Vector 0x20 (PIT timer) feeds the PS round-robin scheduler: the ISR frame
 * is handed to OwPsSchedulerTick, the 8259 is acknowledged with EOI, and the
 * handler returns so the ISR assembly path iretq's back into the interrupted
 * thread (or, if the scheduler switched threads, into the next thread).
 * Every other vector melts the screen into the red crash banner and halts. */
void OwHalCommonInterruptHandler(ow_hal_frame_t* Frame) {
    const char*    Name;
    uint32_t       vec;

    if (!Frame) return;
    vec = (uint32_t)Frame->Vector;

    if (vec == OW_IDT_SYSCALL_VEC) {
        Frame->Rax = (uint64_t)OwSyscallDispatch(
            (uint32_t)Frame->Rax, Frame->Rcx, Frame->Rdx, Frame->R8);
        return;
    }

    if (vec == 0x20u) {
        /* PIT IRQ0 tick: acknowledge the master 8259 FIRST (the scheduler
         * may switch threads and never return here, so the EOI must already
         * be in).  Only then run the round-robin tick. */
        ow_outb(0x20u, 0x20u);        /* EOI to master 8259 */
        OwPsSchedulerTick((void*)Frame);
        return;
    }

    Name = (vec < 32U) ? OwVectorNames[vec] : "Interrupt";

    {
        /* Decode the one relevant qword of the CPU frame for fault analysis:
         * #DF (vector 8) pushes rip/cs/rflags WITHOUT an error code, so the
         * frame layout degenerates as [vector][rip][cs][rflags] for that
         * vector.  Always print the raw qwords starting at the vector. */
        static const char* hx = "0123456789ABCDEF";
        uint64_t  rsp_here = 0U;
        int       w;
        if (vec == 8U) {
            rsp_here = ((const uint64_t*)Frame)[19];
        } else {
            rsp_here = Frame->Rsp;
        }
        for (w = 0; w < 4; w++) {
            uint64_t v = ((const uint64_t*)Frame)[15U + (uint32_t)w];
            int b;
            for (b = 15; b >= 0; b--) {
                OwHalUartWriteChar(hx[(v >> ((uint32_t)b * 4)) & 0xF]);
            }
            OwHalUartWriteChar(' ');
        }
        OwHalUartWriteString("rsp=");
        {
            int b;
            for (b = 15; b >= 0; b--) {
                OwHalUartWriteChar(hx[(rsp_here >> ((uint32_t)b * 4)) & 0xF]);
            }
            OwHalUartWriteChar(' ');
        }
        OwHalUartWriteString("mem@rsp:");
        for (w = -8; w <= 8; w++) {
            uint64_t v = 0U;
            uint64_t addr = rsp_here + (uint64_t)(w * 8);
            if (addr >= 0x100000U) {
                v = *(const uint64_t*)(uintptr_t)addr;
            }
            for (int b = 15; b >= 0; b--) {
                OwHalUartWriteChar(hx[(v >> ((uint32_t)b * 4)) & 0xF]);
            }
            OwHalUartWriteChar(' ');
        }
        OwHalUartWriteString("\r\n");
        {
            const uint64_t* gdt = (const uint64_t*)0x114AE00U;
            OwHalUartWriteString("gdt:");
            for (w = 1; w <= 4; w++) {
                int b;
                for (b = 15; b >= 0; b--) {
                    OwHalUartWriteChar(hx[(gdt[w] >> ((uint32_t)b * 4)) & 0xF]);
                }
                OwHalUartWriteChar(' ');
            }
            OwHalUartWriteString("\r\n");
        }
    }

    OwHalCrashScreen(Name, vec);

    for (;;) {
        __asm__ volatile("cli");
        __asm__ volatile("hlt");
    }
}

void OwHalIdtInit(uint16_t KernelCodeSelector) {
    uint32_t   i;
    ow_idt_ptr_t IdtPtr;

    if (ow_idt_loaded) {
        return;
    }

    for (i = 0U; i < OW_IDT_ENTRIES; i++) {
        ow_idt_entry_t* e = &ow_idt_table[i];
        uintptr_t       isr = (i == OW_IDT_SYSCALL_VEC)
                                  ? (uintptr_t)OwIsr128
                                  : (uintptr_t)OwIsrStubs[i];
        e->IsrLow    = (uint16_t)(isr & 0xFFFFU);
        e->KernelCs  = KernelCodeSelector;
        e->Ist       = 0U;
        e->Attributes= (i == OW_IDT_SYSCALL_VEC)
                           ? (uint8_t)OW_IDT_SYSCALL_ATTR
                           : (uint8_t)OW_IDT_ATTR;
        e->IsrMid    = (uint16_t)((isr >> 16) & 0xFFFFU);
        e->IsrHigh   = (uint32_t)((isr >> 32) & 0xFFFFFFFFU);
        e->Reserved  = 0U;
    }

    IdtPtr.Limit = (uint16_t)((OW_IDT_ENTRIES * 16U) - 1U);
    IdtPtr.Base  = (uint64_t)(uintptr_t)&ow_idt_table[0];
    __asm__ volatile("lidt %0" : : "m"(IdtPtr) : "memory");
    ow_idt_loaded = 1;
}
