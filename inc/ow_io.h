/* ow_io.h - x86 Port I/O (Freestanding Inline Assembly) */
#ifndef OW_IO_H
#define OW_IO_H

#include <stdint.h>

static inline uint8_t ow_inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void ow_outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t ow_inw(uint16_t port) {
    uint16_t value;
    __asm__ volatile ("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static inline void ow_outw(uint16_t port, uint16_t value) {
    __asm__ volatile ("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline void ow_cli(void) {
#ifndef OW_HOST_HAL
    __asm__ volatile ("cli");
#endif
}

static inline void ow_sti(void) {
#ifndef OW_HOST_HAL
    __asm__ volatile ("sti");
#endif
}

/* IF-preserving cli/sti pair: save RFLAGS (including IF), disable
 * interrupts, and restore the original IF state later.  This avoids
 * enabling interrupts that were already off — critical during boot
 * before PIC remapping where IRQ0 collides with vector 8 (#DF).    */
static inline uint64_t ow_irq_save(void) {
#ifndef OW_HOST_HAL
    uint64_t flags;
    __asm__ volatile ("pushfq; popq %0; cli" : "=r"(flags) : : "memory");
    return flags;
#else
    return 0;
#endif
}

static inline void ow_irq_restore(uint64_t flags) {
#ifndef OW_HOST_HAL
    if (flags & 0x200u)
        __asm__ volatile ("sti" : : : "memory");
#else
    (void)flags;
#endif
}

static inline void ow_io_wait(void) {
    ow_outb(0x80, 0x00);
}

static inline void ow_hlt_loop(void) {
#ifndef OW_HOST_HAL
    while (1) {
        __asm__ volatile ("cli; hlt");
    }
#else
    for (;;) { }
#endif
}

static inline void ow_poweroff(void) {
    ow_outw(0x604, 0x2000);
    ow_outw(0xB004, 0x2000);
    ow_outw(0x600, 0x34);
    ow_hlt_loop();
}

#endif /* OW_IO_H */
