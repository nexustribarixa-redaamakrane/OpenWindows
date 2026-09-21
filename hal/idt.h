/* idt.h - OpenWindows long-mode IDT + ISR frame contracts
 *
 * The IDT itself is built in hal/idt.c (16-byte 64-bit gate entries) and
 * loaded with lidt. Each CPU exception vector 0-31 is routed to the matching
 * stub in hal/interrupts.S. The stubs normalise the frame (error-code slot is
 * synthesised to 0 when the CPU does not supply one), push their vector and
 * jump into the shared 64-bit entry, which pushes the 15 GP registers such
 * that RAX ends up at offset +0 (pushed last) and R15 at +112. The C handler
 * (OwHalCommonInterruptHandler) therefore receives ow_hal_frame_t* pointing
 * at RAX.
 *
 * Frame layout (lowest address = RSP at the shared entry, = &RAX):
 *   +0    RAX
 *   +8    RCX
 *   +16   RDX
 *   +24   RSI
 *   +32   RDI
 *   +40   R8
 *   +48   R9
 *   +56   R10
 *   +64   R11
 *   +72   RBP
 *   +80   RBX
 *   +88   R12
 *   +96   R13
 *   +104  R14
 *   +112  R15
 *   +120  Vector
 *   +128  ErrorCode    (synthetic 0 or the CPU-supplied value)
 *   +136  RIP          (CPU-pushed long-mode return frame)
 *   +144  CS
 *   +152  RFLAGS
 *   +160  RSP          (CPU-pushed only from user mode; 0 in ring-0 faults)
 *   +168  SS           (CPU-pushed only from user mode; 0 in ring-0 faults)
 */
#ifndef OW_IDT_H
#define OW_IDT_H

#include <stdint.h>

/* One 16-byte long-mode IDT gate. */
typedef struct {
  uint16_t IsrLow;
  uint16_t KernelCs;
  uint8_t Ist;
  uint8_t Attributes;
  uint16_t IsrMid;
  uint32_t IsrHigh;
  uint32_t Reserved;
} ow_idt_entry_t;

/* Operand for lidt: 16-bit limit + 64-bit base. Packed so the CPU sees the
 * 10-byte long-mode pseudo-descriptor at the exact byte offset. */
typedef struct __attribute__((packed)) {
  uint16_t Limit;
  uint64_t Base;
} ow_idt_ptr_t;

/* Fallout frame handed to the common interrupt handler. */
typedef struct {
  uint64_t Rax;
  uint64_t Rcx;
  uint64_t Rdx;
  uint64_t Rsi;
  uint64_t Rdi;
  uint64_t R8;
  uint64_t R9;
  uint64_t R10;
  uint64_t R11;
  uint64_t Rbp;
  uint64_t Rbx;
  uint64_t R12;
  uint64_t R13;
  uint64_t R14;
  uint64_t R15;
  uint64_t Vector;
  uint64_t ErrorCode;
  uint64_t Rip;
  uint64_t Cs;
  uint64_t Rflags;
  uint64_t Rsp;
  uint64_t Ss;
} ow_hal_frame_t;

/* ----------- public API ----------- */
void OwHalIdtInit(uint16_t KernelCodeSelector);
void OwHalCommonInterruptHandler(ow_hal_frame_t *Frame);

#endif /* OW_IDT_H */
