/* ow_kprintf.h - Kernel Formatted Output (UART Console) */
#ifndef OW_KPRINTF_H
#define OW_KPRINTF_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

int  ow_kprintf(const char* fmt, ...);
int  ow_ksnprintf(char* Buf, uint32_t BufSize, const char* fmt, ...);
int  ow_vsnprintf(char* Buf, uint32_t BufSize, const char* fmt, va_list ap);

#endif /* OW_KPRINTF_H */
