/* kprintf.c - Kernel Formatted Output (UART Console) */
#include "../inc/ow_kprintf.h"
#include "../inc/ow_hal.h"
#include <stdarg.h>

static int kfmt_out(void (*putc)(char, void*), void* ctx, const char* fmt, va_list ap) {
    int count = 0;
    const char* hex = "0123456789ABCDEF";
    const char* hexl = "0123456789abcdef";
    (void)ctx;

    while (*fmt) {
        if (*fmt != '%') { putc(*fmt, ctx); count++; fmt++; continue; }
        fmt++;
        if (*fmt >= '0' && *fmt <= '9') { /* skip width / zero-pad for now */
            while (*fmt >= '0' && *fmt <= '9') fmt++;
        }
        if (*fmt == '%') { putc('%', ctx); count++; fmt++; continue; }
        if (*fmt == 'c') { putc((char)va_arg(ap, int), ctx); count++; fmt++; continue; }
        if (*fmt == 's') {
            const char* s = va_arg(ap, const char*);
            if (!s) s = "(null)";
            while (*s) { putc(*s, ctx); count++; s++; }
            fmt++; continue;
        }
        if (*fmt == 'p') {
            uint64_t v = (uint64_t)(uintptr_t)va_arg(ap, void*);
            int i;
            putc('0', ctx); putc('x', ctx); count += 2;
            for (i = 60; i >= 0; i -= 4) { putc(hexl[(v >> i) & 0xF], ctx); count++; }
            fmt++; continue;
        }
        if (*fmt == 'x') {
            uint64_t v = (uint64_t)va_arg(ap, unsigned int);
            int i, started = 0;
            for (i = 28; i >= 0; i -= 4) {
                uint8_t nib = (uint8_t)((v >> i) & 0xF);
                if (nib || started || i == 0) { putc(hexl[nib], ctx); count++; started = 1; }
            }
            fmt++; continue;
        }
        if (*fmt == 'X') {
            uint64_t v = (uint64_t)va_arg(ap, unsigned int);
            int i, started = 0;
            for (i = 28; i >= 0; i -= 4) {
                uint8_t nib = (uint8_t)((v >> i) & 0xF);
                if (nib || started || i == 0) { putc(hex[nib], ctx); count++; started = 1; }
            }
            fmt++; continue;
        }
        if (*fmt == 'd' || *fmt == 'i') {
            int v = va_arg(ap, int);
            int i = 0;
            char tmp[12];
            if (v < 0) { putc('-', ctx); count++; v = -v; }
            if (v == 0) { putc('0', ctx); count++; }
            else {
                while (v > 0) { tmp[i++] = '0' + (char)(v % 10); v /= 10; }
                while (i > 0) { putc(tmp[--i], ctx); count++; }
            }
            fmt++; continue;
        }
        if (*fmt == 'u') {
            unsigned int v = (unsigned int)va_arg(ap, unsigned int);
            int i = 0;
            char tmp[12];
            if (v == 0) { putc('0', ctx); count++; }
            else {
                while (v > 0) { tmp[i++] = '0' + (char)(v % 10); v /= 10; }
                while (i > 0) { putc(tmp[--i], ctx); count++; }
            }
            fmt++; continue;
        }
        if (*fmt == 'l') {
            fmt++;
            if (*fmt == 'l') {
                fmt++;
                if (*fmt == 'x') {
                    uint64_t v = (uint64_t)va_arg(ap, unsigned long long);
                    int i, started = 0;
                    for (i = 60; i >= 0; i -= 4) {
                        uint8_t nib = (uint8_t)((v >> i) & 0xF);
                        if (nib || started || i == 0) { putc(hexl[nib], ctx); count++; started = 1; }
                    }
                    fmt++; continue;
                }
                if (*fmt == 'X') {
                    uint64_t v = (uint64_t)va_arg(ap, unsigned long long);
                    int i, started = 0;
                    for (i = 60; i >= 0; i -= 4) {
                        uint8_t nib = (uint8_t)((v >> i) & 0xF);
                        if (nib || started || i == 0) { putc(hex[nib], ctx); count++; started = 1; }
                    }
                    fmt++; continue;
                }
                if (*fmt == 'u') {
                    uint64_t v = (uint64_t)va_arg(ap, unsigned long long);
                    int i = 0;
                    char tmp[21];
                    if (v == 0) { putc('0', ctx); count++; }
                    else {
                        while (v > 0) { tmp[i++] = '0' + (char)(v % 10); v /= 10; }
                        while (i > 0) { putc(tmp[--i], ctx); count++; }
                    }
                    fmt++; continue;
                }
                if (*fmt == 'd') {
                    int64_t v = (int64_t)va_arg(ap, long long);
                    int i = 0;
                    char tmp[21];
                    uint64_t uv;
                    if (v < 0) { putc('-', ctx); count++; uv = (uint64_t)(-v); }
                    else uv = (uint64_t)v;
                    if (uv == 0) { putc('0', ctx); count++; }
                    else {
                        while (uv > 0) { tmp[i++] = '0' + (char)(uv % 10); uv /= 10; }
                        while (i > 0) { putc(tmp[--i], ctx); count++; }
                    }
                    fmt++; continue;
                }
            }
        }
        putc(*fmt, ctx);
        count++;
        fmt++;
    }
    return count;
}

static void uart_putc(char c, void* ctx) { (void)ctx; OwHalUartWriteChar(c); }

int ow_kprintf(const char* fmt, ...) {
    va_list ap;
    int r;
    va_start(ap, fmt);
    r = kfmt_out(uart_putc, (void*)0, fmt, ap);
    va_end(ap);
    return r;
}

typedef struct { char* buf; uint32_t pos; uint32_t limit; } buf_ctx_t;

static void buf_putc(char c, void* ctx) {
    buf_ctx_t* b = (buf_ctx_t*)ctx;
    if (b->pos < b->limit - 1) b->buf[b->pos] = c;
    b->pos++;
}

int ow_ksnprintf(char* Buf, uint32_t BufSize, const char* fmt, ...) {
    va_list ap;
    buf_ctx_t ctx;
    int r;
    ctx.buf = Buf;
    ctx.pos = 0;
    ctx.limit = BufSize;
    va_start(ap, fmt);
    r = kfmt_out(buf_putc, &ctx, fmt, ap);
    va_end(ap);
    if (BufSize > 0 && ctx.pos < BufSize) Buf[ctx.pos] = '\0';
    else if (BufSize > 0) Buf[BufSize - 1] = '\0';
    return r;
}

int ow_vsnprintf(char* Buf, uint32_t BufSize, const char* fmt, va_list ap) {
    buf_ctx_t ctx;
    int r;
    ctx.buf = Buf;
    ctx.pos = 0;
    ctx.limit = BufSize;
    r = kfmt_out(buf_putc, &ctx, fmt, ap);
    if (BufSize > 0 && ctx.pos < BufSize) Buf[ctx.pos] = '\0';
    else if (BufSize > 0) Buf[BufSize - 1] = '\0';
    return r;
}
