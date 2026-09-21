/* kmem.c - Freestanding Memory Operations */
#include "../inc/ow_mem.h"

void* ow_memcpy(void* dst, const void* src, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    size_t i;
    if (!dst || !src) return dst;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void* ow_memset(void* dst, int val, size_t n) {
    uint8_t* d = (uint8_t*)dst;
    uint8_t v = (uint8_t)val;
    size_t i;
    if (!dst) return dst;
    for (i = 0; i < n; i++) d[i] = v;
    return dst;
}

int ow_memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* pa = (const uint8_t*)a;
    const uint8_t* pb = (const uint8_t*)b;
    size_t i;
    if (!a || !b) return 0;
    for (i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return (int)pa[i] - (int)pb[i];
    }
    return 0;
}
