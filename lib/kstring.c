/* kstring.c - Freestanding String Operations */
#include "../inc/ow_string.h"

size_t ow_strlen(const char* s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n] != '\0') n++;
    return n;
}

int ow_strcmp(const char* a, const char* b) {
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int ow_strncmp(const char* a, const char* b, size_t n) {
    size_t i;
    if (!a || !b) return 0;
    for (i = 0; i < n && a[i] && a[i] == b[i]; i++) {}
    if (i == n) return 0;
    return (unsigned char)a[i] - (unsigned char)b[i];
}

const char* ow_strchr(const char* s, char c) {
    if (!s) return (void*)0;
    while (*s) {
        if (*s == c) return s;
        s++;
    }
    return (c == '\0') ? s : (void*)0;
}

char* ow_strncpy(char* dst, const char* src, size_t n) {
    size_t i;
    if (!dst || !src) return dst;
    for (i = 0; i < n && src[i]; i++) dst[i] = src[i];
    for (; i < n; i++) dst[i] = '\0';
    return dst;
}

static int ow_isspace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

char* ow_strtok(char* str, const char* delim) {
    static char* state = (void*)0;
    char* start;
    if (!delim) delim = " ";
    if (str) state = str;
    if (!state) return (void*)0;
    while (*state) {
        const char* d = delim;
        bool is_delim = false;
        while (*d) {
            if (*state == *d) { is_delim = true; break; }
            d++;
        }
        if (!is_delim) break;
        state++;
    }
    if (!*state) { state = (void*)0; return (void*)0; }
    start = state;
    while (*state) {
        const char* d = delim;
        while (*d) {
            if (*state == *d) {
                *state = '\0';
                state++;
                return start;
            }
            d++;
        }
        state++;
    }
    return start;
}

size_t ow_strcspn(const char* s, const char* reject) {
    size_t count = 0;
    const char* r;
    if (!s || !reject) return 0;
    while (*s) {
        r = reject;
        while (*r) {
            if (*s == *r) return count;
            r++;
        }
        count++;
        s++;
    }
    return count;
}

uint32_t ow_atoi(const char* s) {
    uint32_t result = 0;
    bool neg = false;
    if (!s) return 0;
    while (ow_isspace(*s)) s++;
    if (*s == '-') { neg = true; s++; }
    else if (*s == '+') s++;
    while (*s >= '0' && *s <= '9') {
        result = result * 10 + (uint32_t)(*s - '0');
        s++;
    }
    return neg ? (uint32_t)(-(int32_t)result) : result;
}

uint64_t ow_strtoull(const char* s, char** end, uint32_t base) {
    uint64_t result = 0;
    if (!s) { if (end) *end = (char*)s; return 0; }
    while (ow_isspace(*s)) s++;
    if (base == 0) {
        if (*s == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
        else if (*s == '0') { base = 8; s++; }
        else { base = 10; }
    } else if (base == 16 && *s == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
    }
    while (*s) {
        uint64_t digit;
        if (*s >= '0' && *s <= '9') digit = (uint64_t)(*s - '0');
        else if (*s >= 'a' && *s <= 'f') digit = 10 + (uint64_t)(*s - 'a');
        else if (*s >= 'A' && *s <= 'F') digit = 10 + (uint64_t)(*s - 'A');
        else break;
        if (digit >= base) break;
        result = result * base + digit;
        s++;
    }
    if (end) *end = (char*)s;
    return result;
}
