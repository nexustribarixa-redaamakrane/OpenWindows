/* ow_string.h - Freestanding String Operations */
#ifndef OW_STRING_H
#define OW_STRING_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

size_t      ow_strlen(const char* s);
int         ow_strcmp(const char* a, const char* b);
int         ow_strncmp(const char* a, const char* b, size_t n);
const char* ow_strchr(const char* s, char c);
char*       ow_strncpy(char* dst, const char* src, size_t n);
char*       ow_strtok(char* str, const char* delim);
size_t      ow_strcspn(const char* s, const char* reject);
uint32_t    ow_atoi(const char* s);
uint64_t    ow_strtoull(const char* s, char** end, uint32_t base);

#endif /* OW_STRING_H */
