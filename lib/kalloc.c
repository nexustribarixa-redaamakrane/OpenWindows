/* kalloc.c - Fixed-Pool Kernel Allocator (Bump Allocator) */
#include "../inc/ow_mem.h"
#include <stddef.h>
#include <stdint.h>

#define KALLOC_HEAP_SIZE (8U * 1024U * 1024U)
#define KALLOC_ALIGN 8U

static uint8_t g_heap[KALLOC_HEAP_SIZE];
static size_t g_used = 0;
static int g_init = 0;

void kalloc_init(void) {
  g_used = 0;
  g_init = 1;
}

static void *kalloc_raw(size_t size) {
  size_t aligned;
  void *ptr;
  if (!g_init)
    kalloc_init();
  if (size == 0)
    size = 1;
  aligned = (size + (KALLOC_ALIGN - 1)) & ~(size_t)(KALLOC_ALIGN - 1);
  if (g_used + aligned > KALLOC_HEAP_SIZE)
    return (void *)0;
  ptr = &g_heap[g_used];
  g_used += aligned;
  return ptr;
}

void *kalloc(size_t size) { return kalloc_raw(size); }
void *kcalloc(size_t count, size_t size) {
  size_t total = count * size;
  void *ptr = kalloc_raw(total);
  if (ptr)
    ow_memset(ptr, 0, total);
  return ptr;
}
void *krealloc(void *ptr, size_t size) {
  void *new_ptr;
  if (!ptr)
    return kalloc_raw(size);
  new_ptr = kalloc_raw(size);
  if (new_ptr)
    ow_memcpy(new_ptr, ptr, size);
  return new_ptr;
}
void kfree(void *ptr) { (void)ptr; }
size_t kalloc_used(void) { return g_used; }
