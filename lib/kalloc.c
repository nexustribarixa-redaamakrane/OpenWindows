/* kalloc.c - Fixed-Pool Kernel Allocator (Bump Allocator) */
#include "../inc/ow_mem.h"
#include <stddef.h>
#include <stdint.h>

#define KALLOC_HEAP_SIZE (8U * 1024U * 1024U)
#define KALLOC_ALIGN 8U
/* Every block carries its requested size immediately in front of the payload.
 * The bump arena never reuses memory, but krealloc still has to know how many
 * bytes it may copy out of the old block without reading past the caller's
 * allocation. */
#define KALLOC_HEADER_SIZE KALLOC_ALIGN

static uint8_t g_heap[KALLOC_HEAP_SIZE] __attribute__((aligned(KALLOC_ALIGN)));
static size_t g_used = 0;
static int g_init = 0;

void kalloc_init(void) {
  g_used = 0;
  g_init = 1;
}

static void *kalloc_raw(size_t size) {
  size_t aligned;
  size_t total;
  uint8_t *block;
  if (!g_init)
    kalloc_init();
  if (size == 0)
    size = 1;
  /* Reject impossible requests before aligning them.  In particular,
   * size + (KALLOC_ALIGN - 1) wraps to zero for SIZE_MAX and would otherwise
   * hand back a zero-byte block that the caller believes is SIZE_MAX bytes. */
  if (size > KALLOC_HEAP_SIZE - KALLOC_HEADER_SIZE)
    return (void *)0;
  aligned = (size + (KALLOC_ALIGN - 1)) & ~(size_t)(KALLOC_ALIGN - 1);
  if (aligned > KALLOC_HEAP_SIZE - KALLOC_HEADER_SIZE)
    return (void *)0;
  total = KALLOC_HEADER_SIZE + aligned;
  /* Compare as a remaining-capacity subtraction: g_used + total can wrap even
   * when total itself is small. */
  if (g_used > KALLOC_HEAP_SIZE - total)
    return (void *)0;
  block = &g_heap[g_used];
  *(size_t *)block = size;
  g_used += total;
  return block + KALLOC_HEADER_SIZE;
}

void *kalloc(size_t size) { return kalloc_raw(size); }

void *kcalloc(size_t count, size_t size) {
  size_t total;
  void *ptr;

  if (size != 0u && count > (size_t)-1 / size)
    return (void *)0;
  total = count * size;
  ptr = kalloc_raw(total);
  if (ptr)
    ow_memset(ptr, 0, total);
  return ptr;
}

/* Return the requested size of a live block, or 0 when ptr is not one of ours.
 * The arena has no free list, so a valid payload is always wholly inside
 * [g_heap, g_heap + g_used) and is preceded by its header. */
static size_t kalloc_block_size(const void *ptr) {
  uintptr_t base = (uintptr_t)g_heap;
  uintptr_t address = (uintptr_t)ptr;
  size_t offset;
  size_t size;

  if (address < base)
    return 0u;
  offset = (size_t)(address - base);
  if (offset < KALLOC_HEADER_SIZE || offset >= g_used)
    return 0u;
  size = *(const size_t *)(address - KALLOC_HEADER_SIZE);
  if (size == 0u || size > g_used - offset)
    return 0u;
  return size;
}

void *krealloc(void *ptr, size_t size) {
  size_t old_size;
  size_t copy_size;
  void *new_ptr;

  if (!ptr)
    return kalloc_raw(size);
  old_size = kalloc_block_size(ptr);
  if (old_size == 0u)
    return (void *)0;
  new_ptr = kalloc_raw(size);
  if (!new_ptr)
    return (void *)0;
  copy_size = (old_size < size) ? old_size : size;
  if (copy_size != 0u)
    ow_memcpy(new_ptr, ptr, copy_size);
  return new_ptr;
}

void kfree(void *ptr) { (void)ptr; }
size_t kalloc_used(void) { return g_used; }
