/* kalloc.c - Fixed-Pool Kernel Allocator (free-list with redzones) */
#include "kalloc.h"
#include "../inc/ow_mem.h"
#include "../inc/owkheapsan.h"
#include "../inc/owkmsan.h"
#include <stddef.h>
#include <stdint.h>

static uint8_t g_heap[KALLOC_HEAP_SIZE] __attribute__((aligned(KALLOC_ALIGN)));
static size_t g_used = 0;
static int g_init = 0;
/* Freed blocks not yet reusable: the bounded quarantine defers reuse so that a
 * use-after-free write is detectable (poison verification) and so a stale
 * payload is handed back less promptly.  Threaded through the payload's first
 * 8 bytes; the header tag stays KALLOC_MAGIC_FREE throughout.  The active
 * depth is runtime-tunable via OwKAsanSetQuarantineLimit(); 0 bypasses the
 * quarantine entirely, KALLOC_QUARANTINE_MAX is the hard bound of the static
 * table. */
#define KALLOC_QUARANTINE_MAX 64u
static uint8_t *s_quarantine[KALLOC_QUARANTINE_MAX];
static uint32_t s_quarantine_count = 0u;
/* Live quarantine depth; default defers up to 32 blocks before reuse. */
static uint32_t s_quarantine_limit = 32u;
static uint8_t *g_free_list = (uint8_t *)0;

void kalloc_init(void) {
  g_used = 0;
  s_quarantine_count = 0u;
  g_init = 1;
}

static size_t align8(size_t size) {
  return (size + (KALLOC_ALIGN - 1u)) & ~(size_t)(KALLOC_ALIGN - 1u);
}

static size_t block_span(size_t size) {
  return KALLOC_HEADER_SIZE + align8(size) + KALLOC_REDZONE;
}

static uint8_t *free_block_next(const uint8_t *block) {
  return (uint8_t *)(uintptr_t)(*(const uint64_t *)(block + KALLOC_HEADER_SIZE));
}

static void free_block_push(uint8_t *block) {
  *(uint64_t *)(block + KALLOC_HEADER_SIZE) = (uint64_t)(uintptr_t)g_free_list;
  g_free_list = block;
}

static void stamp_live(uint8_t *block, size_t size) {
  size_t aligned = align8(size);

  *(uint64_t *)block = (uint64_t)size;
  *(((uint64_t *)block) + 1) = KALLOC_MAGIC_LIVE;
  ow_memset(block + KALLOC_HEADER_SIZE + aligned, KALLOC_REDZONE_BYTE,
            KALLOC_REDZONE);
  OwKMSanNoteAlloc(block + KALLOC_HEADER_SIZE, size);
}

static void *kalloc_raw(size_t size) {
  size_t aligned;
  size_t total;
  uint8_t *block;
  uint8_t *prev = (uint8_t *)0;
  uint8_t *cur = g_free_list;

  if (!g_init)
    kalloc_init();
  if (size == 0)
    size = 1;
  aligned = align8(size);
  total = KALLOC_HEADER_SIZE + aligned + KALLOC_REDZONE;
  if (size > KALLOC_HEAP_SIZE - KALLOC_HEADER_SIZE - KALLOC_REDZONE)
    return (void *)0;

  /* First-fit over the reusable free list. */
  while (cur) {
    size_t cur_size = (size_t)*(const uint64_t *)cur;
    size_t cur_span = block_span(cur_size);

    if (cur_span >= total) {
      uint8_t *next = free_block_next(cur);
      size_t remainder = cur_span - total;

      if (remainder >= KALLOC_MIN_BLOCK) {
        uint8_t *split = cur + total;
        size_t rem_payload = remainder - KALLOC_HEADER_SIZE - KALLOC_REDZONE;

        *(uint64_t *)split = (uint64_t)rem_payload;
        *(((uint64_t *)split) + 1) = KALLOC_MAGIC_FREE;
        *(uint64_t *)(split + KALLOC_HEADER_SIZE) = (uint64_t)(uintptr_t)next;
        ow_memset(split + KALLOC_HEADER_SIZE + align8(rem_payload),
                  KALLOC_REDZONE_BYTE, KALLOC_REDZONE);
        if (prev)
          *(uint64_t *)(prev + KALLOC_HEADER_SIZE) = (uint64_t)(uintptr_t)split;
        else
          g_free_list = split;
      } else {
        if (prev)
          *(uint64_t *)(prev + KALLOC_HEADER_SIZE) = (uint64_t)(uintptr_t)next;
        else
          g_free_list = next;
      }
      stamp_live(cur, size);
      return cur + KALLOC_HEADER_SIZE;
    }
    prev = cur;
    cur = free_block_next(cur);
  }

  /* Bump-allocate from the arena. */
  if (g_used > KALLOC_HEAP_SIZE || total > KALLOC_HEAP_SIZE - g_used)
    return (void *)0;
  block = &g_heap[g_used];
  g_used += total;
  stamp_live(block, size);
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
  if (ptr) {
    ow_memset(ptr, 0, total);
    OwKMSanNoteInit(ptr, total);
  }
  return ptr;
}

/* Return the block base containing Payload, or NULL. */
static uint8_t *find_block(const void *ptr) {
  uintptr_t base = (uintptr_t)g_heap;
  uintptr_t want = (uintptr_t)ptr;
  size_t offset = 0;

  if (want < base)
    return (void *)0;
  if ((size_t)(want - base) >= g_used)
    return (void *)0;
  while (offset + KALLOC_HEADER_SIZE <= g_used) {
    size_t offset_base = offset;
    uint64_t size = *(const uint64_t *)(&g_heap[offset_base]);
    size_t span = block_span((size_t)size);

    if (span > g_used - offset_base)
      break;
    if (base + offset_base + KALLOC_HEADER_SIZE == want)
      return &g_heap[offset_base];
    offset += span;
  }
  return (void *)0;
}

/* Shared allocation-entry lookup used by kfree, krealloc and the audit. */
static size_t live_block_size(const void *ptr) {
  uint8_t *block = find_block(ptr);

  if (!block)
    return 0u;
  if (*(((const uint64_t *)block) + 1) != KALLOC_MAGIC_LIVE)
    return 0u;
  return (size_t)*(const uint64_t *)block;
}

void *krealloc(void *ptr, size_t size) {
  size_t old_size;
  size_t copy_size;
  void *new_ptr;

  if (!ptr)
    return kalloc_raw(size);
  old_size = live_block_size(ptr);
  if (old_size == 0u)
    return (void *)0;
  new_ptr = kalloc_raw(size);
  if (!new_ptr)
    return (void *)0;
  copy_size = (old_size < size) ? old_size : size;
  if (copy_size != 0u)
    ow_memcpy(new_ptr, ptr, copy_size);
  OwKMSanNoteCopy(new_ptr, ptr, copy_size, size);
  kfree(ptr);
  return new_ptr;
}

void kfree(void *ptr) {
  uint8_t *block;
  uint64_t tag;
  size_t size;
  size_t aligned;
  int verdict;

  if (!ptr)
    return;
  block = find_block(ptr);
  if (!block) {
    OwKHeapSanNoteFree(ptr, KALLOC_FREE_FOREIGN);
    return;
  }
  tag = *(((const uint64_t *)block) + 1);
  if (tag != KALLOC_MAGIC_LIVE) {
    OwKHeapSanNoteFree(ptr, KALLOC_FREE_DOUBLE);
    return;
  }
  size = (size_t)*(const uint64_t *)block;
  aligned = align8(size);
  /* Poison the payload and restamp the redzone before the block becomes
   * reusable: a stale pointer that writes into freed memory overwrites the
   * poison, which the audit detects. */
  ow_memset(block + KALLOC_HEADER_SIZE, KALLOC_POISON_BYTE, aligned);
  ow_memset(block + KALLOC_HEADER_SIZE + aligned, KALLOC_REDZONE_BYTE,
            KALLOC_REDZONE);
  *(((uint64_t *)block) + 1) = KALLOC_MAGIC_FREE;

  if (s_quarantine_limit == 0u) {
    /* Quarantine disabled: freed blocks are immediately reusable. */
    free_block_push(block);
  } else if (s_quarantine_count < s_quarantine_limit) {
    s_quarantine[s_quarantine_count++] = block;
  } else {
    /* FIFO: the oldest quarantined block becomes reusable. */
    uint32_t i;
    uint8_t *oldest = s_quarantine[0];

    for (i = 0u; i + 1u < s_quarantine_count; ++i) {
      s_quarantine[i] = s_quarantine[i + 1u];
    }
    s_quarantine[s_quarantine_count - 1u] = block;
    free_block_push(oldest);
  }

  verdict = KALLOC_FREE_OK;
  OwKHeapSanNoteFree(ptr, (uint32_t)verdict);
  OwKMSanNoteFree(ptr, size);
}

size_t kalloc_used(void) { return g_used; }

/* Read-only consistency walk over the committed arena.  The callback sees
 * every intact block (base, requested size, payload, header tag); the walk
 * stops early if the callback asks it to.  Every byte boundary checked here
 * is one the allocator itself maintains, so a caller comparing the accumulated
 * byte sum against kalloc_used() is verifying the chain is packed exactly. */
uint32_t OwKAllocWalk(int (*Callback)(const void* Block, size_t Size,
                                      const void* Payload, uint64_t Magic,
                                      void* Ctx),
                      void* Ctx) {
  size_t offset = 0;
  uint32_t blocks = 0;

  if (!Callback)
    return 0;
  while (offset + KALLOC_HEADER_SIZE <= g_used) {
    size_t offset_base = offset;
    uint64_t size = *(const uint64_t *)(&g_heap[offset_base]);
    size_t span = block_span((size_t)size);
    const void *block = &g_heap[offset_base];
    uint64_t magic = *(((const uint64_t *)block) + 1);

    if (size == 0u)
      break;
    if (span > g_used - offset_base)
      break;
    if (!Callback(block, (size_t)size, block + KALLOC_HEADER_SIZE, magic,
                  Ctx))
      break;
    offset += span;
    blocks++;
  }
  return blocks;
}

/* True when Ptr lies inside the committed part of the arena. */
bool OwKAllocContains(const void *Ptr) {
  uintptr_t base = (uintptr_t)g_heap;
  uintptr_t address = (uintptr_t)Ptr;

  if (address < base)
    return false;
  return (size_t)(address - base) < g_used;
}

uintptr_t OwKAllocArenaBase(void) { return (uintptr_t)g_heap; }

const void *OwKAllocBlockFind(const void *Payload) {
  return find_block(Payload);
}

uint32_t OwKAllocQuarantineCount(void) { return s_quarantine_count; }

/* Quarantine depth control.  Returns the previous live limit.  Setting the
 * limit lower than the current occupancy promotes the newest excess blocks
 * to the reusable list (the oldest stay in quarantine).  0 disables the
 * quarantine; KALLOC_QUARANTINE_MAX is the hard bound of the static table. */
uint32_t OwKAllocQuarantineLimit(void) { return s_quarantine_limit; }

uint32_t OwKAllocQuarantineSetLimit(uint32_t Limit) {
  uint32_t old = s_quarantine_limit;

  if (Limit > KALLOC_QUARANTINE_MAX)
    Limit = KALLOC_QUARANTINE_MAX;
  s_quarantine_limit = Limit;
  while (s_quarantine_count > s_quarantine_limit) {
    uint32_t last = --s_quarantine_count;

    free_block_push(s_quarantine[last]);
  }
  return old;
}

const void *OwKAllocQuarantineAt(uint32_t Index) {
  if (Index >= s_quarantine_count)
    return (const void *)0;
  return s_quarantine[Index];
}
