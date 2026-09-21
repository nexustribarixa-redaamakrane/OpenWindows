/* memory.c - Memory Manager (PML4 + VAD AVL Tree) */
#include "../inc/ow_kprintf.h"
#include "../inc/ow_memory.h"
#include "../lib/kalloc.h"

/* Static 16MB physical frame allocator */
static uint8_t g_PhysicalRam[16U * 1024U * 1024U];
static size_t g_RamPointer = 0;

#define OW_TOTAL_PAGES (sizeof(g_PhysicalRam) / OW_PAGE_SIZE)

/* VAD lookaside pool (slab for the fixed-size OW_VAD_NODE).  Free nodes are
 * chained through RightChild (freed VADs are not part of any tree). */
#define OW_VAD_POOL_SIZE 1024U
static OW_VAD_NODE s_VadPool[OW_VAD_POOL_SIZE];
static OW_VAD_NODE *s_VadFreeList = (void *)0;
static uint8_t s_VadPoolReady = 0;

static void vad_pool_build(void) {
  uint32_t i;
  s_VadFreeList = (void *)0;
  for (i = 0; i < OW_VAD_POOL_SIZE; i++) {
    s_VadPool[i].RightChild = s_VadFreeList;
    s_VadFreeList = &s_VadPool[i];
  }
  s_VadPoolReady = 1;
}

OW_STATUS OwMemInitialize(void) {
  g_RamPointer = 0;
  vad_pool_build();
  return OW_SUCCESS;
}

void *OwMemAllocatePage(void) {
  void *page;
  if (g_RamPointer + OW_PAGE_SIZE > sizeof(g_PhysicalRam))
    return (void *)0;
  page = &g_PhysicalRam[g_RamPointer];
  g_RamPointer += OW_PAGE_SIZE;
  return page;
}

OW_VAD_NODE *OwMemCreateVad(uint64_t Start, uint64_t End, uint32_t Protect) {
  OW_VAD_NODE *node;

  if (!s_VadPoolReady)
    vad_pool_build();
  if (s_VadFreeList) {
    node = s_VadFreeList;
    s_VadFreeList = node->RightChild; /* free-link lives in RightChild */
    node->RightChild = (void *)0;
  } else {
    node = (OW_VAD_NODE *)kcalloc(1, sizeof(OW_VAD_NODE));
    if (!node)
      return (void *)0;
  }
  node->StartingAddress = Start;
  node->EndingAddress = End;
  node->Protection = Protect;
  node->CommitCharge = (uint32_t)((End - Start) / OW_PAGE_SIZE);
  node->LeftChild = (void *)0;
  node->RightChild = (void *)0;
  node->BalanceFactor = 0;
  return node;
}

void OwMemFreeVad(OW_VAD_NODE *Node) {
  if (!Node)
    return;
  if (Node >= &s_VadPool[0] && Node < &s_VadPool[OW_VAD_POOL_SIZE]) {
    Node->RightChild = s_VadFreeList; /* push back onto the pool */
    s_VadFreeList = Node;
  } else {
    kfree(Node); /* bump pool: no-op, as before */
  }
}

static int32_t vad_height(OW_VAD_NODE *n) {
  int32_t lh, rh;
  if (!n)
    return 0;
  lh = vad_height(n->LeftChild);
  rh = vad_height(n->RightChild);
  return (lh > rh ? lh : rh) + 1;
}

static OW_VAD_NODE *rotate_right(OW_VAD_NODE *y) {
  OW_VAD_NODE *x = y->LeftChild;
  OW_VAD_NODE *t2 = x->RightChild;
  x->RightChild = y;
  y->LeftChild = t2;
  return x;
}

static OW_VAD_NODE *rotate_left(OW_VAD_NODE *x) {
  OW_VAD_NODE *y = x->RightChild;
  OW_VAD_NODE *t2 = y->LeftChild;
  y->LeftChild = x;
  x->RightChild = t2;
  return y;
}

static OW_VAD_NODE *rebalance(OW_VAD_NODE *node) {
  int32_t balance;
  if (!node)
    return (void *)0;
  balance = vad_height(node->LeftChild) - vad_height(node->RightChild);
  node->BalanceFactor = balance;

  if (balance > 1 && vad_height(node->LeftChild->LeftChild) >=
                         vad_height(node->LeftChild->RightChild))
    return rotate_right(node);
  if (balance > 1 && vad_height(node->LeftChild->LeftChild) <
                         vad_height(node->LeftChild->RightChild)) {
    node->LeftChild = rotate_left(node->LeftChild);
    return rotate_right(node);
  }
  if (balance < -1 && vad_height(node->RightChild->RightChild) >=
                          vad_height(node->RightChild->LeftChild))
    return rotate_left(node);
  if (balance < -1 && vad_height(node->RightChild->RightChild) <
                          vad_height(node->RightChild->LeftChild)) {
    node->RightChild = rotate_right(node->RightChild);
    return rotate_left(node);
  }
  return node;
}

OW_STATUS OwMemInsertVad(OW_VAD_NODE **Root, OW_VAD_NODE *Node) {
  if (!Node)
    return OW_ERR_NULL_POINTER;
  if (!(*Root)) {
    *Root = Node;
    return OW_SUCCESS;
  }

  if (Node->StartingAddress < (*Root)->StartingAddress) {
    if (!(*Root)->LeftChild)
      (*Root)->LeftChild = Node;
    else
      OwMemInsertVad(&(*Root)->LeftChild, Node);
  } else if (Node->StartingAddress > (*Root)->StartingAddress) {
    if (!(*Root)->RightChild)
      (*Root)->RightChild = Node;
    else
      OwMemInsertVad(&(*Root)->RightChild, Node);
  } else {
    return OW_ERR_ALREADY_EXISTS;
  }

  *Root = rebalance(*Root);
  return OW_SUCCESS;
}

void OwMemWalkPml4(uint64_t VirtualAddress) {
  uint16_t pml4_idx = (uint16_t)((VirtualAddress >> 39) & 0x1FF);
  uint16_t pdpt_idx = (uint16_t)((VirtualAddress >> 30) & 0x1FF);
  uint16_t pd_idx = (uint16_t)((VirtualAddress >> 21) & 0x1FF);
  uint16_t pt_idx = (uint16_t)((VirtualAddress >> 12) & 0x1FF);
  uint16_t offset = (uint16_t)(VirtualAddress & 0xFFF);

  ow_kprintf(
      "[PML4-WALK] VA: 0x%llX -> PML4[%u] PDPT[%u] PD[%u] PT[%u] Off[0x%X]\r\n",
      (unsigned long long)VirtualAddress, (unsigned)pml4_idx,
      (unsigned)pdpt_idx, (unsigned)pd_idx, (unsigned)pt_idx, (unsigned)offset);
}

uint32_t OwMemPagesUsed(void) {
  return (uint32_t)(g_RamPointer / OW_PAGE_SIZE);
}

uint32_t OwMemPagesTotal(void) { return (uint32_t)OW_TOTAL_PAGES; }
