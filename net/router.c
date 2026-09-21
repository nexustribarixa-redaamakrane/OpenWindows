/* router.c - 44-bit Hex Trie Router */
#include "../inc/ow_net.h"
#include "../lib/kalloc.h"
#include "../inc/ow_kprintf.h"

static OW_TRIE_NODE* g_Root = (void*)0;

static OW_TRIE_NODE* net_alloc_node(void) {
    OW_TRIE_NODE* n = (OW_TRIE_NODE*)kcalloc(1, sizeof(OW_TRIE_NODE));
    return n;
}

OW_STATUS OwNetInitialize(void) {
    g_Root = net_alloc_node();
    if (!g_Root) return OW_ERR_INSUFFICIENT;

    OwNetInsertRoute(0x0ULL, 0, 1, 0x7F000001ULL);
    OwNetInsertRoute(0xA0000000000ULL, 4, 2, 0x1E002B1BULL);

    ow_kprintf("[NET] 44-bit Sparse Radix Hex Trie router online.\r\n");
    return OW_SUCCESS;
}

OW_STATUS OwNetInsertRoute(OW_ROUTE_ADDR Prefix, uint8_t PrefixLen, uint32_t InterfaceId, uint64_t NextHop) {
    OW_TRIE_NODE* current;
    int nibbles, i;

    if (!g_Root) return OW_ERR_NOT_INITIALIZED;
    if (PrefixLen > OW_NET_MAX_PREFIX_LEN) return OW_ERR_INVALID_PARAM;

    current = g_Root;
    nibbles = PrefixLen / 4;

    for (i = 0; i < nibbles; i++) {
        int shift = 40 - (i * 4);
        uint8_t nib = (uint8_t)((Prefix >> shift) & 0xF);
        if (!current->Children[nib]) {
            current->Children[nib] = net_alloc_node();
            if (!current->Children[nib]) return OW_ERR_INSUFFICIENT;
        }
        current = current->Children[nib];
    }

    current->IsTerminal = true;
    current->InterfaceId = InterfaceId;
    current->NextHop = NextHop;

    return OW_SUCCESS;
}

OW_STATUS OwNetLookupRoute(OW_ROUTE_ADDR Target, uint32_t* OutInterface, uint64_t* OutNextHop) {
    OW_TRIE_NODE* current;
    OW_TRIE_NODE* best = (void*)0;

    if (!g_Root || !OutInterface || !OutNextHop) return OW_ERR_NULL_POINTER;

    current = g_Root;
    if (current->IsTerminal) best = current;

    {
        uint32_t ii;
        for (ii = 0; ii < OW_NET_NIBBLE_DEPTH; ii++) {
            int shift = 40 - ((int)ii * 4);
            uint8_t nib = (uint8_t)((Target >> shift) & 0xF);
            if (!current->Children[nib]) break;
            current = current->Children[nib];
            if (current->IsTerminal) best = current;
        }
    }

    if (best) {
        *OutInterface = best->InterfaceId;
        *OutNextHop = best->NextHop;
        return OW_SUCCESS;
    }
    return OW_ERR_NOT_FOUND;
}

void OwNetShutdown(void) {
    g_Root = (void*)0;
}
