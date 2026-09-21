/* ow_net.h - Network Router (44-bit Hex Trie) */
#ifndef OW_NET_H
#define OW_NET_H

#include "ow_types.h"

#define OW_NET_MAX_PREFIX_LEN   44U
#define OW_NET_NIBBLE_DEPTH     11U
#define OW_NET_CHILDREN         16U

typedef uint64_t OW_ROUTE_ADDR;

typedef struct _OW_TRIE_NODE {
    struct _OW_TRIE_NODE*   Children[OW_NET_CHILDREN];
    bool                    IsTerminal;
    uint32_t                InterfaceId;
    uint64_t                NextHop;
} OW_TRIE_NODE;

OW_STATUS    OwNetInitialize(void);
OW_STATUS    OwNetInsertRoute(OW_ROUTE_ADDR Prefix, uint8_t PrefixLen, uint32_t InterfaceId, uint64_t NextHop);
OW_STATUS    OwNetLookupRoute(OW_ROUTE_ADDR Target, uint32_t* OutInterface, uint64_t* OutNextHop);
void         OwNetShutdown(void);

#endif /* OW_NET_H */
