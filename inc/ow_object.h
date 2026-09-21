/* ow_object.h - Object Manager (Everything is an Object) */
#ifndef OW_OBJECT_H
#define OW_OBJECT_H

#include "ow_types.h"

#define OW_OBJECT_MAX_ENTRIES   128U
#define OW_OBJECT_HANDLE_BASE   0x1000U

typedef struct _OW_OBJECT_TYPE {
    const char*     TypeName;
    uint32_t        TypeId;
    OW_STATUS       (*Open)(void* Object, uint32_t AccessFlags);
    void            (*Close)(void* Object);
    void            (*Delete)(void* Object);
    OW_STATUS       (*IoControl)(void* Object, uint32_t ControlCode,
                                const void* InBuffer, uint32_t InSize,
                                void* OutBuffer, uint32_t OutSize,
                                uint32_t* BytesReturned);
} OW_OBJECT_TYPE;

typedef struct _OW_OBJECT_HEADER {
    int64_t                 ReferenceCount;
    int64_t                 HandleCount;
    OW_OBJECT_TYPE*         Type;
    char                    Name[OW_MAX_NAME];
    struct _OW_OBJECT_DIR*  ParentDirectory;
    uint32_t                SecurityFlags;
} OW_OBJECT_HEADER;

#define OW_OBJ_TO_HEADER(obj)   ((OW_OBJECT_HEADER*)((char*)(obj) - sizeof(OW_OBJECT_HEADER)))
#define OW_HDR_TO_OBJ(hdr)      ((void*)((char*)(hdr) + sizeof(OW_OBJECT_HEADER)))

typedef struct _OW_OBJECT_DIR {
    OW_OBJECT_HEADER    Header;
    void*               Entries[OW_OBJECT_MAX_ENTRIES];
    uint32_t            EntryCount;
} OW_OBJECT_DIR;

typedef uint32_t OW_HANDLE;

OW_STATUS    OwObjInitialize(void);
OW_OBJECT_DIR* OwObjCreateDirectory(const char* Name, OW_OBJECT_DIR* Parent);
void*        OwObjCreateObject(OW_OBJECT_TYPE* Type, const char* Name, size_t BodySize, OW_OBJECT_DIR* Parent);
void         OwObjReference(void* Object);
void         OwObjDereference(void* Object);
OW_STATUS    OwObjOpenByName(const char* Path, uint32_t AccessFlags, OW_HANDLE* OutHandle);
OW_STATUS    OwObjClose(OW_HANDLE Handle);

#endif /* OW_OBJECT_H */
