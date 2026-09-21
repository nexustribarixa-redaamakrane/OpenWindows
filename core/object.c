/* object.c - Object Manager (Everything is an Object) */
#include "../inc/ow_object.h"
#include "../lib/kalloc.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_string.h"

#define OW_MAX_HANDLE_TABLE    256U

static OW_OBJECT_DIR g_RootNamespace;
static OW_OBJECT_TYPE g_DirType = { "Directory", 0, (void*)0, (void*)0, (void*)0, (void*)0 };

/* Simple handle table for open objects */
static struct {
    void*   Objects[OW_MAX_HANDLE_TABLE];
    uint32_t Count;
} g_HandleTable;

OW_STATUS OwObjInitialize(void) {
    ow_memset(&g_RootNamespace, 0, sizeof(OW_OBJECT_DIR));
    g_RootNamespace.Header.ReferenceCount = 1;
    g_RootNamespace.Header.HandleCount = 0;
    g_RootNamespace.Header.Type = &g_DirType;
    ow_strncpy(g_RootNamespace.Header.Name, "\\", OW_MAX_NAME);
    g_RootNamespace.Header.ParentDirectory = (void*)0;
    g_RootNamespace.Header.SecurityFlags = 0;
    g_RootNamespace.EntryCount = 0;
    ow_memset(g_RootNamespace.Entries, 0, sizeof(g_RootNamespace.Entries));

    g_HandleTable.Count = 0;
    ow_memset(g_HandleTable.Objects, 0, sizeof(g_HandleTable.Objects));

    return OW_SUCCESS;
}

OW_OBJECT_DIR* OwObjCreateDirectory(const char* Name, OW_OBJECT_DIR* Parent) {
    OW_OBJECT_DIR* dir;
    OW_OBJECT_DIR* parent = Parent ? Parent : &g_RootNamespace;

    dir = (OW_OBJECT_DIR*)kcalloc(1, sizeof(OW_OBJECT_DIR));
    if (!dir) return (void*)0;

    dir->Header.ReferenceCount = 1;
    dir->Header.HandleCount = 0;
    dir->Header.Type = &g_DirType;
    ow_strncpy(dir->Header.Name, Name, OW_MAX_NAME);
    dir->Header.ParentDirectory = parent;
    dir->Header.SecurityFlags = 0;
    dir->EntryCount = 0;
    ow_memset(dir->Entries, 0, sizeof(dir->Entries));

    if (parent->EntryCount < OW_OBJECT_MAX_ENTRIES) {
        parent->Entries[parent->EntryCount++] = dir;
    }

    return dir;
}

void* OwObjCreateObject(OW_OBJECT_TYPE* Type, const char* Name, size_t BodySize, OW_OBJECT_DIR* Parent) {
    OW_OBJECT_HEADER* hdr;
    OW_OBJECT_DIR* parent = Parent ? Parent : &g_RootNamespace;
    void* body;

    hdr = (OW_OBJECT_HEADER*)kcalloc(1, sizeof(OW_OBJECT_HEADER) + BodySize);
    if (!hdr) return (void*)0;

    hdr->ReferenceCount = 1;
    hdr->HandleCount = 1;
    hdr->Type = Type;
    ow_strncpy(hdr->Name, Name, OW_MAX_NAME);
    hdr->ParentDirectory = parent;
    hdr->SecurityFlags = 0;

    body = OW_HDR_TO_OBJ(hdr);

    if (parent->EntryCount < OW_OBJECT_MAX_ENTRIES) {
        parent->Entries[parent->EntryCount++] = body;
    }

    return body;
}

void OwObjReference(void* Object) {
    OW_OBJECT_HEADER* hdr;
    if (!Object) return;
    hdr = OW_OBJ_TO_HEADER(Object);
    hdr->ReferenceCount++;
}

void OwObjDereference(void* Object) {
    OW_OBJECT_HEADER* hdr;
    if (!Object) return;
    hdr = OW_OBJ_TO_HEADER(Object);
    hdr->ReferenceCount--;
    if (hdr->ReferenceCount <= 0) {
        if (hdr->Type && hdr->Type->Delete) {
            hdr->Type->Delete(Object);
        }
        kfree(hdr);
    }
}

OW_STATUS OwObjOpenByName(const char* Path, uint32_t AccessFlags, OW_HANDLE* OutHandle) {
    OW_OBJECT_DIR* dir;
    uint32_t i;
    (void)AccessFlags;

    if (!Path || !OutHandle) return OW_ERR_NULL_POINTER;

    dir = &g_RootNamespace;
    for (i = 0; i < dir->EntryCount; i++) {
        OW_OBJECT_HEADER* hdr = OW_OBJ_TO_HEADER(dir->Entries[i]);
        if (ow_strcmp(hdr->Name, Path) == 0) {
            if (g_HandleTable.Count < OW_MAX_HANDLE_TABLE) {
                *OutHandle = OW_OBJECT_HANDLE_BASE + g_HandleTable.Count;
                g_HandleTable.Objects[g_HandleTable.Count] = dir->Entries[i];
                g_HandleTable.Count++;
                hdr->HandleCount++;
                return OW_SUCCESS;
            }
            return OW_ERR_INSUFFICIENT;
        }
    }
    return OW_ERR_NOT_FOUND;
}

OW_STATUS OwObjClose(OW_HANDLE Handle) {
    uint32_t idx = Handle - OW_OBJECT_HANDLE_BASE;
    void* obj;
    OW_OBJECT_HEADER* hdr;

    if (idx >= g_HandleTable.Count) return OW_ERR_INVALID_PARAM;
    obj = g_HandleTable.Objects[idx];
    if (!obj) return OW_ERR_INVALID_PARAM;

    hdr = OW_OBJ_TO_HEADER(obj);
    hdr->HandleCount--;
    g_HandleTable.Objects[idx] = (void*)0;

    return OW_SUCCESS;
}
