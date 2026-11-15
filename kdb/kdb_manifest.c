/* kdb_manifest.c - compose a custom ABI from bounded text manifests.
 *
 * A custom ABI is data, not code: one or more files describe the environment
 * (family, kind, image format, ELF OSABI), the image's base/entry and, when the
 * format is raw, the segments the loader must validate.  Later files override
 * earlier ones, which lets a deployment provide a base manifest and a local
 * overlay without copying the whole description.
 *
 * The parser is deliberately small and total: every line is bounded, every
 * number is range checked, and an unknown key or malformed value fails the
 * whole composition instead of producing a half-understood ABI.
 */
#include "kdb_internal.h"
#include "../inc/ow_memory.h"

#define MANIFEST_LINE_MAX 256U
#define MANIFEST_SECTION_MAX 16U

typedef enum _MANIFEST_SECTION {
    M_SEC_NONE = 0,
    M_SEC_ABI,
    M_SEC_IMAGE,
    M_SEC_POLICY,
    M_SEC_SEGMENT
} MANIFEST_SECTION;

typedef struct _MANIFEST_STATE {
    OW_KDB_ABI_DESC* Abi;
    MANIFEST_SECTION Section;
    bool             NameSet;
    bool             FamilySet;
    bool             KindSet;
    bool             FormatSet;
    bool             IdSet;
    bool             OsabiSet;
    int32_t          SegmentIndex;   /* -1 until the first [segment]         */
    uint32_t         SegmentFields;
} MANIFEST_STATE;

static char lower_ascii(char c) {
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }
    return c;
}

static bool text_equal_ci(const char* A, const char* B) {
    uint32_t i;

    if (A == (const char*)0 || B == (const char*)0) {
        return false;
    }
    for (i = 0U; A[i] != '\0' || B[i] != '\0'; ++i) {
        if (lower_ascii(A[i]) != lower_ascii(B[i])) {
            return false;
        }
    }
    return true;
}

static char* trim(char* Text) {
    char* end;

    while (*Text == ' ' || *Text == '\t' || *Text == '\r') {
        ++Text;
    }
    end = Text;
    while (*end != '\0') {
        ++end;
    }
    while (end > Text &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r')) {
        --end;
    }
    *end = '\0';
    return Text;
}

static bool parse_u64(const char* Text, uint64_t* OutValue) {
    uint64_t value = 0U;
    uint32_t i = 0U;
    uint32_t base = 10U;
    bool any = false;

    if (Text == (const char*)0 || OutValue == (uint64_t*)0) {
        return false;
    }
    if (Text[0] == '0' && (Text[1] == 'x' || Text[1] == 'X')) {
        base = 16U;
        i = 2U;
    }
    for (; Text[i] != '\0'; ++i) {
        uint32_t digit;
        char c = Text[i];

        if (c >= '0' && c <= '9') {
            digit = (uint32_t)(c - '0');
        } else if (base == 16U && c >= 'a' && c <= 'f') {
            digit = (uint32_t)(c - 'a' + 10);
        } else if (base == 16U && c >= 'A' && c <= 'F') {
            digit = (uint32_t)(c - 'A' + 10);
        } else {
            return false;
        }
        if (value > ((uint64_t)0xFFFFFFFFFFFFFFFFULL - digit) / base) {
            return false;
        }
        value = value * base + digit;
        any = true;
    }
    if (!any) {
        return false;
    }
    *OutValue = value;
    return true;
}

static bool parse_bool(const char* Text, bool* OutValue) {
    if (text_equal_ci(Text, "1") || text_equal_ci(Text, "true") ||
        text_equal_ci(Text, "yes") || text_equal_ci(Text, "on")) {
        *OutValue = true;
        return true;
    }
    if (text_equal_ci(Text, "0") || text_equal_ci(Text, "false") ||
        text_equal_ci(Text, "no") || text_equal_ci(Text, "off")) {
        *OutValue = false;
        return true;
    }
    return false;
}

static bool parse_family(const char* Text, OW_KDB_ABI_FAMILY* OutFamily) {
    if (text_equal_ci(Text, "openwindows") || text_equal_ci(Text, "ow")) {
        *OutFamily = OW_KDB_ABI_FAMILY_OPENWINDOWS;
    } else if (text_equal_ci(Text, "linux")) {
        *OutFamily = OW_KDB_ABI_FAMILY_LINUX;
    } else if (text_equal_ci(Text, "bsd")) {
        *OutFamily = OW_KDB_ABI_FAMILY_BSD;
    } else if (text_equal_ci(Text, "unix") || text_equal_ci(Text, "sysv")) {
        *OutFamily = OW_KDB_ABI_FAMILY_UNIX;
    } else if (text_equal_ci(Text, "custom")) {
        *OutFamily = OW_KDB_ABI_FAMILY_CUSTOM;
    } else {
        return false;
    }
    return true;
}

static bool parse_kind(const char* Text, OW_KDB_KERNEL_KIND* OutKind) {
    if (text_equal_ci(Text, "native") ||
        text_equal_ci(Text, "native-openwindows") ||
        text_equal_ci(Text, "openwindows-native")) {
        *OutKind = OW_KDB_KIND_NATIVE_OPENWINDOWS;
    } else if (text_equal_ci(Text, "stripped") ||
               text_equal_ci(Text, "stripped-openwindows")) {
        *OutKind = OW_KDB_KIND_STRIPPED_OPENWINDOWS;
    } else if (text_equal_ci(Text, "modified") ||
               text_equal_ci(Text, "modified-openwindows")) {
        *OutKind = OW_KDB_KIND_MODIFIED_OPENWINDOWS;
    } else if (text_equal_ci(Text, "linux")) {
        *OutKind = OW_KDB_KIND_LINUX;
    } else if (text_equal_ci(Text, "custom")) {
        *OutKind = OW_KDB_KIND_CUSTOM;
    } else if (text_equal_ci(Text, "bsd")) {
        *OutKind = OW_KDB_KIND_BSD;
    } else if (text_equal_ci(Text, "unix") || text_equal_ci(Text, "sysv")) {
        *OutKind = OW_KDB_KIND_UNIX;
    } else {
        return false;
    }
    return true;
}

static bool parse_format(const char* Text, uint32_t* OutFormat) {
    if (text_equal_ci(Text, "owx")) {
        *OutFormat = OW_KDB_FORMAT_OWX;
    } else if (text_equal_ci(Text, "elf") || text_equal_ci(Text, "elf64")) {
        *OutFormat = OW_KDB_FORMAT_ELF;
    } else if (text_equal_ci(Text, "raw") || text_equal_ci(Text, "binary")) {
        *OutFormat = OW_KDB_FORMAT_RAW;
    } else {
        uint64_t value;
        if (!parse_u64(Text, &value) || value < OW_KDB_FORMAT_OWX ||
            value > OW_KDB_FORMAT_RAW) {
            return false;
        }
        *OutFormat = (uint32_t)value;
    }
    return true;
}

static bool parse_osabi(const char* Text, uint32_t* OutOsAbi) {
    if (text_equal_ci(Text, "sysv") || text_equal_ci(Text, "none")) {
        *OutOsAbi = OW_KDB_ELF_OSABI_SYSV;
    } else if (text_equal_ci(Text, "netbsd")) {
        *OutOsAbi = OW_KDB_ELF_OSABI_NETBSD;
    } else if (text_equal_ci(Text, "linux")) {
        *OutOsAbi = OW_KDB_ELF_OSABI_LINUX;
    } else if (text_equal_ci(Text, "freebsd")) {
        *OutOsAbi = OW_KDB_ELF_OSABI_FREEBSD;
    } else if (text_equal_ci(Text, "openbsd")) {
        *OutOsAbi = OW_KDB_ELF_OSABI_OPENBSD;
    } else if (text_equal_ci(Text, "any")) {
        *OutOsAbi = 0xFFU;
    } else {
        uint64_t value;
        if (!parse_u64(Text, &value) || value > 0xFFU) {
            return false;
        }
        *OutOsAbi = (uint32_t)value;
    }
    return true;
}

static bool parse_segment_flags(const char* Text, uint32_t* OutFlags) {
    uint32_t flags = 0U;
    uint32_t i;

    if (Text[0] == '\0') {
        return false;
    }
    for (i = 0U; Text[i] != '\0'; ++i) {
        char c = lower_ascii(Text[i]);
        if (c == 'r') {
            flags |= OW_KDB_SEGMENT_READ;
        } else if (c == 'w') {
            flags |= OW_KDB_SEGMENT_WRITE;
        } else if (c == 'x') {
            flags |= OW_KDB_SEGMENT_EXECUTE;
        } else if (c == ' ' || c == '\t') {
            continue;
        } else if (c == '0' && Text[i + 1U] == '\0') {
            flags = 0U;
        } else {
            return false;
        }
    }
    *OutFlags = flags;
    return true;
}

static bool copy_field(char* Dst, uint32_t DstSize, const char* Src) {
    return OwKdbCopyName(Dst, DstSize, Src);
}

static bool parse_section(const char* Name, MANIFEST_SECTION* OutSection) {
    if (text_equal_ci(Name, "abi")) {
        *OutSection = M_SEC_ABI;
    } else if (text_equal_ci(Name, "image")) {
        *OutSection = M_SEC_IMAGE;
    } else if (text_equal_ci(Name, "policy")) {
        *OutSection = M_SEC_POLICY;
    } else if (text_equal_ci(Name, "segment")) {
        *OutSection = M_SEC_SEGMENT;
    } else {
        return false;
    }
    return true;
}

static OW_STATUS apply_pair(MANIFEST_STATE* State, const char* Key,
                            const char* Value) {
    OW_KDB_ABI_DESC* abi = State->Abi;
    uint64_t number;
    bool flag;

    switch (State->Section) {
    case M_SEC_ABI:
        if (text_equal_ci(Key, "name")) {
            if (!copy_field(abi->Name, OW_KDB_MAX_NAME, Value) ||
                abi->Name[0] == '\0') {
                return OW_ERR_INVALID_PARAM;
            }
            State->NameSet = true;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "id")) {
            if (!parse_u64(Value, &number) || number > 0xFFFFFFFFULL) {
                return OW_ERR_INVALID_PARAM;
            }
            abi->Id = (uint32_t)number;
            State->IdSet = true;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "family")) {
            if (!parse_family(Value, &abi->Family)) {
                return OW_ERR_INVALID_PARAM;
            }
            State->FamilySet = true;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "kind")) {
            if (!parse_kind(Value, &abi->Kind)) {
                return OW_ERR_INVALID_PARAM;
            }
            State->KindSet = true;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "format")) {
            if (!parse_format(Value, &abi->Format)) {
                return OW_ERR_INVALID_PARAM;
            }
            State->FormatSet = true;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "osabi") || text_equal_ci(Key, "elf_osabi")) {
            if (!parse_osabi(Value, &abi->ElfOsAbi)) {
                return OW_ERR_INVALID_PARAM;
            }
            State->OsabiSet = true;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "arch") || text_equal_ci(Key, "target_arch")) {
            if (text_equal_ci(Value, "x86_64") || text_equal_ci(Value, "x64") ||
                text_equal_ci(Value, "amd64")) {
                abi->TargetArch = OW_KDB_ARCH_X86_64;
                return OW_SUCCESS;
            }
            if (!parse_u64(Value, &number) ||
                number != OW_KDB_ARCH_X86_64) {
                return OW_ERR_UNSUPPORTED;
            }
            return OW_SUCCESS;
        }
        /* Unknown keys are refused: a manifest must not silently mean less
         * than it says. */
        return OW_ERR_INVALID_PARAM;

    case M_SEC_IMAGE:
        if (text_equal_ci(Key, "base") || text_equal_ci(Key, "load_base")) {
            if (!parse_u64(Value, &number)) {
                return OW_ERR_INVALID_PARAM;
            }
            abi->LoadBase = number;
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "entry") || text_equal_ci(Key, "entry_point")) {
            if (!parse_u64(Value, &number)) {
                return OW_ERR_INVALID_PARAM;
            }
            abi->EntryPoint = number;
            return OW_SUCCESS;
        }
        return OW_ERR_INVALID_PARAM;

    case M_SEC_POLICY:
        if (text_equal_ci(Key, "shared_memory") ||
            text_equal_ci(Key, "shared")) {
            if (!parse_bool(Value, &flag)) {
                return OW_ERR_INVALID_PARAM;
            }
            if (flag) {
                abi->Flags |= OW_KDB_ABI_FLAG_REQUIRES_SHARED_MEMORY;
            } else {
                abi->Flags &= ~OW_KDB_ABI_FLAG_REQUIRES_SHARED_MEMORY;
            }
            return OW_SUCCESS;
        }
        if (text_equal_ci(Key, "kernel_privilege") ||
            text_equal_ci(Key, "privileged")) {
            if (!parse_bool(Value, &flag)) {
                return OW_ERR_INVALID_PARAM;
            }
            if (flag) {
                abi->Flags |= OW_KDB_ABI_FLAG_REQUIRES_KERNEL_PRIVILEGE;
            } else {
                abi->Flags &= ~OW_KDB_ABI_FLAG_REQUIRES_KERNEL_PRIVILEGE;
            }
            return OW_SUCCESS;
        }
        return OW_ERR_INVALID_PARAM;

    case M_SEC_SEGMENT: {
        OW_KDB_ABI_SEGMENT* seg;

        if (State->SegmentIndex < 0 ||
            (uint32_t)State->SegmentIndex >= OW_KDB_MAX_ABI_SEGMENTS) {
            return OW_ERR_INSUFFICIENT;
        }
        seg = &abi->Segments[State->SegmentIndex];
        if (text_equal_ci(Key, "name")) {
            if (!copy_field(seg->Name, sizeof(seg->Name), Value)) {
                return OW_ERR_INVALID_PARAM;
            }
        } else if (text_equal_ci(Key, "vaddr") ||
                   text_equal_ci(Key, "virtual_address")) {
            if (!parse_u64(Value, &number)) {
                return OW_ERR_INVALID_PARAM;
            }
            seg->VirtualAddress = number;
        } else if (text_equal_ci(Key, "offset") ||
                   text_equal_ci(Key, "file_offset")) {
            if (!parse_u64(Value, &number)) {
                return OW_ERR_INVALID_PARAM;
            }
            seg->FileOffset = number;
        } else if (text_equal_ci(Key, "filesz") ||
                   text_equal_ci(Key, "file_size")) {
            if (!parse_u64(Value, &number)) {
                return OW_ERR_INVALID_PARAM;
            }
            seg->FileSize = number;
        } else if (text_equal_ci(Key, "memsz") ||
                   text_equal_ci(Key, "memory_size")) {
            if (!parse_u64(Value, &number)) {
                return OW_ERR_INVALID_PARAM;
            }
            seg->MemorySize = number;
        } else if (text_equal_ci(Key, "flags")) {
            if (!parse_segment_flags(Value, &seg->Flags)) {
                return OW_ERR_INVALID_PARAM;
            }
        } else {
            return OW_ERR_INVALID_PARAM;
        }
        State->SegmentFields |= 1U;
        return OW_SUCCESS;
    }
    default:
        return OW_ERR_INVALID_PARAM;
    }
}

static OW_STATUS parse_file(MANIFEST_STATE* State,
                            const OW_KDB_MANIFEST_FILE* File) {
    uint32_t pos = 0U;

    if (File->Data == (const uint8_t*)0 || File->Size == 0U) {
        return OW_ERR_INVALID_PARAM;
    }

    while (pos < File->Size) {
        char line[MANIFEST_LINE_MAX];
        uint32_t len = 0U;
        char* text;
        char* equals;

        while (pos < File->Size && File->Data[pos] != '\n') {
            uint8_t c = File->Data[pos++];

            if (c == '\r') {
                continue;
            }
            if (len + 1U >= MANIFEST_LINE_MAX) {
                return OW_ERR_INVALID_PARAM;
            }
            line[len++] = (char)c;
        }
        if (pos < File->Size && File->Data[pos] == '\n') {
            ++pos;
        }
        line[len] = '\0';

        /* Strip an unquoted comment marker. */
        {
            uint32_t k;
            for (k = 0U; line[k] != '\0'; ++k) {
                if (line[k] == '#') {
                    line[k] = '\0';
                    break;
                }
            }
        }

        text = trim(line);
        if (text[0] == '\0') {
            continue;
        }
        if (text[0] == ';') {
            continue;
        }
        if (text[0] == '[') {
            char* close = text;
            MANIFEST_SECTION section;

            while (*close != '\0' && *close != ']') {
                ++close;
            }
            if (*close != ']' || close[1] != '\0') {
                return OW_ERR_INVALID_PARAM;
            }
            *close = '\0';
            if (!parse_section(trim(text + 1), &section)) {
                return OW_ERR_INVALID_PARAM;
            }
            State->Section = section;
            if (section == M_SEC_SEGMENT) {
                ++State->SegmentIndex;
                if ((uint32_t)State->SegmentIndex >= OW_KDB_MAX_ABI_SEGMENTS) {
                    return OW_ERR_INSUFFICIENT;
                }
                State->Abi->Segments[State->SegmentIndex].Name[0] = '\0';
                State->Abi->Segments[State->SegmentIndex].VirtualAddress = 0U;
                State->Abi->Segments[State->SegmentIndex].FileOffset = 0U;
                State->Abi->Segments[State->SegmentIndex].FileSize = 0U;
                State->Abi->Segments[State->SegmentIndex].MemorySize = 0U;
                State->Abi->Segments[State->SegmentIndex].Flags = 0U;
                if ((uint32_t)(State->SegmentIndex + 1) >
                    State->Abi->SegmentCount) {
                    State->Abi->SegmentCount =
                        (uint32_t)(State->SegmentIndex + 1);
                }
            }
            continue;
        }

        equals = text;
        while (*equals != '\0' && *equals != '=') {
            ++equals;
        }
        if (*equals != '=') {
            return OW_ERR_INVALID_PARAM;
        }
        *equals = '\0';
        {
            OW_STATUS status = apply_pair(State, trim(text), trim(equals + 1));
            if (ow_status_error(status)) {
                return status;
            }
        }
    }
    return OW_SUCCESS;
}

static OW_STATUS manifest_finalize(MANIFEST_STATE* State) {
    OW_KDB_ABI_DESC* abi = State->Abi;
    uint32_t i;

    if (!State->NameSet || abi->Name[0] == '\0') {
        return OW_ERR_INVALID_PARAM;
    }

    if (!State->FamilySet) {
        abi->Family = OW_KDB_ABI_FAMILY_CUSTOM;
    }
    if (!State->KindSet) {
        switch (abi->Family) {
        case OW_KDB_ABI_FAMILY_OPENWINDOWS:
            abi->Kind = OW_KDB_KIND_NATIVE_OPENWINDOWS;
            break;
        case OW_KDB_ABI_FAMILY_LINUX: abi->Kind = OW_KDB_KIND_LINUX; break;
        case OW_KDB_ABI_FAMILY_BSD:   abi->Kind = OW_KDB_KIND_BSD; break;
        case OW_KDB_ABI_FAMILY_UNIX:  abi->Kind = OW_KDB_KIND_UNIX; break;
        default:                      abi->Kind = OW_KDB_KIND_CUSTOM; break;
        }
    }
    if (!State->FormatSet) {
        switch (abi->Family) {
        case OW_KDB_ABI_FAMILY_OPENWINDOWS:
            abi->Format = OW_KDB_FORMAT_OWX;
            break;
        case OW_KDB_ABI_FAMILY_LINUX:
        case OW_KDB_ABI_FAMILY_BSD:
        case OW_KDB_ABI_FAMILY_UNIX:
            abi->Format = OW_KDB_FORMAT_ELF;
            break;
        default:
            abi->Format = OW_KDB_FORMAT_RAW;
            break;
        }
    }
    if (!State->OsabiSet) {
        switch (abi->Family) {
        case OW_KDB_ABI_FAMILY_LINUX: abi->ElfOsAbi = OW_KDB_ELF_OSABI_LINUX; break;
        case OW_KDB_ABI_FAMILY_BSD:   abi->ElfOsAbi = OW_KDB_ELF_OSABI_FREEBSD; break;
        default:                      abi->ElfOsAbi = OW_KDB_ELF_OSABI_SYSV; break;
        }
    }

    /* Family and kind must agree. */
    switch (abi->Family) {
    case OW_KDB_ABI_FAMILY_OPENWINDOWS:
        if (abi->Kind != OW_KDB_KIND_NATIVE_OPENWINDOWS &&
            abi->Kind != OW_KDB_KIND_STRIPPED_OPENWINDOWS &&
            abi->Kind != OW_KDB_KIND_MODIFIED_OPENWINDOWS) {
            return OW_ERR_INVALID_PARAM;
        }
        break;
    case OW_KDB_ABI_FAMILY_LINUX:
        if (abi->Kind != OW_KDB_KIND_LINUX) {
            return OW_ERR_INVALID_PARAM;
        }
        break;
    case OW_KDB_ABI_FAMILY_BSD:
        if (abi->Kind != OW_KDB_KIND_BSD) {
            return OW_ERR_INVALID_PARAM;
        }
        break;
    case OW_KDB_ABI_FAMILY_UNIX:
        if (abi->Kind != OW_KDB_KIND_UNIX) {
            return OW_ERR_INVALID_PARAM;
        }
        break;
    default:
        if (abi->Kind != OW_KDB_KIND_CUSTOM) {
            return OW_ERR_INVALID_PARAM;
        }
        break;
    }

    if (abi->TargetArch != OW_KDB_ARCH_X86_64) {
        return OW_ERR_UNSUPPORTED;
    }

    /* Raw images have no self-describing header, so the manifest must say where
     * the image lives and where execution starts. */
    if (abi->Format == OW_KDB_FORMAT_RAW) {
        if (abi->EntryPoint == 0U || abi->LoadBase == 0U) {
            return OW_ERR_INVALID_PARAM;
        }
        if (abi->EntryPoint < abi->LoadBase) {
            return OW_ERR_INVALID_PARAM;
        }
        if (!OwMemInUserWindow(abi->LoadBase) ||
            !OwMemInUserWindow(abi->EntryPoint)) {
            return OW_ERR_INVALID_PARAM;
        }
    }

    for (i = 0U; i < abi->SegmentCount; ++i) {
        OW_KDB_ABI_SEGMENT* seg = &abi->Segments[i];
        uint64_t file_end;
        uint64_t mem_end;

        if (seg->MemorySize == 0U) {
            return OW_ERR_INVALID_PARAM;
        }
        if (seg->FileSize > seg->MemorySize) {
            return OW_ERR_INVALID_PARAM;
        }
        if (seg->FileOffset > (uint64_t)0xFFFFFFFFFFFFFFFFULL - seg->FileSize ||
            seg->VirtualAddress >
                (uint64_t)0xFFFFFFFFFFFFFFFFULL - seg->MemorySize) {
            return OW_ERR_INVALID_PARAM;
        }
        file_end = seg->FileOffset + seg->FileSize;
        mem_end = seg->VirtualAddress + seg->MemorySize;
        (void)file_end;
        if (!OwMemInUserWindow(seg->VirtualAddress) ||
            !OwMemInUserWindow(mem_end - 1U)) {
            return OW_ERR_INVALID_PARAM;
        }
    }

    if (abi->Format == OW_KDB_FORMAT_RAW && abi->SegmentCount > 0U) {
        bool entry_in_segment = false;

        for (i = 0U; i < abi->SegmentCount; ++i) {
            OW_KDB_ABI_SEGMENT* seg = &abi->Segments[i];
            if ((seg->Flags & OW_KDB_SEGMENT_EXECUTE) != 0U &&
                abi->EntryPoint >= seg->VirtualAddress &&
                abi->EntryPoint < seg->VirtualAddress + seg->MemorySize) {
                entry_in_segment = true;
                break;
            }
        }
        if (!entry_in_segment) {
            return OW_ERR_INVALID_PARAM;
        }
    }

    return OW_SUCCESS;
}

OW_STATUS OwKdbManifestCompose(const OW_KDB_MANIFEST_FILE* Files,
                               uint32_t FileCount, OW_KDB_ABI_DESC* OutAbi) {
    MANIFEST_STATE state;
    OW_STATUS status;
    uint32_t i;

    if (Files == (const OW_KDB_MANIFEST_FILE*)0 ||
        FileCount == 0U || FileCount > OW_KDB_MAX_MANIFEST_FILES ||
        OutAbi == (OW_KDB_ABI_DESC*)0) {
        return OW_ERR_INVALID_PARAM;
    }

    /* Leave OutAbi untouched on failure so a caller cannot mistake a partially
     * filled descriptor for a composed ABI. */
    state.Abi = OutAbi;
    state.Section = M_SEC_NONE;
    state.NameSet = false;
    state.FamilySet = false;
    state.KindSet = false;
    state.FormatSet = false;
    state.IdSet = false;
    state.OsabiSet = false;
    state.SegmentIndex = -1;
    state.SegmentFields = 0U;

    for (i = 0U; i < FileCount; ++i) {
        if (Files[i].Name == (const char*)0 && Files[i].Data == (const uint8_t*)0) {
            return OW_ERR_INVALID_PARAM;
        }
        status = parse_file(&state, &Files[i]);
        if (ow_status_error(status)) {
            return status;
        }
    }

    return manifest_finalize(&state);
}
