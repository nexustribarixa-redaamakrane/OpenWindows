/* owx_loader.c - Kernel OWX1 image loader
 *
 * Parses a raw .owx buffer (as read off the OWFS primary volume) into a
 * process object's execution image.  The loader is deliberately simple for
 * the MVP:
 *   - validates the 256-byte OWX1 header;
 *   - copies every loaded section (code/rdata/data/bss) into a fixed
 *     kernel-side exec arena at the section's preferred virtual address
 *     (single flat address space - per-process CR3 isolation is deferred);
 *   - resolves the entry point into the arena;
 *   - zero-fills BSS sections.
 *
 * Zero dynamic heap: all staging buffers are static pools. */
#include "../inc/ow_owx.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_kprintf.h"
#include <stdint.h>

#define OW_OWX_ARENA_SIZE (512U * 1024U)

bool OwOwxValidateHeader(const owx_header_t* H, uint32_t ImageSize) {
    if (!H) return false;
    if (H->magic != OWX_MAGIC) return false;
    if (ImageSize < 8u) return false;
    if (H->format_version != OWX_FORMAT_VERSION) return false;

    if (H->header_size != OWX_HEADER_SIZE) return false;
    if (H->section_count > OWX_MAX_SECTIONS) return false;
    if (H->target_arch != OWX_TARGET_ARCH_X64) return false;
    if (H->image_size > ImageSize || H->image_size == 0) return false;
    if (H->section_table_offset == 0) return false;
    return true;
}

/* One fixed arena, dialable up if a real orchestrator is inserted. */
static uint8_t  s_OwxArenaMemory[OW_OWX_ARENA_SIZE] __attribute__((aligned(4096)));

OW_STATUS OwPsLoadImage(OW_PROCESS_OBJECT* Proc,
                        const uint8_t* OwxBuffer,
                        uint32_t OwxSize) {
    const owx_header_t*  hdr;
    const owx_section_entry_t* secs;
    uint32_t idx;
    uint64_t first_vaddr;
    uint64_t last_vaddr;

    if (!Proc || !OwxBuffer) return OW_ERR_NULL_POINTER;
    hdr = (const owx_header_t*)(const void*)OwxBuffer;
    if (!OwOwxValidateHeader(hdr, OwxSize)) return OW_ERR_CORRUPT;

    Proc->EntryPoint = 0;

    if (OwxSize < OWX_HEADER_SIZE || hdr->section_count == 0 ||
        hdr->entry_point == 0) {
        return OW_ERR_CORRUPT;
    }

    secs = (const owx_section_entry_t*)(const void*)
               (OwxBuffer + hdr->section_table_offset);

    /* Bounds-check the section table against the file. */
    if ((uint64_t)hdr->section_table_offset +
        (uint64_t)hdr->section_count * (uint64_t)sizeof(owx_section_entry_t) >
        OwxSize) {
        return OW_ERR_CORRUPT;
    }

    /* Compute the virtual span so rejections are honest and coverage is
     * guaranteed inside the single flat arena. */
    first_vaddr = ~0ULL;
    last_vaddr = 0;
    for (idx = 0; idx < hdr->section_count; idx++) {
        if (secs[idx].size == 0) continue;
        if (secs[idx].virtual_addr < first_vaddr) {
            first_vaddr = secs[idx].virtual_addr;
        }
        if (secs[idx].virtual_addr + secs[idx].size > last_vaddr) {
            last_vaddr = secs[idx].virtual_addr + secs[idx].size;
        }
    }
    if (last_vaddr <= first_vaddr ||
        last_vaddr - first_vaddr > OW_OWX_ARENA_SIZE) {
        return OW_ERR_INSUFFICIENT;
    }

    /* Copy the sections into the exec arena.  The arena base is the lowest
     * section virtual address, so all relative addressing stays valid. */
    for (idx = 0; idx < hdr->section_count; idx++) {
        uint64_t src = secs[idx].file_offset;
        uint64_t len = secs[idx].size;
        uint64_t rel = secs[idx].virtual_addr - first_vaddr;

        if (src + len > OwxSize) return OW_ERR_CORRUPT;
        if (secs[idx].type == OWX_SECTION_BSS && len > 0) {
            /* Zero-fill: no file payload. */
            ow_memset(&s_OwxArenaMemory[rel], 0, (size_t)len);
            continue;
        }
        if (secs[idx].type == OWX_SECTION_CODE ||
            secs[idx].type == OWX_SECTION_RDATA ||
            secs[idx].type == OWX_SECTION_DATA) {
            ow_memcpy(&s_OwxArenaMemory[rel], OwxBuffer + src, (size_t)len);
        }
        /* RELOC/IMPORT/EXPORT/TLS/resource sections are not loaded for MVP. */
    }

    /* Resolve the entry into the arena. */
    Proc->EntryPoint = (uint64_t)(uintptr_t)
        ((uint8_t*)s_OwxArenaMemory + (hdr->entry_point - first_vaddr));

    OwDiagLogFinished("OWX Image Load", OW_C_OWINIT_IMAGE_LOADED);
    ow_kprintf("[PS] %s image loaded: %u section(s), entry 0x%llX, span 0x%llX\r\n",
               Proc->Header.Name,
               (unsigned)hdr->section_count,
               (unsigned long long)Proc->EntryPoint,
               (unsigned long long)(last_vaddr - first_vaddr));
    return OW_SUCCESS;
}