/* ow_owx.h - OpenWindows Native Executable (.owx) OWX1 format definitions
 *
 * Kernel-side mirror of OpenWindows-Essentials/Extensions/owx_format.h.
 * The kernel parse code must be a byte-exact match for the packer output
 * (tools/owx_pack.py), which the schema below follows.
 *
 * C99 freestanding, fixed-layout.  */
#ifndef OW_OWX_H
#define OW_OWX_H

#include <stdbool.h>
#include <stdint.h>

#define OWX_MAGIC 0x3158574Fu /* "OWX1" read as little-endian u32 */
#define OWX_HEADER_SIZE 256u
#define OWX_FORMAT_VERSION 0x0001u
#define OWX_MAX_SECTIONS 64u

#define OWX_SUBSYSTEM_BOOT 0x04u
#define OWX_SUBSYSTEM_RECOVERY 0x05u

#define OWX_SECTION_CODE 0x01u
#define OWX_SECTION_RDATA 0x02u
#define OWX_SECTION_DATA 0x03u
#define OWX_SECTION_BSS 0x04u
#define OWX_SECTION_RELOC 0x05u
#define OWX_SECTION_IMPORT 0x06u
#define OWX_SECTION_EXPORT 0x07u
#define OWX_SECTION_TLS 0x08u
#define OWX_SECTION_RESOURCE 0x09u
#define OWX_SECTION_SENTINEL 0x0Au

#define OWX_TARGET_ARCH_X64 3u

typedef struct __attribute__((packed)) {
  uint32_t type;
  uint32_t flags;
  uint64_t file_offset;
  uint64_t virtual_addr;
  uint64_t size;
  uint32_t checksum;
  uint32_t reserved;
} owx_section_entry_t;

typedef struct __attribute__((packed)) {
  /* 0x00 */ uint32_t magic;
  /* 0x04 */ uint16_t format_version;
  /* 0x06 */ uint16_t header_size;
  /* 0x08 */ uint32_t image_size;
  /* 0x0C */ uint32_t header_checksum;
  /* 0x10 */ uint64_t entry_point;
  /* 0x18 */ uint64_t preferred_base;
  /* 0x20 */ uint64_t stack_reserve;
  /* 0x28 */ uint64_t stack_commit;
  /* 0x30 */ uint64_t heap_reserve;
  /* 0x38 */ uint64_t heap_commit;
  /* 0x40 */ uint32_t section_count;
  /* 0x44 */ uint32_t import_count;
  /* 0x48 */ uint32_t string_table_size;
  /* 0x4C */ uint8_t subsystem;
  /* 0x4D */ uint8_t target_arch;
  /* 0x4E */ uint8_t target_subarch;
  /* 0x4F */ uint8_t alignment_log2;
  /* 0x50 */ uint32_t flags;
  /* 0x54 */ uint32_t tls_index;
  /* 0x58 */ uint64_t timestamp;
  /* 0x60 */ uint32_t section_table_offset;
  /* 0x64 */ uint32_t import_table_offset;
  /* 0x68 */ uint32_t string_table_offset;
  /* 0x6C */ uint32_t reloc_table_offset;
  /* 0x70 */ uint32_t resource_offset;
  /* 0x74 */ uint32_t resource_size;
  /* 0x78 */ uint32_t debug_offset;
  /* 0x7C */ uint32_t debug_size;
  /* 0x80 */ uint32_t sentinel_bancode;
  /* 0x84 */ uint32_t sentinel_trap_slot;
  /* 0x88 */ uint64_t sentinel_recovery_ep;
  /* 0x90 */ uint32_t image_checksum;
  /* 0x94 */ uint32_t padding[27];
} owx_header_t;

/* OwOwxValidateHeader: sanity-checks magic/version/sizes/arch. */
bool OwOwxValidateHeader(const owx_header_t *H, uint32_t ImageSize);

#endif /* OW_OWX_H */