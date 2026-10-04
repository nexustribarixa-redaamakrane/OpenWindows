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

#define OWX_SUBSYSTEM_NATIVE   0x01u
#define OWX_SUBSYSTEM_GUI      0x02u
#define OWX_SUBSYSTEM_CONSOLE  0x03u
#define OWX_SUBSYSTEM_BOOT     0x04u
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

/* OwOwxImageIsSelfContained: true when the image declares no imports.
 *
 * OWX1 has no import entry structure, no import table and no relocation table,
 * so this loader cannot bind an imported symbol.  The intended mechanism is the
 * .owd dynamic link format (OpenWindows-Essentials/Extensions/owd_format.h):
 * symbol table + relocation table + dependency list, with OWD_RELOC_OWRPCALL
 * for gate calls into the kernel.  None of that is implemented in the kernel
 * yet, so an image with import_count != 0 is rejected at load time rather than
 * mapped and left to fault at CPL3 on its first imported call. */
bool OwOwxImageIsSelfContained(const owx_header_t *H);

/* OwOwxImageIsLoadable: the single pre-load verdict for an image.
 *
 * This is the conjunction of every check OwPsLoadImage applies before it
 * charges a frame, plus the two it used to apply only after the header had
 * already been accepted (a nonzero section count and a nonzero entry point).
 * The loader keeps its own granular checks because it reports WHICH of them
 * failed; this predicate exists so that a caller which is only deciding whether
 * an image is usable -- the boot-time owinit/owinitv/owrs survey -- cannot
 * answer that question with a weaker test than the loader will.
 *
 * That agreement is the point.  A probe that accepts a header the loader then
 * rejects turns a recoverable "owinit is unusable" into a failed boot with no
 * diagnostic, which is the failure this predicate is here to prevent.  The two
 * are held to the same answers by the host test. */
bool OwOwxImageIsLoadable(const owx_header_t *H, uint32_t ImageSize);

/* OwOwxImageIsUsable: loadable AND whole-image CRC32c verified.  This is the
 * verdict the boot-time owinit/owinitv/owrs survey acts on.
 *
 * OwOwxImageIsLoadable() is a question about structure -- would the loader
 * accept this header.  "Invalid" in the userspace policy is a question about
 * contents, so the survey needs both: a scrambled owinit.owx passes every
 * structural check in the loader and then faults at CPL3 on the instruction it
 * was corrupted in, which is the least diagnosable failure there is because the
 * fault address points at code rather than at the disk.
 *
 * The CRC32c verification reproduces tools/owx_pack.py exactly: a per-section
 * checksum over each section's file payload, image_checksum over the file from
 * offset 0x10 with the image_checksum field itself read as zero (it is inside
 * its own hash window), and header_checksum over the header as stored.
 *
 * Image must be at least OWX_HEADER_SIZE bytes; ImageSize is the length the
 * caller actually holds, and H->image_size may be smaller.  The header is read
 * out of Image, so no separate header pointer is taken.
 *
 * Deliberately NOT called by OwPsLoadImage(): refusing to load is a different
 * policy from refusing to boot into an image, and the loader is reachable from
 * many contexts that have no boot survey.  The guarantee that matters is
 * one-directional and sufficient: anything this accepts, the loader accepts. */
bool OwOwxImageIsUsable(const void *Image, uint32_t ImageSize);

#endif /* OW_OWX_H */