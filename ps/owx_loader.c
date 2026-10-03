/* owx_loader.c - Kernel OWX1 image loader
 *
 * Parses a raw .owx buffer (as read off the OWFS primary volume) into the
 * owning PROCESS's own address space:
 *   - validates the 256-byte OWX1 header;
 *   - relocates the section layout into the guarded user window;
 *   - charges every page from that process's PRIVATE frame run;
 *   - maps the code section executable and every data section
 *     execute-disabled;
 *   - publishes one VAD per mapped region with matching NX intent, so the
 *     boot-time window audit can verify the result rather than trust it;
 *   - builds a per-process exit trampoline so a `ret` out of the image entry
 *     terminates the thread instead of jumping into stack garbage.
 *
 * There is deliberately no shared exec arena any more.  The previous design
 * copied every image into one kernel BSS buffer and ran it in Ring 0, which
 * meant two images aliased the same physical pages and a Ring 0 image had no
 * privilege boundary at all -- the only thing separating it from the kernel
 * was the convention that it behaved.
 *
 * Relocation: OWX1 carries no relocation table (reloc_table_offset is 0 and
 * there is no RELOC section), but that is safe here precisely BECAUSE the
 * packer emits position-independent code: every internal reference in a code
 * section is RIP-relative (`lea rdx,[rip+..]`, `call rel32`, `jmp [rip+..]`).
 * Moving the whole image by a single bias therefore moves the code and the
 * data it points at together, and the references stay correct.  An image
 * containing an absolute address would need a real relocation pass; the bias
 * below is the only transformation applied, and it is exact for RIP-relative
 * code.
 *
 * Zero dynamic heap: all staging buffers are static pools.
 *
 * CIS enforcement (Stage 2): the copy in this file that adds the gate below is
 * the one that matters.  OwCisVerifyImage() is called after the OWX header has
 * been structurally validated and before any frame is charged or any VAD is
 * published, so a refused image never acquires an executable mapping, a
 * published descriptor, or an entry point -- there is nothing to unwind.  The
 * one thing this file deliberately does NOT do is reimplement any part of the
 * decision: it passes bytes to cis/cis_verify.c and acts on the verdict. */
#include "../inc/ow_owx.h"
#include "../inc/ow_ps.h"
#include "../inc/ow_mem.h"
#include "../inc/ow_memory.h"
#include "../inc/ow_syscall.h"
#include "../inc/ow_diag.h"
#include "../inc/ow_kprintf.h"
#include "../inc/ow_cis.h"
#include <stdint.h>

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

/* ====================================================================== */
/* Import support: NONE.  This is checked explicitly, not assumed.         */
/* ====================================================================== */
/* The OWX1 container this loader consumes has no import entry structure, no
 * import table, and no relocation table -- there is nowhere in the 256-byte
 * header to record a symbol name, and no pass below that could bind one.  The
 * intended design for that is the .owd dynamic link format
 * (OpenWindows-Essentials/Extensions/owd_format.h): a symbol table, a
 * relocation table, a dependency list, and OWD_RELOC_OWRPCALL for gate calls
 * into the kernel.  None of that exists in the kernel yet.
 *
 * So an image that declares imports is REJECTED here rather than loaded.  The
 * distinction matters: such an image's code reaches its imports through
 * `jmp qword ptr [rip+disp]` slots whose contents are RVAs into the image's
 * own hint/name table, not addresses.  A uniform bias cannot fix those
 * contents, so loading the image "succeeds", and the process then faults the
 * first time it calls an imported function -- at CPL3, with a fault address
 * that points nowhere near the real problem.  Rejecting at load time turns a
 * mystery page fault into a diagnosable load failure. */
bool OwOwxImageIsSelfContained(const owx_header_t* H) {
    return H && (H->import_count == 0u);
}

/* The one pre-load verdict.  Kept adjacent to the two predicates it composes so
 * that a change to the load gate cannot land in one place and be missed in the
 * other; OwPsLoadImage below still checks each condition individually because it
 * reports which one failed, but it accepts exactly this set. */
bool OwOwxImageIsLoadable(const owx_header_t* H, uint32_t ImageSize) {
    if (!OwOwxValidateHeader(H, ImageSize)) return false;
    if (!OwOwxImageIsSelfContained(H)) return false;
    /* A header with no sections maps no pages (the loader's `mapped == 0` guard
     * rejects it), and an entry of 0 would be jumped to at CPL3 with a valid
     * window and nothing mapped there.  Both are corruption, not edge cases. */
    if (H->section_count == 0u) return false;
    if (H->entry_point == 0u) return false;
    return true;
}

/* The verdict from the most recent OwPsLoadImage call, untranslated.
 *
 * OW_STATUS has to compress a dozen CIS verdicts into whatever the process
 * loader's public interface already had, and the caller at core/main.c and
 * syscall/dispatcher.c both want to distinguish "unsigned" from "revoked key"
 * when they decide whether to fall back to a recovery image.  Keeping the enum
 * here means that decision is made against the real reason rather than against
 * a status code someone mapped by hand.
 *
 * Set on every load, before the status is returned, so a failed load reports its
 * own verdict rather than leaving the previous one in place for a caller to
 * read by mistake.  Single global rather than an out-parameter because
 * OwPsLoadImage's signature is also the boot path's and adding a parameter
 * there would mean every caller threading a value only one of them uses. */
static OW_CIS_VERDICT g_OwxLastCisVerdict = OW_CIS_VERDICT_NONE;

OW_CIS_VERDICT OwPsLastCisVerdict(void) {
    return g_OwxLastCisVerdict;
}

/* ====================================================================== */
/* Whole-image verification (CRC32c)                                      */
/* ====================================================================== */
/* tools/owx_pack.py stamps three independent CRC32c values into every image:
 * a per-section checksum over each section's file payload, an image_checksum
 * over the whole file from offset 0x10, and a header_checksum over the header.
 * Nothing on the read side ever looked at any of them, so a single flipped byte
 * in owinit.owx yielded an image that loaded cleanly and then faulted at CPL3
 * on the instruction it had corrupted -- the least diagnosable failure there
 * is, because the fault address points at code rather than at the disk.
 *
 * That matters for the boot policy rather than for a library: "owinit.owx is
 * corrupt" and "owinit.owx is absent" are the same state transition but not the
 * same fault, and the transition is only correct if corruption is actually
 * detected.  A probe that only read the magic number would send a scrambled
 * owinit.owx into state 1 and the machine would die at CPL3 with no diagnostic
 * at all, which is the exact failure the three-state policy exists to prevent.
 *
 * This lives beside the format rather than in the VFS: an executable's
 * integrity is a property of the executable format, not of the filesystem it
 * happens to sit on.  The polynomial is CRC32c (Castagnoli, reflected
 * 0x82F63B78) and MUST stay byte-for-byte identical to OwFsChecksumCalc() in
 * vfs/vfs.c and to crc32c() in tools/owx_pack.py.  The host test asserts all
 * three agree over the same buffer, so a change to one that forgets the others
 * fails the build instead of quietly rejecting every image in existence. */

/* Byte offsets of the two checksum fields.  Spelled out rather than taken with
 * offsetof() so that the hashed ranges below read the same way the packer
 * writes them, and so a drift in the packed struct shows up as a verification
 * failure with a log line instead of as a silently different hash window. */
#define OWX_OFF_HEADER_CHECKSUM 0x0Cu
#define OWX_OFF_IMAGE_CHECKSUM  0x90u

/* One CRC32c pass.  Seed and final inversion are the caller's business, which is
 * what lets the image checksum be taken over one contiguous range with the
 * image_checksum field itself treated as absent. */
static uint32_t owx_crc32c_pass(uint32_t crc, const uint8_t* data, uint32_t n) {
    uint32_t i;
    for (i = 0; i < n; i++) {
        uint32_t bit;
        crc ^= (uint32_t)data[i];
        for (bit = 0; bit < 8u; bit++) {
            crc = (crc >> 1) ^ (0x82F63B78U & (uint32_t)-(int32_t)(crc & 1u));
        }
    }
    return crc;
}

static uint32_t owx_crc32c(const uint8_t* data, uint32_t n) {
    return ~owx_crc32c_pass(0xFFFFFFFFu, data, n);
}

/* image_checksum, as tools/owx_pack.py computed it.
 *
 * The packer hashes blob[0x10:] while the image_checksum field is still zero,
 * then patches the field in.  Verification therefore has to hash the same range
 * with the same four bytes zeroed, or the comparison can never match: the
 * field is inside its own hash window. */
static uint32_t owx_image_checksum(const uint8_t* img, uint32_t image_size) {
    uint32_t crc;
    crc = owx_crc32c_pass(0xFFFFFFFFu, img + 0x10u,
                          (OWX_OFF_IMAGE_CHECKSUM - 0x10u));
    crc = owx_crc32c_pass(crc, (const uint8_t*)"\0\0\0\0", 4u);
    crc = owx_crc32c_pass(crc, img + OWX_OFF_IMAGE_CHECKSUM + 4u,
                          image_size - (OWX_OFF_IMAGE_CHECKSUM + 4u));
    return ~crc;
}

/* OwOwxImageIsUsable: the verdict the boot survey acts on.
 *
 * OwOwxImageIsLoadable() answers "would the loader accept this header", which
 * is a question about structure.  This answers the question the userspace policy
 * actually asks: "is this image intact enough to be PID 1", which is structure
 * AND contents.  Both are required, and this is the conjunction, so the survey
 * has exactly one thing to call and exactly one definition of the answer.
 *
 * Note what is deliberately NOT here: this is not wired into OwPsLoadImage().
 * The loader keeps accepting a structurally sound image whose CRCs do not
 * match, because refusing to load is a different policy decision from refusing
 * to boot into it, and the loader is reachable from a dozen contexts that have
 * no notion of a boot survey.  What the survey guarantees is the property that
 * matters: any image reported usable here is one the loader will accept, and
 * any image the loader would reject is reported unusable here.  That ordering
 * is what keeps a corrupt owinit.owx in state 2 instead of state 1. */
bool OwOwxImageIsUsable(const void* Image, uint32_t ImageSize) {
    const uint8_t* img = (const uint8_t*)Image;
    const owx_header_t* H;
    const owx_section_entry_t* secs;
    uint32_t image_size;
    uint32_t idx;

    if (!img) return false;
    if (ImageSize < OWX_HEADER_SIZE) return false;

    H = (const owx_header_t*)(const void*)img;
    if (!OwOwxImageIsLoadable(H, ImageSize)) return false;

    /* The packer sets image_size to the file length, so a stored value larger
     * than the buffer means the image was truncated in transit. */
    image_size = H->image_size;
    if (image_size > ImageSize) return false;
    if (image_size < OWX_HEADER_SIZE) return false;

    /* Bound the section table before it is dereferenced below.  OwOwxValidateHeader
     * only rejects a ZERO offset, so a stored offset of, say, 0xFFFFFF is
     * structurally "loadable" and the checksum would have to be forged over the
     * bogus offset to reach this point -- but the section walk must not depend on
     * that having happened.  This is the same rule OwPsLoadImage applies, kept
     * identical on purpose: a survey that bounds the image differently from the
     * loader is exactly how a usable-looking image turns into a CPL3 fault. */
    if ((uint64_t)H->section_table_offset +
            (uint64_t)H->section_count * (uint64_t)sizeof(owx_section_entry_t) >
        (uint64_t)image_size) {
        return false;
    }

    if (owx_image_checksum(img, image_size) != H->image_checksum) {
        ow_kprintf("[OWX] image_checksum 0x%08X != stored 0x%08X\r\n",
                   (unsigned)owx_image_checksum(img, image_size),
                   (unsigned)H->image_checksum);
        return false;
    }
    /* The header checksum is taken over the header AS STORED, i.e. with
     * image_checksum already filled in -- the packer runs it second.  Hashing it
     * the other way round would reject every well-formed image. */
    {
        uint32_t computed = owx_crc32c(img + 0x10u, OWX_HEADER_SIZE - 0x10u);
        if (computed != H->header_checksum) {
            ow_kprintf("[OWX] header_checksum 0x%08X != stored 0x%08X\r\n",
                       (unsigned)computed, (unsigned)H->header_checksum);
            return false;
        }
    }

    /* Per-section checksums.  These are what catch a payload edit that also had
     * the image checksum recomputed, and they are the only check that covers a
     * section's file bytes individually.
     *
     * A BSS section is the one case with no file bytes: the packer records
     * file_offset as a placeholder and size as the section's VIRTUAL size, and
     * stores checksum 0.  Applying the bounds rule to it would reject every
     * real BSS -- a zero-fill section is by definition larger than the file
     * that carries it -- so it is checked as "must be zero" instead. */
    secs = (const owx_section_entry_t*)(const void*)(img + H->section_table_offset);
    for (idx = 0; idx < H->section_count; idx++) {
        uint64_t off = secs[idx].file_offset;
        uint64_t len = secs[idx].size;

        if (secs[idx].type == OWX_SECTION_BSS) {
            if (secs[idx].checksum != 0u) return false;
            continue;
        }
        if (len == 0u) {
            if (secs[idx].checksum != 0u) return false;
            continue;
        }
        if (off > image_size || len > (uint64_t)image_size - off) return false;
        if (owx_crc32c(img + off, (uint32_t)len) != secs[idx].checksum) {
            ow_kprintf("[OWX] section %u checksum mismatch\r\n", (unsigned)idx);
            return false;
        }
    }
    return true;
}

/* ---- Exit trampoline ----------------------------------------------------
 * A loaded image's entry point is allowed to `ret` -- that is a normal way for
 * a C main to finish.  At CPL3 there is no caller to return to, so the loader
 * supplies one: a private, per-process, executable page whose only job is to
 * issue OW_SYS_PS_EXIT_THREAD.  It is emitted as bytes rather than written in
 * C so that it contains no absolute address needing relocation, and so it
 * cannot accidentally acquire a stack frame of its own.
 *
 *   mov eax, OW_SYS_PS_EXIT_THREAD   ; B8 imm32
 *   mov rcx, 0                       ; 48 C7 C1 imm32  (exit status)
 *   int 0x80                         ; CD 80
 *   jmp $                            ; EB FE  (unreachable: exit never returns)
 */
/* ---- CIS gate ------------------------------------------------------------
 *
 * The mandatory verification step, and the only place in the loader that decides
 * whether an image may become executable.
 *
 * Placement is the security property.  This runs after OwOwxValidateHeader has
 * established that the header is structurally sound -- so hdr->image_size is a
 * value the loader has already bounded against OwxSize -- and before the
 * relocation arithmetic, before any OwMemRunCharge, before any OwMemMapPage, and
 * before any VAD is published.  Every one of those is after this point in
 * function order, so a refusal cannot leave a mapped page behind: there is no
 * partial state to roll back.  Putting the gate after the mapping loop instead
 * would have meant an unsigned image briefly resident and executable in the
 * process's address space, which is precisely the window the subsystem exists
 * to close.
 *
 * ImageSize and Available, and why both:
 *
 *   ImageSize   hdr->image_size.  The bytes that will be mapped, and exactly the
 *               range the signed SHA-256 digest covers.  Not OwxSize: the CIS
 *               block is appended past this offset, so hashing the whole file
 *               would cover the signature over itself.
 *   Available   OwxSize.  Bytes physically in hand from Image onward.  This is
 *               what bounds the trailing block, and it is the caller's own
 *               count, not anything the image file asserts about itself.
 *
 * The loader derives neither from an unvalidated field: hdr->image_size has
 * already passed OwOwxValidateHeader's `image_size <= ImageSize` check, so
 * Available >= ImageSize holds before the call and the parser's own guard is
 * belt-and-braces rather than load-bearing here.  A second, subtly different
 * idea of "image size" inside the loader is what this avoids -- the loader and
 * CIS must agree on which bytes are authenticated.
 *
 * Relocation does not invalidate the digest, and that is worth stating rather
 * than leaving to be discovered: OWX1 carries no relocation table, and the only
 * transformation is a uniform virtual bias applied at mapping time (see the
 * relocation note at the top of this file).  The bytes CIS authenticates are the
 * on-disk bytes, and the bytes that execute are those same bytes at a different
 * address.  Nothing rewrites a byte between the digest and the instruction
 * pointer, so the hash boundary does not silently shift.
 *
 * The verdict is mapped to a distinct OW_STATUS per reason rather than folded
 * into one OW_ERR_CORRUPT.  Callers that want to distinguish "unsigned" from
 * "revoked key" read OwPsLastCisVerdict(), which holds the untranslated enum.
 *
 * These two functions are outside the OW_HOST_HAL guard below because the host
 * harness enforces the gate too.  A host build that skipped verification would
 * make every loader test meaningless -- the tests would be exercising a path no
 * production build has. */
static OW_STATUS owx_cis_status(OW_CIS_VERDICT Verdict) {
    switch (Verdict) {
    case OW_CIS_VERDICT_TRUSTED:
        return OW_SUCCESS;
    case OW_CIS_VERDICT_REJECT_UNSIGNED:
        return OW_ERR_CIS_UNSIGNED;
    case OW_CIS_VERDICT_REJECT_BAD_SIGNATURE:
        return OW_ERR_CIS_BAD_SIGNATURE;
    case OW_CIS_VERDICT_REJECT_UNKNOWN_KEY:
        return OW_ERR_CIS_UNKNOWN_KEY;
    case OW_CIS_VERDICT_REJECT_KEY_REVOKED:
        return OW_ERR_CIS_KEY_REVOKED;
    case OW_CIS_VERDICT_REJECT_DIGEST_MISMATCH:
        return OW_ERR_CIS_DIGEST_MISMATCH;
    case OW_CIS_VERDICT_REJECT_MALFORMED:
        return OW_ERR_CIS_MALFORMED;
    case OW_CIS_VERDICT_REJECT_POLICY:
        return OW_ERR_CIS_POLICY;
    case OW_CIS_VERDICT_COMPLIANT_REFUSAL:
        return OW_ERR_CIS_COMPLIANT_REFUSAL;
    default:
        /* NONE and ERROR.  ERROR means verification could not run at all, which
         * for a loader is never a licence to proceed. */
        return OW_ERR_CIS_ERROR;
    }
}

static OW_STATUS owx_cis_gate(const OW_PROCESS_OBJECT* Proc,
                              const owx_header_t* Hdr,
                              const uint8_t* Image, uint32_t Available,
                              uint32_t RecordFlags) {
    OW_CIS_VERDICT verdict;
    OW_STATUS status;

    /* Provenance is checked, not assumed.  An unrecognised value is refused: a
     * caller that reaches the load path some other way has to say so, because the
     * alternative is a measurement log holding a load nobody can account for.
     * Note what this is NOT -- no flag here makes verification optional.  The
     * worst outcome is a refused load, never a skipped one. */
    if (RecordFlags != (uint32_t)OW_CIS_RECORD_BOOT &&
        RecordFlags != (uint32_t)OW_CIS_RECORD_SPAWN) {
        g_OwxLastCisVerdict = OW_CIS_VERDICT_ERROR;
        ow_kprintf("[OWX] load refused: unrecognised CIS provenance 0x%08X\r\n",
                   (unsigned)RecordFlags);
        return OW_ERR_CIS_ERROR;
    }

    /* Proc->Header.Name is an inline array, so the label is always printable and
     * the verifier sees the same string the diagnostic below does. */
    verdict = OwCisVerifyImage(Image, Hdr->image_size, Available,
                               (uint32_t)Hdr->subsystem, Proc->ProcessId,
                               Proc->Header.Name, RecordFlags);
    g_OwxLastCisVerdict = verdict;
    status = owx_cis_status(verdict);

    if (ow_status_error(status)) {
        /* The verdict is already in the measurement log with the digest and key
         * id; this line is the console trace of the same decision and adds
         * nothing the log does not already hold. */
        ow_kprintf("[OWX] %s refused by CIS: %s (status 0x%08X)\r\n",
                   Proc->Header.Name, OwCisVerdictName(verdict), (unsigned)status);
    }
    return status;
}

#ifndef OW_HOST_HAL
static const uint8_t s_ExitTrampoline[] = {
    0xB8, 0x0E, 0x00, 0x00, 0x00,
    0x48, 0xC7, 0xC1, 0x00, 0x00, 0x00, 0x00,
    0xCD, 0x80,
    0xEB, 0xFE
};

/* Charge one page from the process's private run, seed it, and map it into the
 * process's own root.  `exec_ok` selects the NX policy: code is executable,
 * everything else is not.  This is the single place a loaded image acquires
 * physical memory, so the charge / map / refund paths cannot drift apart. */
static OW_STATUS owx_map_page(OW_PROCESS_OBJECT* Proc, uint64_t Va,
                              const uint8_t* Src, uint64_t Len,
                              uint64_t Offset, bool ExecOk) {
    uint64_t frame = 0;
    uint8_t* dst;
    uint64_t prot;

    if (ow_status_error(OwMemRunCharge(&Proc->FrameRun, &frame))) {
        ow_kprintf("[OWX] frame charge failed for %llX\r\n",
                   (unsigned long long)Va);
        return OW_ERR_INSUFFICIENT;
    }

    /* The frame arrives zeroed, so a partial tail page needs no explicit fill
     * and a BSS page is handled by passing Src == 0. */
    dst = (uint8_t*)(uintptr_t)(frame + (uintptr_t)Offset);
    if (Src && Len) ow_memcpy(dst, Src, (size_t)Len);

    /* NX is the default; only a code section opts out.  This per-section
     * decision is the point: a data section holding bytes an attacker
     * influences must not become a jump target. */
    prot = ExecOk ? OW_PAGE_USER_RW : OW_PAGE_USER_RW_NX;

    if (ow_status_error(OwMemMapPage(Proc->Pml4Phys, Va, frame, prot))) {
        (void)OwMemRunRelease(&Proc->FrameRun, frame);
        ow_kprintf("[OWX] map failed for %llX\r\n", (unsigned long long)Va);
        return OW_ERR_INVALID_PARAM;
    }
    return OW_SUCCESS;
}

/* Publish one VAD for a mapped region, with NX matching what was mapped so the
 * window audit compares like against like. */
static OW_STATUS owx_publish_vad(OW_PROCESS_OBJECT* Proc, uint64_t Start,
                                 uint64_t End, uint64_t Prot) {
    OW_VAD_NODE* vad = OwMemCreateVad(Start, End, Prot);

    if (!vad) return OW_ERR_INSUFFICIENT;
    if (ow_status_error(OwMemInsertVad(&Proc->VadRoot, vad))) {
        ow_kprintf("[OWX] VAD insert failed for %llX\r\n",
                   (unsigned long long)Start);
        return OW_ERR_NOT_FOUND;
    }
    return OW_SUCCESS;
}
#endif /* !OW_HOST_HAL : everything that needs page tables */

OW_STATUS OwPsLoadImage(OW_PROCESS_OBJECT* Proc,
                        const uint8_t* OwxBuffer,
                        uint32_t OwxSize,
                        uint32_t RecordFlags) {
    const owx_header_t*        hdr;
    const owx_section_entry_t* secs;
    uint32_t idx;
    uint64_t first_vaddr;
    uint64_t last_vaddr;
    uint64_t load_base;
    int64_t  bias;
    uint64_t image_end_va = 0;
#ifndef OW_HOST_HAL
    uint32_t mapped = 0;
#endif

    if (!Proc || !OwxBuffer) return OW_ERR_NULL_POINTER;

    /* Proc->Header.Name is an inline char array (inc/ow_object.h), not a
     * pointer, so the diagnostics below always have a valid string to print.  An
     * empty name prints as an empty field, which is a reporting cosmetic rather
     * than a defect: there is no NULL-name case in this file to defend, and
     * inventing one would be code for a hazard this type does not have. */
    hdr = (const owx_header_t*)(const void*)OwxBuffer;
    if (!OwOwxValidateHeader(hdr, OwxSize)) return OW_ERR_CORRUPT;

    /* Refuse an image that expects imports to be bound.  Without this the load
     * would appear to succeed and the process would fault at CPL3 the first
     * time it called an imported function. */
    if (!OwOwxImageIsSelfContained(hdr)) {
        ow_kprintf("[OWX] %s needs %u import(s); this loader binds none\r\n",
                   Proc->Header.Name, (unsigned)hdr->import_count);
        return OW_ERR_UNSUPPORTED;
    }

    Proc->EntryPoint  = 0;
    Proc->EntryReturn = 0;

    if (OwxSize < OWX_HEADER_SIZE || hdr->section_count == 0 ||
        hdr->entry_point == 0) {
        return OW_ERR_CORRUPT;
    }

    /* CIS gate.  Placed here, after the header is structurally sound and before
     * the section walk, the relocation arithmetic, and every mapping below.
     *
     * Everything past this point runs only on a header that matched a
     * signature, which is why the checks below are defence in depth for a bug in
     * this file rather than the barrier itself.  The gate is the barrier. */
    {
        OW_STATUS cis = owx_cis_gate(Proc, hdr, OwxBuffer, OwxSize,
                                     RecordFlags);
        if (ow_status_error(cis)) {
            return cis;
        }
    }

    secs = (const owx_section_entry_t*)(const void*)
               (OwxBuffer + hdr->section_table_offset);

    /* Bounds-check the section table against the file. */
    if ((uint64_t)hdr->section_table_offset +
        (uint64_t)hdr->section_count * (uint64_t)sizeof(owx_section_entry_t) >
        OwxSize) {
        return OW_ERR_CORRUPT;
    }

    /* Compute the virtual span so coverage is provable. */
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
    if (last_vaddr <= first_vaddr) return OW_ERR_CORRUPT;

    /* Relocate so the lowest section lands on the window base, and reject the
     * load up front if the result cannot fit.  Rejecting BEFORE any frame is
     * charged means a too-large image costs nothing and leaves no half-built
     * address space behind. */
    load_base = OW_USER_IMAGE_BASE;
    bias = (int64_t)load_base - (int64_t)first_vaddr;
    if ((first_vaddr + (uint64_t)bias) != load_base) {
        return OW_ERR_CORRUPT;                  /* bias arithmetic did not close */
    }
    {
        uint64_t span = last_vaddr - first_vaddr;
        uint64_t end  = load_base + span;
        if (end < load_base) return OW_ERR_CORRUPT;           /* overflow */
        /* Keep a page of slack for the exit trampoline, and never reach the
         * guard band: an image that grows into the guard would overwrite the
         * process's own stack-overflow detector. */
        if (end + OW_PAGE_SIZE >= OW_USER_GUARD_BASE) {
            ow_kprintf("[OWX] image span 0x%llX does not fit user window\r\n",
                       (unsigned long long)span);
            return OW_ERR_INSUFFICIENT;
        }
        image_end_va = end;
    }
#ifdef OW_HOST_HAL
    /* The host harness owns no page tables and no frame arena, so a load there
     * is a parse: header, section table, file bounds and window fit are all
     * still verified -- which is the part that has actual logic in it -- and
     * nothing is mapped.  Reporting success with the entry resolved keeps the
     * host boot sequence identical to the real one. */
    Proc->EntryPoint  = hdr->entry_point + (uint64_t)bias;
    Proc->EntryReturn = 0;
    ow_kprintf("[PS] %s image parsed (host): %u section(s), span 0x%llX, "
               "entry 0x%llX, would end 0x%llX\r\n",
               Proc->Header.Name, (unsigned)hdr->section_count,
               (unsigned long long)(last_vaddr - first_vaddr),
               (unsigned long long)Proc->EntryPoint,
               (unsigned long long)image_end_va);
    return OW_SUCCESS;
#else
    if (!Proc->Pml4Phys) {
        ow_kprintf("[OWX] no address space for %s\r\n", Proc->Header.Name);
        return OW_ERR_INVALID_PARAM;
    }

    /* Place every section, one page at a time.  Sections in this format are
     * page-spaced, but the loop is written per page so a section that shares a
     * page with its neighbour still lands byte-accurately. */
    for (idx = 0; idx < hdr->section_count; idx++) {
        uint64_t src = secs[idx].file_offset;
        uint64_t len = secs[idx].size;
        uint64_t va  = secs[idx].virtual_addr + (uint64_t)bias;
        uint64_t off;
        bool     exec_ok;

        if (len == 0) continue;

        /* A BSS section carries no file bytes at all: the packer points
         * file_offset at the start of the payload purely as a placeholder, and
         * `size` is the section's VIRTUAL size, not a file extent.  Applying the
         * file-bounds check to it is therefore meaningless, and it rejects
         * outright any BSS larger than the rest of the image -- which is every
         * BSS that matters, since a BSS is precisely the part of a program that
         * has no initialised content.
         *
         * owinit shipped without a BSS until kconf64 was linked into it, so this
         * never fired; the first real BSS (kconf64's registry, ~70 KiB) made
         * file_offset + size exceed the file and the load failed.  Nothing
         * bounded BSS's virtual extent here before, and nothing needs to now:
         * the image span was already validated against the user window above,
         * and the per-page loop maps page by page inside that span. */
        if (secs[idx].type != OWX_SECTION_BSS && src + len > OwxSize)
            return OW_ERR_CORRUPT;

        /* Only CODE is executable.  RDATA/DATA/BSS are execute-disabled even
         * though the packer marks every one of them read-only. */
        exec_ok = (secs[idx].type == OWX_SECTION_CODE);

        for (off = 0; off < len; off += OW_PAGE_SIZE) {
            uint64_t       page_va  = va + off;
            uint64_t       page_off = page_va & (OW_PAGE_SIZE - 1u);
            uint64_t       in_page  = (len - off) < OW_PAGE_SIZE ? (len - off)
                                                               : OW_PAGE_SIZE;
            uint64_t       copy     = in_page;
            const uint8_t* srcp;
            uint64_t       prot;

            if (page_off + copy > OW_PAGE_SIZE) {
                copy = OW_PAGE_SIZE - page_off;
            }
            srcp = (secs[idx].type == OWX_SECTION_BSS) ? (const uint8_t*)0
                                                        : OwxBuffer + src + off;

            prot = exec_ok ? OW_PAGE_USER_RW : OW_PAGE_USER_RW_NX;
            if (ow_status_error(owx_map_page(Proc, page_va, srcp, copy,
                                             page_off, exec_ok))) {
                return OW_ERR_INSUFFICIENT;
            }
            /* One VAD per page keeps the descriptor's NX intent identical to
             * the mapping actually installed -- which is what the audit
             * compares, and what makes a mismatch detectable at all. */
            if (ow_status_error(owx_publish_vad(
                    Proc, page_va, page_va + OW_PAGE_SIZE - 1u, prot))) {
                return OW_ERR_NOT_FOUND;
            }
            mapped++;
        }
    }
    if (mapped == 0) return OW_ERR_CORRUPT;

    /* Exit trampoline: one private executable page placed immediately above the
     * image, recorded as the process's C-ABI return address. */
    {
        uint64_t stub_va = (image_end_va + (OW_PAGE_SIZE - 1u)) &
                           ~(uint64_t)(OW_PAGE_SIZE - 1u);

        if (stub_va + OW_PAGE_SIZE > OW_USER_GUARD_BASE) {
            ow_kprintf("[OWX] no room for exit trampoline\r\n");
            return OW_ERR_INSUFFICIENT;
        }
        if (ow_status_error(owx_map_page(Proc, stub_va, s_ExitTrampoline,
                                         sizeof(s_ExitTrampoline), 0u,
                                         true))) {
            return OW_ERR_INSUFFICIENT;
        }
        if (ow_status_error(owx_publish_vad(Proc, stub_va,
                                            stub_va + OW_PAGE_SIZE - 1u,
                                            OW_PAGE_USER_RW))) {
            return OW_ERR_NOT_FOUND;
        }
        Proc->EntryReturn = stub_va;
    }

    /* The entry point moves with the bias, so it must land in the window. */
    Proc->EntryPoint = hdr->entry_point + (uint64_t)bias;
    if (!OwMemInUserWindow(Proc->EntryPoint)) {
        ow_kprintf("[OWX] relocated entry 0x%llX outside window\r\n",
                   (unsigned long long)Proc->EntryPoint);
        return OW_ERR_INVALID_PARAM;
    }

    OwDiagLogFinished("OWX Image Load", OW_C_OWINIT_IMAGE_LOADED);
    ow_kprintf("[PS] %s image loaded: %u section(s), %u page(s) charged, "
               "entry 0x%llX (bias 0x%llX), exit 0x%llX\r\n",
               Proc->Header.Name,
               (unsigned)hdr->section_count,
               (unsigned)(mapped + 1u),
               (unsigned long long)Proc->EntryPoint,
               (unsigned long long)bias,
               (unsigned long long)Proc->EntryReturn);
    return OW_SUCCESS;
#endif
}
