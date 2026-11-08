cmake_minimum_required(VERSION 3.20)
project(openwinkrnl C ASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

# ==============================================================================
# CIS_DEV_TRUST: opt-in development trust anchor
# ==============================================================================
# OFF by default, and the default is the point.  A default build trusts no image
# at all -- cis/cis_keys.h ships zero provisioned anchors -- so an unsigned
# owinit is refused and the machine stops at the boot gate.  That is the
# correct state for a build whose owinit was signed by a key nobody holds.
#
# Turning this ON builds with cis/cis_keys_dev.h (one public, checked-in,
# documented test key) and signs the userspace images with it, so a developer can
# boot.  It is a development affordance and nothing else: the seed is public, so
# the anchor proves nothing about who produced an image, and a release must be
# built with this OFF and signed by a key held outside this repository.
#
# The Makefile equivalent is `make CIS_DEV_TRUST=1`.  Both must exist, because a
# security control that one build system honours and the other silently drops is
# not a control -- it is a build-system inconsistency that happens to be
# convenient.
option(CIS_DEV_TRUST
    "Trust and sign with the public development CIS anchor (never for release)"
    OFF)

if(CIS_DEV_TRUST)
    set(CIS_DEV_TRUST_DEFS CIS_DEV_TRUST)
    # Two spellings of the same switch, because the two consumers are different
    # programs: tools/owx_pack.py takes --sign-dev, while tools/embed_owx.py
    # forwards to the packer and only accepts --pack-arg=<arg>.  Passing the bare
    # switch to embed_owx.py fails with "unrecognized arguments", which is the
    # failure this comment exists to prevent someone rediscovering.
    set(CIS_DEV_TRUST_PACKER_ARGS --sign-dev)
    set(CIS_DEV_TRUST_EMBED_ARGS --pack-arg=--sign-dev)
    message(WARNING
        "CIS_DEV_TRUST is ON: images will be signed with a PUBLIC test key from "
        "this repository. This configuration must never produce a release.")
else()
    set(CIS_DEV_TRUST_DEFS "")
    set(CIS_DEV_TRUST_PACKER_ARGS "")
    set(CIS_DEV_TRUST_EMBED_ARGS "")
endif()

# Generated into the CMake BINARY tree, not the source tree.
#
# boot/owinit_image.h is a signed-or-not image, and the Makefile writes that same
# path.  When both build systems wrote there, a CMake build configured without
# CIS_DEV_TRUST picked up the owinit a previous `make CIS_DEV_TRUST=1` had
# signed, and the suite reported UNKNOWN-KEY where it meant UNSIGNED -- observed,
# not feared.  Each build system owning its own generated file removes the
# sharing entirely, which is more reliable than trying to make two systems
# invalidate each other's output correctly.
#
# tools/hosttest/host_boot.c therefore includes this as "owinit_image.h" and
# finds it on the include path: boot/ under the Makefile, this directory under
# CMake.
set(OWINIT_GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY ${OWINIT_GENERATED_DIR})
set(OWINIT_HEADER "${OWINIT_GENERATED_DIR}/owinit_image.h")
# Defaults to a neighboring checkout; override OWINIT_SOURCE for other layouts.
set(OWINIT_SOURCE
    "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Essentials/Artifacts/Software/owinit.owx"
    CACHE FILEPATH "Path to the OpenWindows-Essentials owinit.owx image")

add_custom_command(
    OUTPUT ${OWINIT_HEADER}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owx.py
        ${OWINIT_SOURCE} ${OWINIT_HEADER} --packer ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
        --subsystem 0x04
        --symbol g_owinit_image
        --size-macro OWINIT_IMAGE_SIZE
        --guard OWINIT_IMAGE_GENERATED_H
        --note "Generated from OpenWindows-Essentials/Software/owinit/owinit.c."
        ${CIS_DEV_TRUST_EMBED_ARGS}
    DEPENDS ${OWINIT_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owx.py
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/cis_block.py
    COMMENT "Packaging OpenWindows-Essentials owinit.owx for kernel tests"
)
add_custom_target(owinit_image DEPENDS ${OWINIT_HEADER})

# Ecosystem root directories
set(SUTF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../superunicode/sutf")
set(SUST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../superunicode/sust")
set(EXTSU_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../superunicode/superunicode_extended")
set(SUAS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../superunicode")
set(ESSENTIALS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Essentials")
set(SUF_DIR "${ESSENTIALS_DIR}/vendor/superunicode/suf")
set(OW_TERMINAL_FONT "${CMAKE_CURRENT_SOURCE_DIR}/assets/openwindows-terminal.suf")
set(OW_TERMINAL_FONT_HEADER "${OWINIT_GENERATED_DIR}/ow_terminal_font.h")
add_custom_command(
    OUTPUT ${OW_TERMINAL_FONT_HEADER}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_suf.py
            ${OW_TERMINAL_FONT} ${OW_TERMINAL_FONT_HEADER}
    DEPENDS ${OW_TERMINAL_FONT}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_suf.py
    COMMENT "Embedding OpenWindows terminal SUF font"
)
add_custom_target(ow_terminal_font DEPENDS ${OW_TERMINAL_FONT_HEADER})

# The OpenWindows kernel and hosted harness consume the complete SuperUnicode
# reference surface, not only the ten OS integration adapters. These source
# lists mirror the authoritative SuperUnicode targets so every SUAS, SUTS, and
# implemented SUTR algorithm is compiled into the OS build.
set(SUAS_REFERENCE_SOURCES
    ${SUAS_DIR}/src/suas/suas_sdf.c
    ${SUAS_DIR}/src/suas/suas_sgw.c
    ${SUAS_DIR}/src/suas/suas_sbr.c
    ${SUAS_DIR}/src/suas/suas_sucf.c
    ${SUAS_DIR}/src/suas/suas_ssp.c
    ${SUAS_DIR}/src/suas/suas_sts.c
    ${SUAS_DIR}/src/suas/suas_sis.c
    ${SUAS_DIR}/src/suas/suas_sncs.c
    ${SUAS_DIR}/src/suas/suas_sip.c
    ${SUAS_DIR}/src/suas/suas_ssre.c
    ${SUAS_DIR}/src/suas/suas_scms.c
    ${SUAS_DIR}/src/suas/suas_sucd.c
    ${SUAS_DIR}/src/suas/suas_sisr.c
    ${SUAS_DIR}/src/suas/suas_suvtl.c
    ${SUAS_DIR}/src/suas/suas_suamr.c
    ${SUAS_DIR}/src/suas/suas_sukemet.c
    ${SUAS_DIR}/src/suas/suas_sueasd.c
    ${SUAS_DIR}/src/suas/suas_skto.c
    ${SUAS_DIR}/src/suas/suas_stim.c
    ${SUAS_DIR}/src/suas/suas_sucha.c
    ${SUAS_DIR}/src/suas/suas_stx.c
    ${SUAS_DIR}/src/suas/suas_sktc.c
    ${SUAS_DIR}/src/suas/suas_subsystems.c
    ${SUAS_DIR}/src/suas/suas_core.c
)

set(SUTS_REFERENCE_SOURCES
    ${SUAS_DIR}/src/suts/suts_suca.c
    ${SUAS_DIR}/src/suts/suts_sre.c
    ${SUAS_DIR}/src/suts/suts_sldf.c
    ${SUAS_DIR}/src/suts/suts_sivd.c
    ${SUAS_DIR}/src/suts/suts_scss.c
    ${SUAS_DIR}/src/suts/suts_sidn.c
    ${SUAS_DIR}/src/suts/suts_sueps.c
    ${SUAS_DIR}/src/suts/suts_susch.c
    ${SUAS_DIR}/src/suts/suts_suldf.c
    ${SUAS_DIR}/src/suts/suts_susn.c
    ${SUAS_DIR}/src/suts/suts_scts.c
    ${SUAS_DIR}/src/suts/suts_scte.c
    ${SUAS_DIR}/src/suts/suts_suicl.c
    ${SUAS_DIR}/src/suts/suts_sulp.c
    ${SUAS_DIR}/src/suts/suts_strs.c
    ${SUAS_DIR}/src/suts/suts_module.c
)

set(SUTR_REFERENCE_SOURCES
    ${SUAS_DIR}/src/sutr/sutr_sucsl.c
    ${SUAS_DIR}/src/sutr/sutr_sueas.c
    ${SUAS_DIR}/src/sutr/sutr_sums.c
    ${SUAS_DIR}/src/sutr/sutr_sucem.c
    ${SUAS_DIR}/src/sutr/sutr_sucpm.c
    ${SUAS_DIR}/src/sutr/sutr_sumnls.c
    ${SUAS_DIR}/src/sutr/sutr_sucm.c
    ${SUAS_DIR}/src/sutr/sutr_oktp.c
    ${SUAS_DIR}/src/sutr/sutr_sie.c
    ${SUAS_DIR}/src/sutr/sutr_sfs.c
    ${SUAS_DIR}/src/sutr/sutr_sim.c
    ${SUAS_DIR}/src/sutr/sutr_skc.c
)
set(SUTF_REFERENCE_SOURCES
    ${SUTF_DIR}/src/sutf8.c
    ${SUTF_DIR}/src/sutf16.c
    ${SUTF_DIR}/src/sutf4.c
    ${SUTF_DIR}/src/sutf2.c
    ${SUTF_DIR}/src/sucs_mode.c
)
set(SUST_REFERENCE_SOURCES
    ${SUST_DIR}/src/sust16.c
    ${SUST_DIR}/src/sustfixed.c
    ${SUST_DIR}/src/esust.c
)
set(VIP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../vip")
set(STORAGE_COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Storage/common")
set(OWFS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Storage/owfs")
set(USFS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Storage/usfs")

# Build the reusable SuperUnicode reference libraries once for hosted
# integration tests.  The kernel keeps its existing freestanding source-level
# integration; hosted consumers use the complete reference library targets.
add_subdirectory(${SUAS_DIR} superunicode_reference EXCLUDE_FROM_ALL)

# Include directories common to all targets
set(OW_INCLUDE_DIRS
    ${OWINIT_GENERATED_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/boot
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/bancode
    ${CMAKE_CURRENT_SOURCE_DIR}/bancode
    ${SUTF_DIR}/include
    ${SUST_DIR}/include
    ${EXTSU_DIR}/include
    ${SUF_DIR}/include
    ${SUAS_DIR}/include
    ${ESSENTIALS_DIR}/Software/kconfctl
    ${ESSENTIALS_DIR}/Software/banhammer
    ${ESSENTIALS_DIR}/DLL/kconf64
    ${ESSENTIALS_DIR}/Extensions
    ${VIP_DIR}
    ${STORAGE_COMMON_DIR}/include
    ${OWFS_DIR}/include
    ${USFS_DIR}/include
)

# Common kernel sources (shared by PE kernel and host test harness)
set(KERNEL_COMMON_SOURCES
    core/main.c
    core/object.c
    core/memory.c
    # Page-fault dispatch.  hal/idt.c calls OwPfDispatch from its common
    # interrupt handler, so every target that links hal/idt.c needs this, and
    # the host harness needs it because it exercises the same handler.
    core/pgfault.c
    core/alpc.c
    core/runlevel.c
    rc/rc.c
    hal/acpi.c
    diag/bancode_krnl.c
    vfs/vfs.c
    net/router.c
    net/vip.c
    sentinel/damagecntrl.c
    sentinel/fltrmgr.c
    cis/cis_core.c
    cis/cis_format.c
    cis/cis_verify.c
    dpc/ow_dpc.c
    sync/ow_sync.c
    syscall/dispatcher.c
    kapi/kernel64.c
    # SKTO name admission for the syscall gateway (SUAS-018).  The adapter is
    # kernel-side and freestanding; the SUAS implementation is shared with the
    # host harness so both exercise exactly the same admission code.
    kapi/ow_skto_name.c
    ${SUAS_REFERENCE_SOURCES}
    ${SUTS_REFERENCE_SOURCES}
    ${SUTR_REFERENCE_SOURCES}
    ${SUTF_REFERENCE_SOURCES}
    ${SUST_REFERENCE_SOURCES}
    shell/shell.c
    ps/ps.c
    ps/switch.S
    ps/owx_loader.c
    kdb/kdb_core.c
    kdb/kdb_registry.c
    kdb/kdb_loader.c
    kdb/kdb_manager.c
    kdb/kdb_assoc.c
    kdb/kdb_bridge.c
    kdb/kdb_sweep.c
    kdb/kdb_exec.c
    usermode/usermode.c
    lib/ow_htl.c
    lib/kmem.c
    lib/kstring.c
    lib/kprintf.c
    lib/kalloc.c
    lib/sucs.c
    lib/ow_superunicode.c
    ${ESSENTIALS_DIR}/DLL/kconf64/kconf64.c
    ${SUF_DIR}/src/suf_parser.c
    lib/ow_sha256.c
    lib/ow_sha512.c
    lib/ow_ed25519.c
    storage/owdisk.c
    bancode/bancode.c
    bancode/bancode_trap.c
    ${VIP_DIR}/univip_fvip.c
    ${STORAGE_COMMON_DIR}/src/ow_checksum.c
    ${STORAGE_COMMON_DIR}/src/ow_string.c
    ${STORAGE_COMMON_DIR}/src/ow_sec.c
    ${STORAGE_COMMON_DIR}/src/ow_crypto.c
    ${OWFS_DIR}/src/owfs_bitmap.c
    ${OWFS_DIR}/src/owfs_blockio.c
    ${OWFS_DIR}/src/owfs_blockmap.c
    ${OWFS_DIR}/src/owfs_catalog.c
    ${OWFS_DIR}/src/owfs_file.c
    ${OWFS_DIR}/src/owfs_format.c
    ${OWFS_DIR}/src/owfs_inode.c
    ${OWFS_DIR}/src/owfs_superblock.c
    ${OWFS_DIR}/src/owfs_sync.c
    ${USFS_DIR}/src/usfs_bitmap.c
    ${USFS_DIR}/src/usfs_blockio.c
    ${USFS_DIR}/src/usfs_entry.c
    ${USFS_DIR}/src/usfs_file.c
    ${USFS_DIR}/src/usfs_format.c
    ${USFS_DIR}/src/usfs_superblock.c
    ${USFS_DIR}/src/usfs_sync.c
)

# ==============================================================================
# Emergency recovery images (owinitv.owx, owrs.owx)
# ==============================================================================
# These two are built HERE, from emergency/, and deliberately not taken from
# another repository the way owinit.owx is.  The recovery path cannot depend on
# a second repository being present in order to produce the thing you boot when
# the first repository's output is missing -- that is the whole point of a
# fallback orchestrator.
#
# The three userspace images come out of different pipelines on purpose:
#   owinit.owx   ships from OpenWindows-Essentials as a PE wearing an .owx
#                name, so tools/embed_owx.py packs it above.
#   owinitv.owx  compiled and packed here.
#   owrs.owx     compiled and packed here.
#
# Packing stays a visible step (rather than hidden behind --packer as owinit
# does) so that a failed import check names the image that failed instead of
# surfacing as "header not regenerated".  Subsystem 0x05 is
# OWX_SUBSYSTEM_RECOVERY and is the only thing that distinguishes these two at
# the format level: nothing in the kernel switches on it.  The survey treats all
# three images identically, and the byte is what tells a human reading a volume
# which file is the fallback rather than the orchestrator.

set(EMERGENCY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/emergency")
set(EMERGENCY_IMAGES owinitv owrs)

add_custom_target(emergency_owx)

# ow_emergency_image(<name> <entry-symbol> <size-macro> <guard> <symbol> <note>)
#
# Expressed as a function rather than repeated per image: unlike Make, CMake can
# uppercase a stem with string(TOUPPER ...), so the generated header symbols do
# not have to be spelled out by hand at each use site.  Getting one of those
# wrong is the worst kind of error here -- the bad name compiles fine and then
# fails at the include site, far away from the rule that produced it.
function(ow_emergency_image NAME ENTRY SYMBOL SIZE_MACRO GUARD NOTE)
    set(_src "${EMERGENCY_DIR}/${NAME}.c")
    set(_pe_target "${NAME}_pe")
    set(_pe "${CMAKE_CURRENT_BINARY_DIR}/emergency/${NAME}.pe")
    set(_owx "${EMERGENCY_DIR}/${NAME}.owx")
    set(_hdr "${EMERGENCY_DIR}/${NAME}_image.h")

    # The PE is a genuine intermediate, not a checked-in artifact: owx_pack.py
    # deletes the PE it consumed (the kernel's own image goes the same way, and
    # for the same reason -- a stale PE next to a fresh .owx is a trap).  The
    # .owx rule therefore depends on the *target*, never on the .pe file, or it
    # would rebuild the image on every single invocation.
    add_executable(${_pe_target} "${_src}")
    set_target_properties(${_pe_target} PROPERTIES
        OUTPUT_NAME "${NAME}.pe"
        SUFFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/emergency"
    )
    target_include_directories(${_pe_target} PRIVATE ${EMERGENCY_DIR})
    target_compile_options(${_pe_target} PRIVATE
        -std=c99 -ffreestanding -nostdlib -fno-stack-protector
        -fno-pie -fno-builtin -fno-asynchronous-unwind-tables
        -O2 -Wall -Wextra -Werror -g
    )
    target_link_options(${_pe_target} PRIVATE
        -nostdlib
        -Wl,-e,${ENTRY}
    )
    target_link_libraries(${_pe_target} PRIVATE gcc)

    add_custom_command(
        OUTPUT ${_owx}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
                $<TARGET_FILE:${_pe_target}> ${_owx} --subsystem 0x05
                ${CIS_DEV_TRUST_PACKER_ARGS}
        DEPENDS ${_pe_target} ${_src} "${EMERGENCY_DIR}/ow_gate.h"
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/cis_block.py
        COMMENT "Packing emergency ${NAME}.owx (OWX1 native, subsystem 0x05 recovery)..."
        VERBATIM
    )

    add_custom_command(
        OUTPUT ${_hdr}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owx.py
                ${_owx} ${_hdr} --no-pack
                --symbol ${SYMBOL}
                --size-macro ${SIZE_MACRO}
                --guard ${GUARD}
                --note "${NOTE}"
        DEPENDS ${_owx} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owx.py
        COMMENT "Embedding ${NAME}.owx into ${NAME}_image.h..."
        VERBATIM
    )

    add_custom_target(${NAME}_image DEPENDS ${_hdr})
    add_dependencies(emergency_owx ${NAME}_image)
endfunction()

ow_emergency_image(owinitv owinitv_main g_owinitv_image OWINITV_IMAGE_SIZE
    OWINITV_IMAGE_GENERATED_H "Generated from emergency/owinitv.c by tools/owx_pack.py.")
ow_emergency_image(owrs owrs_main g_owrs_image OWRS_IMAGE_SIZE
    OWRS_IMAGE_GENERATED_H "Generated from emergency/owrs.c by tools/owx_pack.py.")

# ==============================================================================
# Per-image seed objects
# ==============================================================================
# Each image is provisioned into the freshly formatted RAM volume by its own seed
# object, so the SET of images on a test volume is chosen by the link line and
# readable straight off that target's recipe.  The production images
# (openwinkrnl.owx / openwinkrnl.vdi) link none of them.
#
# openwinkrnl.chk is the sentinel's kernel-checksum fixture.  It is not a
# userspace image, so it is not part of the per-image set, but every seeded test
# image needs it: the kernel-integrity phase (Phase 5c.2, before the init
# hand-off) halts with a fatal integrity code when it is absent, so an image
# that omits this looks like a kernel-integrity failure rather than a missing
# fixture.
#
# This mirrors the Makefile's SEED_OBJS and is deliberately NOT in the default
# build: there is no test-image link line in the CMake tree to pull it in, and
# adding it to `all` would change what a default configure builds for no
# benefit.  The `ow_seeds` target exists so it can still be built and checked on
# demand -- which is worth having, because a seed object that no longer compiles
# against the emergency headers is otherwise only discovered by `make qemu`.
add_library(ow_seed_objs OBJECT
    boot/owinit_seed.c
    boot/owinitv_seed.c
    boot/owrs_seed.c
    boot/owchk_seed.c
)
add_dependencies(ow_seed_objs owinit_image owinitv_image owrs_image)
target_include_directories(ow_seed_objs PRIVATE ${OW_INCLUDE_DIRS})
target_compile_options(ow_seed_objs PRIVATE
    -std=c99 -ffreestanding -nostdlib -fno-stack-protector
    -fno-pie -Wall -Wextra -Werror -g
)
add_custom_target(ow_seeds DEPENDS ow_seed_objs)

# ==============================================================================
# Freestanding Kernel (openwinkrnl.pe -> openwinkrnl.owx)
# ==============================================================================
set(KERNEL_BAREMETAL_SOURCES
    ${KERNEL_COMMON_SOURCES}
    hal/htl.c
    hal/kbd.c
    hal/interrupts.S
    hal/idt.c
)

add_executable(openwinkrnl_pe ${KERNEL_BAREMETAL_SOURCES})
add_dependencies(openwinkrnl_pe ow_terminal_font)
set_target_properties(openwinkrnl_pe PROPERTIES
    OUTPUT_NAME "openwinkrnl.pe"
    SUFFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
target_include_directories(openwinkrnl_pe PRIVATE ${OW_INCLUDE_DIRS})
target_compile_definitions(openwinkrnl_pe PRIVATE ${CIS_DEV_TRUST_DEFS})
target_compile_options(openwinkrnl_pe PRIVATE
    -std=c99 -ffreestanding -nostdlib -fno-stack-protector -fno-pie
    -Wall -Wextra -Werror -g
)
target_link_options(openwinkrnl_pe PRIVATE
    -nostdlib
    -Wl,--image-base=0x200000
    # Without an explicit entry, lld/ld defaults the PE AddressOfEntryPoint to
    # the first byte of .text, which is not _start: OWX1 records that field as
    # the image entry point, so every loader would jump into an arbitrary
    # function and the kernel would die silently before its first log line.
    -Wl,-e,_start
)
target_link_libraries(openwinkrnl_pe PRIVATE gcc)

# Custom target: openwinkrnl.owx & openwinkrnl.chk
#
# When CIS_DEV_TRUST is on, the kernel image carries CORE_KERNEL policy class,
# a GPL-3.0-or-later licence, and the SHA-256 of the canonical source manifest.
# The manifest is generated into the CMake binary tree so it cannot collide with
# the Makefile's copy.  Without CIS_DEV_TRUST the image is unsigned anyway, so
# the policy args are omitted.
set(OWX_TARGET "${CMAKE_CURRENT_BINARY_DIR}/openwinkrnl.owx")
set(CHK_TARGET "${CMAKE_CURRENT_BINARY_DIR}/openwinkrnl.chk")
set(MANIFEST_FILE "${CMAKE_CURRENT_BINARY_DIR}/openwinkrnl_manifest.cislm")
set(MANIFEST_DIGEST "${CMAKE_CURRENT_BINARY_DIR}/openwinkrnl_manifest.digest")

if(CIS_DEV_TRUST)
    add_custom_command(
        OUTPUT ${MANIFEST_FILE} ${MANIFEST_DIGEST}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_license_manifest.py
                --repo-root ${CMAKE_CURRENT_SOURCE_DIR}
                --output ${MANIFEST_FILE}
                --digest-out ${MANIFEST_DIGEST}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen_license_manifest.py
        COMMENT "Generating canonical license manifest for CORE_KERNEL policy..."
        VERBATIM
    )
    add_custom_target(license_manifest DEPENDS ${MANIFEST_FILE} ${MANIFEST_DIGEST})

    add_custom_command(
        OUTPUT ${OWX_TARGET} ${CHK_TARGET}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
                $<TARGET_FILE:openwinkrnl_pe> ${OWX_TARGET} --subsystem 0x01
                --policy-class CORE_KERNEL
                --cis-licence GPL-3.0-or-later
                --source-digest ${MANIFEST_DIGEST}
                --sign-dev
        DEPENDS openwinkrnl_pe license_manifest
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/cis_block.py
        COMMENT "Packaging OpenWindows kernel (OWX1 native, CORE_KERNEL policy) & generating openwinkrnl.chk..."
    )
else()
    add_custom_command(
        OUTPUT ${OWX_TARGET} ${CHK_TARGET}
        COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
                $<TARGET_FILE:openwinkrnl_pe> ${OWX_TARGET} --subsystem 0x01
        DEPENDS openwinkrnl_pe ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
        COMMENT "Packaging OpenWindows kernel image (OWX1 native) & generating openwinkrnl.chk..."
    )
endif()
add_custom_target(openwinkrnl_owx ALL DEPENDS ${OWX_TARGET} ${CHK_TARGET})

# Copy openwinkrnl.owx and openwinkrnl.chk to source tree root for convenient runtime access
add_custom_command(
    TARGET openwinkrnl_owx POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${OWX_TARGET}
            ${CMAKE_CURRENT_SOURCE_DIR}/openwinkrnl.owx
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CHK_TARGET}
            ${CMAKE_CURRENT_SOURCE_DIR}/openwinkrnl.chk
    COMMENT "Copying openwinkrnl.owx and openwinkrnl.chk to source root"
)

# ==============================================================================
# Host Boot Harness & Integration Test (hosttest)
# ==============================================================================
set(HOSTTEST_SOURCES
    tools/hosttest/host_hal.c
    tools/hosttest/host_boot.c
    # Verifier tests.  host_boot.c calls test_cis_verify_run(), so this is a link
    # requirement, not an optional extra -- without it the harness does not build.
    tools/hosttest/host_cis_verify.c
    tools/hosttest/host_cis_loader.c
    tools/hosttest/host_skto_name.c
    tools/hosttest/host_superunicode.c
    ${KERNEL_COMMON_SOURCES}
    ${OWINIT_HEADER}
    # The harness audits and mounts all three userspace images, so the emergency
    # headers are real inputs, not optional extras: it cannot build without them
    # and CMake will not know to produce them unless they are listed as sources.
    ${EMERGENCY_DIR}/owinitv_image.h
    ${EMERGENCY_DIR}/owrs_image.h
)

add_executable(hosttest ${HOSTTEST_SOURCES})
add_dependencies(hosttest ow_terminal_font)
add_dependencies(hosttest owinit_image owinitv_image owrs_image)
target_include_directories(hosttest PRIVATE ${OW_INCLUDE_DIRS})
target_link_libraries(hosttest PRIVATE suas_static suts_static sutr_static)
target_compile_definitions(hosttest PRIVATE ${CIS_DEV_TRUST_DEFS})
target_compile_options(hosttest PRIVATE
    -std=c99 -Wall -Wextra -Werror -fno-pie -g -DOW_HOST_HAL
)
target_link_options(hosttest PRIVATE -mconsole)

enable_testing()
add_test(NAME hosttest COMMAND hosttest)

# ==============================================================================
# Hosted SUF renderer end-to-end check (sufrender_host)
# ==============================================================================
# This target deliberately loads the binary asset from disk and uses the
# production sufrender library, so it proves the shipped .suf file is valid and
# rasterises -- separate from hosttest, which proves the kernel-embedded copy
# (generated ow_terminal_font.h) is what the OS queries at runtime.
add_executable(sufrender_host
    tools/sufrender_host.c
    ${ESSENTIALS_DIR}/DLL/sufrender/sufrender.c
    ${SUF_DIR}/src/suf_parser.c
)
target_include_directories(sufrender_host PRIVATE
    ${OW_INCLUDE_DIRS}
    ${ESSENTIALS_DIR}/DLL/sufrender
)
target_compile_definitions(sufrender_host PRIVATE
    OW_SUFRENDER_ASSET="${OW_TERMINAL_FONT}"
    OW_SUFRENDER_PPM="${CMAKE_CURRENT_BINARY_DIR}/sufrender.ppm"
)
target_compile_options(sufrender_host PRIVATE
    -std=c99 -Wall -Wextra -Werror -fno-pie -g
)
target_link_options(sufrender_host PRIVATE -mconsole)
add_test(NAME sufrender_host COMMAND sufrender_host)

# ==============================================================================
# Cross-implementation crypto cross-check
# ==============================================================================
# hosttest proves the C implementation matches tools/hosttest/crypto_vectors.h,
# which tools/cis_sign.py generated.  That generator is itself only trustworthy
# if the Python model is right, so the model gets its own test: it re-derives the
# field and group arithmetic and checks itself against Python's own bignums.
#
# A C binary cannot substitute for this, because the point of the Python model is
# that it is an independent derivation.  Running it from C would compare the C
# against itself.  So it is a separate test that invokes the reference model, and
# it is registered with CTest so `ctest` still covers it -- which is the point of
# putting it here rather than leaving it as a manual script.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME crypto_reference_model
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tools/cis_sign.py selftest)
    # The field sweep is 4800 cases through the Python model; it belongs to
    # tools/fieldref.py, which is where the operand pairs live.
    add_test(NAME crypto_field_reference
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_CURRENT_SOURCE_DIR}/tools/fieldref.py)
    set_tests_properties(crypto_reference_model crypto_field_reference
                         PROPERTIES TIMEOUT 900)
else()
    message(WARNING
        "Python3 not found: the cross-implementation crypto checks "
        "(crypto_reference_model, crypto_field_reference) will not run under "
        "ctest.  hosttest still runs, but it would then be the only crypto "
        "coverage.")
endif()
