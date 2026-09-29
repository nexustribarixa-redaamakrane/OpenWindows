cmake_minimum_required(VERSION 3.20)
project(openwinkrnl C ASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Python3 COMPONENTS Interpreter REQUIRED)

set(OWINIT_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Essentials/Artifacts/Software/owinit.owx")
set(OWINIT_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/boot/owinit_image.h")
add_custom_command(
    OUTPUT ${OWINIT_HEADER}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owx.py
        ${OWINIT_SOURCE} ${OWINIT_HEADER} --packer ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
        --subsystem 0x04
        --symbol g_owinit_image
        --size-macro OWINIT_IMAGE_SIZE
        --guard OWINIT_IMAGE_GENERATED_H
        --note "Generated from OpenWindows-Essentials/Software/owinit/owinit.c."
    DEPENDS ${OWINIT_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owx.py
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
    COMMENT "Packaging OpenWindows-Essentials owinit.owx for kernel tests"
)
add_custom_target(owinit_image DEPENDS ${OWINIT_HEADER})

# Ecosystem root directories
set(SUTF_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../superunicode/sutf")
set(VIP_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../vip")
set(STORAGE_COMMON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Storage/common")
set(OWFS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Storage/owfs")
set(USFS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../OpenWindows-Storage/usfs")

# Include directories common to all targets
set(OW_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/inc
    ${CMAKE_CURRENT_SOURCE_DIR}/inc/bancode
    ${CMAKE_CURRENT_SOURCE_DIR}/bancode
    ${SUTF_DIR}/include
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
    dpc/ow_dpc.c
    sync/ow_sync.c
    syscall/dispatcher.c
    kapi/kernel64.c
    shell/shell.c
    ps/ps.c
    ps/switch.S
    ps/owx_loader.c
    usermode/usermode.c
    lib/ow_htl.c
    lib/kmem.c
    lib/kstring.c
    lib/kprintf.c
    lib/kalloc.c
    lib/sucs.c
    lib/ow_sha256.c
    storage/owdisk.c
    bancode/bancode.c
    bancode/bancode_trap.c
    ${SUTF_DIR}/src/sutf8.c
    ${SUTF_DIR}/src/sucs_mode.c
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
        DEPENDS ${_pe_target} ${_src} "${EMERGENCY_DIR}/ow_gate.h"
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
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
# image needs it: Phase 5d halts with a fatal integrity code when it is absent,
# and that halt lands AFTER the init is entered, so an image that omits this
# looks like a kernel-integrity failure rather than a missing fixture.
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
set_target_properties(openwinkrnl_pe PROPERTIES
    OUTPUT_NAME "openwinkrnl.pe"
    SUFFIX ""
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
)
target_include_directories(openwinkrnl_pe PRIVATE ${OW_INCLUDE_DIRS})
target_compile_options(openwinkrnl_pe PRIVATE
    -std=c99 -ffreestanding -nostdlib -fno-stack-protector -fno-pie
    -Wall -Wextra -Werror -g
)
target_link_options(openwinkrnl_pe PRIVATE
    -nostdlib
    -Wl,--image-base=0x200000
)
target_link_libraries(openwinkrnl_pe PRIVATE gcc)

# Custom target: openwinkrnl.owx & openwinkrnl.chk
set(OWX_TARGET "${CMAKE_CURRENT_BINARY_DIR}/openwinkrnl.owx")
set(CHK_TARGET "${CMAKE_CURRENT_BINARY_DIR}/openwinkrnl.chk")
add_custom_command(
    OUTPUT ${OWX_TARGET} ${CHK_TARGET}
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
            $<TARGET_FILE:openwinkrnl_pe> ${OWX_TARGET} --subsystem 0x01
    DEPENDS openwinkrnl_pe ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
    COMMENT "Packaging OpenWindows kernel image (OWX1 native) & generating openwinkrnl.chk..."
)
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
    ${KERNEL_COMMON_SOURCES}
    ${OWINIT_HEADER}
    # The harness audits and mounts all three userspace images, so the emergency
    # headers are real inputs, not optional extras: it cannot build without them
    # and CMake will not know to produce them unless they are listed as sources.
    ${EMERGENCY_DIR}/owinitv_image.h
    ${EMERGENCY_DIR}/owrs_image.h
)

add_executable(hosttest ${HOSTTEST_SOURCES})
add_dependencies(hosttest owinit_image owinitv_image owrs_image)
target_include_directories(hosttest PRIVATE ${OW_INCLUDE_DIRS})
target_compile_options(hosttest PRIVATE
    -std=c99 -Wall -Wextra -Werror -fno-pie -g -DOW_HOST_HAL
)
target_link_options(hosttest PRIVATE -mconsole)

enable_testing()
add_test(NAME hosttest COMMAND hosttest)
