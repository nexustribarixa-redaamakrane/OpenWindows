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
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owinit.py
        ${OWINIT_SOURCE} ${OWINIT_HEADER} --packer ${CMAKE_CURRENT_SOURCE_DIR}/tools/owx_pack.py
    DEPENDS ${OWINIT_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/embed_owinit.py
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
)

add_executable(hosttest ${HOSTTEST_SOURCES})
add_dependencies(hosttest owinit_image)
target_include_directories(hosttest PRIVATE ${OW_INCLUDE_DIRS})
target_compile_options(hosttest PRIVATE
    -std=c99 -Wall -Wextra -Werror -fno-pie -g -DOW_HOST_HAL
)
target_link_options(hosttest PRIVATE -mconsole)

enable_testing()
add_test(NAME hosttest COMMAND hosttest)
