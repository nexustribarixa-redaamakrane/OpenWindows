# ==============================================================================
# Makefile for OpenWindows - Freestanding C99 Kernel
# Non-POSIX | NT-Like | Everything is an Object
# Produces openwinkrnl.owx (OWX1 native kernel image)
# ==============================================================================

CC = gcc
CFLAGS = -std=c99 -ffreestanding -nostdlib -fno-stack-protector -fno-pie \
         -Wall -Wextra -Werror \
         -I./inc -I./inc/bancode \
         -I../superunicode/sutf/include -I../vip \
         -I../OpenWindows-Storage/common/include \
         -I../OpenWindows-Storage/owfs/include \
         -I../OpenWindows-Storage/usfs/include -g

# Ecosystem source directories
BANCODE_DIR = ./bancode
SUTF_DIR    = ../superunicode/sutf
VIP_DIR     = ../vip
STORAGE_COMMON_DIR = ../OpenWindows-Storage/common
OWFS_DIR    = ../OpenWindows-Storage/owfs
USFS_DIR    = ../OpenWindows-Storage/usfs

# Object files - Kernel Core
CORE_OBJS = core/main.o \
            core/object.o \
            core/memory.o \
            core/alpc.o \
            core/runlevel.o

# Object files - HAL & Diagnostics
HAL_OBJS  = hal/htl.o \
            hal/kbd.o \
            hal/interrupts.o \
            hal/idt.o \
            hal/acpi.o
DIAG_OBJS = diag/bancode_krnl.o

# Object files - Runtime Control (rc.d)
RC_OBJS = rc/rc.o

# Object files - Process/Task subsystem (NT-like executive + scheduler)
PS_OBJS = ps/ps.o \
          ps/switch.o \
          ps/owx_loader.o

# Object files - Dispatcher objects (NT-like event/semaphore/timer sync)
SYNC_OBJS = sync/ow_sync.o

# Object files - Deferred procedure calls (NT-like DPC / work queue)
DPC_OBJS = dpc/ow_dpc.o

# Object files - User-mode (ring 3) launcher
USERMODE_OBJS = usermode/usermode.o

# Object files - Subsystems
VFS_OBJS     = vfs/vfs.o
NET_OBJS     = net/router.o \
               net/vip.o
SENT_OBJS    = sentinel/damagecntrl.o \
               sentinel/fltrmgr.o
SYSCALL_OBJS = syscall/dispatcher.o
KAPI_OBJS    = kapi/kernel64.o
SHELL_OBJS   = shell/shell.o

# Object files - Libraries
LIB_OBJS = lib/ow_htl.o \
           lib/kmem.o \
           lib/kstring.o \
           lib/kprintf.o \
           lib/kalloc.o \
           lib/sucs.o \
           lib/ow_sha256.o

# Object files - Ecosystem (BANcode)
BANCODE_OBJS = bancode/bancode.o \
               bancode/bancode_trap.o

# Object files - Ecosystem (superunicode SUTF)
SUC_OBJS = sucs/sutf8.o \
           sucs/sucs_mode.o

# Object files - Ecosystem (vip UniVIP/FVIP)
VIP_OBJS = vip/univip_fvip.o

# Object files - Ecosystem (OpenWindows-Storage common, sans ow_mem/ow_htl)
STOR_COMMON_OBJS = storage/ow_checksum.o \
                   storage/ow_string.o \
                   storage/ow_sec.o \
                   storage/ow_crypto.o

# Object files - Ecosystem (OWFS filesystem)
OWFS_OBJS = storage/owfs_bitmap.o \
            storage/owfs_blockio.o \
            storage/owfs_blockmap.o \
            storage/owfs_catalog.o \
            storage/owfs_file.o \
            storage/owfs_format.o \
            storage/owfs_inode.o \
            storage/owfs_superblock.o \
            storage/owfs_sync.o

# Object files - Ecosystem (USFS filesystem)
USFS_OBJS = storage/usfs_bitmap.o \
            storage/usfs_blockio.o \
            storage/usfs_entry.o \
            storage/usfs_file.o \
            storage/usfs_format.o \
            storage/usfs_superblock.o \
            storage/usfs_sync.o

# Object files - Kernel storage integration
STOR_CORE_OBJS = storage/owdisk.o

# All object files
ALL_OBJS = $(CORE_OBJS) $(HAL_OBJS) $(RC_OBJS) $(PS_OBJS) $(SYNC_OBJS) $(DPC_OBJS) \
           $(USERMODE_OBJS) \
           $(DIAG_OBJS) $(VFS_OBJS) \
           $(NET_OBJS) $(SENT_OBJS) $(SYSCALL_OBJS) $(KAPI_OBJS) \
           $(SHELL_OBJS) $(LIB_OBJS) $(BANCODE_OBJS) \
           $(SUC_OBJS) $(VIP_OBJS) \
           $(STOR_COMMON_OBJS) $(OWFS_OBJS) $(USFS_OBJS) $(STOR_CORE_OBJS)

# Intermediate image
PE_IMAGE   = openwinkrnl.pe

# Output OWX binary
TARGET = openwinkrnl.owx

# OWX packaging parameters
OWX_SUBSYSTEM = 0x01

# ==============================================================================
# Build Rules
# ==============================================================================

all: $(TARGET)

$(TARGET): $(PE_IMAGE)
	python tools/owx_pack.py $(PE_IMAGE) $(TARGET) \
	    --subsystem $(OWX_SUBSYSTEM)
	@echo "=============================================================================="
	@echo "  OpenWindows Kernel Build Completed Successfully!"
	@echo "  Target: $(TARGET) | Freestanding C99 | NT-Like Object Architecture"
	@echo "=============================================================================="

$(PE_IMAGE): $(ALL_OBJS)
	$(CC) $(CFLAGS) -Wl,--image-base=0x200000 -o $(PE_IMAGE) $(ALL_OBJS) -lgcc

# Core
core/%.o: core/%.c
	@mkdir -p core
	$(CC) $(CFLAGS) -c $< -o $@

# HAL
hal/%.o: hal/%.c
	@mkdir -p hal
	$(CC) $(CFLAGS) -c $< -o $@

# HAL assembly (hal/interrupts.S - long-mode ISR stubs; GNU as / GAS)
hal/%.o: hal/%.S
	@mkdir -p hal
	$(CC) $(CFLAGS) -c $< -o $@

# Diagnostics
diag/%.o: diag/%.c
	@mkdir -p diag
	$(CC) $(CFLAGS) -c $< -o $@

# VFS
vfs/%.o: vfs/%.c
	@mkdir -p vfs
	$(CC) $(CFLAGS) -c $< -o $@

# Network
net/%.o: net/%.c
	@mkdir -p net
	$(CC) $(CFLAGS) -c $< -o $@

# Sentinel
sentinel/%.o: sentinel/%.c
	@mkdir -p sentinel
	$(CC) $(CFLAGS) -c $< -o $@

# Syscall
syscall/%.o: syscall/%.c
	@mkdir -p syscall
	$(CC) $(CFLAGS) -c $< -o $@

# Kernel API
kapi/%.o: kapi/%.c
	@mkdir -p kapi
	$(CC) $(CFLAGS) -c $< -o $@

# Shell
shell/%.o: shell/%.c
	@mkdir -p shell
	$(CC) $(CFLAGS) -c $< -o $@

# Run Control (rc.d)
rc/%.o: rc/%.c
	@mkdir -p rc
	$(CC) $(CFLAGS) -c $< -o $@

# Process/Task subsystem
ps/%.o: ps/%.c
	@mkdir -p ps
	$(CC) $(CFLAGS) -c $< -o $@

# PS assembly (ps/switch.S - context-switch primitives; GNU as / GAS)
ps/%.o: ps/%.S
	@mkdir -p ps
	$(CC) $(CFLAGS) -c $< -o $@

# Dispatcher objects (sync/ow_sync.c)
sync/%.o: sync/%.c
	@mkdir -p sync
	$(CC) $(CFLAGS) -c $< -o $@

# Deferred procedure calls (dpc/ow_dpc.c)
dpc/%.o: dpc/%.c
	@mkdir -p dpc
	$(CC) $(CFLAGS) -c $< -o $@

# User-mode launcher (usermode/usermode.c)
usermode/%.o: usermode/%.c
	@mkdir -p usermode
	$(CC) $(CFLAGS) -c $< -o $@

# Libraries
lib/%.o: lib/%.c
	@mkdir -p lib
	$(CC) $(CFLAGS) -c $< -o $@

# BANcode ecosystem (compiled from local bancode directory)
bancode/%.o: $(BANCODE_DIR)/%.c
	@mkdir -p bancode
	$(CC) $(CFLAGS) -c $< -o $@

# superunicode SUTF ecosystem (compiled from sibling repo)
sucs/%.o: $(SUTF_DIR)/src/%.c
	@mkdir -p sucs
	$(CC) $(CFLAGS) -c $< -o $@

# vip UniVIP/FVIP ecosystem (compiled from sibling repo)
vip/%.o: $(VIP_DIR)/%.c
	@mkdir -p vip
	$(CC) $(CFLAGS) -c $< -o $@

# OpenWindows-Storage common (ow_mem.c/ow_htl.c provided by kernel lib)
storage/ow_%.o: $(STORAGE_COMMON_DIR)/src/ow_%.c
	@mkdir -p storage
	$(CC) $(CFLAGS) -c $< -o $@

# OWFS filesystem (compiled from sibling repo)
storage/owfs_%.o: $(OWFS_DIR)/src/owfs_%.c
	@mkdir -p storage
	$(CC) $(CFLAGS) -c $< -o $@

# USFS filesystem (compiled from sibling repo)
storage/usfs_%.o: $(USFS_DIR)/src/usfs_%.c
	@mkdir -p storage
	$(CC) $(CFLAGS) -c $< -o $@

# Kernel storage integration layer
storage/%.o: storage/%.c
	@mkdir -p storage
	$(CC) $(CFLAGS) -c $< -o $@

# Test-image owinit provisioner (linked into the QEMU/floppy test images only;
# production images openwinkrnl.owx / openwinkrnl.vdi stay without it)
OWINIT_SEED_OBJ = boot/owinit_seed.o
OWINIT_SOURCE = C:/Users/KARIMABENDA/Documents/OpenWindows-Essentials/Artifacts/Software/owinit.owx
OWINIT_IMAGE = boot/owinit_image.owx
OWINIT_HEADER = boot/owinit_image.h

$(OWINIT_HEADER): $(OWINIT_SOURCE) tools/owx_pack.py tools/embed_owinit.py
	python tools/embed_owinit.py $(OWINIT_SOURCE) $@ --packer tools/owx_pack.py

boot/owinit_seed.o: boot/owinit_seed.c storage/owdisk.h $(OWINIT_HEADER)
	@mkdir -p boot
	$(CC) $(CFLAGS) -c $< -o $@

# ==============================================================================
# Clean & Run
# ==============================================================================

clean:
	rm -f $(ALL_OBJS) $(PE_IMAGE) $(TARGET)
	rm -f $(OWINIT_SEED_OBJ)
	rm -f bancode/*.o
	rm -rf sucs/ vip/
	rm -f storage/*.o
	@echo "Clean completed."

vm: all
	@echo "Launching OpenWindows VMM/QEMU launcher..."
	pwsh -ExecutionPolicy Bypass -File ./run_vm.ps1

# ==============================================================================
# QEMU multiboot boot test: links the real kernel sources (boot/qboot.S +
# boot/qemu_entry.c + ALL_OBJS) into a flat a.out-kludge multiboot image at
# 0x100000, then boots it under QEMU and validates the ecosystem transcript.
# Output image is kept out of the repo tree (like hosttest).
# ==============================================================================
QEMU_DIR = $(subst \,/,$(or $(TMPDIR),$(TEMP),/tmp))/openwinkrnl_qemu
QEMU_BIN = $(QEMU_DIR)/openwinkrnl_qemu.bin

$(QEMU_DIR)/qboot.o: boot/qboot.S
	@mkdir -p $(QEMU_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(QEMU_DIR)/qemu_entry.o: boot/qemu_entry.c
	@mkdir -p $(QEMU_DIR)
	$(CC) -std=c99 -Wall -Wextra -Werror -fno-pie -g -c $< -o $@

$(QEMU_BIN): $(ALL_OBJS) $(OWINIT_SEED_OBJ) $(OWINIT_HEADER) $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/qemu.ld
	@mkdir -p $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/qemu.ld" "-Wl,-e,qboot_entry" \
	    -o $(QEMU_DIR)/qemu_image.exe \
	    $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o $(OWINIT_SEED_OBJ) $(ALL_OBJS) -lgcc
	objcopy -O binary $(QEMU_DIR)/qemu_image.exe $(QEMU_BIN)
	@echo "QEMU flat multiboot image (owinit test seed included): $(QEMU_BIN)"

qemu: $(QEMU_BIN)
	pwsh -ExecutionPolicy Bypass -File ./tools/qemu_run.ps1 $(QEMU_BIN)

# ==============================================================================
# VirtualBox floppy boot test: relinks the same flat kernel (boot/qboot.S +
# boot/qemu_entry.c + ALL_OBJS) at 0x10000 via boot/vbox.ld, packs stage1.S +
# the flat image into a 1.44MB floppy (tools/mkboot.py), and launches it in
# VirtualBox (or prints attach/validate instructions when VBoxManage is absent).
# All artifacts are kept out of the repo tree.
# ==============================================================================
VBOX_DIR = $(subst \,/,$(or $(TMPDIR),$(TEMP),/tmp))/openwinkrnl_vbox
VBOX_STAGE1 = $(VBOX_DIR)/stage1.bin
VBOX_KERNEL = $(VBOX_DIR)/openwinkrnl_vbox.bin
VBOX_FLOPPY = $(VBOX_DIR)/owx_boot.flp

$(VBOX_DIR)/stage1.bin: boot/stage1.S
	@mkdir -p $(VBOX_DIR)
	nasm -f bin -w-no-error=label-redef-late -w-label-redef-late boot/stage1.S -o $@

$(VBOX_KERNEL): $(ALL_OBJS) $(OWINIT_SEED_OBJ) $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/vbox.ld
	@mkdir -p $(VBOX_DIR) $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/vbox.ld" "-Wl,-e,qboot_entry" "-Wl,--image-base=0" \
	-o $(VBOX_DIR)/vbox_image.exe \
	$(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o $(OWINIT_SEED_OBJ) $(ALL_OBJS) -lgcc
	objcopy -O binary $(VBOX_DIR)/vbox_image.exe $(VBOX_KERNEL)
	@echo "VBox flat kernel (owinit test seed included): $@"

$(VBOX_FLOPPY): $(VBOX_KERNEL) $(VBOX_DIR)/stage1.bin tools/mkboot.py
	python tools/mkboot.py $(VBOX_DIR)/stage1.bin $(VBOX_KERNEL) $(VBOX_FLOPPY)

vbox-image: $(VBOX_FLOPPY)

vbox: $(VBOX_FLOPPY)
	pwsh -ExecutionPolicy Bypass -File ./tools/vbox_run.ps1 $(VBOX_FLOPPY)

# ==============================================================================
# VirtualBox hard-disk image: PRODUCTION kernel (no owinit test seed), packed
# behind the LBA disk boot sector (boot/stage1disk.S) into a raw image, then
# converted to a VDI with qemu-img so it can be attached to a VirtualBox VM.
# The "actual vdi" keeps the fatal Phase 5c owinit gate (validated by
# vdi_run.ps1); only the QEMU/floppy test images carry the seed.
# ==============================================================================
QEMU_IMG   = "C:/Program Files/qemu/qemu-img.exe"
VDI_BYTES  = 4194304

VBOX_STAGE1DISK = $(VBOX_DIR)/stage1disk.bin
VBOX_DISK_KERNEL = $(VBOX_DIR)/openwinkrnl_disk.bin
VBOX_DISK_RAW   = $(VBOX_DIR)/openwinkrnl_disk.img
VBOX_VDI        = $(VBOX_DIR)/openwinkrnl.vdi

$(VBOX_STAGE1DISK): boot/stage1disk.S
	@mkdir -p $(VBOX_DIR)
	nasm -f bin -w-no-error=label-redef-late -w-label-redef-late boot/stage1disk.S -o $@

$(VBOX_DISK_KERNEL): $(ALL_OBJS) $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/vbox.ld
	@mkdir -p $(VBOX_DIR) $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/vbox.ld" "-Wl,-e,qboot_entry" "-Wl,--image-base=0" \
	-o $(VBOX_DIR)/vbox_disk_image.exe \
	$(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o $(ALL_OBJS) -lgcc
	objcopy -O binary $(VBOX_DIR)/vbox_disk_image.exe $(VBOX_DISK_KERNEL)
	@echo "VBox disk kernel (production, no owinit seed): $@"

$(VBOX_DISK_RAW): $(VBOX_DISK_KERNEL) $(VBOX_STAGE1DISK) tools/mkboot.py
	@mkdir -p $(VBOX_DIR)
	python tools/mkboot.py $(VBOX_STAGE1DISK) $(VBOX_DISK_KERNEL) $(VBOX_DISK_RAW) $(VDI_BYTES)

$(VBOX_VDI): $(VBOX_DISK_RAW)
	@rm -f $@
	$(QEMU_IMG) convert -f raw -O vdi $< $@

vdi: $(VBOX_VDI)
	@echo "=============================================================================="
	@echo "  VirtualBox hard disk ready (attach to a VM as SATA/IDE):"
	@echo "  $@"
	@echo "=============================================================================="

vdi-test: $(VBOX_VDI)
	pwsh -ExecutionPolicy Bypass -File ./tools/vdi_run.ps1 $(VBOX_VDI)

# ==============================================================================
# Host boot harness: runs the real kernel boot + shell on the build host.
# (hal/htl.c is swapped for a stdio HAL; output exe is kept out of the tree.)
# ==============================================================================
HOSTTEST_OUT = $(or $(TMPDIR),$(TEMP),/tmp)/openwinkrnl_host.exe
HOSTTEST_SRC = tools/hosttest/host_hal.c \
               tools/hosttest/host_boot.c \
               core/main.c core/object.c core/memory.c core/alpc.c \
               core/runlevel.c \
               rc/rc.c hal/acpi.c \
               diag/bancode_krnl.c vfs/vfs.c net/router.c net/vip.c \
               sentinel/damagecntrl.c sentinel/fltrmgr.c \
               syscall/dispatcher.c kapi/kernel64.c shell/shell.c \
               lib/ow_htl.c lib/kmem.c lib/kstring.c lib/kprintf.c \
               lib/kalloc.c lib/sucs.c lib/ow_sha256.c storage/owdisk.c \
               ps/ps.c ps/switch.S ps/owx_loader.c sync/ow_sync.c dpc/ow_dpc.c \
               usermode/usermode.c \
               $(BANCODE_DIR)/bancode.c $(BANCODE_DIR)/bancode_trap.c \
               $(SUTF_DIR)/src/sutf8.c $(SUTF_DIR)/src/sucs_mode.c \
               $(VIP_DIR)/univip_fvip.c \
               $(STORAGE_COMMON_DIR)/src/ow_checksum.c \
               $(STORAGE_COMMON_DIR)/src/ow_sec.c \
               $(STORAGE_COMMON_DIR)/src/ow_crypto.c \
               $(STORAGE_COMMON_DIR)/src/ow_string.c \
               $(OWFS_DIR)/src/owfs_bitmap.c $(OWFS_DIR)/src/owfs_blockio.c \
               $(OWFS_DIR)/src/owfs_blockmap.c $(OWFS_DIR)/src/owfs_catalog.c \
               $(OWFS_DIR)/src/owfs_file.c $(OWFS_DIR)/src/owfs_format.c \
               $(OWFS_DIR)/src/owfs_inode.c $(OWFS_DIR)/src/owfs_superblock.c \
               $(OWFS_DIR)/src/owfs_sync.c \
               $(USFS_DIR)/src/usfs_bitmap.c $(USFS_DIR)/src/usfs_blockio.c \
               $(USFS_DIR)/src/usfs_entry.c $(USFS_DIR)/src/usfs_file.c \
               $(USFS_DIR)/src/usfs_format.c $(USFS_DIR)/src/usfs_superblock.c \
               $(USFS_DIR)/src/usfs_sync.c

HOSTTEST_FLAGS = -std=c99 -Wall -Wextra -Werror -fno-pie -g -DOW_HOST_HAL \
                 -I./inc -I./inc/bancode -I$(BANCODE_DIR) \
                 -I../superunicode/sutf/include -I../vip \
                 -I../OpenWindows-Storage/common/include \
                 -I../OpenWindows-Storage/owfs/include \
                 -I../OpenWindows-Storage/usfs/include

hosttest: $(OWINIT_HEADER)
	$(CC) $(HOSTTEST_FLAGS) $(HOSTTEST_SRC) -o $(HOSTTEST_OUT)
	$(HOSTTEST_OUT)

.PHONY: all clean vm hosttest qemu vbox vbox-image vdi vdi-test