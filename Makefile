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
            core/pgfault.o \
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
CIS_OBJS     = cis/cis_core.o cis/cis_format.o cis/cis_verify.o
SYSCALL_OBJS = syscall/dispatcher.o
KAPI_OBJS    = kapi/kernel64.o
SHELL_OBJS   = shell/shell.o

# Object files - Libraries
#
# ow_sha512 and ow_ed25519 are here because CIS verifies signatures: without
# them the kernel links cis/cis_verify.o against an undefined
# ow_crypto_ed25519_verify and the build fails at the link, after the host test
# has already passed using its own copies of both files.  A library the
# verification path needs belongs in the image, not only in the harness.
LIB_OBJS = lib/ow_htl.o \
           lib/kmem.o \
           lib/kstring.o \
           lib/kprintf.o \
           lib/kalloc.o \
           lib/sucs.o \
           lib/ow_sha256.o \
           lib/ow_sha512.o \
           lib/ow_ed25519.o

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
           $(NET_OBJS) $(SENT_OBJS) $(CIS_OBJS) $(SYSCALL_OBJS) $(KAPI_OBJS) \
           $(SHELL_OBJS) $(LIB_OBJS) $(BANCODE_OBJS) \
           $(SUC_OBJS) $(VIP_OBJS) \
           $(STOR_COMMON_OBJS) $(OWFS_OBJS) $(USFS_OBJS) $(STOR_CORE_OBJS)

# Intermediate image
PE_IMAGE   = openwinkrnl.pe

# Output OWX binary
TARGET = openwinkrnl.owx

# OWX packaging parameters
OWX_SUBSYSTEM = 0x01

# Canonical source & license manifest for CORE_KERNEL policy.  Generated before
# packing so the packer can embed the manifest's SHA-256 as the source digest.
# The manifest is deterministic (fixed sort, canonical JSON, LF newlines), so
# two builds from the same tree produce the same digest.
MANIFEST_FILE    = openwinkrnl_manifest.cislm
MANIFEST_DIGEST  = openwinkrnl_manifest.digest

# ==============================================================================
# Build Rules
# ==============================================================================

all: $(TARGET)

# Generate the canonical license manifest and its digest.  Depends on the
# source files the manifest inspects, but listing them all here would duplicate
# the discovery logic in gen_license_manifest.py, so the phony target is
# intentional: the manifest tool is fast and its output is deterministic.
.PHONY: license-manifest
license-manifest:
	python tools/gen_license_manifest.py \
	    --output $(MANIFEST_FILE) \
	    --digest-out $(MANIFEST_DIGEST)

# tools/owx_pack.py is a real prerequisite, not just a command-line argument.
# The image and its openwinkrnl.chk are produced by that script, so editing the
# packer has to invalidate both.  Without it, a change to the packer left a
# stale .owx (and a stale .chk) in place and `make` reported "Nothing to be
# done" -- which is how a mismatched checksum pair survived into a test run.
#
# When CIS_DEV_TRUST is on, the kernel image carries CORE_KERNEL policy class,
# a GPL-3.0-or-later licence declaration, and the SHA-256 of the canonical
# source manifest.  Without CIS_DEV_TRUST the image is unsigned anyway, so the
# policy args are omitted -- adding them to an unsigned image would change
# nothing about the refusal and would add a build step that has no consumer.
ifeq ($(CIS_DEV_TRUST),1)
$(TARGET): $(PE_IMAGE) tools/owx_pack.py tools/gen_license_manifest.py
	$(MAKE) license-manifest
	python tools/owx_pack.py $(PE_IMAGE) $(TARGET) \
	    --subsystem $(OWX_SUBSYSTEM) \
	    --policy-class CORE_KERNEL \
	    --cis-licence GPL-3.0-or-later \
	    --source-digest $(MANIFEST_DIGEST) \
	    --sign-dev
	@echo "=============================================================================="
	@echo "  OpenWindows Kernel Build Completed Successfully!"
	@echo "  Target: $(TARGET) | Freestanding C99 | NT-Like Object Architecture"
	@echo "  Policy: CORE_KERNEL | License: GPL-3.0-or-later | CIS signed"
	@echo "=============================================================================="
else
$(TARGET): $(PE_IMAGE) tools/owx_pack.py
	python tools/owx_pack.py $(PE_IMAGE) $(TARGET) \
	    --subsystem $(OWX_SUBSYSTEM)
	@echo "=============================================================================="
	@echo "  OpenWindows Kernel Build Completed Successfully!"
	@echo "  Target: $(TARGET) | Freestanding C99 | NT-Like Object Architecture"
	@echo "=============================================================================="
endif

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

# ==============================================================================
# Userspace images and their test-image provisioners
# ==============================================================================
# The three user-mode images the Phase 5c survey knows about are produced by two
# different pipelines on purpose:
#
#   owinit.owx   comes from OpenWindows-Essentials, which ships it as a PE wearing
#                an .owx name, so tools/embed_owx.py packs it here.
#   owinitv.owx  built HERE, from emergency/.  The recovery path cannot depend on
#   owrs.owx     another repository being present in order to produce the thing
#                you boot when the first repository's output is missing.
#
# All three become a C header and are provisioned into the freshly formatted RAM
# volume by a per-image seed object, so the SET of images on a test volume is
# chosen by the link line and readable straight off the target's recipe.  The
# production images (openwinkrnl.owx / openwinkrnl.vdi) link none of them.
EMERGENCY_DIR    = emergency
EMERGENCY_CFLAGS = -std=c99 -ffreestanding -nostdlib -fno-stack-protector \
                   -fno-pie -fno-builtin -fno-asynchronous-unwind-tables \
                   -O2 -Wall -Wextra -Werror -I$(EMERGENCY_DIR)

EMERGENCY_IMAGES = owinitv owrs
EMERGENCY_OWX    = $(EMERGENCY_IMAGES:%=$(EMERGENCY_DIR)/%.owx)
EMERGENCY_HDRS   = $(EMERGENCY_IMAGES:%=$(EMERGENCY_DIR)/%_image.h)

# ---- CIS_DEV_TRUST -------------------------------------------------------
#
# Off by default, and the default is the security property rather than an
# inconvenience:
#
#   make                     no trust anchors; the loader refuses every image
#   make CIS_DEV_TRUST=1     trust one development key, and sign images with it
#
# With the gate in ps/owx_loader.c, a default build cannot boot.  That is
# deliberate -- an unreviewed machine that will not run unreviewed code -- but it
# makes CIS_DEV_TRUST the difference between "boots" and "halts at init", so it
# needs to be the only way across.
#
# The flag does two things and both are required.  -DCIS_DEV_TRUST adds the dev
# anchor to the trust store in cis/cis_keys.h, and OWX_SIGN_ARGS makes the
# images carry a signature that anchor accepts.  Either half alone is useless:
# an anchor with nothing signed for it still refuses everything, and a signed
# image with no anchor is refused.  Setting only one produces a build that looks
# configured and boots nothing, which is the correct outcome but a confusing one.
#
# The dev seed is public (tools/cis_block.py), so a CIS_DEV_TRUST build executes
# anything that seed signs.  Never set it for a release.
ifeq ($(CIS_DEV_TRUST),1)
CIS_DEV_CFLAGS   = -DCIS_DEV_TRUST
OWX_SIGN_ARGS    = --sign-dev
else
CIS_DEV_CFLAGS   =
OWX_SIGN_ARGS    =
endif

CFLAGS          += $(CIS_DEV_CFLAGS)
EMERGENCY_CFLAGS += $(CIS_DEV_CFLAGS)

# Switching CIS_DEV_TRUST changes the bytes of every generated image header, but
# nothing on disk changes to tell make so.  Without this stamp, `make hosttest`
# followed by `make hosttest CIS_DEV_TRUST=1` reuses the unsigned header and the
# opt-in build silently boots nothing -- which is exactly the failure the opt-in
# exists to rule out.
#
# The stamp's CONTENT is the setting; its timestamp is what make reads.  Written
# with the value inside so that flipping the flag and flipping it back both
# produce a change, rather than a timestamp that says nothing about what changed.
CIS_STAMP = $(EMERGENCY_DIR)/.cis_dev_trust
CIS_STAMP_VALUE = CIS_DEV_TRUST=$(CIS_DEV_TRUST) SIGN_ARGS=$(OWX_SIGN_ARGS)

# Runs every time (FORCE), but rewrites only on change: a changed value updates
# the timestamp and so forces the affected objects and generated images to
# rebuild, while an unchanged value leaves the timestamp alone and everything
# stays cached.  $(CIS_STAMP) itself must NOT be .PHONY -- make treats a phony
# prerequisite as always newer, which would rebuild every dependent on every run.
.PHONY: FORCE
FORCE:

$(CIS_STAMP): FORCE
	@mkdir -p $(EMERGENCY_DIR)
	@printf '%s\n' '$(CIS_STAMP_VALUE)' > $@.new
	@cmp -s $@.new $@ || mv $@.new $@
	@rm -f $@.new

# Per-image seed objects.  A test image links the ones its volume should carry.
OWINIT_SEED_OBJ  = boot/owinit_seed.o
OWINITV_SEED_OBJ = boot/owinitv_seed.o
OWRS_SEED_OBJ    = boot/owrs_seed.o
# openwinkrnl.chk is the sentinel's kernel-checksum fixture.  It is not a
# userspace image, so it is not part of the per-image set, but every seeded test
# image needs it: the kernel-integrity phase (Phase 5c.2, before the init
# hand-off) halts with a fatal integrity code when it is absent, so an image
# that omits this looks like a kernel-integrity failure rather than a missing
# fixture.
OWCHK_SEED_OBJ   = boot/owchk_seed.o
SEED_OBJS        = $(OWINIT_SEED_OBJ) $(OWINITV_SEED_OBJ) $(OWRS_SEED_OBJ) $(OWCHK_SEED_OBJ)

# CIS_DEV_TRUST changes CFLAGS for every kernel and seed object, but make cannot
# see a flag change on its own.  Depend on the value-stamped CIS_STAMP so that
# flipping the flag rebuilds these objects; without it, a plain `make` after a
# CIS_DEV_TRUST build relinks the kernel from development-trust objects and packs
# a production image that still pins the development key.
$(ALL_OBJS) $(SEED_OBJS): $(CIS_STAMP)

MAKEFILE_ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
# Defaults to a neighboring checkout; override either variable for other layouts.
ESSENTIALS_ARTIFACTS ?= $(MAKEFILE_ROOT)../OpenWindows-Essentials/Artifacts/Software
OWINIT_SOURCE ?= $(ESSENTIALS_ARTIFACTS)/owinit.owx
OWINIT_IMAGE = boot/owinit_image.owx
OWINIT_HEADER = boot/owinit_image.h

$(OWINIT_HEADER): $(OWINIT_SOURCE) tools/owx_pack.py tools/embed_owx.py \
                   tools/cis_block.py $(CIS_STAMP)
	python tools/embed_owx.py $(OWINIT_SOURCE) $@ --packer tools/owx_pack.py \
	    --subsystem 0x04 --symbol g_owinit_image \
	    --size-macro OWINIT_IMAGE_SIZE --guard OWINIT_IMAGE_GENERATED_H \
	    $(if $(OWX_SIGN_ARGS),--pack-arg=--sign-dev,) \
	    --note "Generated from OpenWindows-Essentials/Software/owinit/owinit.c."

boot/owinit_seed.o: boot/owinit_seed.c storage/owdisk.h $(OWINIT_HEADER)
	@mkdir -p boot
	$(CC) $(CFLAGS) -c $< -o $@

boot/owchk_seed.o: boot/owchk_seed.c storage/owdisk.h inc/ow_sentinel.h
	@mkdir -p boot
	$(CC) $(CFLAGS) -c $< -o $@

# Emergency pair: compile to PE, pack to OWX1, embed.  Packing is its own visible
# step (rather than hidden behind the embed tool) so that a failed import check
# names the image that failed instead of surfacing as "header not regenerated".
#
# Subsystem 0x05 is OWX_SUBSYSTEM_RECOVERY, and it is the only thing that
# distinguishes these two images at the format level.  Nothing in the kernel
# switches on it: the survey treats all three images identically, and the
# subsystem byte is what tells a human reading a volume which file is the
# fallback rather than the orchestrator.
# The dependency is on the .c, not on an intermediate .pe: tools/owx_pack.py
# deletes the PE it consumed (the kernel's own image goes the same way, and for
# the same reason -- a stale PE next to a fresh .owx is a trap), so a rule that
# depended on it would rebuild the image on every single invocation.
#
# Spelled out per image rather than as a pattern rule: the generated header's
# symbols are SHOUTING_SNAKE (OWINITV_IMAGE_SIZE), and there is no portable
# Make function to upper-case a stem.  A pattern rule that quietly emitted
# OWowinitv_IMAGE_SIZE would compile, and then fail on the first include of the
# header -- at the include site, far from the rule that got it wrong.
$(EMERGENCY_DIR)/owinitv.owx: $(EMERGENCY_DIR)/owinitv.c $(EMERGENCY_DIR)/ow_gate.h tools/owx_pack.py tools/cis_block.py $(CIS_STAMP)
	$(CC) $(EMERGENCY_CFLAGS) -c $< -o $(EMERGENCY_DIR)/owinitv.o
	$(CC) $(EMERGENCY_CFLAGS) -Wl,-e,owinitv_main -o $(EMERGENCY_DIR)/owinitv.pe $(EMERGENCY_DIR)/owinitv.o
	python tools/owx_pack.py $(EMERGENCY_DIR)/owinitv.pe $@ --subsystem 0x05 $(OWX_SIGN_ARGS)

$(EMERGENCY_DIR)/owrs.owx: $(EMERGENCY_DIR)/owrs.c $(EMERGENCY_DIR)/ow_gate.h tools/owx_pack.py tools/cis_block.py $(CIS_STAMP)
	$(CC) $(EMERGENCY_CFLAGS) -c $< -o $(EMERGENCY_DIR)/owrs.o
	$(CC) $(EMERGENCY_CFLAGS) -Wl,-e,owrs_main -o $(EMERGENCY_DIR)/owrs.pe $(EMERGENCY_DIR)/owrs.o
	python tools/owx_pack.py $(EMERGENCY_DIR)/owrs.pe $@ --subsystem 0x05 $(OWX_SIGN_ARGS)

$(EMERGENCY_DIR)/owinitv_image.h: $(EMERGENCY_DIR)/owinitv.owx tools/embed_owx.py
	python tools/embed_owx.py $< $@ --no-pack \
	    --symbol g_owinitv_image --size-macro OWINITV_IMAGE_SIZE \
	    --guard OWINITV_IMAGE_GENERATED_H \
	    --note "Generated from emergency/owinitv.c by tools/owx_pack.py."

$(EMERGENCY_DIR)/owrs_image.h: $(EMERGENCY_DIR)/owrs.owx tools/embed_owx.py
	python tools/embed_owx.py $< $@ --no-pack \
	    --symbol g_owrs_image --size-macro OWRS_IMAGE_SIZE \
	    --guard OWRS_IMAGE_GENERATED_H \
	    --note "Generated from emergency/owrs.c by tools/owx_pack.py."

boot/owinitv_seed.o: boot/owinitv_seed.c storage/owdisk.h $(EMERGENCY_DIR)/owinitv_image.h
	@mkdir -p boot
	$(CC) $(CFLAGS) -c $< -o $@

boot/owrs_seed.o: boot/owrs_seed.c storage/owdisk.h $(EMERGENCY_DIR)/owrs_image.h
	@mkdir -p boot
	$(CC) $(CFLAGS) -c $< -o $@

# ==============================================================================
# Clean & Run
# ==============================================================================

clean:
	rm -f $(ALL_OBJS) $(PE_IMAGE) $(TARGET)
	rm -f $(SEED_OBJS) $(EMERGENCY_OWX) $(EMERGENCY_HDRS)
	rm -f $(EMERGENCY_DIR)/*.o $(EMERGENCY_DIR)/*.pe
	rm -f bancode/*.o
	rm -rf sucs/ vip/
	rm -f storage/*.o
	rm -f $(MANIFEST_FILE) $(MANIFEST_DIGEST)
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

# The normal test image carries all three userspace images, so the Phase 5c survey
# resolves to state 1 and owinit.owx is PID 1.  The emergency image (make
# qemu-emergency) carries only the other two, which is the same kernel sources
# with a different seed set on the link line and resolves to state 2.
TEST_SEED_OBJS  = $(OWINIT_SEED_OBJ) $(OWINITV_SEED_OBJ) $(OWRS_SEED_OBJ) $(OWCHK_SEED_OBJ)
EMERGENCY_SEEDS = $(OWINITV_SEED_OBJ) $(OWRS_SEED_OBJ) $(OWCHK_SEED_OBJ)

$(QEMU_BIN): $(ALL_OBJS) $(TEST_SEED_OBJS) $(OWINIT_HEADER) $(EMERGENCY_HDRS) $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/qemu.ld
	@mkdir -p $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/qemu.ld" "-Wl,-e,qboot_entry" \
	    -o $(QEMU_DIR)/qemu_image.exe \
	    $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o $(TEST_SEED_OBJS) $(ALL_OBJS) -lgcc
	objcopy -O binary $(QEMU_DIR)/qemu_image.exe $(QEMU_BIN)
	@echo "QEMU flat multiboot image (state 1: owinit/owinitv/owrs seeded): $(QEMU_BIN)"

qemu: $(QEMU_BIN)
	pwsh -ExecutionPolicy Bypass -File ./tools/qemu_run.ps1 $(QEMU_BIN)

# ==============================================================================
# QEMU emergency boot test: the SAME kernel, linked with only the emergency
# seeds.  owinit.owx is absent from the volume, so the survey resolves to state
# 2: owinitv.owx is entered as PID 1 and spawns owrs.owx, which prints a prompt.
# tools/qemu_run.ps1 -Emergency asserts the state-2 transcript.
# ==============================================================================
QEMU_EMERG_BIN = $(QEMU_DIR)/openwinkrnl_qemu_emergency.bin

$(QEMU_EMERG_BIN): $(ALL_OBJS) $(EMERGENCY_SEEDS) $(EMERGENCY_HDRS) $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/qemu.ld
	@mkdir -p $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/qemu.ld" "-Wl,-e,qboot_entry" \
	    -o $(QEMU_DIR)/qemu_emergency_image.exe \
	    $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o $(EMERGENCY_SEEDS) $(ALL_OBJS) -lgcc
	objcopy -O binary $(QEMU_DIR)/qemu_emergency_image.exe $(QEMU_EMERG_BIN)
	@echo "QEMU flat multiboot image (state 2: owinitv/owrs seeded): $(QEMU_EMERG_BIN)"

qemu-emergency: $(QEMU_EMERG_BIN)
	pwsh -ExecutionPolicy Bypass -File ./tools/qemu_run.ps1 $(QEMU_EMERG_BIN) -Emergency

# ==============================================================================
# QEMU kernel provenance/licence regression: the real kernel, two artifacts.
#
# Both cases are packed by tools/owx_pack.py from the SAME kernel PE with the
# same CORE_KERNEL policy class, source digest, and dev signature, so they are
# byte-identical except for the licence declaration (and the signature over
# it).  Each is embedded into its own boot/kprov_seed.c object -- which provides
# the strong OwDiskSeedTestChk hook that writes openwinkrnl.chk + openwinkrnl.owx
# on the test volume, and therefore links IN PLACE OF boot/owchk_seed.o -- and
# booted through the real Phase 5c.2 provenance path:
#
#   control (GPL-3.0-or-later)  CIS trusts it; the boot must reach the shell
#                               hand-off.
#   denied  (Apache-2.0)        CIS refuses the CORE_KERNEL licence; the sentinel
#                               reports a fatal provenance/licence failure and the
#                               kernel halts before the shell hand-off.
#
# The checksum passes in BOTH cases (that is what isolates the licence verdict
# being tested), and is computed at boot from the embedded bytes, so the fixture
# cannot drift from the checksum it is paired with.  tools/qemu_provenance_test.ps1
# asserts the two transcripts; qemu_run.ps1 is not used here because one case is
# expected to halt and that script only knows the healthy transcript.
#
# Both cases need CIS_DEV_TRUST=1: the artifacts are signed with the development
# key, which only a CIS_DEV_TRUST build pins in the trust store, and the seed
# object deliberately replaces boot/owchk_seed.o.
# ==============================================================================
KPROV_CONTROL_DIR = $(QEMU_DIR)/kprov_control
KPROV_DENIED_DIR  = $(QEMU_DIR)/kprov_denied
KPROV_CONTROL_OWX = $(KPROV_CONTROL_DIR)/kprov.owx
KPROV_DENIED_OWX  = $(KPROV_DENIED_DIR)/kprov.owx
KPROV_CONTROL_BIN = $(QEMU_DIR)/openwinkrnl_qemu_prov_control.bin
KPROV_DENIED_BIN  = $(QEMU_DIR)/openwinkrnl_qemu_prov_denied.bin
KPROV_SIGN_ARGS   = --policy-class CORE_KERNEL --source-digest $(MANIFEST_DIGEST) --sign-dev

# license-manifest is phony, so both artifacts are repacked on every invocation;
# a provenance regression should test what a clean build would produce, not what
# a previous run happened to leave behind.
$(KPROV_CONTROL_OWX): $(PE_IMAGE) tools/owx_pack.py license-manifest
	@mkdir -p $(KPROV_CONTROL_DIR)
	python tools/owx_pack.py $(PE_IMAGE) $@ --subsystem $(OWX_SUBSYSTEM) \
	    --cis-licence GPL-3.0-or-later $(KPROV_SIGN_ARGS)

$(KPROV_DENIED_OWX): $(PE_IMAGE) tools/owx_pack.py license-manifest
	@mkdir -p $(KPROV_DENIED_DIR)
	python tools/owx_pack.py $(PE_IMAGE) $@ --subsystem $(OWX_SUBSYSTEM) \
	    --cis-licence Apache-2.0 $(KPROV_SIGN_ARGS)

$(KPROV_CONTROL_DIR)/kprov_image.h: $(KPROV_CONTROL_OWX) tools/embed_owx.py
	@mkdir -p $(KPROV_CONTROL_DIR)
	python tools/embed_owx.py $< $@ --no-pack --symbol g_kprov_image \
	    --size-macro KPROV_IMAGE_SIZE --guard KPROV_IMAGE_GENERATED_H \
	    --note "Control: CORE_KERNEL / GPL-3.0-or-later. Signed kernel artifact for the provenance regression."

$(KPROV_DENIED_DIR)/kprov_image.h: $(KPROV_DENIED_OWX) tools/embed_owx.py
	@mkdir -p $(KPROV_DENIED_DIR)
	python tools/embed_owx.py $< $@ --no-pack --symbol g_kprov_image \
	    --size-macro KPROV_IMAGE_SIZE --guard KPROV_IMAGE_GENERATED_H \
	    --note "Denied: CORE_KERNEL / Apache-2.0 (violates the GPL policy). Signed kernel artifact for the provenance regression."

# The header on each case's include path (via -I), not the object, is what
# carries the case; the source is byte-identical for both.
$(KPROV_CONTROL_DIR)/kprov_seed.o: boot/kprov_seed.c $(KPROV_CONTROL_DIR)/kprov_image.h
	@mkdir -p $(KPROV_CONTROL_DIR)
	$(CC) $(CFLAGS) -I$(KPROV_CONTROL_DIR) -c $< -o $@

$(KPROV_DENIED_DIR)/kprov_seed.o: boot/kprov_seed.c $(KPROV_DENIED_DIR)/kprov_image.h
	@mkdir -p $(KPROV_DENIED_DIR)
	$(CC) $(CFLAGS) -I$(KPROV_DENIED_DIR) -c $< -o $@

# Same picture as the other QEMU images, but with boot/owchk_seed.o swapped for
# the provenance case's seed.
$(KPROV_CONTROL_BIN): $(ALL_OBJS) boot/owinit_seed.o boot/owinitv_seed.o boot/owrs_seed.o \
                      $(KPROV_CONTROL_DIR)/kprov_seed.o $(OWINIT_HEADER) $(EMERGENCY_HDRS) \
                      $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/qemu.ld
	@mkdir -p $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/qemu.ld" "-Wl,-e,qboot_entry" \
	    -o $(QEMU_DIR)/qemu_prov_control.exe \
	    $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o \
	    boot/owinit_seed.o boot/owinitv_seed.o boot/owrs_seed.o \
	    $(KPROV_CONTROL_DIR)/kprov_seed.o $(ALL_OBJS) -lgcc
	objcopy -O binary $(QEMU_DIR)/qemu_prov_control.exe $@
	@echo "QEMU provenance control image (CORE_KERNEL / GPL-3.0-or-later): $@"

$(KPROV_DENIED_BIN): $(ALL_OBJS) boot/owinit_seed.o boot/owinitv_seed.o boot/owrs_seed.o \
                     $(KPROV_DENIED_DIR)/kprov_seed.o $(OWINIT_HEADER) $(EMERGENCY_HDRS) \
                     $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/qemu.ld
	@mkdir -p $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/qemu.ld" "-Wl,-e,qboot_entry" \
	    -o $(QEMU_DIR)/qemu_prov_denied.exe \
	    $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o \
	    boot/owinit_seed.o boot/owinitv_seed.o boot/owrs_seed.o \
	    $(KPROV_DENIED_DIR)/kprov_seed.o $(ALL_OBJS) -lgcc
	objcopy -O binary $(QEMU_DIR)/qemu_prov_denied.exe $@
	@echo "QEMU provenance denied image (CORE_KERNEL / Apache-2.0): $@"

ifeq ($(CIS_DEV_TRUST),1)
qemu-provenance: $(KPROV_CONTROL_BIN) $(KPROV_DENIED_BIN)
	pwsh -ExecutionPolicy Bypass -File ./tools/qemu_provenance_test.ps1 \
	    $(KPROV_CONTROL_BIN) $(KPROV_DENIED_BIN)
else
qemu-provenance:
	@echo "qemu-provenance requires CIS_DEV_TRUST=1: the test artifacts are signed"
	@echo "with the development key, which only a CIS_DEV_TRUST build pins in the"
	@echo "trust store. Run: make CIS_DEV_TRUST=1 qemu-provenance"
	@exit 1
endif

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

$(VBOX_KERNEL): $(ALL_OBJS) $(TEST_SEED_OBJS) $(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o boot/vbox.ld
	@mkdir -p $(VBOX_DIR) $(QEMU_DIR)
	$(CC) $(CFLAGS) -nostdlib "-Wl,-T,boot/vbox.ld" "-Wl,-e,qboot_entry" "-Wl,--image-base=0" \
	-o $(VBOX_DIR)/vbox_image.exe \
	$(QEMU_DIR)/qboot.o $(QEMU_DIR)/qemu_entry.o $(TEST_SEED_OBJS) $(ALL_OBJS) -lgcc
	objcopy -O binary $(VBOX_DIR)/vbox_image.exe $(VBOX_KERNEL)
	@echo "VBox flat kernel (state 1: owinit/owinitv/owrs seeded): $@"

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
QEMU_IMG  ?= qemu-img
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
               tools/hosttest/host_cis_verify.c \
               tools/hosttest/host_cis_loader.c \
               core/main.c core/object.c core/memory.c core/pgfault.c \
               core/alpc.c core/runlevel.c \
               rc/rc.c hal/acpi.c \
               diag/bancode_krnl.c vfs/vfs.c net/router.c net/vip.c \
sentinel/damagecntrl.c sentinel/fltrmgr.c \
                cis/cis_core.c cis/cis_format.c cis/cis_verify.c \
                syscall/dispatcher.c kapi/kernel64.c shell/shell.c \
                lib/ow_htl.c lib/kmem.c lib/kstring.c lib/kprintf.c \
                lib/kalloc.c lib/sucs.c lib/ow_sha256.c \
                lib/ow_sha512.c lib/ow_ed25519.c storage/owdisk.c \
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

# hosttest-asan builds the identical source list with the address and undefined
# behaviour sanitizers.  It exists because several CIS bounds guards cannot be
# caught by any verdict assertion: removing one leaves the verdict unchanged (the
# parse fails anyway, for a different reason) while turning a size subtraction
# into an out-of-bounds read.  Only the sanitizer sees that, so the guards get
# tested here rather than argued about in a comment.
# -I./boot is where boot/owinit_image.h lives.  tools/hosttest/host_boot.c
# includes it as "owinit_image.h" rather than "../../boot/owinit_image.h" so that
# CMake can resolve the same include against its own generated copy; the two build
# systems must therefore agree on the name, not on a relative path.
HOSTTEST_INCLUDES = -I./boot -I./inc -I./inc/bancode -I$(BANCODE_DIR) \
                    -I../superunicode/sutf/include -I../vip \
                    -I../OpenWindows-Storage/common/include \
                    -I../OpenWindows-Storage/owfs/include \
                    -I../OpenWindows-Storage/usfs/include

HOSTTEST_ASAN_FLAGS = -std=c99 -Wall -Wextra -Werror -fno-pie -g \
                      -fsanitize=address,undefined -fno-omit-frame-pointer \
                      -DOW_HOST_HAL $(CIS_DEV_CFLAGS) $(HOSTTEST_INCLUDES)
HOSTTEST_ASAN_OUT = $(or $(TMPDIR),$(TEMP),/tmp)/openwinkrnl_asan.exe

HOSTTEST_FLAGS = -std=c99 -Wall -Wextra -Werror -fno-pie -g -DOW_HOST_HAL \
                 $(CIS_DEV_CFLAGS) $(HOSTTEST_INCLUDES)

# Entry-point audit across all Essentials OWX targets. Runs the checker's own
# negative self-test first, so a signature that stopped discriminating fails the
# gate rather than silently accepting a reverted owinit.
owx-entries:
	python tools/check_owx_entries.py --self-test
	python tools/check_owx_entries.py $(ESSENTIALS_ARTIFACTS)

# The host harness provisions its own volume (tools/hosttest/host_boot.c), so it
# does NOT link the seed objects -- boot/owinit_seed.o would race host_boot.c for
# the same catalog entries.  It does depend on all three image headers, because
# the classifier and CRC tests read the real packed bytes.
hosttest: $(OWINIT_HEADER) $(EMERGENCY_HDRS)
	$(MAKE) owx-entries
	$(CC) $(HOSTTEST_FLAGS) $(HOSTTEST_SRC) -o $(HOSTTEST_OUT)
	$(HOSTTEST_OUT)

# Sanitized build of the same source list.  Kept as a separate target rather than
# folded into hosttest because the sanitizers roughly double the run time and
# slow the edit/test loop down; run both before landing anything that touches
# bounds arithmetic.
hosttest-asan: $(OWINIT_HEADER) $(EMERGENCY_HDRS)
	$(CC) $(HOSTTEST_ASAN_FLAGS) $(HOSTTEST_SRC) -o $(HOSTTEST_ASAN_OUT)
	$(HOSTTEST_ASAN_OUT)

# Build the emergency images and audit them like any other .owx: import-free,
# RIP-relative, entry at the real symbol.  This is the gate that catches the
# failure mode where emergency/owrs.c grows a printf and stops being loadable.
emergency: $(EMERGENCY_OWX)
	python tools/check_owx_entries.py --self-test
	python tools/check_owx_entries.py $(EMERGENCY_DIR)

.PHONY: all clean vm hosttest qemu qemu-emergency qemu-provenance vbox vbox-image vdi vdi-test \
        owx-entries emergency