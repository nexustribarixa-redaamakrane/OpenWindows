; stage1disk.S - OpenWindows hard-disk boot sector (VirtualBox VDI / MBR style)
;
; 16-bit real mode. Boots the flat kernel image (linked at 0x10000) that is
; stored starting at disk LBA 1. Reads are geometry-independent LBA reads via
; INT 13h AH=42 when the BIOS supports the extensions; otherwise it falls
; back to CHS (INT 13h AH=02) using the geometry reported by INT 13h AH=08,
; so disk geometry differences (floppy vs 1.44MB vs hard disk) cannot
; silently corrupt the load.
;
; Assemble: nasm -f bin -o stage1disk.bin boot/stage1disk.S
; Pack:     python tools/mkboot.py stage1disk.bin kernel.bin disk.img [bytes]
;
; mkboot.py locates the sector-count word via the 'NSNS' magic marker, and
; the entry pointer is read from file offset 0x1C of the flat image, exactly
; as stage1.S does for the floppy path.

org 0x7C00
bits 16

IMG_BASE   equ 0x10000
LOAD_SEG0  equ IMG_BASE >> 4        ; 0x1000
RETRIES    equ 4
DAP        equ 0x0500               ; Disk Address Packet scratch area

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov [byte drive_number], dl     ; BIOS hands us the boot drive in DL

    ; Enable A20 via the fast gate
    in al, 0x92
    test al, 0x02
    jnz .a20_ok
    or al, 0x02
    out 0x92, al
.a20_ok:

    ; Probe for LBA extensions: INT 13h AH=41, BX=0x55AA
    mov dl, [byte drive_number]
    mov ah, 0x41
    mov bx, 0x55AA
    int 0x13
    jc .no_lba_ext
    cmp bx, 0xAA55
    je load_lba
.no_lba_ext:
    jmp load_chs

; ===========================================================================
; LBA extended reads (INT 13h AH=42). Preferred path - geometry independent.
; ===========================================================================
load_lba:
    mov cx, [sector_count]          ; total sectors including the boot sector
    mov di, 1                       ; next LBA to read

.loop:
    cmp di, cx
    jae read_done

    ; Buffer segment for LBA di: LOAD_SEG0 + (di-1)*32
    mov ax, di
    dec ax
    shl ax, 5
    add ax, LOAD_SEG0
    mov es, ax
    mov dx, ax                      ; remember segment for the DAP

    ; Build the Disk Address Packet at DAP (DS:SI -> packet before the call)
    mov byte [DAP + 0], 0x10        ; packet size
    mov byte [DAP + 1], 0x00        ; reserved
    mov word [DAP + 2], 0x0001      ; block count
    mov word [DAP + 4], 0x0000      ; buffer offset (bx)
    mov word [DAP + 6], dx          ; buffer segment (es)
    mov word [DAP + 8], di          ; LBA low word
    mov word [DAP + 10], 0x0000     ; LBA high word
    mov word [DAP + 12], 0x0000
    mov word [DAP + 14], 0x0000

    mov word [trycnt], RETRIES
.retry:
    mov dl, [byte drive_number]
    mov ah, 0x42
    mov si, DAP
    int 0x13
    jnc .ok
    xor ah, ah                      ; reset disk on failure
    int 0x13
    dec word [trycnt]
    jnz .retry
    jmp read_fail
.ok:
    inc di
    jmp .loop

; ===========================================================================
; CHS fallback (INT 13h AH=02) using the geometry from INT 13h AH=08.
; ===========================================================================
load_chs:
    mov dl, [byte drive_number]
    mov ax, 0x0800
    int 0x13
    jnc .have_geo
    mov word [heads], 2             ; assume 1.44MB floppy geometry
    mov word [spt], 18
    jmp .geo_ok
.have_geo:
    movzx ax, dh                    ; DH = max head index
    inc ax                          ; head count (1-based)
    mov [heads], ax
    mov ax, cx                      ; CL bits 0-5 = max sector number
    and ax, 0x003F
    mov [spt], ax
.geo_ok:
    mov ax, [spt]
    mul word [heads]
    mov [spc], ax                   ; sectors per cylinder

    mov cx, [sector_count]
    mov di, 1

.loop:
    cmp di, cx
    jae read_done

    ; Buffer segment for sector di: LOAD_SEG0 + (di-1)*32
    mov ax, di
    dec ax
    shl ax, 5
    add ax, LOAD_SEG0
    mov es, ax

    ; LBA -> CHS: cyl = LBA / SPC, tmp = LBA % SPC,
    ;             head = tmp / SPT, sec = (tmp % SPT) + 1
    mov ax, di
    xor dx, dx
    div word [spc]
    mov [chs_cyl], ax
    mov ax, dx
    xor dx, dx
    div word [spt]
    mov [chs_head], al
    inc dx
    mov [chs_sec], dl

    mov ax, [chs_cyl]
    mov ch, al
    mov cl, [chs_sec]
    mov dh, [chs_head]
    mov dl, [byte drive_number]

    mov ah, 0x02
    mov al, 0x01
    mov word [trycnt], RETRIES
.retry:
    int 0x13
    jnc .ok
    xor ah, ah
    int 0x13
    dec word [trycnt]
    jnz .retry
    jmp read_fail
.ok:
    inc di
    jmp .loop

; ===========================================================================
; Read complete: fetch the entry pointer, enter protected mode, jump.
; ===========================================================================
read_done:
    mov ax, LOAD_SEG0
    mov es, ax
    mov esi, [es:0x1C]              ; entry RVA from the flat image header

    mov ax, 0
    mov es, ax
    cli
    lgdt [word gdtr]
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x08:pmode

; ---------------------------------------------------------------------------
bits 32
; ---------------------------------------------------------------------------
pmode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x00090000

    jmp esi

read_fail:
    ; Blink X at the VGA corner forever
.hang:
    mov byte [dword 0xB8000], 0x58
    hlt
    jmp .hang

; ---------------------------------------------------------------------------
; Data
; ---------------------------------------------------------------------------
gdt:
    dq 0x0000000000000000           ; null
    dq 0x00CF9A000000FFFF           ; code32
    dq 0x00CF92000000FFFF           ; data32
gdt_end:

gdtr:
    dw gdt_end - gdt - 1
    dd gdt

drive_number:   db 0
nsec_magic:     dd 'NSNS'           ; mkboot.py locates sector_count via this mark
sector_count:   dw 1                ; patched by mkboot.py
trycnt:         dw 0
heads:          dw 2
spt:            dw 18
spc:            dw 36
chs_cyl:        dw 0
chs_head:       db 0
chs_sec:        db 0

times 510 - ($ - $$) db 0
dw 0xAA55