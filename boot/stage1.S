; stage1.S - OpenWindows VirtualBox boot sector (NASM, 16-bit real mode)
;
; Loads the flat kernel image (linked at 0x10000) from a 1.44MB floppy
; using BIOS int13h CHS reads (AH=02), switches to 32-bit protected mode,
; and jumps to the entry point.
;
; Assemble: nasm -f bin -o stage1.bin boot/stage1.S  (fills the 512-byte sector)

org 0x7C00
bits 16

IMG_BASE   equ 0x10000
LOAD_SEG0  equ IMG_BASE >> 4        ; 0x1000
RETRIES    equ 4
SPT        equ 18                   ; sectors per track (1.44MB floppy)
SPC        equ SPT * 2              ; sectors per cylinder (2 heads)

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7C00
    sti

    mov [word bootdrv], dl          ; BIOS passes drive number in DL

    ; Enable A20 via the fast gate
    in al, 0x92
    test al, 0x02
    jnz .a20_ok
    or al, 0x02
    out 0x92, al
.a20_ok:

    mov si, [word nsec]             ; sector count in SI (int13h CHS clobbers CX)
    mov word [word lba], 1          ; first kernel sector

read_loop:
    mov ax, [word lba]
    cmp ax, si
    jae read_done

    ; buffer segment = LOAD_SEG0 + (lba-1)*32
    mov ax, [word lba]
    dec ax
    shl ax, 5
    add ax, LOAD_SEG0
    mov es, ax
    xor bx, bx

    ; CHS of the LBA: cyl=LBA/SPC, head=(LBA%SPC)/SPT, sector=(LBA%SPT)+1.
    ; LBA 0 = this boot sector (never read), LBA 1 = first kernel sector,
    ; so sector numbers are 1-based (1..18) and LBA 1 maps to CHS (0,0,2).
    mov ax, [word lba]
    xor dx, dx
    mov di, SPC
    div di
    mov [word chs_cyl], ax
    mov ax, dx
    xor dx, dx
    mov di, SPT
    div di
    mov [word chs_head], al
    inc dx
    mov [word chs_sec], dl
    mov ax, [word chs_cyl]
    mov ch, al
    mov dl, [word chs_sec]
    mov cl, dl
    mov dl, [word chs_head]
    mov dh, dl
    mov dl, [word bootdrv]

    mov ah, 0x02
    mov al, 0x01
    mov di, RETRIES
.retry:
    int 0x13
    jnc .ok
    xor ah, ah                      ; reset diskette on failure
    int 0x13
    dec di
    jnz .retry
    jmp read_fail
.ok:
    inc word [word lba]
    jmp read_loop

read_done:
    ; Load entry address into ESI (carried across the mode switch).
    mov ax, LOAD_SEG0
    mov es, ax
    mov esi, [es:0x1C]

    ; Switch to 32-bit protected mode.
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
    dq 0x00CF9A000000FFFF           ; code32: base 0, limit 4G, DPL0
    dq 0x00CF92000000FFFF           ; data32
gdt_end:

gdtr:
    dw gdt_end - gdt - 1
    dd gdt

lba:        dw 1
chs_cyl:    dw 0
chs_head:   db 0
chs_sec:    db 0
nsec_magic: dd 'NSNS'                ; mkboot.py locates nsec via this 4-byte mark
nsec:       dw 1                    ; patched by mkboot.py
bootdrv:    db 0

times 510 - ($ - $$) db 0
dw 0xAA55
