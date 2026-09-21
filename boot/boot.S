# Multiboot1 a.out-kludge flat binary bootstrap for owoskrnl.bin.
# Loaded by QEMU at 1MB, zeroes bss, jumps to _entry (32-bit), which
# builds a 4 GiB identity map and enters long mode before calling
# kernel_main64(magic_ecx, mbi_edx).
.section .text
.global _start
.extern _end_of_file, _end_of_bss, kernel_main64

_start:
    .long 0x1BADB002              # magic
    .long 0x00010003              # flags: align | mem_info | a.out kludge
    .long -(0x1BADB002 + 0x00010003)
    .long 0x100000                # header_addr
    .long 0x100000                # load_addr
    .long _end_of_file            # load_end_addr
    .long _end_of_bss             # bss_end_addr
    .long _entry                  # entry_addr

.code32
.global _entry
_entry:
    cli
    cld
    mov %ebx, %esi              # save multiboot info pointer

    # Zero PML4
    mov $pml4, %edi
    xor %eax, %eax
    mov $1024, %ecx
    rep stosl

    # PML4[0] -> pdpt
    mov $pdpt, %eax
    or  $0x3, %eax
    mov %eax, pml4

    # PDPT[0..3] -> pd0..pd3
    mov $pd0, %eax
    or  $0x3, %eax
    mov %eax, pdpt
    add $0x1000, %eax
    mov %eax, pdpt + 8
    add $0x1000, %eax
    mov %eax, pdpt + 16
    add $0x1000, %eax
    mov %eax, pdpt + 24

    # Fill 2048 PDEs with 2MB huge pages (identity map 4GB)
    mov $pd0, %edi
    mov $0x83, %eax             # present | writable | huge
    mov $2048, %ecx
1:
    mov %eax, (%edi)
    add $8, %edi
    add $0x200000, %eax
    loop 1b

    # Enable PAE
    mov %cr4, %eax
    or  $0x20, %eax
    mov %eax, %cr4

    # Set EFER.LME
    mov $0xC0000080, %ecx
    rdmsr
    or  $0x100, %eax
    wrmsr

    # Load CR3
    mov $pml4, %eax
    mov %eax, %cr3

    # Enable paging + protected mode
    mov %cr0, %eax
    or  $0x80000001, %eax
    mov %eax, %cr0

    # Load GDT
    lgdt gdt_desc

    # Far jump into 64-bit mode
    ljmp $0x08, $long_mode

.code64
long_mode:
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov %ax, %fs
    mov %ax, %gs

    # Enable SSE
    mov %cr4, %rax
    or  $0x600, %rax
    mov %rax, %cr4
    fninit

    mov $boot_stack_top, %rsp
    xor %rbp, %rbp

    # MS x64 ABI: rcx = magic, rdx = mbi
    mov $0x2BADB002, %ecx
    mov %rsi, %rdx
    sub $0x20, %rsp
    call kernel_main64

.halt:
    cli
    hlt
    jmp .halt

.section .rodata
.align 8
gdt:
    .quad 0x0000000000000000
    .quad 0x00209A0000000000
    .quad 0x0000920000000000
gdt_end:
gdt_desc:
    .word gdt_end - gdt - 1
    .quad gdt

.section .bss
.align 4096
pml4:
    .skip 4096
pdpt:
    .skip 4096
pd0:
    .skip 4096
pd1:
    .skip 4096
pd2:
    .skip 4096
pd3:
    .skip 4096
boot_stack_bottom:
    .skip 16384
boot_stack_top:
