# User/kernel syscall ABI

One ABI is supported. Anything that does not match it is unsupported, and
unsupported means the call is not wired up -- not that it silently does
something else.

## The supported ABI

| Property        | Value                                                     |
|-----------------|-----------------------------------------------------------|
| Instruction     | `int 0x80` (`IDT` vector `0x80`, see `hal/idt.c`)         |
| Syscall number  | `RAX`                                                     |
| Argument 1      | `RCX`                                                     |
| Argument 2      | `RDX`                                                     |
| Argument 3      | `R8`                                                      |
| Return value    | `RAX`, signed 64-bit                                      |
| Failure         | negative/`OW_ERR_*` value in `RAX`                        |

### On caller privilege

Vector `0x80` is installed with DPL 3 (`OW_IDT_SYSCALL_ATTR = 0xEE` in
`hal/idt.c`). A DPL 3 gate is reachable from CPL 0 through CPL 3, so this is
"callable from user mode", not "user mode only", and there is no explicit CPL
check in the entry path.

That is acceptable because the dispatcher does not trust the gate for
isolation: `syscall_current_process()` resolves the calling thread's process and
every request is bounded against that process's own window, VADs and frame run
(`OW_SYS_ALLOC`, for example, refuses to grow past `OW_USER_GUARD_BASE`). A
caller that lies about its identity gets its own process's resources, not
another's. The limits are per-process, so the gate being DPL 3 costs nothing.

Worth stating plainly, though: this is "reached from ring 3" rather than
"restricted to ring 3". If ring-0 callers should be refused, that needs an
explicit check in the entry path, and it is not there today.

The wrappers in `inc/ow_syscall.h` are the intended user-side interface, and
they are the only supported way to reach this ABI.

Error convention is currently mixed rather than uniformly negative: some paths
return `-1` and some return an `OW_ERR_*` code. That is a wart in the
implementation, not a second convention -- every failure is non-zero and is
tested with `ow_status_success()`. New calls should return an `OW_ERR_*` code.

## Numbers

`inc/ow_syscall.h` is the single source of truth. The dispatcher in
`syscall/dispatcher.c` dispatches on these exact values.

| ID     | Name                          | ID     | Name                          |
|--------|-------------------------------|--------|-------------------------------|
| `0x01` | `OW_SYS_ALLOC`                | `0x11` | `OW_SYS_PS_CREATE_THREAD`     |
| `0x02` | `OW_SYS_MAP_IO`               | `0x12` | `OW_SYS_SYNC_CREATE_EVENT`    |
| `0x03` | `OW_SYS_VFS_CREATE`           | `0x13` | `OW_SYS_SYNC_SET_EVENT`       |
| `0x04` | `OW_SYS_VFS_WRITE`            | `0x14` | `OW_SYS_SYNC_RESET_EVENT`     |
| `0x05` | `OW_SYS_VFS_READ`             | `0x15` | `OW_SYS_SYNC_CREATE_SEMAPHORE`|
| `0x06` | `OW_SYS_ALPC_CREATE`          | `0x16` | `OW_SYS_SYNC_RELEASE_SEMAPHORE`|
| `0x07` | `OW_SYS_ALPC_SEND`            | `0x17` | `OW_SYS_SYNC_WAIT`            |
| `0x08` | `OW_SYS_ALPC_RECV`            | `0x18` | `OW_SYS_PS_SLEEP`             |
| `0x09` | `OW_SYS_VFS_DELETE`           | `0x19` | `OW_SYS_SYNC_CREATE_MUTEX`    |
| `0x0A` | `OW_SYS_OBJ_OPEN`             | `0x1A` | `OW_SYS_SYNC_RELEASE_MUTEX`   |
| `0x0B` | `OW_SYS_OBJ_CLOSE`            | `0x1B` | `OW_SYS_UART_WRITE`           |
| `0x0C` | `OW_SYS_SAFE_POWEROFF_SCREEN` | `0x1C` | `OW_SYS_SET_AUTOREBOOT`       |
| `0x0D` | `OW_SYS_PS_YIELD`             | `0x1D` | `OW_SYS_SET_KDUMP`            |
| `0x0E` | `OW_SYS_PS_EXIT_THREAD`       | `0x1E` | `OW_SYS_GET_AUTOREBOOT`       |
| `0x0F` | `OW_SYS_PS_GET_PID`           | `0x1F` | `OW_SYS_GET_KDUMP`            |
| `0x10` | `OW_SYS_PS_CREATE_PROCESS`    |        |                               |

`0x00` is not a syscall. There is no `OW_SYS_NOP` in the kernel numbering, and
adding one would collide with the convention every Essentials header assumes.

## `owrp` is not this ABI

`OpenWindows-Essentials/DLL/owrp/owrp.h` describes a different calling
convention, and it is **unsupported by the kernel**. It is recorded here so the
difference is explicit rather than rediscovered by trial and error.

| Property     | Kernel (supported) | `owrp` (unsupported) |
|--------------|--------------------|----------------------|
| Instruction  | `int 0x80`         | `syscall`            |
| Number       | `RAX`              | `RAX`                |
| Arg 1        | `RCX`              | `RDI`                |
| Arg 2        | `RDX`              | `RSI`                |
| Arg 3        | `R8`               | `RDX`                |
| Return       | `RAX`              | `RAX` value, `RDX` error |

The numbering is disjoint as well as the registers. `owrp` starts at
`OWRP_SYS_NOP = 0x000` and reaches `OWRP_SYS_MEM_REQUEST = 0x010`, while the
kernel treats `0x000` as unassigned and gives `0x001` to `OW_SYS_ALLOC`. Even
the register assignment differs, so the same numeric ID would read different
arguments.

There is no compatibility shim, and none should be added by renumbering one
side. The two ABIs cannot be reconciled by picking new numbers: `int 0x80` and
`syscall` are different vectors with different register conventions, and a user
image can only be built against one of them.

### What this blocks, and what it does not

An application that issues `owrp` calls will not work against this kernel. It
will take a fault rather than a diagnosable error, because `syscall` is not a
valid gate here.

This does **not** block the first CPL3 process. `owinit_main` and its entire
dependency closure (`kconf64`, which is pure in-memory configuration) make no
syscalls at all, so reaching the kernel ABI is not a prerequisite for running
them. It becomes a prerequisite as soon as a process actually needs a kernel
service.

## Why the kernel ABI is the one that is authoritative

It is the one that is implemented and gated. `hal/idt.c` installs vector `0x80`
and `syscall/dispatcher.c` services the numbers in the table above, with
`make hosttest`, `make vdi-test` and `make qemu` exercising the launch path
end to end. `owrp` has no implementation behind it in this kernel.

Changing the kernel ABI to match `owrp` would mean moving a working, tested gate
to match an unimplemented one. If `owrp` is to become supported, the work is a
new gate plus a compatibility decision for existing callers, and that decision
belongs to whoever owns the Essentials side.
