# OpenWindows Diagnostic Registry: U+ BANcode Database

This database defines all system diagnostic codes, milestones, advisories, mitigations, and fatal events for OpenWindows. All kernel components (liths) query this Registry via the Diagnostic Nexus. Codes are drawn from the canonical BANcode framework ranges (B+ `0x0011A000`, W+ `0x0011A800`, C+ `0x0011AC00`, S+ `0x0011AE00`).

---

## 1. Classification Overview

| Prefix | Class | Severity | System Action | Description |
| :--- | :--- | :--- | :--- | :--- |
| **C+** | COMcode | Milestone | Continue | Success markers logged during initialization phases. |
| **W+** | WARNcode | Advisory | Continue | Non-fatal warnings logged to console/buffer; system runs normal. |
| **S+** | SOFTcode | Recoverable | Mitigate | Exception intercepted by Guard-Agent (`damagecntrl.sentinel`). |
| **B+** | BANcode | Fatal | KeDropBanHammer | Fatal security/hardware violations triggering a systemic lockdown. |

---

## 2. Comprehensive Code Catalogue

### Milestone Success Indicators (C+)

These codes indicate healthy core subsystem startup and transition phases.

| Code (Hex) | Name | Component | Detailed Description |
| :--- | :--- | :--- | :--- |
| `0x0011AC01` | `C_HAL_INITIALIZED` | `htf.owd` | The Hardware Translation Format engine successfully initialized the MMIO maps, early UART outputs, and interrupt tables. |
| `0x0011AC02` | `C_PML4_BUILT` | `openwinkrnl.owx` | PML4, PDPT, PD, and PT structures successfully built and mapped to kernel spaces. |
| `0x0011AC03` | `C_OBJ_MANAGER_READY` | `openwinkrnl.owx` | Root namespace nodes (`\Device`, `\DosDevices`, `\Kernel`) created and ready for handle allocation. |
| `0x0011AC04` | `C_VFS_PRIMARY_MOUNTED` | `vfs.owc` | The OWFS primary volume mounted cleanly. Checksum validation active. |
| `0x0011AC05` | `C_VFS_SECURE_MOUNTED` | `vfs.owc` | The USFS secure volume mounted cleanly. |
| `0x0011AC06` | `C_NETWORK_ONLINE` | `univip.owc` | The 44-bit Hex Trie Prefix Router is active and accepting Sparse Radix routing table configurations. |
| `0x0011AC07` | `C_SENTINEL_ONLINE` | `damagecntrl.sentinel` | Guard-Agent sentinel trap vectors registered for `#UD` and `#SS` intercept routing. |
| `0x0011AC08` | `C_SYSCALL_GATEWAY_READY` | `openwinkrnl.owx` | The Ring 3-to-0 system call dispatcher is live. |
| `0x0011AC09` | `C_BOOT_COMPLETE` | `openwinkrnl.owx` | Executive-Agent hands over CPU execution state to the Ring 3 Session manager. |
| `0x0011AC0A` | `C_RUNLEVEL_TABLE_READY` | `openwinkrnl.owx` | Runlevel subsystem compiled a valid `-6..6` profile table; boot target locked in. |
| `0x0011AC0B` | `C_RUNLEVEL_TRANSITION` | `openwinkrnl.owx` | A live runlevel switch completed - subsystems re-armed or torn down per the destination profile. |
| `0x0011AC0C` | `C_ACPI_TABLES_READY` | `openwinkrnl.owx` | Firmware ACPI tables (RSDP / RSDT / XSDT / FADT) located and PM1a control registers cached for software power control. |
| `0x0011AC0D` | `C_RC_SHUTDOWN_RUN` | `openwinkrnl.owx` | The rc.d shutdown sequence executed (OpenWindows-Essentials orchestration: daemon teardown, session termination, registry commit, cache flush). |
| `0x0011AC0E` | `C_ACPI_POWEROFF` | `openwinkrnl.owx` | Software power-off (ACPI S5) request issued to firmware. |
| `0x0011AC0F` | `C_PS_READY` | `openwinkrnl.owx` | The process/thread (NT-like executive) subsystem finished compiling its static process and thread tables; the idle system thread 0 is registered. Scheduling remains off until `OwPsStartScheduler()`. |
| `0x0011AC10` | `C_PS_SCHEDULER_RUNNING` | `openwinkrnl.owx` | The round-robin scheduler is live: PIT channel 0 reprogrammed to a 100 Hz periodic tick (IRQ0, vector 0x20), PIC IRQ0 unmasked, timer interrupts enabled. |
| `0x0011AC11` | `C_OWINIT_PROCESS_CREATED` | `openwinkrnl.owx` | The userspace orchestrator `owinit.owx` was handed off as Process 1 (`PID 1`); its VAD root flags the single-flat exec arena. |
| `0x0011AC12` | `C_OWINIT_IMAGE_LOADED` | `openwinkrnl.owx` | The OWX1 image loader validated and mapped the `owinit.owx` sections into the exec arena and resolved the entry point into the process object. |

---

### Non-Fatal Advisories (W+)

These warnings alert system administrators or developers of anomalies that do not jeopardize core stability.

| Code (Hex) | Name | Component | Detailed Description / Remediation |
| :--- | :--- | :--- | :--- |
| `0x0011A800` | `W_PNP_RESOURCE_CONFLICT` | `classpnp.owc` | Two hardware devices requested overlapping physical memory spaces. The arbiter resolved the mapping automatically. |
| `0x0011A801` | `W_DRIVER_UNSIGNED` | `fltrmgr.owc` | An unsigned Tier 3 driver was loaded. Logged for kernel auditing; execution continues. |
| `0x0011A802` | `W_RUNLEVEL_FEATURE_SKIPPED` | `openwinkrnl.owx` | A boot phase was skipped because its subsystem feature is not armed by the active runlevel profile. |
| `0x0011A803` | `W_ACPI_NOT_FOUND` | `openwinkrnl.owx` | No valid ACPI RSDP / FADT (or PM1a control block) was located in low memory. Software power-off falls back to emulator legacy control ports. |
| `0x0011A804` | `W_RC_DIRECTIVE_IGNORED` | `openwinkrnl.owx` | An rc.d script line referenced a directive that the kernel interpreter does not act on; logged and skipped. |

---

### Recoverable Interruptions (S+)

These soft exceptions are trapped by `damagecntrl.sentinel` for runtime mitigation.

| Code (Hex) | Name | Interception Source | Soft Mitigation & Escalation Policy |
| :--- | :--- | :--- | :--- |
| `0x0011AE00` | `S_STACK_ALIGNMENT_FAULT` | Stack Segment Fault (`#SS`) | Sentinel detects misaligned stacks on Ring 3 transitions. Aligns RSP register, logs error, and resumes instruction. |
| `0x0011AE01` | `S_UNDEFINED_INSTRUCTION` | Undefined opcode (`#UD`) | Intercepted CPU instruction. Sentinel invokes the sparse AVX-512 compiler to emulate the instruction. |
| `0x0011AE02` | `S_DRIVER_HOOK_BLOCKED` | System Call Gate hook | An application tried to hook the Ring 3-to-0 Dispatcher Gateway directly. Hook bypassed and thread jailed. Escalates to B+ if repeated. |

---

### Unrecoverable System BANcodes (B+)

These fatal codes trigger immediate crash dumps to `openwinkrnl.chk` and full SMP freeze.

| Code (Hex) | Name | Triggering Event | Emergency Action |
| :--- | :--- | :--- | :--- |
| `0x0011A000` | `B_PAGE_FAULT_FATAL` | Null pointer or unmapped write in Kernel space | Triggers `KeDropBanHammer`. Halts memory paging system to prevent disk corruption. |
| `0x0011A001` | `B_SENTINEL_INTEGRITY_FAIL` | Sentinel checksum mismatch | Triggers `KeDropBanHammer`. Guard-Agent detects that the active defense sentinel memory was modified. |
| `0x0011A002` | `B_TIER_EXTENSION_VIOLATION` | Uncompliant Tier 1 driver | Triggers `KeDropBanHammer`. A Tier 1 driver lacks the `.owc` driver image signature. |
| `0x0011A003` | `B_ALPC_TRIPLE_FAULT` | Corruption of the system call router | Triggers `KeDropBanHammer`. The System Call Dispatcher has encountered an unhandled triple nested fault. |
| `0x0011A004` | `B_VFS_CORRUPT` | Filesystem structure corruption | Triggers `KeDropBanHammer`. A mounted volume CRC32c verification failed. |
| `0x0011A005` | `B_OWINIT_MISSING` | No usable user-mode init on the primary volume | Triggers `KeDropBanHammer`. The Phase 5c userspace survey resolved to state `ABSENT`: `owinit.owx` is missing or its OWX1 header is not loadable, **and** no emergency image (`owinitv.owx` / `owrs.owx`) is available. There is no user-mode init to enter and no rescue path, so the boot cannot be recovered. |

### Advisory Diagnostic Codes (W+)

Non-fatal. Reported and the boot continues; the code records that the machine is
running in a degraded state.

| Code (Hex) | Name | Triggering Event | Effect |
| :--- | :--- | :--- | :--- |
| `0x0011A805` | `W_OWINIT_EMERGENCY` | Primary userspace orchestrator unusable, emergency userspace available | The Phase 5c survey resolved to state `EMERGENCY`. `owinitv.owx` is entered as `PID 1` in place of `owinit.owx` and spawns `owrs.owx` as the rescue shell through `OW_SYS_PS_SPAWN_OWX`. The boot reaches userspace; the orchestrator did not. |

---

## 3. Emergency Diagnostic Output

When `KeDropBanHammer` executes, it dumps hardware states to the console and UART `0x3F8` using the following exact format:

```text
========================================================================
[FATAL] SYSTEM HALTED
========================================================================
CRITICAL ERROR CODE: U+0011A002 (B_TIER_EXTENSION_VIOLATION)
COMPONENT FAULT: fltrmgr.owc
REASON: Unauthorized driver loaded in Tier 1 space without *.owc signature
STATE DUMP: Saved to openwinkrnl.chk
ACTION: CPU cores frozen via IPI. Lock established.
========================================================================
```
