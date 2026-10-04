# qemu_run.ps1 - Boot the multiboot kernel under QEMU and validate it
# end-to-end over the serial console.
# The QEMU/floppy TEST images link boot/owinit_seed.o, which provisions a stub
# owinit.owx onto the in-memory OWFS volume, so the Phase 5c owinit gate is
# passed and the boot reaches the interactive shell. This script then drives
# the shell from the terminal (runlevel list, live runlevel set, exit) and
# validates the full transcript. Phase 1 ends in a real ACPI S5 power-off.
# Phase 2 re-boots, arms the userspace-only secret soft power-off screen
# (safeoff on) and proves the kernel parks on "You can safely power off your
# device now." instead of powering the machine down. Production images
# (openwinkrnl.owx / the actual vdi) carry no seed and are validated separately
# by vdi_run.ps1.
#
# -Emergency validates the degraded path instead: an image seeded with
# boot/owinitv_seed.o and boot/owrs_seed.o but NOT owinit_seed.o, so the survey
# finds no usable primary and the kernel must enter owinitv.owx as PID 1, which
# then spawns owrs.owx as an ordinary user-mode child.  The boot machinery below
# is identical -- only the expected transcript differs, because the interesting
# question is which init was chosen and whether the rescue shell came up under
# it, not whether the kernel still reaches its shell.
#
# Usage: qemu_run.ps1 <path-to-openwinkrnl_qemu.bin> [-Emergency]
param(
    [string]$Image,
    [switch]$Emergency
)

$ErrorActionPreference = "Stop"

if (-not $Image) {
    Write-Host "usage: qemu_run.ps1 <flat multiboot image> [-Emergency]"
    exit 1
}
if (-not (Test-Path $Image)) {
    Write-Host "missing file: $Image"
    exit 1
}

$qemu = $null
$qemuCommand = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if ($qemuCommand) { $qemu = $qemuCommand.Source }
if (-not $qemu) {
    Write-Host "qemu-system-x86_64 not found"
    exit 1
}

$work = Join-Path $env:TEMP "openwinkrnl_qemu_test"
New-Item -ItemType Directory -Path $work -Force | Out-Null

# Stray QEMUs from a previous run would steal our serial port.
Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$port = 12000 + ($PID % 20000)

$captured = Join-Path $work "captured.txt"
Remove-Item -Path $captured -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $qemu -ArgumentList @(
    "-kernel", $Image,
    "-nographic", "-monitor", "none",
    "-chardev", "socket,id=com0,port=$port,host=127.0.0.1,server=on,wait=on,ipv4=on",
    "-serial", "chardev:com0",
    "-m", "512M", "-smp", "1", "-no-reboot", "-no-shutdown"
) -NoNewWindow -RedirectStandardError (Join-Path $work "qemu_stderr.txt") -PassThru

$client = $null
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", $port)
        break
    } catch {
        $client = $null
    }
}
if (-not $client) {
    Write-Host "FAILED to connect to QEMU serial"
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    exit 1
}

$stream = $client.GetStream()
$sb = New-Object System.Text.StringBuilder
$buf = New-Object byte[] 8192

function Read-Available {
    while ($stream.DataAvailable) {
        $n = $stream.Read($buf, 0, $buf.Length)
        if ($n -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) }
    }
}

function Wait-For {
    param([string]$Pattern, [int]$Seconds)
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) {
        Read-Available
        if ($sb.ToString() -match $Pattern) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return ($sb.ToString() -match $Pattern)
}

$failed = $false

# --- Emergency: boot and capture only ---------------------------------------
#
# The rest of this section drives the Ring 0 debug shell (auto-init, runlevel
# transitions, rc.d shutdown, ACPI S5, then the safe power-off screen).  That
# self-test is a property of the KERNEL, and the three-state policy does not
# change it -- the same script and the same assertions cover it on the normal
# image.  It is not run against the emergency image because owrs is a rescue
# shell, not owinit: it does not implement the auto-init/runlevel/rc.d/ACPI
# script that the self-test drives, so running it there would test owrs against
# a contract it was never written for.
#
# So the emergency run boots, waits for the rescue shell to prove itself, and
# captures.  The transcript assertions below then run in full and cover the
# emergency contract.  What is NOT covered is the kernel shell self-test, and
# that is stated in the output rather than left to look like a pass.
if ($Emergency) {
    Write-Host "Waiting for the emergency userspace to come up (kernel shell self-test is NOT run; see qemu_run.ps1)..."
    if (-not (Wait-For -Pattern "Type 'help' for the command list\." -Seconds 180)) {
        Write-Host "[FAIL] the rescue shell never announced itself (owinitv did not start owrs)"
        $failed = $true
    }
    # Let the boot settle so the transcript holds the full phase list.  No input
    # is sent: the kernel shell is not what is under test here, and typing at a
    # console the rescue shell is also polling would be meaningless.
    Start-Sleep -Seconds 3
    Read-Available
    Start-Sleep -Milliseconds 500
    $stream.Close(); $client.Close()
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    $out = $sb.ToString()
    Set-Content -Path $captured -Value $out
    $phase1Failed = $failed
    $phase1Out = $out
    $phase2Out = ""
} else {

# 1) Wait for the kernel to finish its auto-init script and reach the
#    interactive shell prompt (the prompt is echoed with no trailing newline).
Write-Host "Waiting for the interactive shell prompt..."
if (-not (Wait-For -Pattern "ow-krnl> \z" -Seconds 120)) {
    Write-Host "[FAIL] shell never reached interactive prompt (boot did not pass owinit gate)"
    $failed = $true
}

# 2) Drive the shell from the terminal: list runlevels, switch to level 3,
#    then cleanly exit.
if (-not $failed) {
    Write-Host "Sending: runlevel list"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("runlevel list`r`n")
    $stream.Write($bytes, 0, $bytes.Length)
    if (-not (Wait-For -Pattern "profile: level 6, name REBOOT" -Seconds 40)) {
        Write-Host "[FAIL] 'runlevel list' did not complete"
        $failed = $true
    }
}
if (-not $failed) {
    Write-Host "Sending: runlevel set 3"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("runlevel set 3`r`n")
    $stream.Write($bytes, 0, $bytes.Length)
    if (-not (Wait-For -Pattern "transition complete -> level 3 \(NETWORK\)" -Seconds 40)) {
        Write-Host "[FAIL] 'runlevel set 3' did not complete"
        $failed = $true
    }
}
if (-not $failed) {
    Write-Host "Sending: exit"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("exit`r`n")
    $stream.Write($bytes, 0, $bytes.Length)
    if (-not (Wait-For -Pattern "\[SHUTDOWN\] Exiting\.\.\." -Seconds 40)) {
        Write-Host "[FAIL] 'exit' did not shut down the shell"
        $failed = $true
    }
}

# 3) After the shell exits, the kernel runs the rc.d shutdown sequence and
#    issues the software ACPI S5 power-off (QEMU then exits).
if (-not $failed) {
    Write-Host "Waiting for RC shutdown sequence + ACPI S5 power-off..."
    if (-not (Wait-For -Pattern "\[ACPI\] software power-off \(S5\)" -Seconds 60)) {
        Write-Host "[FAIL] ACPI software power-off (S5) never reached"
        $failed = $true
    }
}

Read-Available
Start-Sleep -Milliseconds 500
Set-Content -Path $captured -Value $sb.ToString()
$stream.Close(); $client.Close()
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
$phase1Failed = $failed
$phase1Out = $sb.ToString()

# 4) Secret soft power-off screen. Relaunch, arm the screen through the Ring 3
#    gateway (safeoff on), then exit: the kernel must park on the safe
#    power-off screen instead of issuing a hardware S5 power-off.
Write-Host "=== Phase 2: secret soft power-off screen ==="
$failed = $false
$sb.Clear() | Out-Null
$proc = Start-Process -FilePath $qemu -ArgumentList @(
    "-kernel", $Image,
    "-nographic", "-monitor", "none",
    "-chardev", "socket,id=com0,port=$port,host=127.0.0.1,server=on,wait=on,ipv4=on",
    "-serial", "chardev:com0",
    "-m", "512M", "-smp", "1", "-no-reboot", "-no-shutdown"
) -NoNewWindow -RedirectStandardError (Join-Path $work "qemu_stderr.txt") -PassThru

$client = $null
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 250
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect("127.0.0.1", $port)
        break
    } catch {
        $client = $null
    }
}
if (-not $client) {
    Write-Host "FAILED to connect to QEMU serial (phase 2)"
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    exit 1
}
$stream = $client.GetStream()

if (-not (Wait-For -Pattern "ow-krnl> \z" -Seconds 120)) {
    Write-Host "[FAIL] phase 2: prompt never reached"
    $failed = $true
}
if (-not $failed) {
    Write-Host "Sending: safeoff on"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("safeoff on`r`n")
    $stream.Write($bytes, 0, $bytes.Length)
    if (-not (Wait-For -Pattern "\[ACPI\] safe power-off screen: armed" -Seconds 40)) {
        Write-Host "[FAIL] phase 2: safeoff gateway acknowledge missing"
        $failed = $true
    }
}
if (-not $failed) {
    Write-Host "Sending: exit"
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("exit`r`n")
    $stream.Write($bytes, 0, $bytes.Length)
    if (-not (Wait-For -Pattern "\[SHUTDOWN\] Exiting\.\.\." -Seconds 40)) {
        Write-Host "[FAIL] phase 2: exit did not shut down"
        $failed = $true
    }
}
if (-not $failed) {
    Write-Host "Waiting for the safe power-off screen..."
    if (-not (Wait-For -Pattern "You can safely power off your device now\." -Seconds 60)) {
        Write-Host "[FAIL] phase 2: safe power-off screen never reached"
        $failed = $true
    }
}

Read-Available
Start-Sleep -Milliseconds 500
$stream.Close(); $client.Close()
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
$phase2Out = $sb.ToString()
Add-Content -Path $captured -Value $phase2Out

} # end of: kernel shell self-test (skipped on the emergency image)

$out = $phase1Out + $phase2Out

# The kernel shell self-test lines only exist if that self-test ran, which it does
# not on the emergency image (see the block above).  Keeping them in the list
# unconditionally would report a clean emergency boot as a pile of failures for
# steps that were deliberately skipped; dropping them silently would look like
# coverage.  So the list is built from what the run was actually supposed to do.
$checks = @("[STARTED] HAL Init")
if (-not $Emergency) {
    $checks += @(
        "OpenWindows DEBUG SYSTEM CONTROL SHELL",
        "profile: level 3, name NETWORK",
        "transition complete -> level 3 (NETWORK)",
        "[SHUTDOWN] Exiting...",
        "[RC] running shutdown sequence (OpenWindows-Essentials rc.d)",
        "[RC] rc.shutdown:",
        "[SHUTDOWN] System halted.",
        ":: System safely halted.",
        "[ACPI] software power-off (S5)",
        "[ACPI] safe power-off screen: armed",
        "You can safely power off your device now."
    )
}

# The init-image lines differ by state, and asserting the wrong set is worse than
# asserting nothing: on the emergency image the owinit lines are simply absent, so
# a shared list would report a clean emergency boot as a failure, and a relaxed
# "was there any init" check would pass on a boot that entered nothing.
#
# The survey line is the one that matters most, and it is asserted per state
# rather than loosely: it is the kernel's own record of which images it found and
# which verdict it reached, so it distinguishes "the emergency images were on the
# volume and were used" from "the emergency images happened to be loadable".
if ($Emergency) {
    $checks += @(
        "[OWINITV] test image: seeded owinitv.owx",
        "[OWRS] test image: seeded owrs.owx",
        "[OWINIT] userspace survey: primary(unusable) owinitv(ok) owrs(ok) -> state EMERGENCY",
        "[OWINIT] state EMERGENCY: owinitv.owx is PID 1",
        "[OWINIT] owinitv will spawn owrs.owx (rescue shell available)"
    )
    # owinitv is PID 1, so the thread-1 entry lines are prefixed "[PS] owinitv".
    $initPrefix = "owinitv"
} else {
    $checks += @(
        "[OWINIT] test image: seeded Essentials owinit.owx",
        "[OWINIT] userspace survey: primary(ok) owinitv(ok) owrs(ok) -> state PRIMARY",
        "[OWINIT] state PRIMARY: owinit.owx is PID 1"
    )
    $initPrefix = "owinit"
}

# --- CPL3 init launch chain (regression) -----------------------------------
# These lines only appear together if the whole chain is correct:
#   loader charged private frames and relocated the entry,
#   the window audit saw only NX data pages,
#   the thread was actually entered at CPL3, and
#   the entry's `ret` found the seeded C-ABI return slot, ran the private exit
#   trampoline, and left through int 0x80 (the [EX] tid= line).
$checks += @(
    "[PS] $initPrefix image loaded:",
    "image entered at CPL3"
)

# The exit line is state-specific and asserting it in the wrong state is a false
# failure, not a missed one.  owinit hands control back through int 0x80 once its
# script finishes ([EX] tid=1).  owinitv is PID 1 and by design never exits -- it
# parks and stays resident so the rescue shell it spawned has an owner -- so there
# is no exit line to find and none is expected.
if (-not $Emergency) {
    $checks += "[EX] tid=1"
}

# The window audit for the loaded image must report zero violations: every
# non-code page execute-disabled and NXE on.
#
# The exact page counts are a property of one particular owinit.owx, not of the
# loader: relinking it moves them (static dependencies grow .text and .bss, and
# owinit's BSS is already the bulk of its pages).  So assert the invariants
# instead of one build's numbers, against the audit that follows the
# "owinit image loaded" line specifically rather than whichever audit appears
# first in the log.
#
# This is stronger than the fixed count it replaces, not weaker.  A fixed total
# still passes if one data page silently stopped being NX while another page
# appeared elsewhere, because only the sum is pinned.  Requiring
# code + nx == VADs, with NXE on and zero violations, pins every page
# individually.
$loadIdx = $out.IndexOf("[PS] $initPrefix image loaded:")
$audit = $null
if ($loadIdx -ge 0) {
    $audit = [regex]::Match($out.Substring($loadIdx),
        '\[AUDIT\] user window 4000000-4200000: (\d+) VAD\(s\), (\d+) guard VAD\(s\), (\d+) code page\(s\), (\d+) NX data page\(s\), NXE=(\d+), violations=(\d+)')
}
if ($audit.Success) {
    $vads      = [int]$audit.Groups[1].Value
    $codePages = [int]$audit.Groups[3].Value
    $nxPages   = [int]$audit.Groups[4].Value
    $nxe       = [int]$audit.Groups[5].Value
    $violations= [int]$audit.Groups[6].Value
    if ($nxe -eq 1 -and $violations -eq 0 -and $codePages -ge 1 -and
        $nxPages -ge 1 -and ($codePages + $nxPages) -eq $vads) {
        Write-Host "[PASS] $initPrefix image audit: $codePages code + $nxPages NX data = $vads VAD(s), NXE=1, 0 violations"
    } else {
        Write-Host "[FAIL] $initPrefix image audit: NXE=$nxe violations=$violations code=$codePages nx=$nxPages vads=$vads (need NXE=1, violations=0, code>=1, nx>=1, code+nx==vads)"
        $failed = $true
    }
} else {
    Write-Host "[FAIL] no $initPrefix window-audit line after the image-load line"
    $failed = $true
}

# Native-entry hardening: prove the *real* init entry was entered, not merely
# that some entry ran at ring 3.
#
# Two traps this has to avoid:
#
#  1. "image entered at CPL3" only proves control reached Proc->EntryPoint.  The
#     stub satisfies it identically, so it cannot tell the two apart.
#  2. user-hello is also entered at 0x4000000, in its own process.  A bare
#     address match (or an unprefixed "image entered at CPL3") is therefore
#     ambiguous, and would keep passing even if the init never ran at all.
#
# So every field below is matched from an explicitly "[PS] <init>"-prefixed
# line, and the three init lines are then cross-checked against each other:
# the loader's entry, the entry the thread was created with, and the stack the
# thread actually entered on must all agree.  A user-hello line cannot satisfy
# any of them -- it is thread 2 on a different stack.
#
# The authoritative stub-vs-real decision is still the byte-level one in
# hosttest and check_owx_entries.py, which read the entry instruction out of the
# shipped image.  This is the runtime half.
$ip = [regex]::Escape($initPrefix)
$initLoadedEntry = $null; $initLoadedExit = $null
$initThreadEntry = $null; $initThreadStack = $null
$initEnterRsp = $null; $initEnterExit = $null

if ($out -match "\[PS\] $ip image loaded:.*?entry (0x[0-9A-Fa-f]+).*?exit (0x[0-9A-Fa-f]+)") {
    $initLoadedEntry = $Matches[1]; $initLoadedExit = $Matches[2]
}
if ($out -match "\[PS\] $ip`: USER thread (\d+) created, ring3 entry (0x[0-9A-Fa-f]+) stack (0x[0-9A-Fa-f]+)") {
    $initThreadId = $Matches[1]; $initThreadEntry = $Matches[2]; $initThreadStack = $Matches[3]
}
if ($out -match "\[PS\] $ip`: image entered at CPL3, rsp (0x[0-9A-Fa-f]+), exit (0x[0-9A-Fa-f]+)") {
    $initEnterRsp = $Matches[1]; $initEnterExit = $Matches[2]
}

if ($initLoadedEntry -and $initThreadEntry -and $initEnterRsp) {
    # The init runs as thread 1; user-hello is thread 2 on a different stack.
    if ($initThreadId -eq "1") {
        Write-Host "[PASS] $initPrefix runtime lines are thread 1 (not user-hello thread 2)"
    } else {
        Write-Host "[FAIL] $initPrefix runtime lines are thread '$initThreadId', expected 1"
        $failed = $true
    }

    if ($initLoadedEntry -eq $initThreadEntry) {
        Write-Host "[PASS] $initPrefix loader and thread agree on entry $($initLoadedEntry)"
    } else {
        Write-Host "[FAIL] $initPrefix loader entry '$initLoadedEntry' != thread entry '$initThreadEntry'"
        $failed = $true
    }

    if ($initThreadStack -eq $initEnterRsp) {
        Write-Host "[PASS] $initPrefix entered CPL3 on its seeded stack top $initThreadStack"
    } else {
        Write-Host "[FAIL] $initPrefix seeded stack $initThreadStack != entered rsp $initEnterRsp"
        $failed = $true
    }

    if ($initLoadedExit -eq $initEnterExit) {
        Write-Host "[PASS] $initPrefix entered with the loader's exit trampoline $($initLoadedExit)"
    } else {
        Write-Host "[FAIL] $initPrefix loader exit '$initLoadedExit' != entered exit '$initEnterExit'"
        $failed = $true
    }

    # Tripwire only, and only for the primary image.  The stub was at 0x4000AC0
    # while it was the entry; that is layout-dependent, so a relink that moves
    # code fails the agreement checks above loudly rather than letting a stub
    # slip through as 0x4000000.  The emergency images have no stub to detect --
    # they are real programs -- so pinning them to a stale address would only
    # break them on the next relink.
    if ($initLoadedEntry -ne "0x4000AC0") {
        Write-Host "[PASS] $initPrefix entry is not the stub's former address 0x4000AC0"
    } else {
        Write-Host "[FAIL] $initPrefix entry is 0x4000AC0 -- the owx_entry_stub address"
        $failed = $true
    }
} else {
    Write-Host "[FAIL] could not parse the [PS] $initPrefix load/thread/enter lines"
    $failed = $true
}

# The degraded path's own promise: the rescue shell is started by owinitv, as an
# ordinary user-mode child, through OW_SYS_PS_SPAWN_OWX.  This is the one thing
# state 2 exists to deliver, so a state-2 boot that entered owinitv and stopped
# there has failed even though every check above passed -- the kernel did its
# half correctly and the userspace half silently did not run.
#
# The banner is the evidence, and it is user-mode output: it is printed by the
# running owrs process, so seeing it means the spawn crossed the privilege
# boundary, the second image loaded through the same loader the kernel used, and
# the shell actually got CPU.  The PID in the banner is matched non-specifically
# because it is an allocator detail, not a contract.
if ($Emergency) {
    $spawnChecks = @(
        "owinitv.owx has been entered as PID 1 instead.",
        "owinitv: rescue shell (owrs.owx) started as PID",
        "Type 'help' for the command list."
    )
    foreach ($c in $spawnChecks) {
        if ($out.Contains($c)) { Write-Host "[PASS] rescue chain: $c" }
        else { Write-Host "[FAIL] rescue chain: $c"; $failed = $true }
    }

    # The emergency init must not claim the primary came up, and the survey must
    # not claim a primary it does not have.  Asserting only the positive would
    # let a boot that somehow entered BOTH inits pass.
    foreach ($c in @("[OWINIT] state PRIMARY: owinit.owx is PID 1",
                     "owinit.owx was missing or unusable")) {
        if ($out.Contains($c)) { Write-Host "[FAIL] unexpected on emergency image: $c"; $failed = $true }
        else { Write-Host "[PASS] no '$c'" }
    }
}

foreach ($c in $checks) {
    if ($out.Contains($c)) { Write-Host "[PASS] $c" }
    else { Write-Host "[FAIL] $c"; $failed = $true }
}

# A seeded test image must never hit the fatal owinit halt.  This holds for the
# emergency image too, and is the sharper assertion there: state 2 exists so
# that a machine with a damaged orchestrator does NOT halt, so U+11A005 appearing
# in an emergency boot means the survey picked state 3 over a volume that had a
# usable owinitv.
$neg = @("CRITICAL ERROR CODE: U+11A005", "[FATAL] SYSTEM HALTED", "[FAIL] owinit")

# Regression: an unseeded user resume slot makes the entry's `ret` pop 0, which
# faults fetching at address 0.  That exact signature must never reappear.
$neg += @("cr2=0 rip=0")

# Regression: the guard band belongs to the process stack, so a healthy launch
# must not trip it.
$neg += @("[PF] GUARD")

# Regression: two or more resident CPL3 processes make the scheduler preempt a
# Ring 3 thread inside its own syscall.  OwPsFrameToContext then stamps that
# thread's Context.Cs with the CPL0 value, and a resume that keys TSS.RSP0 off
# Context.Cs silently skips it, leaving RSP0 on a different thread's stack.  The
# next trap then runs on that foreign stack, the two frames overlap, and the
# corrupted register faults in the kernel.  Any Ring 0 page fault is a failure.
$neg += @("[PF] KERNEL")

foreach ($c in $neg) {
    if ($out.Contains($c)) { Write-Host "[FAIL] unexpected: $c"; $failed = $true }
    else { Write-Host "[PASS] no '$c'" }
}

# The armed soft power-off screen must never reach a hardware S5 power-off or
# any fatal halt in its own transcript.  Skipped on the emergency image, which has
# no phase 2.
if (-not $Emergency) {
    $neg2 = @("[ACPI] software power-off (S5)", "CRITICAL ERROR CODE:", "[FATAL] SYSTEM HALTED")
    foreach ($c in $neg2) {
        if ($phase2Out.Contains($c)) { Write-Host "[FAIL] phase 2 unexpected: $c"; $failed = $true }
        else { Write-Host "[PASS] phase 2 no '$c'" }
    }
}

Write-Host ""
if ($phase1Failed -or $failed) {
    Write-Host "=== QEMU BOOT VALIDATION FAILED (see $captured) ==="
    exit 1
}
if ($Emergency) {
    Write-Host "=== QEMU EMERGENCY VALIDATION PASSED ($($checks.Count) checks) ==="
    Write-Host "    NOTE: the Ring 0 kernel shell self-test (auto-init, runlevel, rc.d,"
    Write-Host "    ACPI S5, safe power-off) was NOT run against this image.  It is"
    Write-Host "    covered by 'make qemu' on the normal image.  The emergency image"
    Write-Host "    carries owrs, a rescue shell that does not implement the"
    Write-Host "    auto-init/runlevel/rc.d script, so the self-test is out of scope"
    Write-Host "    here.  The scheduler runs three concurrent CPL3 processes here,"
    Write-Host "    which the normal image does not, and the transcript is asserted"
    Write-Host "    free of any Ring 0 page fault."
    exit 0
}
Write-Host "=== QEMU BOOT VALIDATION PASSED ($($checks.Count) checks) ==="
exit 0