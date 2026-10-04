# fda_run.ps1 - Boot the VirtualBox floppy image under QEMU (-fda) and validate
# it end-to-end over the serial console. This proves the stage1.S boot sector +
# flat kernel layout boots identically to the -kernel multiboot path.
# The floppy is a TEST image: it links boot/owinit_seed.o, which provisions a
# the Essentials owinit.owx onto the in-memory OWFS volume, so the Phase 5c owinit gate
# is passed and the boot reaches the interactive shell. This script drives the
# shell from the terminal (runlevel list, live runlevel set, exit) and
# validates the transcript. The actual vdi (production, no seed) is validated
# separately by vdi_run.ps1.
# Usage: fda_run.ps1 <path-to-owx_boot.flp>
param([string]$Floppy)

if (-not $Floppy) {
    Write-Host "usage: fda_run.ps1 <floppy image>"
    exit 1
}
if (-not (Test-Path $Floppy)) {
    Write-Host "missing file: $Floppy"
    exit 1
}

$qemuCommand = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if (-not $qemuCommand) {
    Write-Host "qemu-system-x86_64 not found; add QEMU to PATH"
    exit 1
}
$qemu = $qemuCommand.Source

$work = Join-Path $env:TEMP "openwinkrnl_fda_test"
New-Item -ItemType Directory -Path $work -Force | Out-Null

Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$port = 12000 + ($PID % 20000)

$captured = Join-Path $work "captured.txt"
Remove-Item -Path $captured -ErrorAction SilentlyContinue

$proc = Start-Process -FilePath $qemu -ArgumentList @(
    "-fda", $Floppy,
    "-boot", "a",
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

# 1) Wait for the kernel to finish its auto-init script and reach the
#    interactive shell prompt.
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

$out = $sb.ToString()
$checks = @(
    "[STARTED] HAL Init",
    "[OWINIT] test image: seeded Essentials owinit.owx",
    "[OWINIT] Root orchestrator executable owinit.owx located",
    "OpenWindows DEBUG SYSTEM CONTROL SHELL",
    "profile: level 3, name NETWORK",
    "transition complete -> level 3 (NETWORK)",
    "[SHUTDOWN] Exiting...",
    "[RC] running shutdown sequence (OpenWindows-Essentials rc.d)",
    "[RC] rc.shutdown:",
    "[SHUTDOWN] System halted.",
    ":: System safely halted.",
    "[ACPI] software power-off (S5)"
)
foreach ($c in $checks) {
    if ($out.Contains($c)) { Write-Host "[PASS] $c" }
    else { Write-Host "[FAIL] $c"; $failed = $true }
}

# A seeded test image must never hit the fatal owinit halt.
$neg = @("CRITICAL ERROR CODE: U+11A005", "[FATAL] SYSTEM HALTED", "[FAIL] owinit")
foreach ($c in $neg) {
    if ($out.Contains($c)) { Write-Host "[FAIL] unexpected: $c"; $failed = $true }
    else { Write-Host "[PASS] no '$c'" }
}

Write-Host ""
if ($failed) {
    Write-Host "=== FLOPPY BOOT VALIDATION FAILED (see $captured) ==="
    exit 1
}
Write-Host "=== FLOPPY BOOT VALIDATION PASSED ($($checks.Count) checks) ==="
exit 0