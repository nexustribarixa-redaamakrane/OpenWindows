# vdi_run.ps1 - Boot the OpenWindows VDI under QEMU and validate it
# end-to-end. The kernel ships WITHOUT the Tier-3 userspace orchestrator
# owinit.owx, so a stock VDI boot must reach the Phase 5c owinit provisioning
# gate and halt with [FATAL] SYSTEM HALTED / U+11A005 rather than booting to
# the shell. Runs headless (-display none), in the foreground.
#
# Usage: pwsh -File tools/vdi_run.ps1 <path-to.vdi>
param(
    [Parameter(Mandatory = $true)] [string]$Vdi,
    [string]$Qemu
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Vdi -PathType Leaf)) {
    Write-Host "VDI not found: $Vdi"
    exit 1
}

if (-not $Qemu) {
    $installedQemu = "C:\Program Files\qemu\qemu-system-x86_64.exe"
    if (Test-Path -LiteralPath $installedQemu -PathType Leaf) {
        $Qemu = $installedQemu
    } else {
        $qemuCommand = Get-Command "qemu-system-x86_64.exe" -ErrorAction SilentlyContinue
        if ($qemuCommand) { $Qemu = $qemuCommand.Source }
    }
}
if (-not $Qemu -or -not (Test-Path -LiteralPath $Qemu -PathType Leaf)) {
    Write-Host "qemu-system-x86_64 not found; pass -Qemu <path> or add QEMU to PATH"
    exit 1
}

$dir = Join-Path $env:TEMP "openwinkrnl_vdi_test"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$cap = Join-Path $dir "captured.txt"
$err = Join-Path $dir "qemu_stderr.txt"
if (Test-Path $cap) { Remove-Item $cap -Force }

$port = 12000 + (Get-Random -Maximum 20000)
$args = @(
    "-drive", "file=$Vdi,format=vdi,if=ide",
    "-boot", "order=c",
    "-serial", "file:$cap",
    "-m", "512M",
    "-smp", "1",
    "-no-reboot", "-no-shutdown",
    "-display", "none"
)

$proc = Start-Process -FilePath $Qemu -ArgumentList $args -PassThru -NoNewWindow -RedirectStandardError $err

try {

# The kernel ships without owinit, so no input is needed: it self-runs its
# init diagnostics until the Phase 5c owinit gate halts the machine. Poll the
# serial capture instead of relying on a single fixed boot duration.
$deadline = (Get-Date).AddSeconds(180)
$foundHalt = $false
while ((Get-Date) -lt $deadline -and -not $foundHalt) {
    Start-Sleep -Milliseconds 500
    $out = if (Test-Path $cap) { Get-Content -Raw $cap } else { "" }
    $foundHalt = $out -match "CRITICAL ERROR CODE: U\+0*11A005" -and
                 $out -match "\[FATAL\] SYSTEM HALTED"
    if ($proc.HasExited) { break }
}

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
$out = if (Test-Path $cap) { Get-Content -Raw $cap } else { "" }

$checks = @(
    "[STARTED] HAL Init",
    "[FAIL] owinit",
    # The production VDI carries no userspace images at all, so the survey must
    # reach state ABSENT -- not "primary missing but a fallback was available",
    # which is state EMERGENCY and would be a completely different boot.  These
    # two lines are what prove the halt was a deliberate policy decision rather
    # than a failure to find anything at all.
    "userspace survey: primary(unusable) owinitv(unusable) owrs(unusable) -> state ABSENT",
    "state ABSENT: no usable owinit and no emergency userspace",
    "CRITICAL ERROR CODE: U+11A005",
    "[FATAL] SYSTEM HALTED",
    "REASON: owinit.owx missing or unusable and no emergency userspace",
    "STATE DUMP: Collection was not requested."
)

$failed = $false
foreach ($c in $checks) {
    if ($out.Contains($c)) {
        Write-Host "[PASS] $c"
    } else {
        Write-Host "[FAIL] $c"
        $failed = $true
    }
}

if ($failed) {
    Write-Host "=== VDI OWINIT HALTS AS REQUIRED - VALIDATION FAILED (see $cap) ==="
    exit 1
}
Write-Host "=== VDI OWINIT GATE VALIDATION PASSED ($($checks.Count) checks) ==="
exit 0
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}
