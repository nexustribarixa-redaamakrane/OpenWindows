# qemu_provenance_test.ps1 - two-case kernel provenance/licence regression.
#
# Boots two otherwise-identical kernel images, each carrying a signed
# openwinkrnl.owx and its matching openwinkrnl.chk, through the real Phase 5d
# path (OwSentinelVerifyKernelProvenanceFromVolume), and checks the outcome the
# CORE_KERNEL policy demands:
#
#   control  CORE_KERNEL / GPL-3.0-or-later  -> CIS TRUSTED, boot reaches the
#                                               shell hand-off.
#   denied   CORE_KERNEL / Apache-2.0        -> CIS refuses the licence, the
#                                               sentinel reports a critical
#                                               provenance/licence failure, and
#                                               the kernel halts before the shell
#                                               hand-off.
#
# Both cases must pass the checksum check first: a mismatch there would halt for
# the wrong reason and prove nothing about the provenance decision, so the
# negative case asserting "integrity verified" is what isolates the licence
# verdict being tested.
#
# This is deliberately NOT qemu_run.ps1.  That script asserts the healthy
# transcript of the normal image and drives the interactive kernel shell; here
# one case is expected to halt, so the expected transcript is a different shape
# and the assertions say so explicitly instead of leaning on a general validator.
#
# Usage: qemu_provenance_test.ps1 <control.bin> <denied.bin>
param(
    [Parameter(Mandatory = $true)][string]$ControlImage,
    [Parameter(Mandatory = $true)][string]$DeniedImage
)

$ErrorActionPreference = "Stop"

$qemu = $null
$qemuCommand = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if ($qemuCommand) { $qemu = $qemuCommand.Source }
if (-not $qemu) {
    Write-Host "[FAIL] qemu-system-x86_64 not found"
    exit 1
}
foreach ($img in @($ControlImage, $DeniedImage)) {
    if (-not (Test-Path $img)) { Write-Host "[FAIL] missing image: $img"; exit 1 }
}

$work = Join-Path $env:TEMP "openwinkrnl_qemu_prov"
New-Item -ItemType Directory -Path $work -Force | Out-Null

# Stray QEMUs from a previous run would steal the serial port.
Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

$script:failed = $false
$basePort = 12000 + ($PID % 20000)

function Assert-Present {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.Contains($Needle)) { Write-Host "[PASS] $Name" }
    else { Write-Host "[FAIL] $Name -- expected to find: $Needle"; $script:failed = $true }
}
function Assert-Absent {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.Contains($Needle)) { Write-Host "[FAIL] $Name -- must NOT contain: $Needle"; $script:failed = $true }
    else { Write-Host "[PASS] $Name" }
}

# Boot one image, stream its serial output, and return the transcript.  $Done is
# the substring that marks the run's terminal state (the shell hand-off for the
# control, the halt banner for the denied case); it bounds the wait so a boot
# that never gets there fails rather than hanging forever.
function Invoke-QemuCase {
    param([string]$Image, [string]$Done, [int]$TimeoutSeconds, [int]$Port)

    $proc = Start-Process -FilePath $qemu -ArgumentList @(
        "-kernel", $Image, "-nographic", "-monitor", "none",
        "-chardev", "socket,id=com0,port=$Port,host=127.0.0.1,server=on,wait=on,ipv4=on",
        "-serial", "chardev:com0",
        "-m", "512M", "-smp", "1", "-no-reboot", "-no-shutdown"
    ) -NoNewWindow -RedirectStandardError (Join-Path $work "qemu_stderr.txt") -PassThru

    $client = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 250
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect("127.0.0.1", $Port)
            break
        } catch { $client = $null }
    }
    if (-not $client) {
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
        throw "could not connect to the QEMU serial console for $Image"
    }

    $stream = $client.GetStream()
    $sb = New-Object System.Text.StringBuilder
    $buf = New-Object byte[] 8192
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $matched = $false
    try {
        while ((Get-Date) -lt $deadline) {
            while ($stream.DataAvailable) {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) }
            }
            if ($sb.ToString().Contains($Done)) {
                $matched = $true
                # Drain whatever the terminal state flushed right after the marker.
                Start-Sleep -Milliseconds 500
                while ($stream.DataAvailable) {
                    $n = $stream.Read($buf, 0, $buf.Length)
                    if ($n -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) }
                }
                break
            }
            if ($proc.HasExited) { break }
            Start-Sleep -Milliseconds 100
        }
    } finally {
        try { $stream.Close(); $client.Close() } catch { }
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    }
    return @{ Text = $sb.ToString(); Matched = $matched; Exited = $proc.HasExited }
}

# ---------------------------------------------------------------------------
# Case A (control): a correctly signed CORE_KERNEL / GPL-3.0-or-later artifact.
# ---------------------------------------------------------------------------
Write-Host "=== Case A (control): CORE_KERNEL / GPL-3.0-or-later -- must be trusted ==="
$a = Invoke-QemuCase -Image $ControlImage -Done "[INIT] handing off to shell" `
                     -TimeoutSeconds 120 -Port $basePort
$ta = $a.Text
Set-Content -Path (Join-Path $work "control.txt") -Value $ta

if (-not $a.Matched) {
    Write-Host "[FAIL] control boot never reached the shell hand-off within the timeout"
    $script:failed = $true
}
Assert-Present "control: provenance fixture seeded onto the volume" $ta "[KPROV] test volume: seeded openwinkrnl.owx"
Assert-Present "control: kernel integrity verified (checksum OK)"   $ta "Kernel integrity verified via openwinkrnl.chk:"
Assert-Absent  "control: no checksum mismatch"                      $ta "SHA-256 checksum mismatch"
Assert-Present "control: CIS trusts the artifact"                   $ta "[CIS] openwinkrnl.owx: TRUSTED"
Assert-Present "control: GPL CORE_KERNEL policy verified"           $ta "Kernel provenance & CORE_KERNEL GPL policy verified (OK)"
Assert-Present "control: sentinel records provenance verified"      $ta "[SENT] kernel provenance verified (openwinkrnl.owx)"
Assert-Present "control: boot reaches the shell hand-off"           $ta "[INIT] handing off to shell 'sh' as init process..."
Assert-Absent  "control: no fatal halt"                             $ta "[FATAL] SYSTEM HALTED"
Assert-Absent  "control: no critical error code"                    $ta "CRITICAL ERROR CODE:"

# ---------------------------------------------------------------------------
# Case B (denied): the same image under a licence CORE_KERNEL refuses.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Case B (denied): CORE_KERNEL / Apache-2.0 -- must be refused ==="
$b = Invoke-QemuCase -Image $DeniedImage -Done "[FATAL] SYSTEM HALTED" `
                     -TimeoutSeconds 120 -Port ($basePort + 1)
$tb = $b.Text
Set-Content -Path (Join-Path $work "denied.txt") -Value $tb

if (-not $b.Matched) {
    Write-Host "[FAIL] denied boot never reached the halt within the timeout"
    $script:failed = $true
}
Assert-Present "denied: provenance fixture seeded onto the volume"  $tb "[KPROV] test volume: seeded openwinkrnl.owx"
Assert-Present "denied: the integrity phase ran"                    $tb "[STARTED] Kernel Integrity"
Assert-Present "denied: kernel integrity verified (checksum OK)"    $tb "Kernel integrity verified via openwinkrnl.chk:"
Assert-Absent  "denied: no checksum mismatch (isolation holds)"     $tb "SHA-256 checksum mismatch"
Assert-Present "denied: CIS refuses the licence specifically"       $tb "[CIS] policy refused: CORE_KERNEL requires GPL-3.0-or-later"
Assert-Present "denied: artifact refused by policy"                 $tb "[CIS] openwinkrnl.owx refused: policy refused"
Assert-Present "denied: critical provenance/licence failure"        $tb "kernel provenance/license policy failed: POLICY-REFUSED"
Assert-Present "denied: system halts"                               $tb "[FATAL] SYSTEM HALTED"
Assert-Present "denied: halt reports a critical error code"         $tb "CRITICAL ERROR CODE:"
Assert-Absent  "denied: shell hand-off is never reached"            $tb "[INIT] handing off to shell"
Assert-Absent  "denied: interactive shell prompt is never reached"  $tb "ow-krnl>"

# ---------------------------------------------------------------------------
Write-Host ""
if ($script:failed) {
    Write-Host "=== KERNEL PROVENANCE REGRESSION FAILED ==="
    Write-Host "    transcripts kept in $work (control.txt, denied.txt)"
    exit 1
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host "=== KERNEL PROVENANCE REGRESSION PASSED (control trusted, denied refused) ==="
exit 0
