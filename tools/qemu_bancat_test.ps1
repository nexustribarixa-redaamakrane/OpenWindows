# qemu_bancat_test.ps1 - CPL3 primary-volume read regression (bancat).
#
# Boots one kernel image whose seed writes a real OpenWindows-Essentials
# `bancat.owx` onto the primary OWFS volume under OW_INIT_EXEC_NAME, so the Phase
# 5c survey enters it as PID 1, and writes a protected root-owned crash.bdmp
# alongside it.  bancat then reads the dump through OW_SYS_VFS_READ and decodes
# it, and this script asserts the decoded fields are the fixture's exact values.
#
# Two things are proven at once, and neither would be provable from a stub:
#   * the read path really moves the bytes -- the magic, version, sizes and trap
#     fields can only be printed if OwFsOwfsReadOffset returned the seeded dump;
#   * authority is carried on the process -- bancat runs as a BOOT-subsystem
#     image (UID 0), so the OWFS permission model admits it to a root-owned,
#     OWFS_SEC_HIDDEN file that an ordinary process is refused.
#
# Usage: qemu_bancat_test.ps1 <bancat.bin>
param(
    [Parameter(Mandatory = $true)][string]$BancatImage
)

$ErrorActionPreference = "Stop"

$qemu = $null
$qemuCommand = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if ($qemuCommand) { $qemu = $qemuCommand.Source }
if (-not $qemu) {
    Write-Host "[FAIL] qemu-system-x86_64 not found"
    exit 1
}
if (-not (Test-Path $BancatImage)) { Write-Host "[FAIL] missing image: $BancatImage"; exit 1 }

$work = Join-Path $env:TEMP "openwinkrnl_qemu_bancat"
New-Item -ItemType Directory -Path $work -Force | Out-Null

Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# Record exactly what is being booted.  The flake investigation needs the artifact
# identity pinned to the run, not reconstructed afterwards from a file that a
# later build may have replaced.
$imageSha = (Get-FileHash -LiteralPath $BancatImage -Algorithm SHA256).Hash
$imageSize = (Get-Item -LiteralPath $BancatImage).Length
Write-Host "image:  $BancatImage"
Write-Host "sha256: $imageSha"
Write-Host "size:   $imageSize bytes"

$script:failed = $false
$script:failures = New-Object System.Collections.Generic.List[string]
$port = 14000 + ($PID % 20000)

function Assert-Present {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.Contains($Needle)) { Write-Host "[PASS] $Name" }
    else { Write-Host "[FAIL] $Name -- expected to find: $Needle"; $script:failed = $true; $script:failures.Add($Name) }
}
function Assert-Absent {
    param([string]$Name, [string]$Text, [string]$Needle)
    if ($Text.Contains($Needle)) { Write-Host "[FAIL] $Name -- must NOT contain: $Needle"; $script:failed = $true; $script:failures.Add($Name) }
    else { Write-Host "[PASS] $Name" }
}

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
    $exited = $false
    try {
        while ((Get-Date) -lt $deadline) {
            while ($stream.DataAvailable) {
                $n = $stream.Read($buf, 0, $buf.Length)
                if ($n -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) }
            }
            if ($sb.ToString().Contains($Done)) {
                $matched = $true
                while ($stream.DataAvailable) {
                    $n = $stream.Read($buf, 0, $buf.Length)
                    if ($n -gt 0) { [void]$sb.Append([System.Text.Encoding]::ASCII.GetString($buf, 0, $n)) }
                }
                break
            }
            if ($proc.HasExited) { $exited = $true; break }
            Start-Sleep -Milliseconds 100
        }
    } finally {
        try { $stream.Close(); $client.Close() } catch { }
        if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
    }
    $timedOut = (-not $matched) -and (-not $exited)
    return @{ Text = $sb.ToString(); Matched = $matched;
              TimedOut = $timedOut; Exited = $exited }
}

Write-Host "=== bancat: a real .owx reads crash.bdmp off the primary OWFS volume ==="
$r = Invoke-QemuCase -Image $BancatImage -Done "bancat: done" -TimeoutSeconds 120 -Port $port
$t = $r.Text
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$runId = "$stamp-$PID"
$transcript = Join-Path $work "bancat-$runId.txt"
Set-Content -Path $transcript -Value $t
Set-Content -Path (Join-Path $work "bancat.txt") -Value $t

Write-Host ("qemu: matched={0} timedOut={1} exited={2}" -f $r.Matched, $r.TimedOut, $r.Exited)

if (-not $r.Matched) {
    Write-Host "[FAIL] bancat boot never reached the decoder's terminal line within the timeout"
    $script:failed = $true
    $script:failures.Add("boot never reached 'bancat: done'")
}

Assert-Present "bancat: the decoder was seeded as the init"      $t "[OWBANCAT] test image: seeded bancat.owx"
Assert-Present "bancat: the crash dump was seeded restricted"    $t "[OWBANCAT] test fixture: seeded crash.bdmp"
Assert-Present "bancat: the dump is root-owned, 0600, hidden"    $t "root 0600 hidden"
Assert-Present "bancat: survey resolves to PRIMARY"              $t "-> state PRIMARY"
Assert-Present "bancat: the decoder enters at CPL3 as PID 1"     $t "[OWINIT] owinit entered at CPL3 (PID 1)"
Assert-Present "bancat: the read succeeded"                      $t "bancat: reading crash.bdmp"
Assert-Present "bancat: the file validated as a dump"            $t "bancat: dump OK size=512 version=1"
Assert-Present "bancat: bitmap of the primary bancode"           $t "bancat: primary_bancode=0x000000000000badc cpu=0 traps=2 sentinel=0"
Assert-Present "bancat: the register frame decoded"              $t "bancat: rip=0x0000000000401234 rsp=0x000000000041ff00 cr2=0x0000000000000000 tsc=0x0000000000001234"
Assert-Present "bancat: trap 0 decoded"                          $t "bancat: trap[0] bancode=0x000000000000badc ip=0x0000000000401230"
Assert-Present "bancat: trap 1 decoded"                          $t "bancat: trap[1] bancode=0x000000000000badc ip=0x00000000004011f0"
Assert-Present "bancat: the memory region decoded"               $t "bancat: memory offset=480 size=32"
Assert-Present "bancat: the program ran to completion"           $t "bancat: done"
Assert-Absent  "bancat: the read was not refused"                $t "bancat: read failed"
Assert-Absent  "bancat: the dump was not malformed"              $t "bancat: not a valid .bdmp"
Assert-Absent  "bancat: no critical error"                       $t "CRITICAL ERROR CODE:"

Write-Host ""
if ($script:failed) {
    $failedList = ($script:failures -join "; ")
    $report = @(
        "bancat QEMU regression FAILURE",
        "time   : $stamp",
        "image  : $BancatImage",
        "sha256 : $imageSha",
        "size   : $imageSize bytes",
        "qemu   : matched=$($r.Matched) timedOut=$($r.TimedOut) exited=$($r.Exited)",
        "failed : $failedList",
        "transcript: $transcript"
    ) -join [Environment]::NewLine
    Set-Content -Path (Join-Path $work "bancat-failure-$runId.txt") -Value $report
    Write-Host "=== BANCAT OWFS READ REGRESSION FAILED ==="
    Write-Host "    image    : $BancatImage (sha256 $imageSha)"
    Write-Host "    failed   : $failedList"
    Write-Host "    evidence : $work (bancat.txt, $transcript, qemu_stderr.txt)"
    exit 1
}
Write-Host "=== BANCAT OWFS READ REGRESSION PASSED ==="
exit 0
