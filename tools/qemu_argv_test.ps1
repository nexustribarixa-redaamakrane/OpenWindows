# qemu_argv_test.ps1 - five-case CPL3 argument-vector regression.
#
# Boots three otherwise-identical kernel images whose seed writes a real
# OpenWindows-Essentials `.owx` onto the volume under OW_INIT_EXEC_NAME, so the
# Phase 5c survey enters it as PID 1.  The images differ only in the program
# seeded and the argument vector baked into core/main.c by the probe variant each
# links:
#
#   multi   owsh.owx      argc = 4, argv = { owsh, --probe, "hello world",
#                                         "two words" }
#   zero    owsh.owx      argc = 0, no argv[] block at all
#   kconf   kconfctl.owx  argv = { kconfctl, get, kernel/panic/action }, which
#                         must print the built-in default at CPL3
#   kconfset  kconfctl.owx     argv = { kconfctl, set, ui/wm/theme, custom_at_cpl3 }
#   banhammer banhammer_cli.owx argv = { banhammer_cli, quote, sarcastic, 1 },
#                              whose output is the panic-text table entry the
#                              seed selects, so it is checked against that table
#
# The kconfctl and banhammer_cli cases matter because those programs compute
# their answer from the argv (a config lookup, a seeded table lookup) rather than
# printing a constant, so the argv is proven to reach a program whose answer
# depends on it, not merely a stub.,
#                         which must set and read the value back before it
#                         reports success (kconfctl verifies the write landed)
#
# Together they prove the Microsoft x64 process-entry contract (RCX = argc,
# RDX = argv, R8 = envp) end to end: boot_launch_init() builds the initial stack,
# the kernel stamps the registers under OwPsStampEntryArgs, and real Ring 3 code
# reads the argument vector it was handed.  The kconfctl cases exercise a program
# whose answer depends on argv plus a statically linked library, not on a stub.
#
# Do not read "MS x64" as "SysV": this kernel delivers arguments in RCX/RDX/R8,
# the registers a MinGW-built image actually reads.  Stamping RDI/RSI instead is
# exactly the bug the register host test guards against.
#
# Usage: qemu_argv_test.ps1 <multi.bin> <zero.bin> <kconf.bin> <kconfset.bin> <banhammer.bin>
param(
    [Parameter(Mandatory = $true)][string]$MultiImage,
    [Parameter(Mandatory = $true)][string]$ZeroImage,
    [Parameter(Mandatory = $true)][string]$KconfImage,
    [Parameter(Mandatory = $true)][string]$KconfSetImage,
    [Parameter(Mandatory = $true)][string]$BanhammerImage
)

$ErrorActionPreference = "Stop"

$qemu = $null
$qemuCommand = Get-Command "qemu-system-x86_64" -ErrorAction SilentlyContinue
if ($qemuCommand) { $qemu = $qemuCommand.Source }
if (-not $qemu) {
    Write-Host "[FAIL] qemu-system-x86_64 not found"
    exit 1
}
foreach ($img in @($MultiImage, $ZeroImage, $KconfImage, $KconfSetImage, $BanhammerImage)) {
    if (-not (Test-Path $img)) { Write-Host "[FAIL] missing image: $img"; exit 1 }
}

$work = Join-Path $env:TEMP "openwinkrnl_qemu_argv"
New-Item -ItemType Directory -Path $work -Force | Out-Null

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
# the shell's own terminal line, which bounds the wait so a boot that never
# launches it fails rather than hanging.
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
    return @{ Text = $sb.ToString(); Matched = $matched }
}

# ---------------------------------------------------------------------------
# Case A: several arguments, two of them containing spaces.
# ---------------------------------------------------------------------------
Write-Host "=== Case A (multi): owsh as PID 1 receives argc=4 ==="
$a = Invoke-QemuCase -Image $MultiImage -Done "owsh: done" -TimeoutSeconds 120 -Port $basePort
$ta = $a.Text
Set-Content -Path (Join-Path $work "multi.txt") -Value $ta

if (-not $a.Matched) {
    Write-Host "[FAIL] multi boot never reached the shell's terminal line within the timeout"
    $script:failed = $true
}
Assert-Present "multi: shell image seeded as the init"        $ta "[OWARGV] test image: seeded owsh.owx"
Assert-Present "multi: survey resolves to PRIMARY"            $ta "-> state PRIMARY"
Assert-Present "multi: survey sees a usable primary"          $ta "[OWINIT] userspace survey: primary(ok)"
Assert-Present "multi: the kernel-integrity phase ran"        $ta "[STARTED] Kernel Integrity"
Assert-Present "multi: shell enters at CPL3 as PID 1"         $ta "[OWINIT] owinit entered at CPL3 (PID 1)"
Assert-Present "multi: image entered at CPL3"                 $ta "[PS] owinit: image entered at CPL3"
Assert-Present "multi: argc reaches user space"               $ta "owsh: argc=4"
Assert-Present "multi: argv[0] is the probe's first word"     $ta "owsh: argv[0]=owsh"
Assert-Present "multi: argv[1] is a plain flag"               $ta "owsh: argv[1]=--probe"
Assert-Present "multi: argv[2] preserves a space"             $ta "owsh: argv[2]=hello world"
Assert-Present "multi: argv[3] preserves two spaces"          $ta "owsh: argv[3]=two words"
Assert-Present "multi: the shell ran to completion"           $ta "owsh: done"
Assert-Absent  "multi: no argv build fallback"                $ta "argv build failed"
Assert-Absent  "multi: no critical error"                     $ta "CRITICAL ERROR CODE:"

# ---------------------------------------------------------------------------
# Case B: no arguments at all.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Case B (zero): owsh as PID 1 receives argc=0 ==="
$b = Invoke-QemuCase -Image $ZeroImage -Done "owsh: done" -TimeoutSeconds 120 -Port ($basePort + 1)
$tb = $b.Text
Set-Content -Path (Join-Path $work "zero.txt") -Value $tb

if (-not $b.Matched) {
    Write-Host "[FAIL] zero boot never reached the shell's terminal line within the timeout"
    $script:failed = $true
}
Assert-Present "zero: shell image seeded as the init"        $tb "[OWARGV] test image: seeded owsh.owx"
Assert-Present "zero: survey resolves to PRIMARY"            $tb "-> state PRIMARY"
Assert-Present "zero: shell enters at CPL3 as PID 1"         $tb "[OWINIT] owinit entered at CPL3 (PID 1)"
Assert-Present "zero: zero reaches user space"               $tb "owsh: argc=0"
Assert-Present "zero: the shell ran to completion"           $tb "owsh: done"
Assert-Absent  "zero: no argv[] entries were printed"        $tb "owsh: argv["
Assert-Absent  "zero: no argv build fallback"                $tb "argv build failed"
Assert-Absent  "zero: no critical error"                     $tb "CRITICAL ERROR CODE:"

# ---------------------------------------------------------------------------
# Case C: a program whose output depends on argv and a linked library.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Case C (kconf): kconfctl as PID 1 answers a query ==="
$c = Invoke-QemuCase -Image $KconfImage -Done "kconfctl: done" -TimeoutSeconds 120 -Port ($basePort + 2)
$tc = $c.Text
Set-Content -Path (Join-Path $work "kconf.txt") -Value $tc

if (-not $c.Matched) {
    Write-Host "[FAIL] kconf boot never reached kconfctl's terminal line within the timeout"
    $script:failed = $true
}
Assert-Present "kconf: kconfctl image seeded as the init"     $tc "[OWKCONF] test image: seeded kconfctl.owx"
Assert-Present "kconf: survey resolves to PRIMARY"            $tc "-> state PRIMARY"
Assert-Present "kconf: config CLI enters at CPL3 as PID 1"    $tc "[OWINIT] owinit entered at CPL3 (PID 1)"
Assert-Present "kconf: image entered at CPL3"                 $tc "[PS] owinit: image entered at CPL3"
Assert-Present "kconf: the real query prints the default"     $tc "kconfctl: kernel/panic/action=banhammer"
Assert-Present "kconf: argv reached the config core"          $tc "kconfctl: kernel/panic/action="
Assert-Present "kconf: the program ran to completion"         $tc "kconfctl: done"
Assert-Absent  "kconf: the query key was not misread"         $tc "unknown string key"
Assert-Absent  "kconf: no argv build fallback"                $tc "argv build failed"
Assert-Absent  "kconf: no critical error"                     $tc "CRITICAL ERROR CODE:"

# ---------------------------------------------------------------------------
# Case D: a set whose success the program only reports after reading it back.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Case D (kconfset): kconfctl as PID 1 sets and verifies ==="
$d = Invoke-QemuCase -Image $KconfSetImage -Done "kconfctl: done" -TimeoutSeconds 120 -Port ($basePort + 3)
$td = $d.Text
Set-Content -Path (Join-Path $work "kconfset.txt") -Value $td

if (-not $d.Matched) {
    Write-Host "[FAIL] kconfset boot never reached kconfctl's terminal line within the timeout"
    $script:failed = $true
}
Assert-Present "kconfset: kconfctl image seeded as the init"  $td "[OWKCONF] test image: seeded kconfctl.owx"
Assert-Present "kconfset: survey resolves to PRIMARY"         $td "-> state PRIMARY"
Assert-Present "kconfset: config CLI enters at CPL3 as PID 1" $td "[OWINIT] owinit entered at CPL3 (PID 1)"
# This line is printed only after kconfctl reads the key back and finds the new
# value, so seeing it proves the write landed -- not merely that the verb ran.
Assert-Present "kconfset: the set landed and read back"       $td "kconfctl: set ui/wm/theme=custom_at_cpl3 (in-memory, not persisted)"
Assert-Present "kconfset: the program ran to completion"      $td "kconfctl: done"
Assert-Absent  "kconfset: verification did not fail"          $td "verification failed"
Assert-Absent  "kconfset: the key was not rejected as long"   $td "key or value too long"
Assert-Absent  "kconfset: no argv build fallback"             $td "argv build failed"
Assert-Absent  "kconfset: no critical error"                  $td "CRITICAL ERROR CODE:"

# ---------------------------------------------------------------------------
# Case E: a seeded table lookup whose answer depends on the argv.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Case E (banhammer): banhammer_cli as PID 1 selects a quote ==="
$e = Invoke-QemuCase -Image $BanhammerImage -Done "banhammer_cli: done" -TimeoutSeconds 120 -Port ($basePort + 4)
$te = $e.Text
Set-Content -Path (Join-Path $work "banhammer.txt") -Value $te

if (-not $e.Matched) {
    Write-Host "[FAIL] banhammer boot never reached the CLI's terminal line within the timeout"
    $script:failed = $true
}
Assert-Present "banhammer: the quote CLI was seeded as the init" $te "[OWBH] test image: seeded banhammer_cli.owx"
Assert-Present "banhammer: survey resolves to PRIMARY"           $te "-> state PRIMARY"
Assert-Present "banhammer: the CLI enters at CPL3 as PID 1"      $te "[OWINIT] owinit entered at CPL3 (PID 1)"
# seed 1, category sarcastic, resolves to index 7 of the panic-text table; this
# line can only appear if argv reached the program and drove the table lookup.
Assert-Present "banhammer: argv selected the expected quote"     $te "banhammer_cli: quote sarcastic seed 1: System crashed successfully. No humans were harmed in this disaster."
Assert-Present "banhammer: the program ran to completion"        $te "banhammer_cli: done"
Assert-Absent  "banhammer: the category was not rejected"        $te "unknown category"
Assert-Absent  "banhammer: the seed was not rejected"           $te "invalid seed"
Assert-Absent  "banhammer: no missing-quote fallback"           $te "no quote available"
Assert-Absent  "banhammer: no argv build fallback"              $te "argv build failed"
Assert-Absent  "banhammer: no critical error"                   $te "CRITICAL ERROR CODE:"

# ---------------------------------------------------------------------------
Write-Host ""
if ($script:failed) {
    Write-Host "=== CPL3 ARGUMENT-VECTOR REGRESSION FAILED ==="
    Write-Host "    transcripts kept in $work (multi.txt, zero.txt, kconf.txt, kconfset.txt, banhammer.txt)"
    exit 1
}
Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
Write-Host "=== CPL3 ARGUMENT-VECTOR REGRESSION PASSED (multi argc=4, zero argc=0, kconf query, kconfset set, banhammer quote) ==="
exit 0
