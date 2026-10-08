param(
    [Parameter(Mandatory = $true)][string]$Image,
    [ValidateSet("floppy", "disk", "kernel")][string]$Media = "disk",
    [Parameter(Mandatory = $true)][string]$OutDir,
    [int]$SerialPort = 13031,
    [int]$MonPort = 13032,
    [int]$BootWaitSec = 240
)

$ErrorActionPreference = "Stop"
$qemu = "C:\Program Files\qemu\qemu-system-x86_64.exe"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Get-Process qemu-system-x86_64 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

# Serial first: -chardev ...,wait=on blocks QEMU initialisation until the
# client connects, so the monitor must be created with wait=off.
$common = @("-display", "none", "-vga", "std",
            "-m", "512M", "-smp", "1", "-no-reboot", "-no-shutdown")
$argList = switch ($Media) {
    "floppy" { @("-fda", $Image, "-boot", "a") + $common }
    "disk"   { @("-drive", "file=$Image,format=raw,if=ide,index=0,media=disk", "-boot", "c") + $common }
    "kernel" { @("-kernel", $Image) + $common }
}
$argList += @("-chardev", "socket,id=com0,port=$SerialPort,host=127.0.0.1,server=on,wait=on,ipv4=on",
              "-serial", "chardev:com0",
              "-monitor", "tcp:127.0.0.1:$MonPort,server=on,wait=off")

$log = Join-Path $OutDir "qemu_stderr.txt"
$p = Start-Process -FilePath $qemu -ArgumentList $argList -NoNewWindow -PassThru `
                  -RedirectStandardError $log
"qemu pid=$($p.Id) media=$Media image=$Image"

function Connect-Tcp([int]$port, [int]$tries) {
    for ($i = 0; $i -lt $tries; $i++) {
        Start-Sleep -Milliseconds 250
        try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect("127.0.0.1", $port); return $c } catch { }
    }
    return $null
}

$sc = Connect-Tcp $SerialPort 80
if (-not $sc) { "SERIAL CONNECT FAILED"; Get-Content $log; exit 1 }
$ss = $sc.GetStream()

$mc = Connect-Tcp $MonPort 80
if (-not $mc) { "MONITOR CONNECT FAILED"; Get-Content $log; exit 1 }
$ms = $mc.GetStream()
$script:T0 = Get-Date
Write-Host ("connected t=+{0:n1}s" -f ((Get-Date) - $script:T0).TotalSeconds)

$sb = New-Object System.Text.StringBuilder
$buf = New-Object byte[] 16384

function Read-Serial {
    while ($script:ss.DataAvailable) {
        $n = $script:ss.Read($script:buf, 0, $script:buf.Length)
        if ($n -gt 0) { [void]$script:sb.Append([System.Text.Encoding]::ASCII.GetString($script:buf, 0, $n)) }
    }
}

function Wait-Serial([string]$pat, [int]$sec) {
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) {
        Read-Serial
        if ($script:sb.ToString() -match $pat) {
            Write-Host ("  wait '{0}' matched t=+{1:n1}s bytes={2}" -f $pat, ((Get-Date) - $script:T0).TotalSeconds, $script:sb.Length)
            return $true
        }
        Start-Sleep -Milliseconds 20
    }
    Read-Serial
    return ($script:sb.ToString() -match $pat)
}

function Drain-Monitor([int]$ms2) {
    $end = (Get-Date).AddMilliseconds($ms2)
    while ((Get-Date) -lt $end) {
        while ($script:ms.DataAvailable) { [void]$script:ms.Read($script:buf, 0, $script:buf.Length) }
        Start-Sleep -Milliseconds 50
    }
}

function Send-Monitor([string]$cmd) {
    $b = [System.Text.Encoding]::ASCII.GetBytes($cmd + "`n")
    $script:ms.Write($b, 0, $b.Length); $script:ms.Flush()
    Drain-Monitor 400
}

function Capture([string]$name) {
    # QEMU's monitor treats backslash as an escape inside quoted strings, so
    # Windows paths must be handed over with forward slashes.
    $dir = $OutDir.Replace("\", "/")
    $ppm = "$dir/$name.ppm"
    $vga = "$dir/$name.vgabin"
    $pf = Join-Path $OutDir "$name.ppm"
    $vf = Join-Path $OutDir "$name.vgabin"
    Remove-Item $pf, $vf -Force -ErrorAction SilentlyContinue

    # stop -> screendump -> pmemsave -> cont as a single monitor write, so the
    # framebuffer is frozen at the instant the sequence starts.  The guest boots
    # to a shell prompt in ~2 s, and the on-screen log area holds only 19 lines,
    # so any round-trip latency lets the boot log scroll away.
    $cmd = "stop`nscreendump `"$ppm`"`npmemsave 0xb8000 4000 `"$vga`"`ncont"
    $b = [System.Text.Encoding]::ASCII.GetBytes($cmd + "`n")
    $script:ms.Write($b, 0, $b.Length); $script:ms.Flush()

    $end = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $end -and -not ((Test-Path $pf) -and (Test-Path $vf))) {
        Start-Sleep -Milliseconds 20
    }
    Drain-Monitor 200
    $ok = (Test-Path $pf) -and (Test-Path $vf)
    Write-Host ("  capture {0} t=+{1:n1}s bytes={2} ok={3}" -f $name, ((Get-Date) - $script:T0).TotalSeconds, $script:sb.Length, $ok)
    return $ok
}

function Type-Line([string]$line) {
    $b = [System.Text.Encoding]::ASCII.GetBytes($line + "`r")
    $script:ss.Write($b, 0, $b.Length); $script:ss.Flush()
    Start-Sleep -Milliseconds 400
}

# ---------------------------------------------------------------- sequence
$script:results = @()

# Early: mid-boot, while the boot log still shows Phase 1/2.  The guest boots
# to a shell in ~2 s, so capture immediately -- no settling delay.
$early = Wait-Serial "\[STARTED\] HAL Init" $BootWaitSec
$script:results += ,@("01-boot", $early)
$script:results += ,@("01-boot.png", (Capture "01-boot"))

# Mid: right after the boot-complete banner, before the init script finishes.
$mid = Wait-Serial "\[BOOT\] kernel boot complete" $BootWaitSec
$script:results += ,@("01b-bootcomplete", $mid)
$script:results += ,@("01b-bootcomplete.png", (Capture "01b-bootcomplete"))

$ok = Wait-Serial "ow-krnl> \z" $BootWaitSec
"prompt reached: $ok"
$script:results += ,@("02-shell", $ok)
$script:results += ,@("02-shell.png", (Capture "02-shell"))

$steps = @(
    @{ n = "03-help";    cmd = "help" },
    @{ n = "04-runlevel"; cmd = "runlevel features" },
    @{ n = "05-fs";      cmd = "fs list" },
    @{ n = "06-sucs";     cmd = "sucs" },
    @{ n = "07-alloc";   cmd = "alloc 4096" }
)
foreach ($s in $steps) {
    Type-Line $s.cmd
    Start-Sleep -Seconds 2
    [void](Wait-Serial ([regex]::Escape($s.cmd)) 5)
    Start-Sleep -Seconds 1
    $script:results += ,@($s.n, (Capture $s.n))
}

# Shutdown path: arm the safe power-off screen, then leave the shell.
Type-Line "safeoff on"
Start-Sleep -Seconds 2
Type-Line "exit"
$off = Wait-Serial "You can safely power off your device now\." 60
"power-off screen: $off"
Start-Sleep -Seconds 2
$script:results += ,@("08-poweroff", $off)
$script:results += ,@("08-poweroff", (Capture "08-poweroff"))

# ---------------------------------------------------------------- teardown
$txt = $sb.ToString()
Set-Content -Path (Join-Path $OutDir "serial_transcript.txt") -Value $txt
"transcript bytes: $($txt.Length)"

$ss.Close(); $sc.Close()
$ms.Close(); $mc.Close()
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue

"=== capture summary ==="
$script:results | ForEach-Object { "{0,-14} {1}" -f $_[0], $_[1] }
