param(
    [Parameter(Mandatory = $true)]
    [string]$Floppy
)

$ErrorActionPreference = "Continue"

$Floppy = (Resolve-Path $Floppy).Path
$FloppyDir = Split-Path $Floppy -Parent
$SerialLog = Join-Path $FloppyDir "owx_serial.log"

function Find-VBoxManage {
    $cmd = Get-Command "VBoxManage" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Invoke-VBox {
    param([string[]]$ArgsList)
    & $VBox @ArgsList 2>&1 | ForEach-Object { "[VBox] $_" }
    return $LASTEXITCODE
}

$VBox = Find-VBoxManage
if (-not $VBox) {
    Write-Host "VirtualBox was not found on this machine. The floppy image is ready:"
    Write-Host "  $Floppy"
    Write-Host ""
    Write-Host "To boot OpenWindows in VirtualBox (GUI):"
    Write-Host "  1. File > New Machine > Name: OpenWindows"
    Write-Host "     Type: Other > Other (or Other/Unknown 64-bit), RAM: 512 MB"
    Write-Host "     - No virtual hard disk -"
    Write-Host "  2. Select VM > Settings > Storage > Add Floppy Controller,"
    Write-Host "     then Add Optical/Floppy Drive > Choose disk > browse to the .flp file"
    Write-Host "  3. Settings > System > Motherboard > Boot Order: Floppy first"
    Write-Host "  4. (optional) Settings > Ports > Serial Ports: Port1 = COM1, IRQ4, port 0x3F8,"
    Write-Host "     Mode = Host File, Path = $SerialLog"
    Write-Host "  5. Start the VM. The floppy boots OpenWindows; the VGA console shows output."
    Write-Host ""
    Write-Host "You can also validate the exact same image under QEMU now:"
    Write-Host "  qemu-system-x86_64 -fda `"$Floppy`" -boot a -nographic"
    exit 1
}

Write-Host "Using VirtualBox: $VBox"
$vm = "OpenWindows"

Invoke-VBox @("unregistervm", $vm, "--delete") | Out-Null
Invoke-VBox @("createvm", "--name", $vm, "--register") | Out-Null
Invoke-VBox @("modifyvm", $vm, "--ostype", "Other", "--memory", "512", "--vram", "16",
    "--acpi", "on", "--ioapic", "on",
    "--boot1", "floppy", "--boot2", "disk", "--boot3", "none", "--boot4", "none",
    "--uart1", "0x3F8", "4", "--uartmode1", "file", $SerialLog) | Out-Null
Invoke-VBox @("storagectl", $vm, "--name", "Floppy", "--add", "floppy", "--controller", "I82078") | Out-Null
Invoke-VBox @("storageattach", $vm, "--storagectl", "Floppy", "--port", "0", "--device", "0",
    "--type", "fdd", "--medium", $Floppy) | Out-Null

Write-Host "VM '$vm' configured. Starting..."
Invoke-VBox @("startvm", $vm) | Out-Null
Write-Host "Started. Console: close the VM window or 'VBoxManage controlvm $vm poweroff'."
Write-Host "Serial log will be written to: $SerialLog"