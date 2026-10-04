# vbox_setup.ps1 - Create/configure the OpenWindows VirtualBox VM and attach
# the freshly built VDI by PATH. Stale registrations of the same file (long vs
# short 8.3 path spellings from earlier builds) are closed first, and the disk
# is never pinned to a fixed UUID, so every rebuild gets a clean attachment.
#
# Usage: pwsh -ExecutionPolicy Bypass -File tools/vbox_setup.ps1 [<path-to.vdi>] [-Start]
param(
    [string]$Vdi = "$env:TEMP\openwinkrnl_vbox\openwinkrnl.vdi",
    [string]$VmName = "OpenWindows",
    [string]$VboxManage,
    [switch]$Start
)

$ErrorActionPreference = "Stop"
$PSNativeCommandUseErrorActionPreference = $false

if (-not $VboxManage) {
    $vboxCommand = Get-Command "VBoxManage" -ErrorAction SilentlyContinue
    if ($vboxCommand) { $VboxManage = $vboxCommand.Source }
}
if (-not $VboxManage -or -not (Test-Path -LiteralPath $VboxManage)) {
    Write-Error "VBoxManage not found; pass -VboxManage <path> or add VirtualBox to PATH"
    exit 1
}
if (-not (Test-Path $Vdi)) { Write-Error "VDI not found: $Vdi (run 'make vdi' first)"; exit 1 }

# Canonicalize a path to the long fully-expanded lowercase form so the REGISTRY
# location (which may use 8.3 short names like KARIMA~1) matches our file.
function Get-Canonical([string]$Path) {
    $full = [System.IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($null -ne $item) { $full = $item.FullName }
    return $full.TrimEnd('\').ToLowerInvariant()
}

$canon = Get-Canonical $Vdi

# 1. Create the VM if it does not exist yet.
$exists = $null -ne (& $VboxManage list vms | Select-String -SimpleMatch ('"' + $VmName + '"'))
if (-not $exists) {
    & $VboxManage createvm --name $VmName --ostype "Other" --register
    & $VboxManage modifyvm $VmName --memory 512 --vram 16 --cpus 1 --ioapic on
    & $VboxManage modifyvm $VmName --boot1 disk --acpi on --hwvirtex on
    & $VboxManage modifyvm $VmName --bioslogofadein off --bioslogofadeout off --bioslogodisplaytime 0
}

# 2. Stop the VM if it is running so we can swap the disk.
$ml = & $VboxManage showvminfo $VmName --machinereadable | Out-String
if ($ml -match 'VMState="(running|paused|live)"') {
    Write-Host "VM is running - powering off to swap the disk..."
    & $VboxManage controlvm $VmName poweroff
    Start-Sleep -Milliseconds 1000
}

# 3. Detach anything currently on SATA port 0 (ignore "nothing attached").
& $VboxManage storageattach $VmName --storagectl "SATA" --port 0 --device 0 --type hdd --medium none 2>&1 | Out-Null

# 4. Free the floppy drive so the VM can never boot the floppy instead of the
#    freshly attached VDI. (Note: --type fdd, not floppy.)
if ($ml -match 'Floppy-0-0="[^"]+"') {
    & $VboxManage storageattach $VmName --storagectl "Floppy" --port 0 --device 0 --type fdd --medium none | Out-Null
}

# 5. Close every stale VirtualBox registration that points at this same file
#    (same canonical path, possibly a different UUID from an older build).
$lines = & $VboxManage list hdds
$current = $null
foreach ($line in $lines) {
    if ($line -match '^UUID:\s*(.+)$') { $current = $Matches[1].Trim(); continue }
    if ($line -match '^Location:\s*(.+)$') {
        if ($null -ne $current -and (Get-Canonical $Matches[1].Trim()) -eq $canon) {
            Write-Host "Closing stale registration uuid=$current (same file)"
            & $VboxManage closemedium disk $current 2>&1 | Out-Null
        }
        $current = $null
    }
}

# 6. Force disk boot, then attach the freshly built VDI by PATH. VirtualBox
#    registers the medium under the UUID the file currently carries, so a new
#    build always shows its real (new) UUID.
& $VboxManage modifyvm $VmName --boot1 disk
& $VboxManage storageattach $VmName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $Vdi
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "VM '$VmName' configured; disk attached by path: $Vdi"

if ($Start) {
    & $VboxManage startvm $VmName --type gui
    Write-Host "VM started."
}

exit 0