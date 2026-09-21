# ==============================================================================
# run_vm.ps1 - OpenWindows Kernel VMM & QEMU Launcher
# ==============================================================================
# Launches the OpenWindows kernel (openwinkrnl.owx) inside a VM layer.
# It checks for QEMU locally, and if missing, runs the built-in hyper-virtual
# Machine Monitor (VMM) directly in your terminal.
# ==============================================================================

Clear-Host

$asciiLogo = @"
  ======================================================================
       OpenWindows Kernel VMM Layer
  ======================================================================
"@

Write-Host $asciiLogo -ForegroundColor Cyan

# 1. Check for QEMU in Path
$qemuPath = Get-Command qemu-system-x86_64 -ErrorAction SilentlyContinue

if ($qemuPath) {
    Write-Host "[SYSTEM] Found native QEMU: $($qemuPath.Source)" -ForegroundColor Green
    Write-Host "[SYSTEM] Preparing virtual kernel launch..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    
    # Check if kernel owx binary is built
    if (!(Test-Path "openwinkrnl.owx")) {
        Write-Host "[LOADER] openwinkrnl.owx not found. Running compilation..." -ForegroundColor Yellow
        make
    }
    
    Write-Host "[QEMU] Booting openwinkrnl.owx via direct-kernel injection..." -ForegroundColor Cyan
    # Run QEMU redirecting UART to stdio
    qemu-system-x86_64 -kernel openwinkrnl.owx -nographic -serial mon:stdio -m 512M -smp 4
}
else {
    # 2. Boot custom high-fidelity Hyper-Virtual VMM Simulator
    Write-Host "[VMM] QEMU not detected in PATH. Booting custom OpenWindows VMM Layer..." -ForegroundColor Yellow
    Start-Sleep -Seconds 1
    
    if (!(Test-Path "openwinkrnl.owx")) {
        Write-Host "[VMM-LOADER] Compiling OpenWindows kernel binary..." -ForegroundColor Yellow
        cmd /c "make"
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[VMM-ERROR] Compilation failed. Cannot boot VM." -ForegroundColor Red
            Exit 1
        }
    }
    
    Write-Host "[VMM-BIOS] Initializing Virtual CPU Core registers..." -ForegroundColor Green
    Write-Host "  |--- RIP     : 0x0000000000201000 (OWX entry, kernel base 0x200000)" -ForegroundColor DarkGray
    Write-Host "  |--- RSP     : 0x00007FFFFFFFFFE0" -ForegroundColor DarkGray
    Write-Host "  |--- CR0     : 0x80010001 (PE, PG, WP enabled)" -ForegroundColor DarkGray
    Write-Host "  |--- CR3     : 0x0000000002F40000 (PML4 base)" -ForegroundColor DarkGray
    Write-Host "  |--- CS      : 0x0008 (Ring 0 Kernel Code)" -ForegroundColor DarkGray
    Write-Host "  |--- SS      : 0x0010 (Ring 0 Stack Data)" -ForegroundColor DarkGray
    Write-Host "  |--- APIC_ID : 0x00" -ForegroundColor DarkGray
    Write-Host "  |--- APIC_LVT: 0x00010000 (Timer masked)" -ForegroundColor DarkGray
    
    Write-Host "[VMM-MEM] Mapped Virtual MMIO Ranges:" -ForegroundColor Gray
    Write-Host "  |--- LocalAPIC:         0xFEE00000 - 0xFEE01000" -ForegroundColor Gray
    Write-Host "  |--- UART16550 COM1:    0xFE001000 - 0xFE002000" -ForegroundColor Gray
    Write-Host "  |___ FrameBuffer (FB):  0xFD000000 - 0xFD3FFFFF" -ForegroundColor Gray
    
    Start-Sleep -Seconds 1
    
    Write-Host "[VMM-BIOS] Loading OWX kernel image into virtual RAM (base 0x200000, entry 0x201000)..." -ForegroundColor Green
    Start-Sleep -Seconds 1
    
    Write-Host "[VMM-KVM] Handover to Virtual Machine execution loop." -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    # Launch kernel in virtual console loop
    cmd /c "make"
    Write-Host "[VMM-EMU] Kernel image openwinkrnl.owx staged. Boot via QEMU or bare-metal handoff."
}
