 # Simplified Parameters and Configuration
[CmdletBinding()]
param(
    [string]$ConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [switch]$UseDefaultConfig,
    [switch]$Force
)

# Simplified Configuration
$SysmonPath = 'C:\Windows\System32\Sysmon64.exe'
$SysmonDownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip'

# =======================
# Status Check
# =======================
function Test-SysmonRunning {
    $service = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
    return $service -and $service.Status -eq 'Running'
}

function Test-SysmonInstalled {
    return (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) -ne $null
}

# =======================
# Prerequisites
# =======================
function Test-Prerequisites {
    # Administrator check
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Administrator privileges required"
    }
}

# =======================
# Simplified Download
# =======================
function Install-SysmonBinary {
    Write-Host "Downloading Sysmon..." -ForegroundColor Yellow
    
    $tempZip = "$env:TEMP\Sysmon.zip"
    $tempExtract = "$env:TEMP\SysmonExtract"
    
    try {
        # Download
        Invoke-WebRequest -Uri $SysmonDownloadUrl -OutFile $tempZip -UseBasicParsing
        
        # Extract
        if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
        
        # Find and copy Sysmon64.exe
        $sysmonExe = Get-ChildItem -Path $tempExtract -Name "Sysmon64.exe" -Recurse | Select-Object -First 1
        if (-not $sysmonExe) { throw "Sysmon64.exe not found in download" }
        
        Copy-Item -Path (Join-Path $tempExtract $sysmonExe) -Destination $SysmonPath -Force
        Write-Host "Sysmon binary installed" -ForegroundColor Green
        
    } finally {
        # Cleanup
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =======================
# Sysmon Config Download
# =======================
function Get-SysmonConfig {
    if ($UseDefaultConfig) { return $null }
    
    $configPath = "$env:TEMP\sysmonconfig.xml"
    
    try {
        Write-Host "Downloading configuration..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath -UseBasicParsing -TimeoutSec 30
        
        # Basic XML validation
        $null = [xml](Get-Content $configPath)
        Write-Host "Configuration downloaded" -ForegroundColor Green
        return $configPath
        
    } catch {
        Write-Warning "Config download failed, using default: $($_.Exception.Message)"
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
        return $null
    }
}

# =======================
# Installation
# =======================
function Install-SysmonService {
    param([string]$ConfigPath)
    
    Write-Host "Installing Sysmon service..." -ForegroundColor Yellow
    
    # Uninstall if exists (
    if (Test-SysmonInstalled) {
        Write-Host "Uninstalling existing Sysmon..." -ForegroundColor Yellow
        & $SysmonPath -u force 2>$null | Out-Null
        Start-Sleep -Seconds 2
    }
    
    # Install
    $args = @('-accepteula', '-i')
    if ($ConfigPath) { $args += $ConfigPath }
    
    $result = Start-Process -FilePath $SysmonPath -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    # Handle common exit codes
    switch ($result.ExitCode) {
        0 { Write-Host "Sysmon service installed" -ForegroundColor Green }
        13 { 
            Write-Host "Sysmon already installed, updating configuration..." -ForegroundColor Yellow
            # Try to update config if provided
            if ($ConfigPath) {
                & $SysmonPath -c $ConfigPath | Out-Null
            }
        }
        1242 { Write-Host "Sysmon service installed (was already present)" -ForegroundColor Green }
        default { throw "Sysmon installation failed with exit code: $($result.ExitCode)" }
    }
}

# =======================
# Installation Verification
# =======================
function Test-Installation {
    Write-Host "Verifying installation..." -ForegroundColor Yellow
    
    # Wait a moment for service to start
    Start-Sleep -Seconds 3
    
    if (Test-SysmonRunning) {
        Write-Host "SUCCESS: Sysmon is running!" -ForegroundColor Green
             
        return $true
    } else {
        throw "Sysmon installation verification failed"
    }
}

# =======================
# Main Logic
# =======================
try {
    Write-Host "=== Sysmon Installer ===" -ForegroundColor Cyan
    
    # Check prerequisites
    Test-Prerequisites
    Write-Host "Prerequisites OK" -ForegroundColor Green
    
    # Check if already running
    if (Test-SysmonRunning) {
        if ($Force) {
            Write-Host "Force reinstall requested..." -ForegroundColor Yellow
        } else {
            Write-Host "Sysmon is already running! Use -Force to reinstall" -ForegroundColor Green
            exit 0
        }
    }
    
    # Install binary if needed
    if (-not (Test-Path $SysmonPath) -or $Force) {
        Install-SysmonBinary
    }
    
    # Get configuration
    $configPath = Get-SysmonConfig
    
    # Install service
    Install-SysmonService -ConfigPath $configPath
    
    # Verify
    Test-Installation | Out-Null
    
    Write-Host "Installation complete!" -ForegroundColor Green
    
} catch {
    Write-Error "Installation failed: $($_.Exception.Message)"
    exit 1
} 
