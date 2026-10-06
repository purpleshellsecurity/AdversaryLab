<#
.SYNOPSIS
    Installs Blue Team defensive monitoring tools.

.DESCRIPTION
    This script automates the installation of defensive monitoring tools:
    - Sysmon (System Monitor) for process, network, and file events
    - PowerShell Script Block Logging
    - PowerShell Module Logging
    - Windows Audit Policies for security events

.PARAMETER All
    Install all components (default if no specific flags provided)

.PARAMETER Sysmon
    Install Sysmon only

.PARAMETER PSLogging
    Enable PowerShell logging only

.PARAMETER AuditPolicies
    Enable Windows audit policies only

.PARAMETER SysmonConfigUrl
    URL to Sysmon configuration XML. Default: SwiftOnSecurity config

.PARAMETER UseDefaultSysmonConfig
    Use Sysmon's default configuration instead of downloading one

.PARAMETER Force
    Force reinstallation even if components are already installed

.EXAMPLE
    .\Install-BlueTeamTools.ps1 -All
    
.EXAMPLE
    .\Install-BlueTeamTools.ps1 -Sysmon -PSLogging

.EXAMPLE
    .\Install-BlueTeamTools.ps1 -Sysmon -SysmonConfigUrl "https://example.com/config.xml"
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$All,
    [switch]$Sysmon,
    [switch]$PSLogging,
    [switch]$AuditPolicies,
    [string]$SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',
    [switch]$UseDefaultSysmonConfig,
    [switch]$Force
)

# ============================================================================
# Configuration
# ============================================================================

$SysmonPath = 'C:\Windows\Sysmon64.exe'
$SysmonDownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip'

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error")]
        [string]$Type = "Info"
    )
    
    switch ($Type) {
        "Info"    { Write-Host "  $Message" -ForegroundColor Cyan }
        "Success" { Write-Host "  [OK] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "  [!] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "  [X] $Message" -ForegroundColor Red }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n[+] $Title" -ForegroundColor White
}

# ============================================================================
# Prerequisites
# ============================================================================

function Test-Administrator {
    Write-Section "Checking Prerequisites..."
    
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Status "Administrator privileges required" -Type Error
        Write-Host ""
        Write-Host "  To fix this:" -ForegroundColor Yellow
        Write-Host "    1. Right-click PowerShell" -ForegroundColor Gray
        Write-Host "    2. Select 'Run as Administrator'" -ForegroundColor Gray
        Write-Host "    3. Re-run this script" -ForegroundColor Gray
        Write-Host ""
        
        $reply = Read-Host "  Restart as Administrator? (y/N)"
        if ($reply -match '^[Yy]') {
            $scriptPath = $PSCommandPath
            if ($scriptPath) {
                Start-Process pwsh -ArgumentList "-File `"$scriptPath`"" -Verb RunAs
            } else {
                Write-Status "Could not determine script path for elevation" -Type Error
            }
        }
        exit 1
    }
    
    Write-Status "Administrator privileges confirmed" -Type Success
}

# ============================================================================
# Sysmon Installation
# ============================================================================

function Test-SysmonRunning {
    $service = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
    return $service -and $service.Status -eq 'Running'
}

function Test-SysmonInstalled {
    return (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) -ne $null
}

function Install-SysmonBinary {
    Write-Status "Downloading Sysmon from Sysinternals..."
    
    $tempZip = "$env:TEMP\Sysmon.zip"
    $tempExtract = "$env:TEMP\SysmonExtract"
    
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $SysmonDownloadUrl -OutFile $tempZip -UseBasicParsing
        
        if (Test-Path $tempExtract) { 
            Remove-Item $tempExtract -Recurse -Force 
        }
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
        
        $sysmonExe = Get-ChildItem -Path $tempExtract -Name "Sysmon64.exe" -Recurse | Select-Object -First 1
        if (-not $sysmonExe) { 
            throw "Sysmon64.exe not found in download" 
        }
        
        Copy-Item -Path (Join-Path $tempExtract $sysmonExe) -Destination $SysmonPath -Force
        Write-Status "Sysmon binary installed to $SysmonPath" -Type Success
        
    } finally {
        Remove-Item $tempZip -Force -ErrorAction SilentlyContinue
        Remove-Item $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Get-SysmonConfig {
    if ($UseDefaultSysmonConfig) { 
        Write-Status "Using Sysmon default configuration" -Type Info
        return $null 
    }
    
    $configPath = "$env:TEMP\sysmonconfig.xml"
    
    try {
        Write-Status "Downloading Sysmon configuration..."
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configPath -UseBasicParsing -TimeoutSec 30
        
        # Validate XML
        $null = [xml](Get-Content $configPath)
        Write-Status "Configuration downloaded (SwiftOnSecurity)" -Type Success
        return $configPath
        
    } catch {
        Write-Status "Config download failed, using default: $($_.Exception.Message)" -Type Warning
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
        return $null
    }
}

function Install-SysmonService {
    param([string]$ConfigPath)
    
    Write-Status "Installing Sysmon service..."
    
    if (Test-SysmonInstalled) {
        Write-Status "Uninstalling existing Sysmon..."
        & $SysmonPath -u force 2>$null | Out-Null
        Start-Sleep -Seconds 2
    }
    
    $sysmonArgs = @('-accepteula', '-i')
    if ($ConfigPath) { 
        $sysmonArgs += $ConfigPath 
    }
    
    $result = Start-Process -FilePath $SysmonPath -ArgumentList $sysmonArgs -Wait -PassThru -NoNewWindow
    
    switch ($result.ExitCode) {
        0 { Write-Status "Sysmon service installed" -Type Success }
        13 { 
            Write-Status "Sysmon already installed, updating configuration..." -Type Info
            if ($ConfigPath) {
                & $SysmonPath -c $ConfigPath | Out-Null
                Write-Status "Configuration updated" -Type Success
            }
        }
        1242 { Write-Status "Sysmon service installed" -Type Success }
        default { throw "Sysmon installation failed with exit code: $($result.ExitCode)" }
    }
}

function Install-Sysmon {
    Write-Section "Installing Sysmon..."
    
    # Check if already running
    if (Test-SysmonRunning -and -not $Force) {
        Write-Status "Sysmon is already running (use -Force to reinstall)" -Type Success
        return
    }
    
    # Download binary if needed
    if (-not (Test-Path $SysmonPath) -or $Force) {
        Install-SysmonBinary
    } else {
        Write-Status "Sysmon binary already present" -Type Info
    }
    
    # Get configuration
    $configPath = Get-SysmonConfig
    
    # Install service
    Install-SysmonService -ConfigPath $configPath
    
    # Verify
    Start-Sleep -Seconds 2
    if (Test-SysmonRunning) {
        Write-Status "Sysmon is running and logging events" -Type Success
        Write-Status "Events logged to: Microsoft-Windows-Sysmon/Operational" -Type Info
    } else {
        Write-Status "Sysmon may not be running - check services" -Type Warning
    }
    
    # Clean up config file
    if ($configPath) {
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
    }
}

# ============================================================================
# PowerShell Logging
# ============================================================================

function Enable-PSLogging {
    Write-Section "Enabling PowerShell Logging..."
    
    try {
        # Script Block Logging
        $scriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $scriptBlockPath)) {
            New-Item -Path $scriptBlockPath -Force | Out-Null
        }
        Set-ItemProperty -Path $scriptBlockPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
        Write-Status "Script Block Logging enabled" -Type Success
        
        # Module Logging
        $moduleLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $moduleNamesPath = "$moduleLogPath\ModuleNames"
        
        if (-not (Test-Path $moduleLogPath)) {
            New-Item -Path $moduleLogPath -Force | Out-Null
        }
        if (-not (Test-Path $moduleNamesPath)) {
            New-Item -Path $moduleNamesPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $moduleLogPath -Name "EnableModuleLogging" -Value 1 -Type DWord
        
        # Log all modules with wildcard
        Set-ItemProperty -Path $moduleNamesPath -Name "*" -Value "*" -Type String
        Write-Status "Module Logging enabled (all modules)" -Type Success
        
        # Transcription (optional but useful)
        $transcriptPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (-not (Test-Path $transcriptPath)) {
            New-Item -Path $transcriptPath -Force | Out-Null
        }
        Set-ItemProperty -Path $transcriptPath -Name "EnableTranscripting" -Value 1 -Type DWord
        Set-ItemProperty -Path $transcriptPath -Name "EnableInvocationHeader" -Value 1 -Type DWord
        
        # Create transcript output directory
        $transcriptDir = "C:\PSTranscripts"
        if (-not (Test-Path $transcriptDir)) {
            New-Item -Path $transcriptDir -ItemType Directory -Force | Out-Null
        }
        Set-ItemProperty -Path $transcriptPath -Name "OutputDirectory" -Value $transcriptDir -Type String
        Write-Status "Transcription enabled (output: $transcriptDir)" -Type Success
        
        Write-Status "Events logged to: Microsoft-Windows-PowerShell/Operational" -Type Info
        Write-Status "Settings take effect in new PowerShell sessions" -Type Info
        
    } catch {
        Write-Status "Failed to enable PowerShell logging: $($_.Exception.Message)" -Type Error
    }
}

# ============================================================================
# Windows Audit Policies
# ============================================================================

function Enable-AuditPolicies {
    Write-Section "Enabling Windows Audit Policies..."
    
    try {
        # Process Creation (Event ID 4688)
        auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null
        Write-Status "Process Creation auditing enabled (4688)" -Type Success
        
        # Include command line in process creation events
        $cmdLinePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $cmdLinePath)) {
            New-Item -Path $cmdLinePath -Force | Out-Null
        }
        Set-ItemProperty -Path $cmdLinePath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
        Write-Status "Command line logging for process creation enabled" -Type Success
        
        # Logon/Logoff
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
        auditpol /set /subcategory:"Logoff" /success:enable | Out-Null
        Write-Status "Logon/Logoff auditing enabled (4624, 4625, 4634)" -Type Success
        
        # Account Logon
        auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
        Write-Status "Credential Validation auditing enabled (4776)" -Type Success
        
        # Privilege Use
        auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
        Write-Status "Sensitive Privilege Use auditing enabled (4672, 4673)" -Type Success
        
        # Object Access - Registry & File System (can be noisy, enable selectively)
        # auditpol /set /subcategory:"Registry" /success:enable /failure:enable | Out-Null
        # auditpol /set /subcategory:"File System" /success:enable /failure:enable | Out-Null
        
        # Security Group Management
        auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable | Out-Null
        Write-Status "Security Group Management auditing enabled (4727, 4728, 4732)" -Type Success
        
        # User Account Management
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
        Write-Status "User Account Management auditing enabled (4720, 4722, 4724)" -Type Success
        
        Write-Status "Events logged to: Security event log" -Type Info
        
    } catch {
        Write-Status "Failed to enable audit policies: $($_.Exception.Message)" -Type Error
    }
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Blue Team Tools Installation Complete" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Installed Components:" -ForegroundColor White
    
    if ($installSysmon) {
        $sysmonStatus = if (Test-SysmonRunning) { "Running" } else { "Check services" }
        Write-Host "    - Sysmon: $sysmonStatus" -ForegroundColor Gray
    }
    if ($installPSLogging) {
        Write-Host "    - PowerShell Logging: Enabled" -ForegroundColor Gray
    }
    if ($installAuditPolicies) {
        Write-Host "    - Windows Audit Policies: Enabled" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  Event Log Locations:" -ForegroundColor White
    Write-Host "    - Sysmon: Microsoft-Windows-Sysmon/Operational" -ForegroundColor Gray
    Write-Host "    - PowerShell: Microsoft-Windows-PowerShell/Operational" -ForegroundColor Gray
    Write-Host "    - Security: Security" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Quick Checks:" -ForegroundColor White
    Write-Host "    Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 5" -ForegroundColor DarkGray
    Write-Host "    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 5" -ForegroundColor DarkGray
    Write-Host ""
}

# ============================================================================
# Main
# ============================================================================

# Determine what to install
$installSysmon = $Sysmon -or $All
$installPSLogging = $PSLogging -or $All
$installAuditPolicies = $AuditPolicies -or $All

# If nothing specified, install all
if (-not ($Sysmon -or $PSLogging -or $AuditPolicies -or $All)) {
    $installSysmon = $true
    $installPSLogging = $true
    $installAuditPolicies = $true
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Blue Team Tools Installer" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check admin
Test-Administrator

# Confirm
Write-Host ""
Write-Host "  Components to install:" -ForegroundColor White
if ($installSysmon) { Write-Host "    - Sysmon (System Monitor)" -ForegroundColor Gray }
if ($installPSLogging) { Write-Host "    - PowerShell Script Block & Module Logging" -ForegroundColor Gray }
if ($installAuditPolicies) { Write-Host "    - Windows Security Audit Policies" -ForegroundColor Gray }
Write-Host ""

$confirm = Read-Host "  Proceed with installation? (Y/n)"
if ($confirm -match '^[Nn]') {
    Write-Host "  Installation cancelled." -ForegroundColor Yellow
    exit 0
}

# Install components
try {
    if ($installSysmon) { Install-Sysmon }
    if ($installPSLogging) { Enable-PSLogging }
    if ($installAuditPolicies) { Enable-AuditPolicies }
    
    Show-Summary
    
} catch {
    Write-Status "Installation failed: $($_.Exception.Message)" -Type Error
    exit 1
}