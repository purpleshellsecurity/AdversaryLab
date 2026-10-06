<#
.SYNOPSIS
    Removes Blue Team defensive monitoring tools.

.DESCRIPTION
    This script removes defensive monitoring tools installed by Install-BlueTeamTools.ps1:
    - Sysmon (System Monitor)
    - PowerShell Script Block Logging
    - PowerShell Module Logging
    - PowerShell Transcription
    - Windows Audit Policies (resets to defaults)

.PARAMETER All
    Remove all components (default if no specific flags provided)

.PARAMETER Sysmon
    Remove Sysmon only

.PARAMETER PSLogging
    Disable PowerShell logging only

.PARAMETER AuditPolicies
    Reset Windows audit policies only

.PARAMETER KeepTranscripts
    Keep existing transcript files when disabling PS logging

.PARAMETER Force
    Skip confirmation prompts

.EXAMPLE
    .\Uninstall-BlueTeamTools.ps1 -All
    
.EXAMPLE
    .\Uninstall-BlueTeamTools.ps1 -Sysmon

.EXAMPLE
    .\Uninstall-BlueTeamTools.ps1 -PSLogging -KeepTranscripts
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$All,
    [switch]$Sysmon,
    [switch]$PSLogging,
    [switch]$AuditPolicies,
    [switch]$KeepTranscripts,
    [switch]$Force
)

# ============================================================================
# Configuration
# ============================================================================

$SysmonPath = 'C:\Windows\Sysmon64.exe'
$TranscriptDir = 'C:\PSTranscripts'

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet("Info", "Success", "Warning", "Error", "DryRun")]
        [string]$Type = "Info"
    )
    
    switch ($Type) {
        "Info"    { Write-Host "  $Message" -ForegroundColor Cyan }
        "Success" { Write-Host "  [OK] $Message" -ForegroundColor Green }
        "Warning" { Write-Host "  [!] $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "  [X] $Message" -ForegroundColor Red }
        "DryRun"  { Write-Host "  [DRYRUN] Would remove: $Message" -ForegroundColor Magenta }
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
            }
        }
        exit 1
    }
    
    Write-Status "Administrator privileges confirmed" -Type Success
}

# ============================================================================
# Sysmon Removal
# ============================================================================

function Test-SysmonInstalled {
    return (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue) -ne $null
}

function Remove-Sysmon {
    Write-Section "Removing Sysmon..."
    
    # Check for service AND files (files may remain after service removal)
    $serviceExists = Test-SysmonInstalled
    $filePaths = @(
        $SysmonPath,
        "C:\Windows\Sysmon.exe",
        "C:\Windows\Sysmon64.exe"
    )
    $filesExist = $filePaths | Where-Object { Test-Path $_ }
    $driversExist = Get-ChildItem -Path "C:\Windows\System32\drivers\Sysmon*.sys" -ErrorAction SilentlyContinue
    
    if (-not $serviceExists -and -not $filesExist -and -not $driversExist) {
        Write-Status "Sysmon is not installed" -Type Info
        return
    }
    
    try {
        # Find Sysmon executable - check all known locations
        $sysmonExe = $null
        $allPaths = @(
            $SysmonPath,
            "C:\Windows\Sysmon64.exe",
            "C:\Windows\Sysmon.exe",
            "C:\Windows\System32\Sysmon.exe"
        )
        
        foreach ($path in $allPaths) {
            if (Test-Path $path) {
                $sysmonExe = $path
                break
            }
        }
        
        # Fallback: try to find via service
        if (-not $sysmonExe) {
            $service = Get-WmiObject -Class Win32_Service -Filter "Name LIKE 'Sysmon%'" -ErrorAction SilentlyContinue
            if ($service) {
                $exePath = $service.PathName -replace '"', '' -replace ' .*', ''
                if (Test-Path $exePath) {
                    $sysmonExe = $exePath
                }
            }
        }
        
        if ($sysmonExe -and (Test-Path $sysmonExe)) {
            # Only uninstall service if it exists
            if ($serviceExists) {
                Write-Status "Uninstalling Sysmon service..."
                
                if ($PSCmdlet.ShouldProcess("Sysmon", "Uninstall service")) {
                    $result = Start-Process -FilePath $sysmonExe -ArgumentList "-u", "force" -Wait -PassThru -NoNewWindow
                    
                    # Wait for handles to release
                    Start-Sleep -Seconds 5
                    
                    # Verify removal
                    if (-not (Test-SysmonInstalled)) {
                        Write-Status "Sysmon service removed" -Type Success
                    } else {
                        Write-Status "Sysmon service may still be present" -Type Warning
                    }
                }
            } else {
                Write-Status "Sysmon service already removed, cleaning up files..." -Type Info
                Start-Sleep -Seconds 2
            }
            
            # Remove the binary - may need retries as handles release
            if ($PSCmdlet.ShouldProcess($sysmonExe, "Remove binary")) {
                $deleted = $false
                for ($i = 1; $i -le 5; $i++) {
                    try {
                        Remove-Item -Path $sysmonExe -Force -ErrorAction Stop
                        $deleted = $true
                        break
                    } catch {
                        if ($i -lt 5) {
                            Start-Sleep -Seconds 2
                        }
                    }
                }
                
                # Fallback: try cmd.exe
                if (-not $deleted -and (Test-Path $sysmonExe)) {
                    cmd /c "del /f /q `"$sysmonExe`"" 2>$null
                    Start-Sleep -Seconds 1
                }
                
                if (Test-Path $sysmonExe) {
                    Write-Status "Sysmon binary locked - will be deleted on reboot" -Type Warning
                    # Schedule for deletion on reboot using PendingFileRenameOperations
                    $pendingKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"
                    $pending = (Get-ItemProperty -Path $pendingKey -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
                    if (-not $pending) { $pending = @() }
                    $pending += "\??\$sysmonExe"
                    $pending += ""
                    Set-ItemProperty -Path $pendingKey -Name PendingFileRenameOperations -Value $pending -Type MultiString -ErrorAction SilentlyContinue
                } else {
                    Write-Status "Sysmon binary removed" -Type Success
                }
            }
            
        } else {
            Write-Status "Sysmon executable not found, trying service removal..." -Type Warning
            
            # Try to stop and remove service directly
            $service = Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue
            if ($service) {
                Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
                sc.exe delete $service.Name | Out-Null
                Write-Status "Sysmon service removed via sc.exe" -Type Success
            }
        }
        
        # Clean up driver if present
        $driverPath = "C:\Windows\System32\drivers\Sysmon*.sys"
        Get-ChildItem -Path $driverPath -ErrorAction SilentlyContinue | ForEach-Object {
            $deleted = $false
            for ($i = 1; $i -le 3; $i++) {
                try {
                    Remove-Item -Path $_.FullName -Force -ErrorAction Stop
                    $deleted = $true
                    break
                } catch {
                    Start-Sleep -Seconds 1
                }
            }
            if (-not $deleted) {
                cmd /c "del /f /q `"$($_.FullName)`"" 2>$null
            }
        }
        
        # Also check for Sysmon files in C:\Windows (common alternate location)
        $altPaths = @(
            "C:\Windows\Sysmon.exe",
            "C:\Windows\Sysmon64.exe",
            "C:\Windows\System32\Sysmon.exe",
            "C:\Windows\System32\Sysmon64.exe"
        )
        foreach ($path in $altPaths) {
            if (Test-Path $path) {
                Write-Status "Found leftover file: $path" -Type Info
                $deleted = $false
                for ($i = 1; $i -le 5; $i++) {
                    try {
                        Remove-Item -Path $path -Force -ErrorAction Stop
                        $deleted = $true
                        break
                    } catch {
                        Start-Sleep -Seconds 2
                    }
                }
                if (-not $deleted) {
                    cmd /c "del /f /q `"$path`"" 2>$null
                    Start-Sleep -Seconds 1
                    $deleted = -not (Test-Path $path)
                }
                if ($deleted) {
                    Write-Status "Removed: $path" -Type Success
                } else {
                    Write-Status "Could not delete $path - may need reboot" -Type Warning
                }
            }
        }
        
    } catch {
        Write-Status "Failed to remove Sysmon: $($_.Exception.Message)" -Type Error
    }
}

# ============================================================================
# PowerShell Logging Removal
# ============================================================================

function Disable-PSLogging {
    Write-Section "Disabling PowerShell Logging..."
    
    try {
        # Script Block Logging
        $scriptBlockPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (Test-Path $scriptBlockPath) {
            if ($PSCmdlet.ShouldProcess($scriptBlockPath, "Remove registry key")) {
                Remove-Item -Path $scriptBlockPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Script Block Logging disabled" -Type Success
            }
        } else {
            Write-Status "Script Block Logging was not configured" -Type Info
        }
        
        # Module Logging
        $moduleLogPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        if (Test-Path $moduleLogPath) {
            if ($PSCmdlet.ShouldProcess($moduleLogPath, "Remove registry key")) {
                Remove-Item -Path $moduleLogPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Module Logging disabled" -Type Success
            }
        } else {
            Write-Status "Module Logging was not configured" -Type Info
        }
        
        # Transcription
        $transcriptPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription"
        if (Test-Path $transcriptPath) {
            if ($PSCmdlet.ShouldProcess($transcriptPath, "Remove registry key")) {
                Remove-Item -Path $transcriptPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Transcription disabled" -Type Success
            }
        } else {
            Write-Status "Transcription was not configured" -Type Info
        }
        
        # Clean up parent key if empty
        $psPath = "HKLM:\Software\Policies\Microsoft\Windows\PowerShell"
        if (Test-Path $psPath) {
            $children = Get-ChildItem -Path $psPath -ErrorAction SilentlyContinue
            if (-not $children) {
                Remove-Item -Path $psPath -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Remove transcript files if requested
        if (-not $KeepTranscripts -and (Test-Path $TranscriptDir)) {
            if ($PSCmdlet.ShouldProcess($TranscriptDir, "Remove transcript directory")) {
                $transcriptCount = (Get-ChildItem -Path $TranscriptDir -Recurse -File -ErrorAction SilentlyContinue).Count
                Remove-Item -Path $TranscriptDir -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed transcript directory ($transcriptCount files)" -Type Success
            }
        } elseif ($KeepTranscripts -and (Test-Path $TranscriptDir)) {
            Write-Status "Transcript files preserved at $TranscriptDir" -Type Info
        }
        
        Write-Status "Changes take effect in new PowerShell sessions" -Type Info
        
    } catch {
        Write-Status "Failed to disable PowerShell logging: $($_.Exception.Message)" -Type Error
    }
}

# ============================================================================
# Audit Policy Reset
# ============================================================================

function Reset-AuditPolicies {
    Write-Section "Resetting Windows Audit Policies..."
    
    try {
        # Process Creation
        if ($PSCmdlet.ShouldProcess("Process Creation", "Disable auditing")) {
            auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable | Out-Null
            Write-Status "Process Creation auditing disabled" -Type Success
        }
        
        # Remove command line logging
        $cmdLinePath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (Test-Path $cmdLinePath) {
            if ($PSCmdlet.ShouldProcess($cmdLinePath, "Remove registry key")) {
                Remove-Item -Path $cmdLinePath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Command line logging disabled" -Type Success
            }
        }
        
        # Logon/Logoff - reset to defaults (usually success only)
        if ($PSCmdlet.ShouldProcess("Logon/Logoff", "Reset to defaults")) {
            auditpol /set /subcategory:"Logon" /success:enable /failure:disable | Out-Null
            auditpol /set /subcategory:"Logoff" /success:disable /failure:disable | Out-Null
            Write-Status "Logon/Logoff auditing reset to defaults" -Type Success
        }
        
        # Credential Validation
        if ($PSCmdlet.ShouldProcess("Credential Validation", "Disable auditing")) {
            auditpol /set /subcategory:"Credential Validation" /success:disable /failure:disable | Out-Null
            Write-Status "Credential Validation auditing disabled" -Type Success
        }
        
        # Sensitive Privilege Use
        if ($PSCmdlet.ShouldProcess("Sensitive Privilege Use", "Disable auditing")) {
            auditpol /set /subcategory:"Sensitive Privilege Use" /success:disable /failure:disable | Out-Null
            Write-Status "Sensitive Privilege Use auditing disabled" -Type Success
        }
        
        # Security Group Management
        if ($PSCmdlet.ShouldProcess("Security Group Management", "Disable auditing")) {
            auditpol /set /subcategory:"Security Group Management" /success:disable /failure:disable | Out-Null
            Write-Status "Security Group Management auditing disabled" -Type Success
        }
        
        # User Account Management
        if ($PSCmdlet.ShouldProcess("User Account Management", "Disable auditing")) {
            auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable | Out-Null
            Write-Status "User Account Management auditing disabled" -Type Success
        }
        
        Write-Status "Audit policies reset to Windows defaults" -Type Info
        
    } catch {
        Write-Status "Failed to reset audit policies: $($_.Exception.Message)" -Type Error
    }
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " Blue Team Tools Removal Complete" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Removed Components:" -ForegroundColor White
    
    if ($removeSysmon) {
        $sysmonStatus = if (Test-SysmonInstalled) { "May need reboot" } else { "Removed" }
        Write-Host "    - Sysmon: $sysmonStatus" -ForegroundColor Gray
    }
    if ($removePSLogging) {
        Write-Host "    - PowerShell Logging: Disabled" -ForegroundColor Gray
    }
    if ($removeAuditPolicies) {
        Write-Host "    - Windows Audit Policies: Reset to defaults" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "  Note: A reboot may be required for all changes to take effect." -ForegroundColor Yellow
    Write-Host ""
}

# ============================================================================
# Main
# ============================================================================

# Determine what to remove
$removeSysmon = $Sysmon -or $All
$removePSLogging = $PSLogging -or $All
$removeAuditPolicies = $AuditPolicies -or $All

# If nothing specified, remove all
if (-not ($Sysmon -or $PSLogging -or $AuditPolicies -or $All)) {
    $removeSysmon = $true
    $removePSLogging = $true
    $removeAuditPolicies = $true
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Blue Team Tools Uninstaller" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Check admin
Test-Administrator

# Confirm
Write-Host ""
Write-Host "  Components to remove:" -ForegroundColor White
if ($removeSysmon) { Write-Host "    - Sysmon (System Monitor)" -ForegroundColor Gray }
if ($removePSLogging) { 
    Write-Host "    - PowerShell Script Block & Module Logging" -ForegroundColor Gray 
    if (-not $KeepTranscripts) {
        Write-Host "    - PowerShell Transcript files ($TranscriptDir)" -ForegroundColor Gray
    }
}
if ($removeAuditPolicies) { Write-Host "    - Windows Security Audit Policies (reset to defaults)" -ForegroundColor Gray }
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "  Proceed with removal? (y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Removal cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Remove components
try {
    if ($removeSysmon) { Remove-Sysmon }
    if ($removePSLogging) { Disable-PSLogging }
    if ($removeAuditPolicies) { Reset-AuditPolicies }
    
    Show-Summary
    
} catch {
    Write-Status "Removal failed: $($_.Exception.Message)" -Type Error
    exit 1
}