 <#
.SYNOPSIS
    Removes Azure Red Team tools installed by Install-RedTeamTools.ps1

.DESCRIPTION
    This script removes tools, modules, and packages installed by the companion
    installation script to allow for clean re-testing.

.PARAMETER ToolsPath
    The directory where tools were installed. Default: C:\AzureRedTeamTools

.PARAMETER RemoveChocolatey
    Also remove Chocolatey itself (not just packages).

.PARAMETER RemoveAll
    Remove everything including Chocolatey. Equivalent to -RemoveChocolatey.

.PARAMETER KeepPython
    Keep Python installed (useful if you use it for other projects).

.PARAMETER KeepGit
    Keep Git installed.

.EXAMPLE
    .\Uninstall-RedTeamTools.ps1
    
.EXAMPLE
    .\Uninstall-RedTeamTools.ps1 -RemoveAll

.EXAMPLE
    .\Uninstall-RedTeamTools.ps1 -WhatIf
    Preview what would be removed without making changes.

.NOTES
    Author: Security Team
    Requires: PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ToolsPath = "C:\AzureRedTeamTools",
    [switch]$RemoveChocolatey,
    [switch]$RemoveAll,
    [switch]$RemoveDefenderExclusion,
    [switch]$KeepPython,
    [switch]$KeepGit,
    [switch]$Force
)

#Requires -RunAsAdministrator

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"  # Suppress noisy progress bars

# ============================================================================
# Configuration - Must match Install-RedTeamTools.ps1
# ============================================================================

$PSModules = @(
    "AADInternals",
    "Az",
    "Microsoft.Graph",
    "AzureADPreview",
    "MSOnline"
)

$ChocoPackages = @(
    "git",
    "python3",
    "vscode",
    "azure-cli",
    "powershell-core",
    "golang"
)

$PythonPackages = @(
    "roadrecon",
    "scoutsuite"
)

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
        "Success" { Write-Host "  ✓ $Message" -ForegroundColor Green }
        "Warning" { Write-Host "  ! $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "  ✗ $Message" -ForegroundColor Red }
        "DryRun"  { Write-Host "  [DRY RUN] Would remove: $Message" -ForegroundColor Magenta }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n[+] $Title" -ForegroundColor White
}

function Test-CommandExists {
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

# ============================================================================
# Removal Functions
# ============================================================================

function Remove-PSModules {
    Write-Section "Removing PowerShell Modules..."
    
    foreach ($module in $PSModules) {
        try {
            # Special handling for Az - it's a meta-module with 70+ sub-modules
            # and may be installed in Windows PowerShell or PowerShell 7 paths
            if ($module -eq "Az") {
                $azModules = Get-Module -ListAvailable -Name "Az*" | Select-Object -ExpandProperty Name -Unique
                
                if ($azModules.Count -eq 0) {
                    Write-Status "Az not installed" -Type Info
                    continue
                }
                
                if ($PSCmdlet.ShouldProcess("Az (and all Az.* sub-modules)", "Uninstall PowerShell Module")) {
                    # Remove from current session first
                    Get-Module -Name "Az*" | Remove-Module -Force -ErrorAction SilentlyContinue
                    
                    # Try Uninstall-Module first
                    $removedCount = 0
                    $failedModules = @()
                    
                    foreach ($azMod in $azModules) {
                        try {
                            Uninstall-Module -Name $azMod -AllVersions -Force -ErrorAction Stop
                            $removedCount++
                        }
                        catch {
                            $failedModules += $azMod
                        }
                    }
                    
                    # Fallback: Remove any remaining Az modules directly from both module paths
                    $modulePaths = @(
                        "C:\Program Files\PowerShell\Modules",
                        "C:\Program Files\WindowsPowerShell\Modules",
                        "$env:USERPROFILE\Documents\PowerShell\Modules",
                        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
                    )
                    
                    foreach ($path in $modulePaths) {
                        $azFolders = Get-ChildItem -Path $path -Directory -Filter "Az*" -ErrorAction SilentlyContinue
                        foreach ($folder in $azFolders) {
                            try {
                                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                                $removedCount++
                            }
                            catch { }
                        }
                    }
                    
                    Write-Status "Az removed ($removedCount items)" -Type Success
                }
                else {
                    Write-Status "Az" -Type DryRun
                }
                continue
            }
            
            # Special handling for Microsoft.Graph - also has many sub-modules
            if ($module -eq "Microsoft.Graph") {
                $graphModules = Get-Module -ListAvailable -Name "Microsoft.Graph*" | Select-Object -ExpandProperty Name -Unique
                
                if ($graphModules.Count -eq 0) {
                    Write-Status "Microsoft.Graph not installed" -Type Info
                    continue
                }
                
                if ($PSCmdlet.ShouldProcess("Microsoft.Graph (and all sub-modules)", "Uninstall PowerShell Module")) {
                    Get-Module -Name "Microsoft.Graph*" | Remove-Module -Force -ErrorAction SilentlyContinue
                    
                    $removedCount = 0
                    foreach ($graphMod in $graphModules) {
                        try {
                            Uninstall-Module -Name $graphMod -AllVersions -Force -ErrorAction Stop
                            $removedCount++
                        }
                        catch { }
                    }
                    
                    # Fallback: Remove directly from module paths
                    $modulePaths = @(
                        "C:\Program Files\PowerShell\Modules",
                        "C:\Program Files\WindowsPowerShell\Modules",
                        "$env:USERPROFILE\Documents\PowerShell\Modules",
                        "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
                    )
                    
                    foreach ($path in $modulePaths) {
                        $graphFolders = Get-ChildItem -Path $path -Directory -Filter "Microsoft.Graph*" -ErrorAction SilentlyContinue
                        foreach ($folder in $graphFolders) {
                            try {
                                Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop
                                $removedCount++
                            }
                            catch { }
                        }
                    }
                    
                    Write-Status "Microsoft.Graph removed ($removedCount items)" -Type Success
                }
                else {
                    Write-Status "Microsoft.Graph" -Type DryRun
                }
                continue
            }
            
            # Standard module removal
            $installed = Get-Module -ListAvailable -Name $module
            
            # Also check for orphaned/corrupted module folders
            $modulePaths = @(
                "C:\Program Files\PowerShell\Modules\$module",
                "C:\Program Files\WindowsPowerShell\Modules\$module",
                "$env:USERPROFILE\Documents\PowerShell\Modules\$module",
                "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\$module"
            )
            $orphanedFolders = $modulePaths | Where-Object { Test-Path $_ }
            
            if ($installed -or $orphanedFolders) {
                if ($PSCmdlet.ShouldProcess($module, "Uninstall PowerShell Module")) {
                    # Remove from current session first
                    Remove-Module -Name $module -Force -ErrorAction SilentlyContinue
                    
                    # Try Uninstall-Module if module was properly installed
                    $uninstallSuccess = $false
                    if ($installed) {
                        try {
                            Uninstall-Module -Name $module -AllVersions -Force -ErrorAction Stop
                            $uninstallSuccess = $true
                        }
                        catch { }
                    }
                    
                    # Always clean up folders (catches orphaned/corrupted installs)
                    $removed = $false
                    foreach ($path in $modulePaths) {
                        if (Test-Path $path) {
                            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                            $removed = $true
                        }
                    }
                    
                    if ($uninstallSuccess) {
                        Write-Status "$module removed" -Type Success
                    }
                    elseif ($removed) {
                        Write-Status "$module removed (orphaned folder cleanup)" -Type Success
                    }
                    else {
                        Write-Status "Failed to remove $module" -Type Warning
                    }
                }
                else {
                    Write-Status $module -Type DryRun
                }
            }
            else {
                Write-Status "$module not installed" -Type Info
            }
        }
        catch {
            Write-Status "Failed to remove $module`: $_" -Type Warning
        }
    }
}

function Remove-PythonPackages {
    Write-Section "Removing Python Packages..."
    
    if (-not (Test-CommandExists "pip")) {
        Write-Status "pip not found, skipping Python packages" -Type Warning
        return
    }
    
    foreach ($package in $PythonPackages) {
        try {
            $installed = pip show $package 2>$null
            if ($installed) {
                if ($PSCmdlet.ShouldProcess($package, "Uninstall Python Package")) {
                    pip uninstall $package -y --quiet 2>$null
                    Write-Status "$package removed" -Type Success
                }
                else {
                    Write-Status $package -Type DryRun
                }
            }
            else {
                Write-Status "$package not installed" -Type Info
            }
        }
        catch {
            Write-Status "Failed to remove $package`: $_" -Type Warning
        }
    }
}

function Remove-ChocoPackages {
    param(
        [switch]$KeepPython,
        [switch]$KeepGit
    )
    
    Write-Section "Removing Chocolatey Packages..."
    
    if (-not (Test-CommandExists "choco")) {
        Write-Status "Chocolatey not found, skipping" -Type Warning
        Write-Status "Note: Programs installed by Chocolatey may still exist as Windows apps" -Type Warning
        return
    }
    
    $packagesToRemove = $ChocoPackages.Clone()
    
    if ($KeepPython) {
        $packagesToRemove = $packagesToRemove | Where-Object { $_ -notlike "python*" }
        Write-Status "Keeping Python as requested" -Type Info
    }
    
    if ($KeepGit) {
        $packagesToRemove = $packagesToRemove | Where-Object { $_ -ne "git" }
        Write-Status "Keeping Git as requested" -Type Info
    }
    
    foreach ($package in $packagesToRemove) {
        try {
            # Choco v2.x: check if package exists in local list
            $listOutput = choco list --limit-output 2>$null
            $isInstalled = $listOutput | Where-Object { $_ -match "^$package\|" }
            
            if ($isInstalled) {
                if ($PSCmdlet.ShouldProcess($package, "Uninstall Chocolatey Package")) {
                    $result = choco uninstall $package -y --remove-dependencies 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Status "$package removed" -Type Success
                    }
                    else {
                        Write-Status "Failed to remove $package" -Type Warning
                    }
                }
                else {
                    Write-Status $package -Type DryRun
                }
            }
            else {
                Write-Status "$package not installed" -Type Info
            }
        }
        catch {
            Write-Status "Failed to remove $package`: $_" -Type Warning
        }
    }
}

function Remove-Chocolatey {
    Write-Section "Removing Chocolatey..."
    
    if ($PSCmdlet.ShouldProcess("Chocolatey", "Completely remove Chocolatey")) {
        try {
            # Remove Chocolatey directory
            $chocoPath = $env:ChocolateyInstall
            if (-not $chocoPath) {
                $chocoPath = "C:\ProgramData\chocolatey"
            }
            
            if (Test-Path $chocoPath) {
                Remove-Item -Path $chocoPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed $chocoPath" -Type Success
            }
            
            # Remove Chocolatey temp files
            $chocoTemp = "$env:LOCALAPPDATA\Temp\chocolatey"
            if (Test-Path $chocoTemp) {
                Remove-Item -Path $chocoTemp -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed temp files: $chocoTemp" -Type Success
            }
            
            # Remove Chocolatey cache
            $chocoCache = "$env:LOCALAPPDATA\NuGet"
            if (Test-Path $chocoCache) {
                Remove-Item -Path $chocoCache -Recurse -Force -ErrorAction SilentlyContinue
                Write-Status "Removed cache: $chocoCache" -Type Success
            }
            
            # Remove environment variables
            [System.Environment]::SetEnvironmentVariable("ChocolateyInstall", $null, "Machine")
            [System.Environment]::SetEnvironmentVariable("ChocolateyToolsLocation", $null, "Machine")
            [System.Environment]::SetEnvironmentVariable("ChocolateyInstall", $null, "User")
            
            # Remove from PATH
            $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
            $newPath = ($machinePath -split ';' | Where-Object { $_ -notlike "*chocolatey*" }) -join ';'
            [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
            
            $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
            if ($userPath) {
                $newUserPath = ($userPath -split ';' | Where-Object { $_ -notlike "*chocolatey*" }) -join ';'
                [System.Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
            }
            
            Write-Status "Chocolatey removed" -Type Success
        }
        catch {
            Write-Status "Failed to remove Chocolatey: $_" -Type Error
        }
    }
    else {
        Write-Status "Chocolatey" -Type DryRun
    }
}

function Remove-ToolsDirectory {
    param([string]$Path)
    
    Write-Section "Removing Tools Directory..."
    
    if (Test-Path $Path) {
        if ($PSCmdlet.ShouldProcess($Path, "Remove directory")) {
            try {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
                Write-Status "Removed $Path" -Type Success
            }
            catch {
                Write-Status "Failed to remove $Path`: $_" -Type Error
            }
        }
        else {
            Write-Status $Path -Type DryRun
        }
    }
    else {
        Write-Status "Tools directory not found: $Path" -Type Info
    }
}

function Remove-Shortcuts {
    Write-Section "Removing Desktop Shortcuts..."
    
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    $shortcuts = @(
        "Azure Red Team Tools.lnk",
        "Red Team PowerShell.lnk"
    )
    
    foreach ($shortcut in $shortcuts) {
        $shortcutPath = Join-Path $desktopPath $shortcut
        if (Test-Path $shortcutPath) {
            if ($PSCmdlet.ShouldProcess($shortcut, "Remove shortcut")) {
                Remove-Item -Path $shortcutPath -Force
                Write-Status "Removed $shortcut" -Type Success
            }
            else {
                Write-Status $shortcut -Type DryRun
            }
        }
        else {
            Write-Status "$shortcut not found" -Type Info
        }
    }
}

function Remove-AzureHoundFromPath {
    Write-Section "Cleaning PATH entries..."
    
    if ($PSCmdlet.ShouldProcess("AzureHound PATH entry", "Remove from system PATH")) {
        try {
            $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
            $pathEntries = $machinePath -split ';'
            $cleanedEntries = $pathEntries | Where-Object { 
                $_ -and 
                $_ -notlike "*AzureHound*" -and 
                $_ -notlike "*AzureRedTeamTools*"
            }
            $newPath = $cleanedEntries -join ';'
            
            if ($newPath -ne $machinePath) {
                [System.Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
                Write-Status "Cleaned AzureHound/Tools entries from PATH" -Type Success
            }
            else {
                Write-Status "No PATH entries to clean" -Type Info
            }
        }
        catch {
            Write-Status "Failed to clean PATH: $_" -Type Warning
        }
    }
}

function Remove-DefenderExclusion {
    param([string]$Path)
    
    Write-Section "Removing Windows Defender Exclusion..."
    
    try {
        $exclusions = (Get-MpPreference).ExclusionPath
        
        if ($exclusions -notcontains $Path) {
            Write-Status "No Defender exclusion found for $Path" -Type Info
            return
        }
        
        if ($PSCmdlet.ShouldProcess($Path, "Remove Defender exclusion")) {
            Remove-MpPreference -ExclusionPath $Path -ErrorAction Stop
            Write-Status "Defender exclusion removed for $Path" -Type Success
        }
        else {
            Write-Status "Defender exclusion for $Path" -Type DryRun
        }
    }
    catch {
        Write-Status "Failed to remove Defender exclusion: $_" -Type Warning
    }
}

function Remove-RedTeamProfile {
    Write-Section "Cleaning PowerShell Profile..."
    
    $profiles = @(
        "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
        "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        "$env:USERPROFILE\Documents\PowerShell\profile.ps1",
        "$env:USERPROFILE\Documents\PowerShell\Microsoft.PowerShell_profile.ps1"
    )
    
    foreach ($profilePath in $profiles) {
        if (-not (Test-Path $profilePath)) {
            continue
        }
        
        try {
            $content = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
            
            if ($content -notlike "*Azure Red Team Tools Configuration*") {
                Write-Status "No red team config in: $profilePath" -Type Info
                continue
            }
            
            if ($PSCmdlet.ShouldProcess($profilePath, "Remove red team configuration")) {
                # Remove everything between the start and end markers (inclusive)
                $pattern = '(?s)\r?\n*# =+\r?\n# Azure Red Team Tools Configuration.*?# End Azure Red Team Tools Configuration\r?\n# =+\r?\n*'
                $newContent = $content -replace $pattern, "`n"
                
                # Clean up extra blank lines
                $newContent = $newContent -replace "(\r?\n){3,}", "`n`n"
                $newContent = $newContent.Trim()
                
                if ($newContent -and $newContent.Length -gt 10) {
                    Set-Content -Path $profilePath -Value $newContent -Encoding UTF8
                    Write-Status "Cleaned profile: $profilePath" -Type Success
                }
                else {
                    # Profile is now empty or nearly empty, remove it
                    Remove-Item -Path $profilePath -Force
                    Write-Status "Removed empty profile: $profilePath" -Type Success
                }
            }
            else {
                Write-Status "Profile: $profilePath" -Type DryRun
            }
        }
        catch {
            Write-Status "Failed to clean profile $profilePath`: $_" -Type Warning
        }
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host @"

============================================================
     Azure Red Team Tools Cleanup Script
============================================================

"@ -ForegroundColor Yellow

if ($WhatIfPreference -or $PSBoundParameters.ContainsKey('WhatIf')) {
    Write-Host "Running in DRY RUN mode - no changes will be made`n" -ForegroundColor Magenta
}

Write-Host "This will remove tools installed by Install-RedTeamTools.ps1"
Write-Host "Tools path: $ToolsPath`n"

if (-not $WhatIfPreference -and -not $PSBoundParameters.ContainsKey('WhatIf') -and -not $Force) {
    $confirm = Read-Host "Are you sure you want to proceed? (y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`nCleanup cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Execute cleanup in reverse order of installation
Remove-Shortcuts
Remove-ToolsDirectory -Path $ToolsPath
Remove-PythonPackages
Remove-ChocoPackages -KeepPython:$KeepPython -KeepGit:$KeepGit
Remove-PSModules
Remove-AzureHoundFromPath
Remove-RedTeamProfile

if ($RemoveChocolatey -or $RemoveAll) {
    Remove-Chocolatey
}

if ($RemoveDefenderExclusion -or $RemoveAll) {
    Remove-DefenderExclusion -Path $ToolsPath
}

Write-Host @"

============================================================
[✓] Cleanup Complete!
============================================================

Next Steps:
1. Restart PowerShell to refresh environment
2. Run Install-RedTeamTools.ps1 to reinstall

"@ -ForegroundColor Green

if (-not ($RemoveChocolatey -or $RemoveAll)) {
    Write-Host "Note: Chocolatey was kept. Use -RemoveChocolatey to remove it too.`n" -ForegroundColor Cyan
}

if (-not ($RemoveDefenderExclusion -or $RemoveAll)) {
    Write-Host "Note: Defender exclusion was kept. Use -RemoveDefenderExclusion to remove it.`n" -ForegroundColor Cyan
} 
