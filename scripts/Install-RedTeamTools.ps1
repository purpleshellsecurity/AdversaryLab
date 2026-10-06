 <#
.SYNOPSIS
    Installs Azure Red Team tools for security testing and assessment.

.DESCRIPTION
    This script automates the installation of common Azure red team and security 
    assessment tools including PowerShell modules, Python tools, and GitHub repositories.

.PARAMETER ToolsPath
    The directory where tools will be installed. Default: C:\AzureRedTeamTools

.PARAMETER SkipChocolatey
    Skip Chocolatey and Chocolatey-based tool installations.

.PARAMETER SkipPython
    Skip Python tool installations.

.PARAMETER SkipGitHub
    Skip cloning GitHub repositories.

.PARAMETER Force
    Skip confirmation prompt. Use for automated/unattended installs.

.EXAMPLE
    .\Install-RedTeamTools.ps1
    
.EXAMPLE
    .\Install-RedTeamTools.ps1 -ToolsPath "D:\Tools" -SkipChocolatey

.EXAMPLE
    .\Install-RedTeamTools.ps1 -Force
    Skip confirmation prompt for automated installs.

.NOTES
    Author: Security Team
    Requires: PowerShell 5.1+, Administrator privileges
    Version: 2.0.1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ToolsPath = "C:\AzureRedTeamTools",
    [switch]$SkipChocolatey,
    [switch]$SkipPython,
    [switch]$SkipGitHub,
    [switch]$Force
)

#Requires -RunAsAdministrator

# ============================================================================
# Configuration
# ============================================================================

$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"  # Suppress noisy progress bars

# PowerShell Modules to install
$PSModules = @(
    "AADInternals",
    "Az",
    "Microsoft.Graph",
    "AzureADPreview",
    "MSOnline"
)

# Chocolatey packages to install
$ChocoPackages = @(
    "git",
    "python3",
    "vscode",
    "azure-cli",
    "powershell-core",
    "golang"
)

# Python packages to install
$PythonPackages = @(
    "roadrecon",
    "scoutsuite"
)

# GitHub repositories to clone
$GitHubRepos = @(
    @{ Name = "GraphRunner"; Url = "https://github.com/dafthack/GraphRunner.git" },
    @{ Name = "TokenTacticsV2"; Url = "https://github.com/f-bader/TokenTacticsV2.git" },
    @{ Name = "o365spray"; Url = "https://github.com/0xZDH/o365spray.git" },
    @{ Name = "ScoutSuite"; Url = "https://github.com/nccgroup/ScoutSuite.git" },
    @{ Name = "Masky"; Url = "https://github.com/Z4kSec/Masky.git" },
    @{ Name = "MicroBurst"; Url = "https://github.com/NetSPI/MicroBurst.git" },
    @{ Name = "PowerZure"; Url = "https://github.com/hausec/PowerZure.git" },
    @{ Name = "ROADtools"; Url = "https://github.com/dirkjanm/ROADtools.git" }
)

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
        "Success" { Write-Host "  ✓ $Message" -ForegroundColor Green }
        "Warning" { Write-Host "  ! $Message" -ForegroundColor Yellow }
        "Error"   { Write-Host "  ✗ $Message" -ForegroundColor Red }
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

function Refresh-EnvironmentPath {
    # Reload PATH from registry (picks up changes made by installers)
    $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
    $env:Path = "$machinePath;$userPath"
    
    # Also refresh ChocolateyInstall variable if it was just set
    $chocoInstall = [System.Environment]::GetEnvironmentVariable("ChocolateyInstall", "Machine")
    if ($chocoInstall) {
        $env:ChocolateyInstall = $chocoInstall
    }
}

# ============================================================================
# Installation Functions
# ============================================================================

function Install-PSModules {
    Write-Section "Installing PowerShell Modules..."
    
    # Ensure NuGet provider is installed
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Status "Installing NuGet provider..."
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    }
    
    # Trust PSGallery
    if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
    
    foreach ($module in $PSModules) {
        Write-Host "Checking $module..."
        try {
            # Use Get-Module -ListAvailable to verify module is actually valid (not just folder exists)
            $existingModule = Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue | Select-Object -First 1
            
            if ($existingModule) {
                Write-Status "$module already installed (v$($existingModule.Version))" -Type Success
            }
            else {
                # Clean up any corrupted/partial installs first
                $allModulePaths = @(
                    "C:\Program Files\PowerShell\Modules\$module",
                    "C:\Program Files\WindowsPowerShell\Modules\$module",
                    "$env:USERPROFILE\Documents\PowerShell\Modules\$module",
                    "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\$module"
                )
                foreach ($path in $allModulePaths) {
                    if (Test-Path $path) {
                        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                
                Install-Module -Name $module -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
                
                # Verify install succeeded
                $verifyModule = Get-Module -ListAvailable -Name $module -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($verifyModule) {
                    Write-Status "$module installed successfully (v$($verifyModule.Version))" -Type Success
                }
                else {
                    Write-Status "$module install may have failed - verify manually" -Type Warning
                }
            }
        }
        catch {
            Write-Status "Failed to install $module`: $_" -Type Error
        }
    }
}

function Install-Chocolatey {
    Write-Section "Installing Chocolatey..."
    
    if (Test-CommandExists "choco") {
        Write-Status "Chocolatey already installed" -Type Success
        return $true
    }
    
    try {
        # Clean up any leftover temp files from previous installs
        $chocoTemp = "$env:LOCALAPPDATA\Temp\chocolatey"
        if (Test-Path $chocoTemp) {
            Remove-Item -Path $chocoTemp -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Pre-create profile directory so Chocolatey doesn't warn about it
        $profileDir = Split-Path $PROFILE -Parent
        if (-not (Test-Path $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }
        
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        
        # Suppress Chocolatey's own warnings during install (we handle PATH ourselves)
        $WarningPreference = 'SilentlyContinue'
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')) *> $null
        $WarningPreference = 'Continue'
        
        # Refresh environment to pick up new PATH
        Refresh-EnvironmentPath
        
        # Verify choco is now available
        if (Test-CommandExists "choco") {
            Write-Status "Chocolatey installed successfully" -Type Success
            return $true
        }
        else {
            Write-Status "Chocolatey installed but not in PATH - restart may be required" -Type Warning
            return $true
        }
    }
    catch {
        Write-Status "Failed to install Chocolatey: $_" -Type Error
        return $false
    }
}

function Install-ChocoPackages {
    Write-Section "Installing Tools via Chocolatey..."
    
    Refresh-EnvironmentPath
    
    foreach ($package in $ChocoPackages) {
        Write-Host "Checking $package..."
        try {
            # Choco v2.x: use --limit-output for parseable format (package|version)
            $listOutput = choco list --limit-output 2>$null
            $isInstalled = $listOutput | Where-Object { $_ -match "^$package\|" }
            
            if ($isInstalled) {
                Write-Status "$package already installed" -Type Success
            }
            else {
                choco install $package -y --no-progress | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Status "$package installed successfully" -Type Success
                }
                else {
                    Write-Status "Failed to install $package" -Type Error
                }
            }
        }
        catch {
            Write-Status "Failed to install $package`: $_" -Type Error
        }
    }
    
    Refresh-EnvironmentPath
}

function Install-PythonTools {
    Write-Section "Installing Python Tools..."
    
    Refresh-EnvironmentPath
    
    # Ensure pip is available
    if (-not (Test-CommandExists "pip")) {
        if (Test-CommandExists "pip3") {
            Set-Alias -Name pip -Value pip3 -Scope Script
        }
        else {
            Write-Status "pip not found. Skipping Python tools." -Type Warning
            return
        }
    }
    
    foreach ($package in $PythonPackages) {
        Write-Host "Checking $package..."
        try {
            $installed = pip show $package 2>$null
            if ($installed) {
                Write-Status "$package already installed" -Type Success
            }
            else {
                pip install $package --quiet --break-system-packages 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Status "$package installed successfully" -Type Success
                }
                else {
                    # Try without --break-system-packages for older pip versions
                    pip install $package --quiet 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Status "$package installed successfully" -Type Success
                    }
                    else {
                        Write-Status "Failed to install $package" -Type Warning
                    }
                }
            }
        }
        catch {
            Write-Status "Failed to install $package`: $_" -Type Error
        }
    }
}

function Install-GitHubRepos {
    param([string]$BasePath)
    
    Write-Section "Installing GitHub Tools..."
    
    Refresh-EnvironmentPath
    
    if (-not (Test-CommandExists "git")) {
        Write-Status "Git not found. Skipping GitHub repositories." -Type Warning
        return
    }
    
    foreach ($repo in $GitHubRepos) {
        $repoPath = Join-Path $BasePath $repo.Name
        Write-Host "Cloning $($repo.Name)..."
        
        try {
            if (Test-Path $repoPath) {
                # Update existing repo
                Push-Location $repoPath
                git pull --quiet 2>$null
                Pop-Location
                Write-Status "$($repo.Name) updated successfully" -Type Success
            }
            else {
                git clone $repo.Url $repoPath --quiet 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Write-Status "$($repo.Name) cloned successfully" -Type Success
                }
                else {
                    Write-Status "Failed to clone $($repo.Name)" -Type Error
                }
            }
        }
        catch {
            Write-Status "Failed to clone $($repo.Name)`: $_" -Type Error
        }
    }
}

function Install-AzureHound {
    param([string]$InstallPath)
    
    Write-Section "Installing AzureHound..."
    
    $azureHoundPath = Join-Path $InstallPath "AzureHound"
    
    try {
        # Query GitHub API for latest release
        Write-Host "Fetching latest release information..."
        $apiUrl = "https://api.github.com/repos/SpecterOps/AzureHound/releases/latest"
        $headers = @{ 
            "User-Agent" = "PowerShell-RedTeamInstaller"
            "Accept" = "application/vnd.github.v3+json"
        }
        
        $release = Invoke-RestMethod -Uri $apiUrl -Headers $headers -ErrorAction Stop
        $version = $release.tag_name
        
        # Determine architecture
        $arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
        $osType = "windows"
        
        # Find matching asset (exclude .sha256 files)
        $asset = $release.assets | Where-Object { 
            $_.name -like "*${osType}_${arch}.zip" -and 
            $_.name -notlike "*.sha256"
        } | Select-Object -First 1
        
        if (-not $asset) {
            throw "Could not find matching binary for ${osType}_${arch}"
        }
        
        Write-Status "Found AzureHound $version"
        Write-Host "  Downloading $($asset.name)..."
        
        # Download
        $zipPath = Join-Path $env:TEMP $asset.name
        
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("User-Agent", "PowerShell-RedTeamInstaller")
        $webClient.DownloadFile($asset.browser_download_url, $zipPath)
        
        # Verify checksum if digest is available
        if ($asset.digest) {
            $expectedHash = ($asset.digest -split ':')[1].ToUpper()
            $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash
            
            if ($expectedHash -ne $actualHash) {
                Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
                throw "Checksum verification failed!"
            }
            Write-Status "Checksum verified" -Type Success
        }
        
        # Extract
        if (Test-Path $azureHoundPath) {
            Remove-Item $azureHoundPath -Recurse -Force
        }
        
        Expand-Archive -Path $zipPath -DestinationPath $azureHoundPath -Force
        Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        
        # Verify installation
        $exe = Get-ChildItem -Path $azureHoundPath -Filter "azurehound.exe" -Recurse | 
               Select-Object -First 1
        
        if ($exe) {
            # Add to PATH for current session
            $env:Path += ";$($exe.DirectoryName)"
            Write-Status "AzureHound $version installed to $($exe.FullName)" -Type Success
        }
        else {
            throw "azurehound.exe not found after extraction"
        }
        
        return $true
    }
    catch {
        Write-Status "Failed to install AzureHound: $_" -Type Error
        Write-Status "Manual download: https://github.com/SpecterOps/AzureHound/releases" -Type Warning
        return $false
    }
}

function Test-Installations {
    Write-Section "Verifying Installations..."
    
    $results = @()
    
    # Check PowerShell modules
    foreach ($module in $PSModules) {
        $installed = [bool](Get-Module -ListAvailable -Name $module)
        $results += [PSCustomObject]@{ Tool = $module; Type = "PSModule"; Installed = $installed }
        if ($installed) {
            Write-Status $module -Type Success
        }
        else {
            Write-Status $module -Type Error
        }
    }
    
    # Check Python tools
    foreach ($package in $PythonPackages) {
        $installed = $null -ne (pip show $package 2>$null)
        $results += [PSCustomObject]@{ Tool = $package; Type = "Python"; Installed = $installed }
        if ($installed) {
            Write-Status $package -Type Success
        }
        else {
            Write-Status $package -Type Error
        }
    }
    
    # Check AzureHound
    $azureHoundInstalled = Test-Path (Join-Path $ToolsPath "AzureHound\azurehound.exe")
    $results += [PSCustomObject]@{ Tool = "AzureHound"; Type = "Binary"; Installed = $azureHoundInstalled }
    if ($azureHoundInstalled) {
        Write-Status "AzureHound" -Type Success
    }
    else {
        Write-Status "AzureHound" -Type Error
    }
    
    return $results
}

function New-Shortcuts {
    param([string]$ToolsPath)
    
    Write-Section "Creating Shortcuts..."
    
    try {
        $shell = New-Object -ComObject WScript.Shell
        $desktopPath = [Environment]::GetFolderPath("Desktop")
        
        # Tools folder shortcut
        $shortcut = $shell.CreateShortcut("$desktopPath\Azure Red Team Tools.lnk")
        $shortcut.TargetPath = $ToolsPath
        $shortcut.Save()
        
        # Find PowerShell 7 (pwsh.exe)
        $pwshPath = Get-Command pwsh -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
        if (-not $pwshPath) {
            # Common install locations
            $possiblePaths = @(
                "$env:ProgramFiles\PowerShell\7\pwsh.exe",
                "$env:ProgramFiles\PowerShell\7-preview\pwsh.exe",
                "$env:LOCALAPPDATA\Microsoft\PowerShell\pwsh.exe"
            )
            foreach ($path in $possiblePaths) {
                if (Test-Path $path) {
                    $pwshPath = $path
                    break
                }
            }
        }
        
        # Fall back to Windows PowerShell if PS7 not found
        if (-not $pwshPath) {
            $pwshPath = "powershell.exe"
            Write-Status "PowerShell 7 not found, using Windows PowerShell" -Type Warning
        }
        
        # PowerShell with modules shortcut
        $shortcut = $shell.CreateShortcut("$desktopPath\Red Team PowerShell.lnk")
        $shortcut.TargetPath = $pwshPath
        $shortcut.Arguments = "-NoExit -Command `"rtload`""
        $shortcut.WorkingDirectory = $ToolsPath
        $shortcut.Save()
        
        Write-Status "Shortcuts created on Desktop" -Type Success
    }
    catch {
        Write-Status "Failed to create shortcuts: $_" -Type Warning
    }
}

function Install-RedTeamProfile {
    param([string]$ToolsPath)
    
    Write-Section "Configuring PowerShell Profile..."
    
    # Profile content to add
    $profileContent = @"

# ============================================================================
# Azure Red Team Tools Configuration
# Added by Install-RedTeamTools.ps1
# ============================================================================

# Add tools directory to PSModulePath
`$ToolsPath = "$ToolsPath"
if (`$env:PSModulePath -notlike "*`$ToolsPath*") {
    `$env:PSModulePath = "`$ToolsPath;`$env:PSModulePath"
}

# Tool loader functions
function Load-GraphRunner {
    . "`$ToolsPath\GraphRunner\GraphRunner.ps1"
    Write-Host "GraphRunner loaded" -ForegroundColor Green
}

function Load-TokenTactics {
    Import-Module "`$ToolsPath\TokenTacticsV2\TokenTactics.psd1" -Global
    Write-Host "TokenTacticsV2 loaded" -ForegroundColor Green
}

function Load-AllRedTeamTools {
    Write-Host ""
    Write-Host "Available tools (type command to load):" -ForegroundColor Cyan
    Write-Host "  aadint        - AADInternals" -ForegroundColor White
    Write-Host "  graphrunner   - GraphRunner" -ForegroundColor White
    Write-Host "  tokentactics  - TokenTacticsV2" -ForegroundColor White
    Write-Host "  microburst    - MicroBurst (load azmodule first)" -ForegroundColor White
    Write-Host "  powerzure     - PowerZure (requires Connect-AzAccount)" -ForegroundColor White
    Write-Host "  azmodule      - Az.Accounts" -ForegroundColor White
    Write-Host "  msgraph       - Microsoft.Graph.Authentication" -ForegroundColor White
    Write-Host ""
    Write-Host "CLI tools (ready to use):" -ForegroundColor Cyan
    Write-Host "  azurehound --help" -ForegroundColor White
    Write-Host "  roadrecon gather" -ForegroundColor White
    Write-Host ""
}

function Load-AADInternals {
    Write-Host "Loading AADInternals..." -ForegroundColor Gray -NoNewline
    Import-Module AADInternals -Global -DisableNameChecking 3>`$null
    Write-Host " Done" -ForegroundColor Green
}

function Load-AzModule {
    Write-Host "Loading Az.Accounts..." -ForegroundColor Gray -NoNewline
    Import-Module Az.Accounts -Global -DisableNameChecking
    Write-Host " Done" -ForegroundColor Green
    Write-Host "Run 'Connect-AzAccount' to authenticate" -ForegroundColor Yellow
}

function Load-MSGraph {
    Write-Host "Loading Microsoft.Graph.Authentication..." -ForegroundColor Gray -NoNewline
    Import-Module Microsoft.Graph.Authentication -Global -DisableNameChecking
    Write-Host " Done" -ForegroundColor Green
    Write-Host "Run 'Connect-MgGraph' to authenticate" -ForegroundColor Yellow
}

function Load-MicroBurst {
    if (-not (Get-Module -Name Az.Accounts)) {
        Write-Host "Loading Az.Accounts first..." -ForegroundColor Yellow
        Import-Module Az.Accounts -Global -DisableNameChecking -ErrorAction SilentlyContinue
    }
    Import-Module "`$ToolsPath\MicroBurst\MicroBurst.psm1" -Global
    Write-Host "MicroBurst loaded" -ForegroundColor Green
}

function Load-PowerZure {
    if (-not (Get-Module -Name Az.Accounts)) {
        Write-Host "Loading Az.Accounts first..." -ForegroundColor Yellow
        Import-Module Az.Accounts -Global -DisableNameChecking
    }
    # PowerZure requires an active Az connection before import
    `$ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not `$ctx) {
        Write-Host "PowerZure requires an active Azure connection." -ForegroundColor Yellow
        Write-Host "Run 'Connect-AzAccount' first, then 'powerzure'" -ForegroundColor Yellow
        return
    }
    Import-Module "`$ToolsPath\PowerZure\PowerZure.psd1" -Global
    Write-Host "PowerZure loaded" -ForegroundColor Green
}

# Aliases for convenience
Set-Alias -Name rtload -Value Load-AllRedTeamTools
Set-Alias -Name aadint -Value Load-AADInternals
Set-Alias -Name graphrunner -Value Load-GraphRunner
Set-Alias -Name tokentactics -Value Load-TokenTactics
Set-Alias -Name microburst -Value Load-MicroBurst
Set-Alias -Name powerzure -Value Load-PowerZure
Set-Alias -Name azmodule -Value Load-AzModule
Set-Alias -Name msgraph -Value Load-MSGraph

Write-Host "Azure Red Team tools ready. Type 'rtload' to see available tools." -ForegroundColor Cyan

# ============================================================================
# End Azure Red Team Tools Configuration
# ============================================================================
"@

    try {
        # Only use AllHosts profiles to avoid duplicate loading
        # (CurrentHost profiles like Microsoft.PowerShell_profile.ps1 would cause double-load)
        $profiles = @(
            "$env:USERPROFILE\Documents\WindowsPowerShell\profile.ps1",
            "$env:USERPROFILE\Documents\PowerShell\profile.ps1"
        )
        
        foreach ($profilePath in $profiles) {
            # Create profile directory if needed
            $profileDir = Split-Path $profilePath -Parent
            if (-not (Test-Path $profileDir)) {
                New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
            }
            
            # Check if already configured - if so, remove old config first
            if (Test-Path $profilePath) {
                $existingContent = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
                if ($existingContent -like "*Azure Red Team Tools Configuration*") {
                    # Remove old config block
                    $pattern = '(?s)\r?\n*# =+\r?\n# Azure Red Team Tools Configuration.*?# End Azure Red Team Tools Configuration\r?\n# =+\r?\n*'
                    $cleanedContent = $existingContent -replace $pattern, "`n"
                    $cleanedContent = $cleanedContent.Trim()
                    
                    if ($cleanedContent) {
                        Set-Content -Path $profilePath -Value $cleanedContent -Encoding UTF8
                    }
                    else {
                        Remove-Item -Path $profilePath -Force
                    }
                    Write-Status "Removed old config from: $profilePath" -Type Info
                }
            }
            
            # Add new profile content
            Add-Content -Path $profilePath -Value $profileContent -Encoding UTF8
            Write-Status "Profile updated: $profilePath" -Type Success
        }
        
        Write-Host ""
        Write-Host "  Quick reference:" -ForegroundColor White
        Write-Host "    rtload         - Show available tools" -ForegroundColor Gray
        Write-Host "    graphrunner    - Load GraphRunner" -ForegroundColor Gray
        Write-Host "    tokentactics   - Load TokenTacticsV2" -ForegroundColor Gray
        Write-Host "    aadint         - Load AADInternals" -ForegroundColor Gray
        Write-Host "    azmodule       - Load Az.Accounts (for Azure access)" -ForegroundColor Gray
        Write-Host "    microburst     - Load MicroBurst" -ForegroundColor Gray
        Write-Host "    powerzure      - Load PowerZure" -ForegroundColor Gray
        Write-Host ""
    }
    catch {
        Write-Status "Failed to configure profile: $_" -Type Warning
    }
}

# ============================================================================
# Defender Exclusion
# ============================================================================

function Add-DefenderExclusion {
    param([string]$Path)
    
    Write-Section "Configuring Windows Defender..."
    
    try {
        $exclusions = (Get-MpPreference).ExclusionPath
        
        if ($exclusions -contains $Path) {
            Write-Status "Defender exclusion already exists for $Path" -Type Success
            return
        }
        
        Add-MpPreference -ExclusionPath $Path -ErrorAction Stop
        Write-Status "Defender exclusion added for $Path" -Type Success
        
    }
    catch {
        Write-Status "Failed to add Defender exclusion: $_" -Type Error
        Write-Status "You may need to manually exclude $Path or tools may be quarantined" -Type Warning
    }
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Host @"

============================================================
     Azure Red Team Lab Setup Script v2.0
============================================================

"@ -ForegroundColor Cyan

Write-Host "This script will install Azure red team and security assessment tools."
Write-Host "Tools will be installed to: $ToolsPath"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "WARNING: This script will:" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host "  - Add a Windows Defender exclusion for $ToolsPath" -ForegroundColor Yellow
Write-Host "  - Install offensive security tools (AzureHound, ROADtools, etc.)" -ForegroundColor Yellow
Write-Host "  - Modify your PowerShell profile" -ForegroundColor Yellow
Write-Host "  - Install Chocolatey and various packages" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Only run this on a dedicated security testing machine!" -ForegroundColor Red
Write-Host "============================================================" -ForegroundColor Yellow
Write-Host ""

if (-not $Force) {
    $confirm = Read-Host "Are you sure you want to proceed? (y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`nInstallation cancelled." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host ""
Write-Host "Starting Azure Red Team Lab Setup..."

# Create tools directory
if (-not (Test-Path $ToolsPath)) {
    New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null
    Write-Host "Created tools directory: $ToolsPath"
}

# Add Defender exclusion before installing tools
Add-DefenderExclusion -Path $ToolsPath

# Install components
Install-PSModules

if (-not $SkipChocolatey) {
    if (Install-Chocolatey) {
        Install-ChocoPackages
    }
}

if (-not $SkipPython) {
    Install-PythonTools
}

if (-not $SkipGitHub) {
    Install-GitHubRepos -BasePath $ToolsPath
}

Install-AzureHound -InstallPath $ToolsPath

# Verify and create shortcuts
$verificationResults = Test-Installations
New-Shortcuts -ToolsPath $ToolsPath
Install-RedTeamProfile -ToolsPath $ToolsPath

# Summary
Write-Host @"

============================================================
[✓] Setup Complete!
============================================================

Tools Directory: $ToolsPath
Installed: $(@($verificationResults | Where-Object Installed).Count)/$($verificationResults.Count) tools

Quick Start:
1. Restart PowerShell to load the new profile
2. Type 'rtload' to see available tools
3. Load only what you need: graphrunner, tokentactics, aadint, etc.

CLI Tools (available after restart):
- azurehound --help
- roadrecon gather / roadrecon gui
- scout azure --help

Documentation:
- BloodHound CE: https://github.com/SpecterOps/BloodHound/releases

"@ -ForegroundColor Green

# Return results for pipeline usage
return $verificationResults 
