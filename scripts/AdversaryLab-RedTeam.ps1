<#
.SYNOPSIS
    Installs, removes, or verifies Azure/Entra red-team tooling on an AdversaryLab VM.

.DESCRIPTION
    Single entry point for the offensive tooling stack. Every component declares
    its Test / Install / Remove behaviour once, in the $Components table;
    Install, Remove and Test are three walks over that table (Remove walks it in
    reverse), so the three code paths cannot drift apart.

    Install records what it actually changed to a state file. Remove reverses
    only those changes, so packages and modules that pre-dated this script are
    left alone instead of being uninstalled out from under you.

.PARAMETER Action
    Install  - deploy the selected components (default)
    Remove   - reverse what Install recorded in the state file
    Test     - report what is present, without changing anything

.PARAMETER Component
    One or more of: DefenderExclusion, PSModules, Chocolatey, ChocoPackages,
    PythonPackages, GitHubRepos, AzureHound, Profile, Shortcuts.
    Defaults to all.

.PARAMETER ToolsPath
    Where tools are installed. Default: C:\AzureRedTeamTools

.PARAMETER Yes
    Skip the confirmation prompt without changing any other behaviour. Use this
    for unattended runs; -Force also skips the prompt but additionally reinstalls
    components already present and removes ones that pre-dated this script.

.PARAMETER Force
    Skip the confirmation prompt (required for unattended runs), reinstall
    components already present, and on Remove also remove components that
    pre-dated this script.

.PARAMETER IncludeRetired
    Also install the retired modules (AzureADPreview, MSOnline). Azure AD Graph
    is decommissioned, so most of their cmdlets fail at runtime - they are
    excluded by default rather than costing install time for nothing.

.PARAMETER RemoveChocolatey
    On Remove, also remove Chocolatey itself, not just the packages.

.PARAMETER StatePath
    Install manifest. Default: C:\ProgramData\AdversaryLab\redteam-state.json

.EXAMPLE
    .\AdversaryLab-RedTeam.ps1
    Interactive install of everything.

.EXAMPLE
    .\AdversaryLab-RedTeam.ps1 -Action Test
    Report what is installed. Makes no changes.

.EXAMPLE
    .\AdversaryLab-RedTeam.ps1 -Component PSModules,AzureHound -WhatIf
    Show the plan without touching the machine.

.EXAMPLE
    .\AdversaryLab-RedTeam.ps1 -Action Remove -RemoveChocolatey -Force

.NOTES
    Requires: Windows PowerShell 5.1+, Administrator privileges.
    Replaces: Install-RedTeamTools.ps1, Uninstall-RedTeamTools.ps1

    This installs offensive security tooling and adds a Windows Defender
    exclusion. Run it only on a dedicated, isolated lab machine.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Install', 'Remove', 'Test')]
    [string]$Action = 'Install',

    [ValidateSet('DefenderExclusion', 'PSModules', 'Chocolatey', 'ChocoPackages',
                 'PythonPackages', 'GitHubRepos', 'AzureHound', 'Profile', 'Shortcuts')]
    [string[]]$Component,

    [ValidateNotNullOrEmpty()]
    [string]$ToolsPath = 'C:\AzureRedTeamTools',

    [switch]$Force,
    [switch]$Yes,
    [switch]$IncludeRetired,
    [switch]$RemoveChocolatey,

    [ValidateNotNullOrEmpty()]
    [string]$StatePath = 'C:\ProgramData\AdversaryLab\redteam-state.json'
)

#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# PSGallery requires TLS 1.2. Windows PowerShell 5.1 does not always negotiate it
# by default, so set it before the first gallery call rather than midway through.
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

# ============================================================================
# Data - single source of truth for all three verbs
# ============================================================================

# 'Az' and 'Microsoft.Graph' are meta-modules: manifests whose only content is a
# dependency list, 102 and 39 modules respectively. They are kept because
# MicroBurst gates its entire Az function set on 'Get-InstalledModule -Name Az',
# which matches only the meta-module itself - installing the sub-modules alone
# would silently disable half of it. Install-PSResource is what makes the cost
# of keeping them acceptable.
#
# Retired modules are opt-in (-IncludeRetired): Azure AD Graph is decommissioned,
# so most MSOnline / AzureADPreview cmdlets fail at runtime. Installing them by
# default spent minutes on tooling that is already broken.
$PSModules = [ordered]@{
    'AADInternals'     = @{ Retired = $false }
    'Az'               = @{ Retired = $false; Prefix = 'Az*' }
    'Microsoft.Graph'  = @{ Retired = $false; Prefix = 'Microsoft.Graph*' }
    'AzureADPreview'   = @{ Retired = $true }
    'MSOnline'         = @{ Retired = $true }
}

$ChocoPackages = @('git', 'python3', 'vscode', 'azure-cli', 'powershell-core', 'golang')
$PythonPackages = @('roadrecon', 'scoutsuite')

$GitHubRepos = @(
    @{ Name = 'GraphRunner';    Url = 'https://github.com/dafthack/GraphRunner.git' }
    @{ Name = 'TokenTacticsV2'; Url = 'https://github.com/f-bader/TokenTacticsV2.git' }
    @{ Name = 'o365spray';      Url = 'https://github.com/0xZDH/o365spray.git' }
    @{ Name = 'ScoutSuite';     Url = 'https://github.com/nccgroup/ScoutSuite.git' }
    @{ Name = 'Masky';          Url = 'https://github.com/Z4kSec/Masky.git' }
    @{ Name = 'MicroBurst';     Url = 'https://github.com/NetSPI/MicroBurst.git' }
    @{ Name = 'PowerZure';      Url = 'https://github.com/hausec/PowerZure.git' }
    @{ Name = 'ROADtools';      Url = 'https://github.com/dirkjanm/ROADtools.git' }
)

$AzureHoundApi  = 'https://api.github.com/repos/SpecterOps/AzureHound/releases/latest'
$AzureHoundDir  = Join-Path $ToolsPath 'AzureHound'
$UserAgent      = 'PowerShell-AdversaryLab'

$ModulePathRoots = @(
    'C:\Program Files\PowerShell\Modules'
    'C:\Program Files\WindowsPowerShell\Modules'
    "$env:USERPROFILE\Documents\PowerShell\Modules"
    "$env:USERPROFILE\Documents\WindowsPowerShell\Modules"
)

# AllUsersAllHosts profiles. Deliberately NOT the per-user
# $env:USERPROFILE\Documents\... paths: when this runs under SYSTEM (Custom
# Script Extension, Invoke-AzVMRunCommand) those resolve to
# C:\Windows\system32\config\systemprofile and no interactive user ever sees
# them - the install reports success while the RDP admin gets nothing.
# Machine-wide profiles are also the right scope for a machine-wide tool install.
function Get-ProfileTargetPaths {
    $paths = @(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\profile.ps1')

    $pwshExe = Get-Command pwsh -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty Source
    if (-not $pwshExe) {
        foreach ($c in @("$env:ProgramFiles\PowerShell\7\pwsh.exe",
                         "$env:ProgramFiles\PowerShell\7-preview\pwsh.exe")) {
            if (Test-Path $c) { $pwshExe = $c; break }
        }
    }
    if ($pwshExe) { $paths += (Join-Path (Split-Path $pwshExe -Parent) 'profile.ps1') }

    return $paths
}
$ProfileMarkerStart = '# Azure Red Team Tools Configuration'
$ProfileMarkerEnd   = '# End Azure Red Team Tools Configuration'

$ShortcutNames = @('Azure Red Team Tools.lnk', 'Red Team PowerShell.lnk')

# ============================================================================
# Output helpers
# ============================================================================

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error', 'Plan')]
        [string]$Type = 'Info'
    )
    switch ($Type) {
        'Info'    { Write-Host "  $Message"      -ForegroundColor Cyan }
        'Success' { Write-Host "  [OK] $Message" -ForegroundColor Green }
        'Warning' { Write-Host "  [!]  $Message" -ForegroundColor Yellow }
        'Error'   { Write-Host "  [X]  $Message" -ForegroundColor Red }
        'Plan'    { Write-Host "  [ ]  $Message" -ForegroundColor Magenta }
    }
}

function Write-Section {
    param([string]$Title)
    Write-Host "`n[+] $Title" -ForegroundColor White
}

function Write-Banner {
    param([string]$Text)
    Write-Host ''
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
}

# ============================================================================
# State file
# ============================================================================

function Get-LabState {
    if (-not (Test-Path $StatePath)) { return @{} }
    try {
        $raw = Get-Content -Path $StatePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }
        $obj = $raw | ConvertFrom-Json
        $state = @{}
        foreach ($prop in $obj.PSObject.Properties) { $state[$prop.Name] = $prop.Value }
        return $state
    }
    catch {
        Write-Status "Could not read state file ($($_.Exception.Message)); treating as empty" -Type Warning
        return @{}
    }
}

function Save-LabState {
    param([hashtable]$State)
    $dir = Split-Path $StatePath -Parent
    if (-not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
    $State | ConvertTo-Json -Depth 8 | Set-Content -Path $StatePath -Encoding UTF8
}

function Set-ComponentState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param([string]$Name, [hashtable]$Data)
    $state = Get-LabState
    $state[$Name] = $Data
    Save-LabState -State $state
}

function Remove-ComponentState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param([string]$Name)
    $state = Get-LabState
    if ($state.ContainsKey($Name)) { $state.Remove($Name) }
    if ($state.Count -eq 0) { Remove-Item -Path $StatePath -Force -ErrorAction SilentlyContinue }
    else { Save-LabState -State $state }
}

function Get-ComponentState {
    param([string]$Name)
    $state = Get-LabState
    if ($state.ContainsKey($Name)) { return $state[$Name] }
    return $null
}

function Get-InstalledByUs {
    <#
        Returns the list this script recorded as actually installed by it (as
        opposed to already present). Remove uses this so it never uninstalls
        something that pre-dated the lab.
    #>
    param([string]$Name, [string]$Property = 'Installed')

    $state = Get-ComponentState -Name $Name
    if (-not $state) { return @() }
    if (-not $state.PSObject.Properties[$Property]) { return @() }
    return @($state.$Property)
}

# ============================================================================
# Environment helpers
# ============================================================================

function Update-EnvironmentPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    # Reload PATH from the registry so installers' changes are visible in-process.
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user    = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"

    $choco = [Environment]::GetEnvironmentVariable('ChocolateyInstall', 'Machine')
    if ($choco) { $env:ChocolateyInstall = $choco }
}

function Test-CommandExists {
    param([string]$Command)
    return [bool](Get-Command -Name $Command -ErrorAction SilentlyContinue)
}

function Add-MachinePath {
    <#
        The old installer only appended to $env:Path, which vanished when the
        session ended - so azurehound was never actually on PATH after a restart
        despite the summary claiming it was. Persist to the machine PATH.
    #>
    param([string]$Directory)

    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $entries = @($machine -split ';' | Where-Object { $_ })
    if ($entries -contains $Directory) { return $false }

    [Environment]::SetEnvironmentVariable('Path', (($entries + $Directory) -join ';'), 'Machine')
    $env:Path = "$env:Path;$Directory"
    return $true
}

function Remove-MachinePath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param([string]$Directory)

    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $entries = @($machine -split ';' | Where-Object { $_ })
    $kept    = @($entries | Where-Object { $_ -ne $Directory })
    if ($kept.Count -eq $entries.Count) { return $false }

    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'Machine')
    return $true
}

function Get-ChocoInstalledPackages {
    # choco v2 uses --limit-output for parseable "package|version" output.
    # On v1 'choco list' without --local-only lists the REMOTE feed, which would
    # make every package look installed, so pin to the local source explicitly.
    if (-not (Test-CommandExists 'choco')) { return @() }
    $out = & choco list --limit-output --local-only 2>$null
    if (-not $out) { $out = & choco list --limit-output 2>$null }
    return @($out | ForEach-Object { ($_ -split '\|')[0] } | Where-Object { $_ })
}

function Get-PipCommand {
    foreach ($c in 'pip', 'pip3') { if (Test-CommandExists $c) { return $c } }
    return $null
}

# ============================================================================
# Component: DefenderExclusion
# ============================================================================

function Test-DefenderExclusionComponent {
    $ex = @()
    try { $ex = @((Get-MpPreference -ErrorAction Stop).ExclusionPath) }
    catch { Write-Verbose "Defender preferences unavailable: $($_.Exception.Message)" }
    $present = $ex -contains $ToolsPath
    return [pscustomobject]@{ Present = $present; Detail = if ($present) { "exclusion set for $ToolsPath" } else { 'no exclusion' } }
}

function Install-DefenderExclusionComponent {
    if ((Test-DefenderExclusionComponent).Present) {
        Write-Status "Defender exclusion already present for $ToolsPath" -Type Success
        Set-ComponentState -Name 'DefenderExclusion' -Data @{ PreExisting = $true; Path = $ToolsPath }
        return
    }
    Add-MpPreference -ExclusionPath $ToolsPath -ErrorAction Stop
    Write-Status "Defender exclusion added for $ToolsPath" -Type Success
    Write-Status 'Offensive tooling in this directory is no longer scanned' -Type Warning
    Set-ComponentState -Name 'DefenderExclusion' -Data @{ PreExisting = $false; Path = $ToolsPath }
}

function Remove-DefenderExclusionComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    $state = Get-ComponentState -Name 'DefenderExclusion'
    if ($state -and $state.PreExisting -and -not $Force) {
        Write-Status 'Defender exclusion pre-dated this script; leaving it' -Type Warning
        return
    }
    if (-not (Test-DefenderExclusionComponent).Present) {
        Write-Status 'No Defender exclusion to remove' -Type Info
    }
    else {
        Remove-MpPreference -ExclusionPath $ToolsPath -ErrorAction SilentlyContinue
        Write-Status "Defender exclusion removed for $ToolsPath" -Type Success
    }
    Remove-ComponentState -Name 'DefenderExclusion'
}

# ============================================================================
# Gallery installer
# ============================================================================

$script:GalleryInstaller = $null

function Initialize-GalleryInstaller {
    <#
        PowerShellGet v2's Install-Module resolves dependencies serially through
        PackageManagement, so a default run is ~141 sequential module installs
        (Az pulls 102, Microsoft.Graph 39) behind a progress bar that
        $ProgressPreference cannot suppress - PackageManagement writes it from a
        child runspace that never sees this scope's preference.

        PSResourceGet's Install-PSResource does the same work substantially
        faster and quietly, so prefer it and bootstrap it when it is missing.
        Falls back to Install-Module if the bootstrap fails, since a slow
        install is better than no install.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    if ($script:GalleryInstaller) { return $script:GalleryInstaller }

    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Write-Status 'Installing NuGet provider...'
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
    }

    if (-not (Test-CommandExists 'Install-PSResource')) {
        Write-Status 'Installing PSResourceGet (much faster module installs)...'
        try {
            Install-Module -Name Microsoft.PowerShell.PSResourceGet -Force -AllowClobber `
                           -Scope AllUsers -ErrorAction Stop
            Import-Module Microsoft.PowerShell.PSResourceGet -ErrorAction Stop
        }
        catch {
            Write-Status "PSResourceGet unavailable ($($_.Exception.Message)); using Install-Module" -Type Warning
        }
    }

    if (Test-CommandExists 'Install-PSResource') {
        try { Set-PSResourceRepository -Name PSGallery -Trusted -ErrorAction Stop }
        catch { Write-Verbose "Could not mark PSGallery trusted: $($_.Exception.Message)" }
        $script:GalleryInstaller = 'PSResource'
    }
    else {
        if ((Get-PSRepository -Name PSGallery).InstallationPolicy -ne 'Trusted') {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
        $script:GalleryInstaller = 'PowerShellGet'
    }

    Write-Status "Module installer: $script:GalleryInstaller" -Type Info
    return $script:GalleryInstaller
}

function Install-GalleryModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param([string]$Name)

    if ((Initialize-GalleryInstaller) -eq 'PSResource') {
        Install-PSResource -Name $Name -Scope AllUsers -TrustRepository -Reinstall:$Force -ErrorAction Stop
    }
    else {
        Install-Module -Name $Name -Force -AllowClobber -Scope AllUsers -ErrorAction Stop
    }
}

function Uninstall-GalleryModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param([string]$Name)

    # Whichever installer was used, the folder sweep in Remove-PSModulesComponent
    # is the backstop - PSResourceGet and PowerShellGet do not read each other's
    # install metadata, so the matching uninstall cmdlet may not find the module.
    if (Test-CommandExists 'Uninstall-PSResource') {
        Uninstall-PSResource -Name $Name -SkipDependencyCheck -ErrorAction Stop
    }
    else {
        Uninstall-Module -Name $Name -AllVersions -Force -ErrorAction Stop
    }
}

# ============================================================================
# Component: PSModules
# ============================================================================

function Get-SelectedPSModules {
    # Retired modules are opt-in; see the note on $PSModules.
    return @($PSModules.Keys | Where-Object { $IncludeRetired -or -not $PSModules[$_].Retired })
}

function Get-ModuleFamily {
    param([string]$Name)
    $spec = $PSModules[$Name]
    $filter = if ($spec.PSObject.Properties['Prefix'] -or $spec.ContainsKey('Prefix')) { $spec.Prefix } else { $Name }
    return @(Get-Module -ListAvailable -Name $filter -ErrorAction SilentlyContinue |
             Select-Object -ExpandProperty Name -Unique)
}

function Test-PSModulesComponent {
    $selected = @(Get-SelectedPSModules)
    $found = @(); $missing = @()
    foreach ($name in $selected) {
        if (@(Get-ModuleFamily -Name $name).Count -gt 0) { $found += $name } else { $missing += $name }
    }
    return [pscustomobject]@{
        Present = $missing.Count -eq 0
        Detail  = "$($found.Count)/$($selected.Count) present" + $(if ($missing) { "; missing: $($missing -join ', ')" } else { '' })
    }
}

function Install-PSModulesComponent {
    $null = Initialize-GalleryInstaller

    $skipped = @($PSModules.Keys | Where-Object { $_ -notin (Get-SelectedPSModules) })
    if ($skipped) {
        Write-Status "Skipping retired module(s): $($skipped -join ', ') (use -IncludeRetired)" -Type Info
    }

    $installed = @()
    foreach ($name in (Get-SelectedPSModules)) {
        $spec = $PSModules[$name]
        $existing = Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1

        if ($existing -and -not $Force) {
            Write-Status "$name already installed (v$($existing.Version))" -Type Success
            continue
        }

        try {
            Write-Status "Installing $name..."
            Install-GalleryModule -Name $name
            $verify = Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($verify) {
                Write-Status "$name installed (v$($verify.Version))" -Type Success
                $installed += $name
            }
            else {
                Write-Status "$name install could not be verified" -Type Warning
            }
        }
        catch {
            Write-Status "Failed to install $name`: $($_.Exception.Message)" -Type Error
        }

        if ($spec.Retired) {
            Write-Status "$name is retired - Azure AD Graph is decommissioned and most cmdlets will fail" -Type Warning
        }
    }

    Set-ComponentState -Name 'PSModules' -Data @{ InstalledAt = (Get-Date).ToString('o'); Installed = $installed }
}

function Remove-PSModulesComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    $ours = @(Get-InstalledByUs -Name 'PSModules')
    $targets = @(if ($Force) { @($PSModules.Keys) } else { $ours })

    if ($targets.Count -eq 0) {
        Write-Status 'No modules were installed by this script (use -Force to remove all)' -Type Info
        Remove-ComponentState -Name 'PSModules'
        return
    }

    foreach ($name in $targets) {
        $family = @(Get-ModuleFamily -Name $name)
        if ($family.Count -eq 0) { Write-Status "$name not installed" -Type Info; continue }

        Get-Module -Name $name -ErrorAction SilentlyContinue | Remove-Module -Force -ErrorAction SilentlyContinue

        $removed = 0
        foreach ($mod in $family) {
            try { Uninstall-GalleryModule -Name $mod; $removed++ }
            catch { Write-Verbose "Uninstall-Module failed for $mod; folder cleanup below will handle it" }
        }

        # Uninstall-Module leaves folders behind when a module was side-loaded.
        $spec = $PSModules[$name]
        $filter = if ($spec.ContainsKey('Prefix')) { $spec.Prefix } else { $name }
        foreach ($root in $ModulePathRoots) {
            foreach ($folder in @(Get-ChildItem -Path $root -Directory -Filter $filter -ErrorAction SilentlyContinue)) {
                try { Remove-Item -Path $folder.FullName -Recurse -Force -ErrorAction Stop; $removed++ }
                catch { Write-Verbose "Could not remove $($folder.FullName): $($_.Exception.Message)" }
            }
        }

        Write-Status "$name removed ($removed item(s))" -Type Success
    }

    Remove-ComponentState -Name 'PSModules'
}

# ============================================================================
# Component: Chocolatey
# ============================================================================

function Test-ChocolateyComponent {
    $present = Test-CommandExists 'choco'
    return [pscustomobject]@{ Present = $present; Detail = if ($present) { (& choco --version 2>$null) -join '' } else { 'not installed' } }
}

function Install-ChocolateyComponent {
    if ((Test-ChocolateyComponent).Present) {
        Write-Status 'Chocolatey already installed' -Type Success
        Set-ComponentState -Name 'Chocolatey' -Data @{ PreExisting = $true }
        return
    }

    $profileDir = Split-Path $PROFILE -Parent
    if (-not (Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }

    Set-ExecutionPolicy Bypass -Scope Process -Force
    $script = (New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1')
    Invoke-Expression $script *> $null

    Update-EnvironmentPath

    if (Test-CommandExists 'choco') { Write-Status 'Chocolatey installed' -Type Success }
    else { Write-Status 'Chocolatey installed but not yet on PATH - a new session may be required' -Type Warning }

    Set-ComponentState -Name 'Chocolatey' -Data @{ PreExisting = $false }
}

function Remove-ChocolateyComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    if (-not $RemoveChocolatey -and -not $Force) {
        Write-Status 'Keeping Chocolatey (use -RemoveChocolatey to remove it)' -Type Info
        return
    }

    $state = Get-ComponentState -Name 'Chocolatey'
    if ($state -and $state.PreExisting -and -not $Force) {
        Write-Status 'Chocolatey pre-dated this script; leaving it' -Type Warning
        return
    }

    $root = $env:ChocolateyInstall
    if (-not $root) { $root = 'C:\ProgramData\chocolatey' }

    foreach ($path in @($root, "$env:LOCALAPPDATA\Temp\chocolatey")) {
        if (Test-Path $path) {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Status "Removed $path" -Type Success
        }
    }

    foreach ($scope in 'Machine', 'User') {
        [Environment]::SetEnvironmentVariable('ChocolateyInstall', $null, $scope)
        $p = [Environment]::GetEnvironmentVariable('Path', $scope)
        if ($p) {
            $kept = ($p -split ';' | Where-Object { $_ -and $_ -notlike '*chocolatey*' }) -join ';'
            [Environment]::SetEnvironmentVariable('Path', $kept, $scope)
        }
    }
    [Environment]::SetEnvironmentVariable('ChocolateyToolsLocation', $null, 'Machine')

    Write-Status 'Chocolatey removed' -Type Success
    Remove-ComponentState -Name 'Chocolatey'
}

# ============================================================================
# Component: ChocoPackages
# ============================================================================

function Test-ChocoPackagesComponent {
    if (-not (Test-CommandExists 'choco')) {
        return [pscustomobject]@{ Present = $false; Detail = 'chocolatey not installed' }
    }
    $have = @(Get-ChocoInstalledPackages)
    $missing = @($ChocoPackages | Where-Object { $_ -notin $have })
    return [pscustomobject]@{
        Present = $missing.Count -eq 0
        Detail  = "$($ChocoPackages.Count - $missing.Count)/$($ChocoPackages.Count) present" +
                  $(if ($missing) { "; missing: $($missing -join ', ')" } else { '' })
    }
}

function Install-ChocoPackagesComponent {
    if (-not (Test-CommandExists 'choco')) {
        Write-Status 'Chocolatey not available - skipping packages' -Type Warning
        return
    }

    Update-EnvironmentPath
    $have = @(Get-ChocoInstalledPackages)
    $installed = @()

    foreach ($pkg in $ChocoPackages) {
        if ($pkg -in $have -and -not $Force) { Write-Status "$pkg already installed" -Type Success; continue }
        & choco install $pkg -y --no-progress | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Status "$pkg installed" -Type Success; $installed += $pkg }
        else { Write-Status "Failed to install $pkg (exit $LASTEXITCODE)" -Type Error }
    }

    Update-EnvironmentPath
    Set-ComponentState -Name 'ChocoPackages' -Data @{ InstalledAt = (Get-Date).ToString('o'); Installed = $installed }
}

function Remove-ChocoPackagesComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    if (-not (Test-CommandExists 'choco')) {
        Write-Status 'Chocolatey not available - skipping packages' -Type Warning
        return
    }

    # Only remove what we installed. This is what makes the old -KeepPython /
    # -KeepGit flags unnecessary: git and python that pre-dated the lab are
    # simply never touched.
    $ours = @(Get-InstalledByUs -Name 'ChocoPackages')
    $targets = @(if ($Force) { $ChocoPackages } else { $ours })

    if ($targets.Count -eq 0) {
        Write-Status 'No packages were installed by this script (use -Force to remove all)' -Type Info
        Remove-ComponentState -Name 'ChocoPackages'
        return
    }

    # Uninstalling powershell-core can kill the host running this script.
    $self = (Get-Process -Id $PID).Path
    $have = @(Get-ChocoInstalledPackages)

    foreach ($pkg in $targets) {
        if ($pkg -notin $have) { Write-Status "$pkg not installed" -Type Info; continue }

        if ($pkg -eq 'powershell-core' -and $self -and $self -like '*\pwsh.exe') {
            Write-Status 'Skipping powershell-core: it is the host running this script' -Type Warning
            Write-Status 'Re-run from Windows PowerShell (powershell.exe) to remove it' -Type Info
            continue
        }

        & choco uninstall $pkg -y --remove-dependencies 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { Write-Status "$pkg removed" -Type Success }
        else { Write-Status "Failed to remove $pkg (exit $LASTEXITCODE)" -Type Warning }
    }

    Remove-ComponentState -Name 'ChocoPackages'
}

# ============================================================================
# Component: PythonPackages
# ============================================================================

function Test-PythonPackagesComponent {
    $pip = Get-PipCommand
    if (-not $pip) { return [pscustomobject]@{ Present = $false; Detail = 'pip not available' } }

    $missing = @()
    foreach ($pkg in $PythonPackages) {
        $shown = & $pip show $pkg 2>$null
        if (-not $shown) { $missing += $pkg }
    }
    return [pscustomobject]@{
        Present = $missing.Count -eq 0
        Detail  = "$($PythonPackages.Count - $missing.Count)/$($PythonPackages.Count) present" +
                  $(if ($missing) { "; missing: $($missing -join ', ')" } else { '' })
    }
}

function Install-PythonPackagesComponent {
    Update-EnvironmentPath
    $pip = Get-PipCommand
    if (-not $pip) { Write-Status 'pip not found - skipping Python tools' -Type Warning; return }

    $installed = @()
    foreach ($pkg in $PythonPackages) {
        $shown = & $pip show $pkg 2>$null
        if ($shown -and -not $Force) { Write-Status "$pkg already installed" -Type Success; continue }

        & $pip install $pkg --quiet --break-system-packages 2>$null
        if ($LASTEXITCODE -ne 0) {
            # --break-system-packages does not exist before pip 23.
            & $pip install $pkg --quiet 2>$null
        }

        if ($LASTEXITCODE -eq 0) { Write-Status "$pkg installed" -Type Success; $installed += $pkg }
        else { Write-Status "Failed to install $pkg" -Type Warning }
    }

    Set-ComponentState -Name 'PythonPackages' -Data @{ InstalledAt = (Get-Date).ToString('o'); Installed = $installed }
}

function Remove-PythonPackagesComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    $pip = Get-PipCommand
    if (-not $pip) { Write-Status 'pip not found - skipping' -Type Warning; return }

    $ours = @(Get-InstalledByUs -Name 'PythonPackages')
    $targets = @(if ($Force) { $PythonPackages } else { $ours })

    if ($targets.Count -eq 0) {
        Write-Status 'No Python packages were installed by this script' -Type Info
        Remove-ComponentState -Name 'PythonPackages'
        return
    }

    foreach ($pkg in $targets) {
        $shown = & $pip show $pkg 2>$null
        if (-not $shown) { Write-Status "$pkg not installed" -Type Info; continue }
        & $pip uninstall $pkg -y --quiet 2>$null
        Write-Status "$pkg removed" -Type Success
    }

    Remove-ComponentState -Name 'PythonPackages'
}

# ============================================================================
# Component: GitHubRepos
# ============================================================================

function Test-GitHubReposComponent {
    $missing = @($GitHubRepos | Where-Object { -not (Test-Path (Join-Path $ToolsPath $_.Name)) } |
                 ForEach-Object { $_.Name })
    return [pscustomobject]@{
        Present = $missing.Count -eq 0
        Detail  = "$($GitHubRepos.Count - $missing.Count)/$($GitHubRepos.Count) cloned" +
                  $(if ($missing) { "; missing: $($missing -join ', ')" } else { '' })
    }
}

function Install-GitHubReposComponent {
    Update-EnvironmentPath
    if (-not (Test-CommandExists 'git')) { Write-Status 'git not found - skipping repositories' -Type Warning; return }

    if (-not (Test-Path $ToolsPath)) { New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null }

    $cloned = @()
    foreach ($repo in $GitHubRepos) {
        $path = Join-Path $ToolsPath $repo.Name
        if (Test-Path $path) {
            Push-Location $path
            & git pull --quiet 2>$null
            Pop-Location
            Write-Status "$($repo.Name) updated" -Type Success
            continue
        }
        & git clone $repo.Url $path --quiet 2>$null
        if ($LASTEXITCODE -eq 0) { Write-Status "$($repo.Name) cloned" -Type Success; $cloned += $repo.Name }
        else { Write-Status "Failed to clone $($repo.Name)" -Type Error }
    }

    Set-ComponentState -Name 'GitHubRepos' -Data @{ InstalledAt = (Get-Date).ToString('o'); Installed = $cloned }
}

function Remove-GitHubReposComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    $ours = @(Get-InstalledByUs -Name 'GitHubRepos')
    $targets = @(if ($Force) { @($GitHubRepos | ForEach-Object { $_.Name }) } else { $ours })

    if ($targets.Count -eq 0) {
        Write-Status 'No repositories were cloned by this script (use -Force to remove all)' -Type Info
        Remove-ComponentState -Name 'GitHubRepos'
        return
    }

    foreach ($name in $targets) {
        $path = Join-Path $ToolsPath $name
        if (-not (Test-Path $path)) { continue }
        Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "$name removed" -Type Success
    }

    # Drop the tools directory only if nothing else is left in it.
    if ((Test-Path $ToolsPath) -and @(Get-ChildItem -Path $ToolsPath -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -Path $ToolsPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Removed empty $ToolsPath" -Type Success
    }

    Remove-ComponentState -Name 'GitHubRepos'
}

# ============================================================================
# Component: AzureHound
# ============================================================================

function Get-AzureHoundExe {
    return Get-ChildItem -Path $AzureHoundDir -Filter 'azurehound.exe' -Recurse -ErrorAction SilentlyContinue |
           Select-Object -First 1
}

function Test-AzureHoundComponent {
    $exe = Get-AzureHoundExe
    if (-not $exe) { return [pscustomobject]@{ Present = $false; Detail = 'not installed' } }

    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $onPath  = @($machine -split ';') -contains $exe.DirectoryName
    return [pscustomobject]@{
        Present = $true
        Detail  = "$($exe.FullName); on machine PATH: $onPath"
    }
}

function Install-AzureHoundComponent {
    if ((Test-AzureHoundComponent).Present -and -not $Force) {
        Write-Status 'AzureHound already installed' -Type Success
        # Record that it pre-dated us. Every other component does this, and
        # without it Remove deleted a directory this script never created.
        Set-ComponentState -Name 'AzureHound' -Data @{ PreExisting = $true }
        return
    }

    $headers = @{ 'User-Agent' = $UserAgent; 'Accept' = 'application/vnd.github.v3+json' }
    $release = Invoke-RestMethod -Uri $AzureHoundApi -Headers $headers -ErrorAction Stop
    $arch    = if ([Environment]::Is64BitOperatingSystem) { 'amd64' } else { '386' }

    $asset = $release.assets |
             Where-Object { $_.name -like "*windows_$arch.zip" -and $_.name -notlike '*.sha256' } |
             Select-Object -First 1
    if (-not $asset) { throw "No AzureHound binary found for windows_$arch" }

    Write-Status "Downloading AzureHound $($release.tag_name)..."
    $zip = Join-Path $env:TEMP $asset.name

    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', $UserAgent)
        $wc.DownloadFile($asset.browser_download_url, $zip)

        if ($asset.PSObject.Properties['digest'] -and $asset.digest) {
            $expected = ($asset.digest -split ':')[1].ToUpper()
            $actual   = (Get-FileHash -Path $zip -Algorithm SHA256).Hash
            if ($expected -ne $actual) { throw 'AzureHound checksum verification failed' }
            Write-Status 'Checksum verified' -Type Success
        }

        if (Test-Path $AzureHoundDir) { Remove-Item $AzureHoundDir -Recurse -Force }
        Expand-Archive -Path $zip -DestinationPath $AzureHoundDir -Force
    }
    finally {
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
    }

    $exe = Get-AzureHoundExe
    if (-not $exe) { throw 'azurehound.exe not found after extraction' }

    # Persist to the machine PATH. The old installer only touched $env:Path, so
    # azurehound was never actually available after a restart despite the
    # completion banner claiming it was.
    $added = Add-MachinePath -Directory $exe.DirectoryName
    Write-Status "AzureHound $($release.tag_name) installed to $($exe.FullName)" -Type Success
    if ($added) { Write-Status "Added $($exe.DirectoryName) to the machine PATH" -Type Success }

    Set-ComponentState -Name 'AzureHound' -Data @{
        InstalledAt = (Get-Date).ToString('o')
        PreExisting = $false
        Version     = $release.tag_name
        PathEntry   = if ($added) { $exe.DirectoryName } else { $null }
    }
}

function Remove-AzureHoundComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    $state = Get-ComponentState -Name 'AzureHound'

    if (-not (Test-Path $AzureHoundDir)) {
        Write-Status 'AzureHound not installed' -Type Info
        Remove-ComponentState -Name 'AzureHound'
        return
    }

    # Leave alone anything this script did not install: either Install recorded
    # it as pre-existing, or there is no manifest entry at all (installed by
    # hand, or by a build that pre-dated state tracking). This is what every
    # other component does; AzureHound used to delete the directory regardless.
    $preExisting = (-not $state) -or
                   ($state.PSObject.Properties['PreExisting'] -and $state.PreExisting)
    if ($preExisting -and -not $Force) {
        Write-Status 'AzureHound pre-dated this script; leaving it (use -Force to remove)' -Type Warning
        return
    }

    if ($state -and $state.PSObject.Properties['PathEntry'] -and $state.PathEntry) {
        if (Remove-MachinePath -Directory $state.PathEntry) {
            Write-Status "Removed $($state.PathEntry) from the machine PATH" -Type Success
        }
    }

    Remove-Item -Path $AzureHoundDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Status 'AzureHound removed' -Type Success
    Remove-ComponentState -Name 'AzureHound'
}

# ============================================================================
# Component: Profile
# ============================================================================

function Get-ProfileBlock {
    # Single-quoted here-string: nothing below is expanded at build time except
    # the explicit -replace for the tools path.
    $block = @'
# ============================================================================
# Azure Red Team Tools Configuration
# Managed by AdversaryLab-RedTeam.ps1 - do not edit between these markers
# ============================================================================

$ToolsPath = '__TOOLSPATH__'
if ($env:PSModulePath -notlike "*$ToolsPath*") {
    $env:PSModulePath = "$ToolsPath;$env:PSModulePath"
}

function Load-GraphRunner  { . "$ToolsPath\GraphRunner\GraphRunner.ps1"; Write-Host 'GraphRunner loaded' -ForegroundColor Green }
function Load-TokenTactics { Import-Module "$ToolsPath\TokenTacticsV2\TokenTactics.psd1" -Global; Write-Host 'TokenTacticsV2 loaded' -ForegroundColor Green }
function Load-AADInternals { Import-Module AADInternals -Global -DisableNameChecking 3>$null; Write-Host 'AADInternals loaded' -ForegroundColor Green }
function Load-AzModule     { Import-Module Az.Accounts -Global -DisableNameChecking; Write-Host "Az.Accounts loaded - run 'Connect-AzAccount'" -ForegroundColor Green }
function Load-MSGraph      { Import-Module Microsoft.Graph.Authentication -Global -DisableNameChecking; Write-Host "Microsoft.Graph loaded - run 'Connect-MgGraph'" -ForegroundColor Green }

function Load-MicroBurst {
    if (-not (Get-Module -Name Az.Accounts)) { Import-Module Az.Accounts -Global -DisableNameChecking -ErrorAction SilentlyContinue }
    Import-Module "$ToolsPath\MicroBurst\MicroBurst.psm1" -Global
    Write-Host 'MicroBurst loaded' -ForegroundColor Green
}

function Load-PowerZure {
    if (-not (Get-Module -Name Az.Accounts)) { Import-Module Az.Accounts -Global -DisableNameChecking }
    if (-not (Get-AzContext -ErrorAction SilentlyContinue)) {
        Write-Host "PowerZure needs an active Azure connection. Run 'Connect-AzAccount' first." -ForegroundColor Yellow
        return
    }
    Import-Module "$ToolsPath\PowerZure\PowerZure.psd1" -Global
    Write-Host 'PowerZure loaded' -ForegroundColor Green
}

function Load-AllRedTeamTools {
    Write-Host ''
    Write-Host 'Loaders:' -ForegroundColor Cyan
    'aadint       - AADInternals',
    'graphrunner  - GraphRunner',
    'tokentactics - TokenTacticsV2',
    'microburst   - MicroBurst',
    'powerzure    - PowerZure (needs Connect-AzAccount)',
    'azmodule     - Az.Accounts',
    'msgraph      - Microsoft.Graph.Authentication' | ForEach-Object { Write-Host "  $_" }
    Write-Host ''
    Write-Host 'CLI (already on PATH):' -ForegroundColor Cyan
    '  azurehound --help', '  roadrecon gather', '  scout azure --help' | ForEach-Object { Write-Host $_ }
    Write-Host ''
}

Set-Alias -Name rtload       -Value Load-AllRedTeamTools
Set-Alias -Name aadint       -Value Load-AADInternals
Set-Alias -Name graphrunner  -Value Load-GraphRunner
Set-Alias -Name tokentactics -Value Load-TokenTactics
Set-Alias -Name microburst   -Value Load-MicroBurst
Set-Alias -Name powerzure    -Value Load-PowerZure
Set-Alias -Name azmodule     -Value Load-AzModule
Set-Alias -Name msgraph      -Value Load-MSGraph

Write-Host "Azure Red Team tools ready. Type 'rtload' for the tool list." -ForegroundColor Cyan

# End Azure Red Team Tools Configuration
# ============================================================================
'@
    return $block -replace '__TOOLSPATH__', $ToolsPath
}

function Get-ProfileBlockPattern {
    return '(?s)\r?\n*# =+\r?\n' + [regex]::Escape($ProfileMarkerStart) + '.*?' +
           [regex]::Escape($ProfileMarkerEnd) + '\r?\n# =+\r?\n*'
}

function Test-ProfileComponent {
    $targets = @(Get-ProfileTargetPaths)
    $configured = @($targets | Where-Object {
        (Test-Path $_) -and ((Get-Content $_ -Raw -ErrorAction SilentlyContinue) -like "*$ProfileMarkerStart*")
    })
    return [pscustomobject]@{
        Present = $configured.Count -gt 0
        Detail  = "$($configured.Count)/$($targets.Count) profile(s) configured"
    }
}

function Install-ProfileComponent {
    $block   = Get-ProfileBlock
    $pattern = Get-ProfileBlockPattern
    $written = @()

    foreach ($path in @(Get-ProfileTargetPaths)) {
        $dir = Split-Path $path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

        $existedBefore = Test-Path $path

        if ($existedBefore) {
            $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
            if ($content -like "*$ProfileMarkerStart*") {
                # Replace the old block rather than appending a second copy.
                $content = ($content -replace $pattern, "`n").Trim()
                if ($content) { Set-Content -Path $path -Value $content -Encoding UTF8 }
                else { Remove-Item -Path $path -Force }
            }
        }

        Add-Content -Path $path -Value "`n$block" -Encoding UTF8
        Write-Status "Profile updated: $path" -Type Success
        $written += @{ Path = $path; ExistedBefore = $existedBefore }
    }

    Set-ComponentState -Name 'Profile' -Data @{ InstalledAt = (Get-Date).ToString('o'); Profiles = $written }
}

function Remove-ProfileComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    $pattern = Get-ProfileBlockPattern

    # Prefer the paths Install actually wrote, so a change of host layout
    # between install and removal cannot orphan a block.
    $state   = Get-ComponentState -Name 'Profile'
    $targets = @(Get-ProfileTargetPaths)
    if ($state -and $state.PSObject.Properties['Profiles'] -and $state.Profiles) {
        # Flatten defensively: a state file written by an older build could
        # record Path as an array rather than one entry per profile.
        $recorded = @($state.Profiles | ForEach-Object { $_.Path } | ForEach-Object { $_ }) |
                    Where-Object { $_ -is [string] -and $_ }
        $targets  = @(@($targets) + @($recorded) | Select-Object -Unique)
    }

    foreach ($path in $targets) {
        if (-not (Test-Path $path)) { continue }
        $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
        if ($content -notlike "*$ProfileMarkerStart*") {
            Write-Status "No red team block in $path" -Type Info
            continue
        }

        $cleaned = ($content -replace $pattern, "`n") -replace '(\r?\n){3,}', "`n`n"
        $cleaned = $cleaned.Trim()

        if ($cleaned) {
            Set-Content -Path $path -Value $cleaned -Encoding UTF8
            Write-Status "Cleaned profile: $path" -Type Success
        }
        else {
            Remove-Item -Path $path -Force
            Write-Status "Removed now-empty profile: $path" -Type Success
        }
    }

    Remove-ComponentState -Name 'Profile'
}

# ============================================================================
# Component: Shortcuts
# ============================================================================

function Get-DesktopPath {
    <#
        Under SYSTEM - which is how Custom Script Extension and
        Invoke-AzVMRunCommand execute - the per-user Desktop resolves to an
        empty string and Join-Path throws. Fall back to the all-users desktop,
        which is where a machine-wide tool install belongs anyway.
    #>
    $desktop = [Environment]::GetFolderPath('Desktop')
    if (-not [string]::IsNullOrWhiteSpace($desktop) -and (Test-Path $desktop)) { return $desktop }

    if ($env:PUBLIC) {
        $public = Join-Path $env:PUBLIC 'Desktop'
        if (Test-Path $public) { return $public }
    }
    return $null
}

function Test-ShortcutsComponent {
    $desktop = Get-DesktopPath
    if (-not $desktop) {
        return [pscustomobject]@{ Present = $false; Detail = 'no writable desktop folder available' }
    }
    $found = @($ShortcutNames | Where-Object { Test-Path (Join-Path $desktop $_) })
    return [pscustomobject]@{
        Present = $found.Count -eq $ShortcutNames.Count
        Detail  = "$($found.Count)/$($ShortcutNames.Count) on desktop"
    }
}

function Install-ShortcutsComponent {
    $desktop = Get-DesktopPath
    if (-not $desktop) {
        Write-Status 'No writable desktop folder; skipping shortcuts' -Type Warning
        return
    }
    $shell = New-Object -ComObject WScript.Shell

    $sc = $shell.CreateShortcut((Join-Path $desktop 'Azure Red Team Tools.lnk'))
    $sc.TargetPath = $ToolsPath
    $sc.Save()

    $host_exe = (Get-Command pwsh -ErrorAction SilentlyContinue |
                 Select-Object -ExpandProperty Source -First 1)
    if (-not $host_exe) {
        foreach ($p in @("$env:ProgramFiles\PowerShell\7\pwsh.exe", "$env:LOCALAPPDATA\Microsoft\PowerShell\pwsh.exe")) {
            if (Test-Path $p) { $host_exe = $p; break }
        }
    }
    if (-not $host_exe) {
        $host_exe = 'powershell.exe'
        Write-Status 'PowerShell 7 not found; shortcut will use Windows PowerShell' -Type Warning
    }

    $sc = $shell.CreateShortcut((Join-Path $desktop 'Red Team PowerShell.lnk'))
    $sc.TargetPath       = $host_exe
    $sc.Arguments        = '-NoExit -Command "rtload"'
    $sc.WorkingDirectory = $ToolsPath
    $sc.Save()

    Write-Status "Desktop shortcuts created in $desktop" -Type Success
    Set-ComponentState -Name 'Shortcuts' -Data @{ InstalledAt = (Get-Date).ToString('o'); Names = $ShortcutNames; Desktop = $desktop }
}

function Remove-ShortcutsComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Mutations are gated by Invoke-ComponentAction.')]
    param()

    # Prefer the desktop Install actually wrote to, in case it differed.
    $state   = Get-ComponentState -Name 'Shortcuts'
    $desktop = if ($state -and $state.PSObject.Properties['Desktop'] -and $state.Desktop) { $state.Desktop } else { Get-DesktopPath }
    if (-not $desktop) { Write-Status 'No desktop folder to clean' -Type Info; Remove-ComponentState -Name 'Shortcuts'; return }

    foreach ($name in $ShortcutNames) {
        $path = Join-Path $desktop $name
        if (Test-Path $path) { Remove-Item -Path $path -Force; Write-Status "Removed $name" -Type Success }
    }
    Remove-ComponentState -Name 'Shortcuts'
}

# ============================================================================
# Component table - each component declares its three verbs exactly once.
# Install walks this table in order; Remove walks it in reverse, so the
# Defender exclusion is added first and removed last.
#
# Requires declares what a component needs in order to do anything, so Test and
# -WhatIf can say 'blocked' rather than just 'absent'. It probes the capability
# (is git on PATH?) rather than the providing component's completeness, because
# git or Python installed by some other means is perfectly valid and must not be
# reported as blocked. From names the component that would supply it. These are
# reporting only: the checks inside each Install remain the real gate.
# ============================================================================

$Components = [ordered]@{
    DefenderExclusion = @{ Description = 'Windows Defender exclusion for the tools directory'
                           Test = { Test-DefenderExclusionComponent }; Install = { Install-DefenderExclusionComponent }; Remove = { Remove-DefenderExclusionComponent } }
    PSModules         = @{ Description = 'PowerShell modules (AADInternals, Az, Microsoft.Graph, ...)'
                           Test = { Test-PSModulesComponent };         Install = { Install-PSModulesComponent };         Remove = { Remove-PSModulesComponent } }
    Chocolatey        = @{ Description = 'Chocolatey package manager'
                           Test = { Test-ChocolateyComponent };        Install = { Install-ChocolateyComponent };        Remove = { Remove-ChocolateyComponent } }
    ChocoPackages     = @{ Description = 'Chocolatey packages (git, python3, vscode, azure-cli, ...)'
                           Requires = @( @{ Test = { Test-CommandExists 'choco' };   Name = 'choco'; From = 'Chocolatey' } )
                           Test = { Test-ChocoPackagesComponent };     Install = { Install-ChocoPackagesComponent };     Remove = { Remove-ChocoPackagesComponent } }
    PythonPackages    = @{ Description = 'Python tools (roadrecon, scoutsuite)'
                           Requires = @( @{ Test = { [bool](Get-PipCommand) };       Name = 'pip';   From = 'ChocoPackages' } )
                           Test = { Test-PythonPackagesComponent };    Install = { Install-PythonPackagesComponent };    Remove = { Remove-PythonPackagesComponent } }
    GitHubRepos       = @{ Description = 'GitHub tooling repositories'
                           Requires = @( @{ Test = { Test-CommandExists 'git' };     Name = 'git';   From = 'ChocoPackages' } )
                           Test = { Test-GitHubReposComponent };       Install = { Install-GitHubReposComponent };       Remove = { Remove-GitHubReposComponent } }
    AzureHound        = @{ Description = 'AzureHound collector binary'
                           Test = { Test-AzureHoundComponent };        Install = { Install-AzureHoundComponent };        Remove = { Remove-AzureHoundComponent } }
    Profile           = @{ Description = 'PowerShell profile loaders and aliases'
                           Test = { Test-ProfileComponent };           Install = { Install-ProfileComponent };           Remove = { Remove-ProfileComponent } }
    Shortcuts         = @{ Description = 'Desktop shortcuts'
                           Test = { Test-ShortcutsComponent };         Install = { Install-ShortcutsComponent };         Remove = { Remove-ShortcutsComponent } }
}

# ============================================================================
# Engine
# ============================================================================

function Get-SelectedComponents {
    $names = if ($Component) { @($Component) } else { @($Components.Keys) }
    # Remove reverses install order so dependants go before their dependencies.
    if ($Action -eq 'Remove') { [array]::Reverse($names) }
    return $names
}

function Get-UnmetRequirements {
    param([string]$Name)

    $spec = $Components[$Name]
    if (-not $spec.ContainsKey('Requires')) { return @() }

    $unmet = @()
    foreach ($req in $spec.Requires) {
        $met = $false
        try { $met = [bool](& $req.Test) } catch { $met = $false }
        if (-not $met) { $unmet += "$($req.Name) (from $($req.From))" }
    }
    return $unmet
}

function Get-ComponentReport {
    param([string[]]$Names)

    $report = @()
    foreach ($name in $Names) {
        $spec = $Components[$name]
        try { $result = & $spec.Test }
        catch { $result = [pscustomobject]@{ Present = $false; Detail = "test failed: $($_.Exception.Message)" } }

        # Only worth probing when something is missing; a component that is
        # already present has satisfied its requirements by definition.
        $unmet = @(if ($result.Present) { @() } else { Get-UnmetRequirements -Name $name })

        $report += [pscustomobject]@{
            Component = $name
            Present   = $result.Present
            Detail    = $result.Detail
            Unmet     = $unmet
        }
    }
    return $report
}

function Show-Plan {
    param([string[]]$Names)

    Write-Section "Plan: $Action"
    foreach ($row in (Get-ComponentReport -Names $Names)) {
        $state = if ($row.Present) { 'present' } else { 'absent' }
        $verb  = switch ($Action) {
            'Install' {
                if ($row.Present -and -not $Force) { 'skip (already present)' }
                elseif ($row.Unmet)                { "skip (needs $($row.Unmet -join ', '))" }
                else                               { 'install' }
            }
            'Remove'  { if ($row.Present) { 'remove' } else { 'skip (absent)' } }
        }
        Write-Status "$($row.Component): currently $state -> would $verb" -Type Plan
    }
}

function Invoke-ComponentAction {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Name, [string]$Verb)

    $spec = $Components[$Name]
    Write-Section "$Verb`: $($spec.Description)"

    # Single ShouldProcess gate for every mutation in the component.
    if (-not $PSCmdlet.ShouldProcess($Name, "$Verb red-team component")) { return }

    try { & $spec.$Verb }
    catch {
        Write-Status "$Verb failed for $Name`: $($_.Exception.Message)" -Type Error
        throw   # caught per-component in main so siblings still run
    }
}

function Show-TestReport {
    param([string[]]$Names)

    Write-Banner 'Red Team Tooling Status'
    $report = Get-ComponentReport -Names $Names

    foreach ($row in $report) {
        Write-Host ''
        if ($row.Present) { Write-Status "$($row.Component): present" -Type Success }
        else              { Write-Status "$($row.Component): not installed" -Type Error }
        Write-Host "         $($row.Detail)" -ForegroundColor DarkGray
        if ($row.Unmet) { Write-Host "         blocked by missing: $($row.Unmet -join ', ')" -ForegroundColor DarkGray }
    }

    $missing = @($report | Where-Object { -not $_.Present })
    Write-Host ''
    if ($missing.Count -eq 0) { Write-Status 'All selected components are present' -Type Success }
    else { Write-Status "$($missing.Count) of $($report.Count) component(s) missing" -Type Warning }
    Write-Host ''

    return $report
}

function Show-Summary {
    param([string[]]$Names)

    Write-Banner "Red Team Tools - $Action Complete"
    foreach ($row in (Get-ComponentReport -Names $Names)) {
        $state = if ($row.Present) { 'present' } else { 'absent' }
        Write-Host "    - $($row.Component): $state" -ForegroundColor Gray
    }

    Write-Host ''
    if ($Action -eq 'Install') {
        Write-Host '  Restart PowerShell, then type: rtload' -ForegroundColor White
        Write-Host "  State file: $StatePath" -ForegroundColor DarkGray
        Write-Host '  Remove reverses only what this file records.' -ForegroundColor DarkGray
    }
    Write-Host ''
}

# ============================================================================
# Main
# ============================================================================

# Pick up PATH changes made by earlier installs before probing anything.
Update-EnvironmentPath

$selected = Get-SelectedComponents

Write-Banner "AdversaryLab Red Team - $Action"
Write-Host "  Tools path: $ToolsPath" -ForegroundColor Gray
Write-Host "  Components: $($selected -join ', ')" -ForegroundColor Gray
Write-Host ''

try {
    if ($Action -eq 'Test') {
        $report = Show-TestReport -Names $selected
        if (@($report | Where-Object { -not $_.Present }).Count -gt 0) { exit 2 }
        exit 0
    }

    if ($WhatIfPreference) { Show-Plan -Names $selected }

    if (-not $Force -and -not $WhatIfPreference -and $Action -eq 'Install') {
        Write-Host '  This will:' -ForegroundColor Yellow
        Write-Host "    - Add a Windows Defender exclusion for $ToolsPath" -ForegroundColor Yellow
        Write-Host '    - Install offensive security tooling (AzureHound, AADInternals, PowerZure, ...)' -ForegroundColor Yellow
        Write-Host '    - Modify your PowerShell profile and machine PATH' -ForegroundColor Yellow
        Write-Host ''
        Write-Host '  Only run this on a dedicated, isolated lab machine.' -ForegroundColor Red
        Write-Host ''
    }

    if (-not $Force -and -not $Yes -and -not $WhatIfPreference) {
        $confirm = Read-Host "  Proceed with $($Action.ToLower())? (y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
            exit 0
        }
    }

    if ($Action -eq 'Install' -and -not (Test-Path $ToolsPath)) {
        New-Item -ItemType Directory -Path $ToolsPath -Force | Out-Null
    }

    # Components are independent: a failure in one must not prevent the others.
    $failed = @()
    foreach ($name in $selected) {
        try { Invoke-ComponentAction -Name $name -Verb $Action }
        catch { $failed += $name }
    }

    if (-not $WhatIfPreference) { Show-Summary -Names $selected }

    if ($failed.Count -gt 0) {
        Write-Status "Failed component(s): $($failed -join ', ')" -Type Error
        exit 1
    }
    exit 0
}
catch {
    Write-Host ''
    Write-Status "$Action failed: $($_.Exception.Message)" -Type Error
    Write-Verbose $_.ScriptStackTrace
    exit 1
}
