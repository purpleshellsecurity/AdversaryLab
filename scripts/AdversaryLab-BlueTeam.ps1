<#
.SYNOPSIS
    Installs, removes, or verifies blue-team telemetry on an AdversaryLab VM.

.DESCRIPTION
    Single entry point for the defensive monitoring stack that feeds the lab's
    Log Analytics workspace:

      - Sysmon        (SwiftOnSecurity config) -> Microsoft-Windows-Sysmon/Operational
      - PSLogging     (script block, module, transcription) -> Microsoft-Windows-PowerShell/Operational
      - AuditPolicy   (process creation w/ cmdline, logon, privilege use, ...) -> Security

    Every component declares its Test / Install / Remove behaviour once, in the
    $Components table. Install, Remove and Test are three walks over that same
    table, so the three code paths cannot drift apart.

    Install records what it actually changed to a state file. Remove reverses
    only those changes, restoring prior audit settings and registry values
    rather than guessing at Windows defaults. Components that were already
    present before Install ran are left alone by Remove.

.PARAMETER Action
    Install  - deploy the selected components (default)
    Remove   - reverse what Install recorded in the state file
    Test     - report current state and whether events are actually flowing

.PARAMETER Component
    One or more of: Sysmon, PSLogging, AuditPolicy. Defaults to all three.

.PARAMETER SysmonConfigUrl
    URL to a Sysmon configuration XML. Default: SwiftOnSecurity.

.PARAMETER UseDefaultSysmonConfig
    Use Sysmon's built-in configuration instead of downloading one.

.PARAMETER KeepTranscripts
    On Remove, leave C:\PSTranscripts in place.

.PARAMETER Yes
    Skip the confirmation prompt without changing any other behaviour. Use this
    for unattended runs; -Force also skips the prompt but additionally reinstalls
    components already present and removes ones that pre-dated this script.

.PARAMETER Force
    Skip the confirmation prompt (required for unattended runs via Custom Script
    Extension or Invoke-AzVMRunCommand), reinstall components already present,
    and remove components that pre-dated this script.

.PARAMETER StatePath
    Location of the install manifest. Default: C:\ProgramData\AdversaryLab\blueteam-state.json

.PARAMETER SkipAgentRestart
    Do not restart the Azure Monitor Agent after installing Sysmon. By default
    the agent is restarted so it picks up the newly registered Sysmon channel;
    without this the DCR may not collect Sysmon events until the next reboot.

.EXAMPLE
    .\AdversaryLab-BlueTeam.ps1
    Interactive install of all three components.

.EXAMPLE
    .\AdversaryLab-BlueTeam.ps1 -Action Install -Force
    Unattended install. Safe to call from a Custom Script Extension.

.EXAMPLE
    .\AdversaryLab-BlueTeam.ps1 -Action Test
    Report what is configured and whether Sysmon/PowerShell/Security events are
    arriving. Makes no changes.

.EXAMPLE
    .\AdversaryLab-BlueTeam.ps1 -Action Install -Component Sysmon -WhatIf
    Show the plan without touching the machine.

.EXAMPLE
    .\AdversaryLab-BlueTeam.ps1 -Action Remove -KeepTranscripts

.NOTES
    Requires: Windows PowerShell 5.1+ or PowerShell 7+, Administrator privileges.
    Replaces: Install-BlueTeamTools.ps1, Uninstall-BlueTeamTools.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Install', 'Remove', 'Test')]
    [string]$Action = 'Install',

    [ValidateSet('Sysmon', 'PSLogging', 'AuditPolicy')]
    [string[]]$Component,

    [ValidateNotNullOrEmpty()]
    [string]$SysmonConfigUrl = 'https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml',

    [switch]$UseDefaultSysmonConfig,
    [switch]$KeepTranscripts,
    [switch]$Force,
    [switch]$Yes,
    [switch]$SkipAgentRestart,

    [ValidateNotNullOrEmpty()]
    [string]$StatePath = 'C:\ProgramData\AdversaryLab\blueteam-state.json'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================================
# Data - single source of truth for all three verbs
# ============================================================================

$SysmonPrimaryPath = 'C:\Windows\Sysmon64.exe'
$SysmonDownloadUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$SysmonChannel     = 'Microsoft-Windows-Sysmon/Operational'
$SysmonDriverGlob  = 'C:\Windows\System32\drivers\Sysmon*.sys'

# Every location Sysmon might have left a binary, checked by both Test and Remove.
$SysmonBinaryPaths = @(
    'C:\Windows\Sysmon64.exe'
    'C:\Windows\Sysmon.exe'
    'C:\Windows\System32\Sysmon64.exe'
    'C:\Windows\System32\Sysmon.exe'
)

$PSChannel     = 'Microsoft-Windows-PowerShell/Operational'
$PSPolicyRoot  = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
$TranscriptDir = 'C:\PSTranscripts'

# Module logging scope. '*' captures every module, which is what makes 4103 the
# single largest contributor to Log Analytics ingestion on this lab. Narrow this
# list to cut cost; the DCR ships whatever lands in $PSChannel.
$ModuleLogNames = @('*')

# Registry policy declared once. Install writes these, Test compares against
# them, Remove restores whatever was captured in the state file.
$PSLoggingKeys = [ordered]@{
    ScriptBlockLogging = @{
        Path   = "$PSPolicyRoot\ScriptBlockLogging"
        Values = [ordered]@{ EnableScriptBlockLogging = @{ Data = 1; Type = 'DWord' } }
    }
    ModuleLogging      = @{
        Path   = "$PSPolicyRoot\ModuleLogging"
        Values = [ordered]@{ EnableModuleLogging = @{ Data = 1; Type = 'DWord' } }
    }
    Transcription      = @{
        Path   = "$PSPolicyRoot\Transcription"
        Values = [ordered]@{
            EnableTranscripting    = @{ Data = 1;              Type = 'DWord' }
            EnableInvocationHeader = @{ Data = 1;              Type = 'DWord' }
            OutputDirectory        = @{ Data = $TranscriptDir; Type = 'String' }
        }
    }
}

$CmdLineAuditKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'

# Audit subcategories and the event IDs each one produces, declared once.
# 'Desired' is what Install sets. Remove restores the setting captured at
# install time; 'Fallback' is used only when no state file exists.
$AuditSubcategories = [ordered]@{
    'Process Creation'          = @{ Desired = 'Success and Failure'; Fallback = 'No Auditing'; Events = '4688' }
    'Logon'                     = @{ Desired = 'Success and Failure'; Fallback = 'Success';     Events = '4624, 4625' }
    'Logoff'                    = @{ Desired = 'Success';             Fallback = 'Success';     Events = '4634' }
    'Credential Validation'     = @{ Desired = 'Success and Failure'; Fallback = 'No Auditing'; Events = '4776' }
    'Sensitive Privilege Use'   = @{ Desired = 'Success and Failure'; Fallback = 'No Auditing'; Events = '4672, 4673' }
    'Security Group Management' = @{ Desired = 'Success and Failure'; Fallback = 'No Auditing'; Events = '4727, 4728, 4732' }
    'User Account Management'   = @{ Desired = 'Success and Failure'; Fallback = 'No Auditing'; Events = '4720, 4722, 4724' }
}


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
# State file - what Install actually changed, so Remove can reverse exactly that
# ============================================================================

function Get-LabState {
    if (-not (Test-Path $StatePath)) {
        return @{}
    }

    try {
        $raw = Get-Content -Path $StatePath -Raw -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($raw)) { return @{} }

        # ConvertFrom-Json returns PSCustomObject; normalise to a hashtable keyed
        # by component name so callers can index it consistently on PS 5.1.
        $obj   = $raw | ConvertFrom-Json
        $state = @{}
        foreach ($prop in $obj.PSObject.Properties) {
            $state[$prop.Name] = $prop.Value
        }
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
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    $State | ConvertTo-Json -Depth 8 | Set-Content -Path $StatePath -Encoding UTF8
}

function Set-ComponentState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param(
        [string]$Name,
        [hashtable]$Data
    )

    $state = Get-LabState
    $state[$Name] = $Data
    Save-LabState -State $state
}

function Remove-ComponentState {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param([string]$Name)

    $state = Get-LabState
    if ($state.ContainsKey($Name)) {
        $state.Remove($Name)
    }

    if ($state.Count -eq 0) {
        Remove-Item -Path $StatePath -Force -ErrorAction SilentlyContinue
    }
    else {
        Save-LabState -State $state
    }
}

function Get-ComponentState {
    param([string]$Name)

    $state = Get-LabState
    if ($state.ContainsKey($Name)) { return $state[$Name] }
    return $null
}

# ============================================================================
# Prerequisites
# ============================================================================

function Assert-Administrator {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity

    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    Write-Status 'Administrator privileges are required' -Type Error
    Write-Host ''
    Write-Host '  Re-run from an elevated prompt:' -ForegroundColor Yellow

    # Relaunch with the host that is actually running, not a hardcoded pwsh.exe.
    # PowerShell 7 is not present on a fresh Windows 11 image, and this script is
    # meant to run before the red-team installer puts it there.
    $hostExe = (Get-Process -Id $PID).Path
    if (-not $hostExe) { $hostExe = 'powershell.exe' }

    $scriptPath = $PSCommandPath
    if ($scriptPath) {
        Write-Host "    Start-Process '$hostExe' -Verb RunAs -ArgumentList '-File `"$scriptPath`" -Action $Action'" -ForegroundColor Gray
    }
    Write-Host ''

    throw 'Administrator privileges are required.'
}

# ============================================================================
# Shared probes
# ============================================================================

function Get-SysmonService {
    return Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Select-Object -First 1
}

function Get-ChannelEventCount {
    <#
        Returns the number of events in a channel within the lookback window, or
        -1 when the channel does not exist yet. Used by Test to distinguish
        "configured" from "actually producing telemetry".
    #>
    param(
        [string]$LogName,
        [int]$MinutesBack = 60,
        [int[]]$EventId
    )

    try {
        $filter = @{
            LogName   = $LogName
            StartTime = (Get-Date).AddMinutes(-$MinutesBack)
        }
        if ($EventId) { $filter['Id'] = $EventId }

        $events = Get-WinEvent -FilterHashtable $filter -MaxEvents 500 -ErrorAction Stop
        return @($events).Count
    }
    catch {
        # "No events were found" is a successful query with an empty result.
        if ($_.Exception.Message -match 'No events were found') { return 0 }
        return -1
    }
}

function Get-MonitorAgentState {
    <#
        AMA does not always register a Windows service. On some builds the
        extension handler launches MonAgent* directly and no 'AzureMonitorAgent'
        service exists, so a service-only probe reports a false negative on a
        perfectly healthy agent. Check service, processes and the extension
        package, and distinguish "running" from the silent failure mode where
        the package is present but nothing is actually running.
    #>
    $service   = Get-Service -Name 'AzureMonitorAgent' -ErrorAction SilentlyContinue
    $processes = @(Get-Process -Name 'MonAgentCore', 'MonAgentHost', 'MonAgentLauncher' -ErrorAction SilentlyContinue)
    $package   = Get-ChildItem -Path 'C:\Packages\Plugins\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent' `
                               -Directory -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($service -and $service.Status -eq 'Running') {
        return [pscustomobject]@{ Status = 'Running'; Detail = "service $($service.Name) running"; Service = $service }
    }
    if ($processes.Count -gt 0) {
        $names = ($processes | Select-Object -ExpandProperty Name -Unique) -join ', '
        $ver   = if ($package) { " (v$($package.Name))" } else { '' }
        return [pscustomobject]@{ Status = 'Running'; Detail = "$names running, no registered service$ver"; Service = $null }
    }
    if ($service) {
        return [pscustomobject]@{ Status = 'Stopped'; Detail = "service $($service.Name) is $($service.Status)"; Service = $service }
    }
    if ($package) {
        return [pscustomobject]@{ Status = 'Stopped'; Detail = "extension v$($package.Name) installed but no agent process is running"; Service = $null }
    }
    return [pscustomobject]@{ Status = 'Absent'; Detail = 'extension not present'; Service = $null }
}

function Restart-MonitorAgent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param()

    <#
        The DCR references Microsoft-Windows-Sysmon/Operational, but that channel
        does not exist until Sysmon installs - which happens long after the agent
        was deployed. Restarting AMA makes it enumerate channels again so Sysmon
        events start flowing without waiting for a reboot.
    #>
    if ($SkipAgentRestart) {
        Write-Status 'Skipping Azure Monitor Agent restart (-SkipAgentRestart)' -Type Info
        return
    }

    $ama = Get-MonitorAgentState

    if ($ama.Status -eq 'Absent') {
        Write-Status 'Azure Monitor Agent not present - Sysmon events stay local' -Type Warning
        return
    }

    if (-not $ama.Service) {
        # No registered service to restart. AMA re-reads its DCR configuration on
        # a periodic refresh, so the new channel is picked up without help.
        Write-Status "Azure Monitor Agent: $($ama.Detail)" -Type Info
        Write-Status 'No service to restart; the agent will pick up the Sysmon channel on its next config refresh' -Type Info
        return
    }

    try {
        Restart-Service -Name $ama.Service.Name -Force -ErrorAction Stop
        Write-Status 'Azure Monitor Agent restarted (picks up the Sysmon channel)' -Type Success
    }
    catch {
        Write-Status "Could not restart Azure Monitor Agent: $($_.Exception.Message)" -Type Warning
        Write-Status 'Sysmon events may not reach Log Analytics until the VM reboots' -Type Warning
    }
}

# ============================================================================
# Component: Sysmon
# ============================================================================

function Test-SysmonComponent {
    $service = Get-SysmonService
    $binary  = $SysmonBinaryPaths | Where-Object { Test-Path $_ } | Select-Object -First 1
    $driver  = @(Get-ChildItem -Path $SysmonDriverGlob -ErrorAction SilentlyContinue).Count -gt 0
    $running = $null -ne $service -and $service.Status -eq 'Running'

    $details = @()
    if ($service) { $details += "service $($service.Name) [$($service.Status)]" } else { $details += 'service absent' }
    if ($binary)  { $details += "binary $binary" }
    if ($driver)  { $details += 'driver present' }

    $eventCount = -1
    if ($running) {
        $eventCount = Get-ChannelEventCount -LogName $SysmonChannel -MinutesBack 60
        if ($eventCount -ge 0) {
            $details += "$eventCount events in last 60m"
        }
        else {
            $details += 'channel not registered'
        }
    }

    return [pscustomobject]@{
        Present    = $running
        Healthy    = $running -and $eventCount -gt 0
        EventCount = $eventCount
        Detail     = ($details -join ', ')
    }
}

function Install-SysmonBinary {
    $tempZip     = Join-Path $env:TEMP 'Sysmon.zip'
    $tempExtract = Join-Path $env:TEMP 'SysmonExtract'

    try {
        Write-Status 'Downloading Sysmon from Sysinternals...'
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $SysmonDownloadUrl -OutFile $tempZip -UseBasicParsing -TimeoutSec 120

        if (Test-Path $tempExtract) { Remove-Item $tempExtract -Recurse -Force }
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force

        $sysmonExe = Get-ChildItem -Path $tempExtract -Filter 'Sysmon64.exe' -Recurse -File |
                     Select-Object -First 1
        if (-not $sysmonExe) { throw 'Sysmon64.exe not found in the downloaded archive' }

        try {
            Copy-Item -Path $sysmonExe.FullName -Destination $SysmonPrimaryPath -Force -ErrorAction Stop
            Write-Status "Sysmon binary installed to $SysmonPrimaryPath" -Type Success
        }
        catch {
            # A previous Remove can leave the binary locked and scheduled for
            # deletion on reboot. Overwriting then fails, but the file on disk is
            # already Sysmon, so reuse it rather than aborting the install.
            if (-not (Test-Path $SysmonPrimaryPath)) { throw }
            Write-Status "$SysmonPrimaryPath is locked by a pending removal" -Type Warning
            Write-Status 'Reusing the existing binary instead of overwriting it' -Type Warning
        }

        # Whether we copied or reused, make sure a queued reboot-delete does not
        # remove the binary out from under the install we are about to perform.
        Clear-PendingFileRename -Path $SysmonPrimaryPath
    }
    finally {
        Remove-Item $tempZip     -Force -Recurse -ErrorAction SilentlyContinue
        Remove-Item $tempExtract -Force -Recurse -ErrorAction SilentlyContinue
    }
}

function Get-SysmonConfigFile {
    if ($UseDefaultSysmonConfig) {
        Write-Status 'Using Sysmon built-in configuration' -Type Info
        return $null
    }

    $configPath = Join-Path $env:TEMP 'sysmonconfig.xml'

    try {
        Write-Status 'Downloading Sysmon configuration...'
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $configPath -UseBasicParsing -TimeoutSec 30

        $null = [xml](Get-Content -Path $configPath -Raw)
        Write-Status 'Sysmon configuration downloaded and parsed' -Type Success
        return $configPath
    }
    catch {
        Write-Status "Config download failed, falling back to built-in: $($_.Exception.Message)" -Type Warning
        Remove-Item $configPath -Force -ErrorAction SilentlyContinue
        return $null
    }
}

function Install-SysmonComponent {
    $before      = Test-SysmonComponent
    $preExisting = $before.Present

    if ($preExisting -and -not $Force) {
        # Parenthesised deliberately: `if (Test-X -and -not $Force)` binds '-and'
        # and '-not' as arguments to Test-X and silently discards the $Force check.
        Write-Status "Sysmon already running ($($before.Detail))" -Type Success
        Write-Status 'Use -Force to reinstall and refresh the configuration' -Type Info
        return
    }

    if (-not (Test-Path $SysmonPrimaryPath) -or $Force) {
        Install-SysmonBinary
    }
    else {
        Write-Status 'Sysmon binary already present' -Type Info
    }

    $configPath = Get-SysmonConfigFile

    try {
        if ($before.Present) {
            Write-Status 'Updating configuration on the running service...'
            if ($configPath) {
                & $SysmonPrimaryPath -c $configPath 2>&1 | Out-Null
            }
            else {
                & $SysmonPrimaryPath -c -- 2>&1 | Out-Null
            }
            Write-Status 'Sysmon configuration updated' -Type Success
        }
        else {
            $sysmonArgs = @('-accepteula', '-i')
            if ($configPath) { $sysmonArgs += $configPath }

            $proc = Start-Process -FilePath $SysmonPrimaryPath -ArgumentList $sysmonArgs `
                                  -Wait -PassThru -NoNewWindow

            switch ($proc.ExitCode) {
                0     { Write-Status 'Sysmon service installed' -Type Success }
                13    { Write-Status 'Sysmon service already installed' -Type Info }
                1242  { Write-Status 'Sysmon service already started' -Type Info }
                default { throw "Sysmon installation failed with exit code $($proc.ExitCode)" }
            }
        }
    }
    finally {
        if ($configPath) { Remove-Item $configPath -Force -ErrorAction SilentlyContinue }
    }

    Start-Sleep -Seconds 3

    $after = Test-SysmonComponent
    if ($after.Present) {
        Write-Status "Sysmon is running ($($after.Detail))" -Type Success
        Write-Status "Events: $SysmonChannel" -Type Info
    }
    else {
        # Sysmon registers its event manifest at install time. Uninstalling and
        # reinstalling within the same boot leaves the manifest half-removed and
        # wevtutil fails, so the service never comes up. A reboot clears it.
        Write-Status 'Sysmon did not start' -Type Warning
        if ($before.Present -or (Test-Path $SysmonPrimaryPath)) {
            Write-Status 'This usually means Sysmon was uninstalled earlier in this boot session' -Type Warning
            Write-Status 'Reboot, then re-run: -Action Install -Component Sysmon' -Type Warning
        }
    }

    Set-ComponentState -Name 'Sysmon' -Data @{
        InstalledAt = (Get-Date).ToString('o')
        PreExisting = $preExisting
        BinaryPath  = $SysmonPrimaryPath
        ConfigUrl   = if ($UseDefaultSysmonConfig) { 'built-in' } else { $SysmonConfigUrl }
    }

    Restart-MonitorAgent
}

function Clear-PendingFileRename {
    <#
        Removes a path from PendingFileRenameOperations. Without this, a binary
        that Remove queued for reboot-deletion would be deleted after a
        subsequent Install reused it.
    #>
    param([string]$Path)

    $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $existing = Get-ItemProperty -Path $key -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if (-not $existing -or -not $existing.PendingFileRenameOperations) { return }

    $entries = @($existing.PendingFileRenameOperations)
    $kept    = @($entries | Where-Object { $_ -notmatch [regex]::Escape($Path) })

    if ($kept.Count -eq $entries.Count) { return }

    if ($kept.Count -eq 0) {
        Remove-ItemProperty -Path $key -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    }
    else {
        Set-ItemProperty -Path $key -Name PendingFileRenameOperations -Value $kept -Type MultiString -ErrorAction SilentlyContinue
    }
    Write-Status "Cancelled queued reboot-deletion of $Path" -Type Info
}

function Remove-SysmonFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param([string]$Path)

    for ($i = 1; $i -le 5; $i++) {
        try {
            Remove-Item -Path $Path -Force -ErrorAction Stop
            return $true
        }
        catch {
            if ($i -lt 5) { Start-Sleep -Seconds 2 }
        }
    }

    if (Test-Path $Path) {
        # Last resort: schedule deletion for the next boot.
        $key     = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pending = @()
        $existing = (Get-ItemProperty -Path $key -Name PendingFileRenameOperations -ErrorAction SilentlyContinue)
        if ($existing -and $existing.PendingFileRenameOperations) {
            $pending = @($existing.PendingFileRenameOperations)
        }
        $pending += "\??\$Path"
        $pending += ''
        Set-ItemProperty -Path $key -Name PendingFileRenameOperations -Value $pending `
                         -Type MultiString -ErrorAction SilentlyContinue
        return $false
    }

    return $true
}

function Remove-SysmonComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param()

    $state = Get-ComponentState -Name 'Sysmon'

    if ($state -and $state.PreExisting -and -not $Force) {
        Write-Status 'Sysmon pre-dated this script; leaving it in place' -Type Warning
        Write-Status 'Use -Force to remove it anyway' -Type Info
        return
    }

    $service = Get-SysmonService
    $binary  = $SysmonBinaryPaths | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $service -and -not $binary) {
        Write-Status 'Sysmon is not installed' -Type Info
        Remove-ComponentState -Name 'Sysmon'
        return
    }

    if ($service -and $binary) {
        Write-Status 'Uninstalling Sysmon service...'
        Start-Process -FilePath $binary -ArgumentList '-u', 'force' -Wait -PassThru -NoNewWindow | Out-Null
        Start-Sleep -Seconds 5
    }
    elseif ($service) {
        Write-Status 'Sysmon binary missing; removing service via sc.exe' -Type Warning
        Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        & sc.exe delete $service.Name | Out-Null
    }

    if (Get-SysmonService) {
        Write-Status 'Sysmon service still present - a reboot may be required' -Type Warning
    }
    else {
        Write-Status 'Sysmon service removed' -Type Success
    }

    foreach ($path in ($SysmonBinaryPaths | Where-Object { Test-Path $_ })) {
        if (Remove-SysmonFile -Path $path) {
            Write-Status "Removed $path" -Type Success
        }
        else {
            Write-Status "$path is locked - scheduled for deletion on reboot" -Type Warning
        }
    }

    foreach ($driver in @(Get-ChildItem -Path $SysmonDriverGlob -ErrorAction SilentlyContinue)) {
        if (Remove-SysmonFile -Path $driver.FullName) {
            Write-Status "Removed $($driver.Name)" -Type Success
        }
        else {
            Write-Status "$($driver.Name) is locked - scheduled for deletion on reboot" -Type Warning
        }
    }

    Remove-ComponentState -Name 'Sysmon'
}

# ============================================================================
# Component: PSLogging
# ============================================================================

function Get-RegistrySnapshot {
    <#
        Captures a key's existence and current values so Remove can restore it
        rather than deleting a key that was configured before we arrived.
    #>
    param([string]$Path, [string[]]$Names)

    if (-not (Test-Path $Path)) {
        return @{ Existed = $false; Values = @{} }
    }

    $values = @{}
    foreach ($name in $Names) {
        $item = Get-ItemProperty -Path $Path -Name $name -ErrorAction SilentlyContinue
        if ($item -and $item.PSObject.Properties[$name]) {
            $values[$name] = $item.$name
        }
    }

    return @{ Existed = $true; Values = $values }
}

function Test-PSLoggingComponent {
    $configured = @()
    $missing    = @()

    foreach ($entry in $PSLoggingKeys.GetEnumerator()) {
        $spec = $entry.Value
        $ok   = $true

        foreach ($valueEntry in $spec.Values.GetEnumerator()) {
            $item = Get-ItemProperty -Path $spec.Path -Name $valueEntry.Key -ErrorAction SilentlyContinue
            if (-not $item -or -not $item.PSObject.Properties[$valueEntry.Key] -or
                $item.$($valueEntry.Key) -ne $valueEntry.Value.Data) {
                $ok = $false
                break
            }
        }

        if ($ok) { $configured += $entry.Key } else { $missing += $entry.Key }
    }

    $present    = $missing.Count -eq 0
    $eventCount = Get-ChannelEventCount -LogName $PSChannel -MinutesBack 60 -EventId 4103, 4104

    $details = @()
    if ($configured) { $details += "enabled: $($configured -join ', ')" }
    if ($missing)    { $details += "missing: $($missing -join ', ')" }
    if ($eventCount -ge 0) { $details += "$eventCount 4103/4104 events in last 60m" }

    return [pscustomobject]@{
        Present    = $present
        Healthy    = $present -and $eventCount -gt 0
        EventCount = $eventCount
        Detail     = ($details -join '; ')
    }
}

function Install-PSLoggingComponent {
    $snapshot = @{}

    foreach ($entry in $PSLoggingKeys.GetEnumerator()) {
        $name = $entry.Key
        $spec = $entry.Value

        $snapshot[$name] = Get-RegistrySnapshot -Path $spec.Path -Names @($spec.Values.Keys)

        if (-not (Test-Path $spec.Path)) {
            New-Item -Path $spec.Path -Force | Out-Null
        }

        foreach ($valueEntry in $spec.Values.GetEnumerator()) {
            Set-ItemProperty -Path $spec.Path -Name $valueEntry.Key `
                             -Value $valueEntry.Value.Data -Type $valueEntry.Value.Type
        }

        Write-Status "$name enabled" -Type Success
    }

    # Module logging needs the modules it applies to listed under a subkey.
    $moduleNamesPath = "$PSPolicyRoot\ModuleLogging\ModuleNames"
    $snapshot['ModuleNames'] = Get-RegistrySnapshot -Path $moduleNamesPath -Names $ModuleLogNames
    if (-not (Test-Path $moduleNamesPath)) {
        New-Item -Path $moduleNamesPath -Force | Out-Null
    }
    foreach ($moduleName in $ModuleLogNames) {
        Set-ItemProperty -Path $moduleNamesPath -Name $moduleName -Value $moduleName -Type String
    }
    Write-Status "Module logging scope: $($ModuleLogNames -join ', ')" -Type Info
    if ($ModuleLogNames -contains '*') {
        Write-Status 'Scope is all modules - the largest single driver of ingestion cost' -Type Warning
    }

    $transcriptDirCreated = $false
    if (-not (Test-Path $TranscriptDir)) {
        New-Item -Path $TranscriptDir -ItemType Directory -Force | Out-Null
        $transcriptDirCreated = $true
    }
    Write-Status "Transcripts: $TranscriptDir (local only - the DCR does not collect files)" -Type Info
    Write-Status "Events: $PSChannel" -Type Info
    Write-Status 'Takes effect in new PowerShell sessions' -Type Info

    Set-ComponentState -Name 'PSLogging' -Data @{
        InstalledAt          = (Get-Date).ToString('o')
        Registry             = $snapshot
        TranscriptDirCreated = $transcriptDirCreated
        ModuleLogNames       = $ModuleLogNames
    }
}

function Remove-PSLoggingComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param()

    $state = Get-ComponentState -Name 'PSLogging'

    $paths = @("$PSPolicyRoot\ModuleLogging\ModuleNames") +
             @($PSLoggingKeys.Values | ForEach-Object { $_.Path })

    foreach ($path in $paths) {
        if (-not (Test-Path $path)) { continue }

        # Restore rather than delete when the key pre-dated this script.
        $keyName  = Split-Path $path -Leaf
        $snapshot = $null
        if ($state -and $state.Registry -and $state.Registry.PSObject.Properties[$keyName]) {
            $snapshot = $state.Registry.$keyName
        }

        if ($snapshot -and $snapshot.Existed) {
            foreach ($prop in $snapshot.Values.PSObject.Properties) {
                Set-ItemProperty -Path $path -Name $prop.Name -Value $prop.Value -ErrorAction SilentlyContinue
            }
            Write-Status "Restored prior values on $keyName" -Type Success
        }
        else {
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            Write-Status "$keyName removed" -Type Success
        }
    }

    # Drop the PowerShell policy root only if we left it empty.
    if (Test-Path $PSPolicyRoot) {
        $hasChildren = @(Get-ChildItem -Path $PSPolicyRoot -ErrorAction SilentlyContinue).Count -gt 0
        if (-not $hasChildren) {
            Remove-Item -Path $PSPolicyRoot -Force -ErrorAction SilentlyContinue
        }
    }

    if ($KeepTranscripts) {
        if (Test-Path $TranscriptDir) {
            Write-Status "Transcripts preserved at $TranscriptDir" -Type Info
        }
    }
    elseif (Test-Path $TranscriptDir) {
        $count = @(Get-ChildItem -Path $TranscriptDir -Recurse -File -ErrorAction SilentlyContinue).Count
        Remove-Item -Path $TranscriptDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Removed $TranscriptDir ($count transcript files)" -Type Success
    }

    Remove-ComponentState -Name 'PSLogging'
}

# ============================================================================
# Component: AuditPolicy
# ============================================================================

function Get-AuditSetting {
    <#
        Returns the current inclusion setting for a subcategory, e.g.
        'Success and Failure', 'Success', 'Failure', 'No Auditing'.
    #>
    param([string]$Subcategory)

    try {
        $csv = & auditpol /get /subcategory:"$Subcategory" /r 2>$null
        if (-not $csv) { return $null }

        $row = $csv | ConvertFrom-Csv | Where-Object { $_.Subcategory -eq $Subcategory } | Select-Object -First 1
        if (-not $row) { return $null }

        return $row.'Inclusion Setting'
    }
    catch {
        return $null
    }
}

function Set-AuditSetting {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param([string]$Subcategory, [string]$Setting)

    switch -Regex ($Setting) {
        'Success and Failure' { $success = 'enable';  $failure = 'enable'  }
        '^Success$'           { $success = 'enable';  $failure = 'disable' }
        '^Failure$'           { $success = 'disable'; $failure = 'enable'  }
        default               { $success = 'disable'; $failure = 'disable' }
    }

    & auditpol /set /subcategory:"$Subcategory" /success:$success /failure:$failure | Out-Null
    return $LASTEXITCODE -eq 0
}

function Test-AuditPolicyComponent {
    $matched = @()
    $drifted = @()

    foreach ($entry in $AuditSubcategories.GetEnumerator()) {
        $current = Get-AuditSetting -Subcategory $entry.Key
        if ($current -eq $entry.Value.Desired) {
            $matched += $entry.Key
        }
        else {
            $drifted += "$($entry.Key) [$current]"
        }
    }

    $cmdLine = $false
    $item = Get-ItemProperty -Path $CmdLineAuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -ErrorAction SilentlyContinue
    if ($item -and $item.PSObject.Properties['ProcessCreationIncludeCmdLine_Enabled']) {
        $cmdLine = $item.ProcessCreationIncludeCmdLine_Enabled -eq 1
    }

    $present    = $drifted.Count -eq 0 -and $cmdLine
    $eventCount = Get-ChannelEventCount -LogName 'Security' -MinutesBack 60 -EventId 4688

    $details = @("$($matched.Count)/$($AuditSubcategories.Count) subcategories set")
    if ($drifted) { $details += "drifted: $($drifted -join ', ')" }
    $details += "cmdline capture: $(if ($cmdLine) { 'on' } else { 'off' })"
    if ($eventCount -ge 0) { $details += "$eventCount 4688 events in last 60m" }

    return [pscustomobject]@{
        Present    = $present
        Healthy    = $present -and $eventCount -gt 0
        EventCount = $eventCount
        Detail     = ($details -join '; ')
    }
}

function Install-AuditPolicyComponent {
    $priorSettings = @{}

    foreach ($entry in $AuditSubcategories.GetEnumerator()) {
        $name = $entry.Key

        # Capture what was there before so Remove restores it exactly.
        $priorSettings[$name] = Get-AuditSetting -Subcategory $name

        if (Set-AuditSetting -Subcategory $name -Setting $entry.Value.Desired) {
            Write-Status "$name -> $($entry.Value.Desired) (events $($entry.Value.Events))" -Type Success
        }
        else {
            Write-Status "Failed to set audit policy for $name" -Type Error
        }
    }

    $cmdLineSnapshot = Get-RegistrySnapshot -Path $CmdLineAuditKey -Names @('ProcessCreationIncludeCmdLine_Enabled')
    if (-not (Test-Path $CmdLineAuditKey)) {
        New-Item -Path $CmdLineAuditKey -Force | Out-Null
    }
    Set-ItemProperty -Path $CmdLineAuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord
    Write-Status 'Command line captured in 4688 events' -Type Success
    Write-Status 'Events: Security log' -Type Info

    Set-ComponentState -Name 'AuditPolicy' -Data @{
        InstalledAt   = (Get-Date).ToString('o')
        PriorSettings = $priorSettings
        CmdLineKey    = $cmdLineSnapshot
    }
}

function Remove-AuditPolicyComponent {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Internal helper. Every mutation is gated by Invoke-ComponentAction, which owns the single ShouldProcess call.')]
    param()

    $state = Get-ComponentState -Name 'AuditPolicy'

    foreach ($entry in $AuditSubcategories.GetEnumerator()) {
        $name = $entry.Key

        # Prefer the setting captured at install time; fall back to the
        # documented Windows default only when no state was recorded.
        $target = $entry.Value.Fallback
        $source = 'documented default'
        if ($state -and $state.PriorSettings -and $state.PriorSettings.PSObject.Properties[$name] -and
            $state.PriorSettings.$name) {
            $target = $state.PriorSettings.$name
            $source = 'captured at install'
        }

        if (Set-AuditSetting -Subcategory $name -Setting $target) {
            Write-Status "$name -> $target ($source)" -Type Success
        }
        else {
            Write-Status "Failed to restore audit policy for $name" -Type Error
        }
    }

    $snapshot = $null
    if ($state -and $state.CmdLineKey) { $snapshot = $state.CmdLineKey }

    if ($snapshot -and $snapshot.Existed -and $snapshot.Values.PSObject.Properties['ProcessCreationIncludeCmdLine_Enabled']) {
        Set-ItemProperty -Path $CmdLineAuditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' `
                         -Value $snapshot.Values.ProcessCreationIncludeCmdLine_Enabled -Type DWord -ErrorAction SilentlyContinue
        Write-Status 'Restored prior command line capture setting' -Type Success
    }
    elseif (Test-Path $CmdLineAuditKey) {
        Remove-Item -Path $CmdLineAuditKey -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status 'Command line capture disabled' -Type Success
    }

    Remove-ComponentState -Name 'AuditPolicy'
}

# ============================================================================
# Component table - each component declares its three verbs exactly once.
# Install / Remove / Test are three walks over this table, so they cannot
# drift apart the way two mirrored scripts do.
# ============================================================================

$Components = [ordered]@{
    Sysmon      = @{
        Description = 'Sysmon system monitor'
        Channel     = $SysmonChannel
        Test        = { Test-SysmonComponent }
        Install     = { Install-SysmonComponent }
        Remove      = { Remove-SysmonComponent }
    }
    PSLogging   = @{
        Description = 'PowerShell script block, module and transcription logging'
        Channel     = $PSChannel
        Test        = { Test-PSLoggingComponent }
        Install     = { Install-PSLoggingComponent }
        Remove      = { Remove-PSLoggingComponent }
    }
    AuditPolicy = @{
        Description = 'Windows security audit policy'
        Channel     = 'Security'
        Test        = { Test-AuditPolicyComponent }
        Install     = { Install-AuditPolicyComponent }
        Remove      = { Remove-AuditPolicyComponent }
    }
}

# ============================================================================
# Engine
# ============================================================================

function Get-SelectedComponents {
    if ($Component) {
        return @($Component)
    }
    return @($Components.Keys)
}

function Get-ComponentReport {
    <#
        Runs every selected component's Test verb. Used by -Action Test, by the
        -WhatIf plan, and by the post-run summary.
    #>
    param([string[]]$Names)

    $report = @()
    foreach ($name in $Names) {
        $spec = $Components[$name]
        try {
            $result = & $spec.Test
        }
        catch {
            $result = [pscustomobject]@{
                Present    = $false
                Healthy    = $false
                EventCount = -1
                Detail     = "test failed: $($_.Exception.Message)"
            }
        }

        $report += [pscustomobject]@{
            Component  = $name
            Present    = $result.Present
            Healthy    = $result.Healthy
            EventCount = $result.EventCount
            Channel    = $spec.Channel
            Detail     = $result.Detail
        }
    }

    return $report
}

function Show-Plan {
    param([string[]]$Names)

    Write-Section "Plan: $Action"

    foreach ($row in (Get-ComponentReport -Names $Names)) {
        $state = if ($row.Present) { 'configured' } else { 'not configured' }
        $verb  = switch ($Action) {
            'Install' { if ($row.Present -and -not $Force) { 'skip (already configured)' } else { 'install' } }
            'Remove'  { if ($row.Present) { 'remove' } else { 'skip (not configured)' } }
        }
        Write-Status "$($row.Component): currently $state -> would $verb" -Type Plan
    }
}

function Invoke-ComponentAction {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Name, [string]$Verb)

    $spec = $Components[$Name]
    Write-Section "$Verb`: $($spec.Description)"

    # Single ShouldProcess gate for every mutation in the component. This is the
    # reason -WhatIf is trustworthy here: there is one place to get it right,
    # not twenty-four scattered call sites.
    if (-not $PSCmdlet.ShouldProcess($Name, "$Verb blue-team component")) {
        return
    }

    try {
        & $spec.$Verb
    }
    catch {
        Write-Status "$Verb failed for $Name`: $($_.Exception.Message)" -Type Error
        throw   # caught per-component in main so siblings still run
    }
}

function Show-TestReport {
    param([string[]]$Names)

    Write-Banner 'Blue Team Telemetry Status'

    $report = Get-ComponentReport -Names $Names

    foreach ($row in $report) {
        Write-Host ''
        if ($row.Healthy) {
            Write-Status "$($row.Component): healthy" -Type Success
        }
        elseif ($row.Present) {
            Write-Status "$($row.Component): configured, no recent events" -Type Warning
        }
        else {
            Write-Status "$($row.Component): not configured" -Type Error
        }
        Write-Host "         channel: $($row.Channel)" -ForegroundColor DarkGray
        Write-Host "         $($row.Detail)" -ForegroundColor DarkGray
    }

    # The agent is the seam between this machine and Log Analytics, so report it
    # even though it is not a component this script manages.
    Write-Host ''
    $ama = Get-MonitorAgentState
    switch ($ama.Status) {
        'Running' { Write-Status "Azure Monitor Agent: running - $($ama.Detail)" -Type Success }
        'Stopped' { Write-Status "Azure Monitor Agent: NOT running - $($ama.Detail)" -Type Error
                    Write-Status 'Events are being generated but nothing is shipping them to Log Analytics' -Type Error
                    Write-Status 'Repair: az vm extension set --publisher Microsoft.Azure.Monitor --name AzureMonitorWindowsAgent --force-update' -Type Info }
        default   { Write-Status "Azure Monitor Agent: not installed - $($ama.Detail)" -Type Warning
                    Write-Status 'Events stay local; nothing reaches Log Analytics' -Type Warning }
    }

    $unhealthy = @($report | Where-Object { -not $_.Healthy })
    Write-Host ''
    if ($unhealthy.Count -eq 0) {
        Write-Status 'All selected components are configured and producing events' -Type Success
    }
    else {
        Write-Status "$($unhealthy.Count) of $($report.Count) component(s) need attention" -Type Warning
        Write-Host ''
        Write-Host '  If a component is configured but quiet, generate some activity and re-test:' -ForegroundColor Gray
        Write-Host '    Get-Process | Out-Null; notepad.exe; Stop-Process -Name notepad' -ForegroundColor DarkGray
        Write-Host '  Script block logging only applies to new PowerShell sessions.' -ForegroundColor Gray
    }
    Write-Host ''

    return $report
}

function Show-Summary {
    param([string[]]$Names)

    Write-Banner "Blue Team Tools - $Action Complete"

    foreach ($row in (Get-ComponentReport -Names $Names)) {
        $state = if ($row.Present) { 'configured' } else { 'not configured' }
        Write-Host "    - $($row.Component): $state" -ForegroundColor Gray
    }

    Write-Host ''
    if ($Action -eq 'Install') {
        Write-Host '  Verify telemetry once activity has occurred:' -ForegroundColor White
        Write-Host "    .\AdversaryLab-BlueTeam.ps1 -Action Test" -ForegroundColor DarkGray
        Write-Host ''
        Write-Host '  Then confirm ingestion in Log Analytics after 10-15 minutes:' -ForegroundColor White
        Write-Host '    Event | where Source == "Microsoft-Windows-Sysmon" | take 10' -ForegroundColor DarkGray
        Write-Host ''
        Write-Host "  State file: $StatePath" -ForegroundColor DarkGray
        Write-Host '  Remove reverses only what this file records.' -ForegroundColor DarkGray
    }
    else {
        Write-Host '  A reboot may be required to release locked Sysmon files.' -ForegroundColor Yellow
    }
    Write-Host ''
}

# ============================================================================
# Main
# ============================================================================

$selected = Get-SelectedComponents

Write-Banner "AdversaryLab Blue Team - $Action"
Write-Host "  Components: $($selected -join ', ')" -ForegroundColor Gray
Write-Host ''

try {
    Assert-Administrator

    if ($Action -eq 'Test') {
        $report = Show-TestReport -Names $selected
        # Non-zero exit when anything is unhealthy, so CI and Run Command can gate on it.
        if (@($report | Where-Object { -not $_.Healthy }).Count -gt 0) { exit 2 }
        exit 0
    }

    if ($WhatIfPreference) {
        Show-Plan -Names $selected
    }

    # -WhatIf and -Force both imply no interactive confirmation.
    if (-not $Force -and -not $Yes -and -not $WhatIfPreference) {
        foreach ($row in (Get-ComponentReport -Names $selected)) {
            $state = if ($row.Present) { 'configured' } else { 'not configured' }
            Write-Host "    - $($row.Component): currently $state" -ForegroundColor Gray
        }
        Write-Host ''

        if ($Action -eq 'Remove' -and -not $KeepTranscripts -and $selected -contains 'PSLogging') {
            Write-Host "  Transcript files in $TranscriptDir will be deleted (-KeepTranscripts to keep)." -ForegroundColor Yellow
            Write-Host ''
        }

        $confirm = Read-Host "  Proceed with $($Action.ToLower())? (y/N)"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host '  Cancelled.' -ForegroundColor Yellow
            exit 0
        }
    }

    # Components are independent: a failure in one must not prevent the others
    # from being applied. Collect failures and surface them in the exit code.
    $failed = @()
    foreach ($name in $selected) {
        try {
            Invoke-ComponentAction -Name $name -Verb $Action
        }
        catch {
            $failed += $name
        }
    }

    if (-not $WhatIfPreference) {
        Show-Summary -Names $selected
    }

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
