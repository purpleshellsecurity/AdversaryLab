<#
.SYNOPSIS
    Deploys an Azure logging lab solution with VM, Log Analytics workspace, storage for flow logs.

.DESCRIPTION
    Deploys a comprehensive logging lab solution including VM, Log Analytics workspace, 
    Storage for flow logs, Network security groups, and Azure Activity log integration.
    Uses standard Azure secure parameter approach for password handling.
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = "",
    [string]$Location = "",
    [string]$SubscriptionId = "",
    [string]$AdminUsername = "",
    [SecureString]$AdminPassword = $null,
    [string]$MyIP = "",
    [string]$namePrefix = "adversarylab",
    [string]$ResourceSuffix = "",
    [string]$VmSize = "Standard_D2s_v4",
    [int]$RetentionInDays = 30,
    [bool]$EnableAzureActivity = $true,
    [switch]$ForceLogin,
    [bool]$EnableAutoShutdown = $true,
    [string]$ShutdownTime = "2330",
    [string]$ShutdownTimeZone = "Eastern Standard Time",
    [bool]$EnableShutdownNotificationEmails = $false,
    [string]$NotificationEmail = "",
    [int]$NotificationMinutesBefore = 15,
    [bool]$EnableFlowLogs = $true,
    [switch]$SkipTelemetryCheck,
    [int]$TelemetryTimeoutMinutes = 15
)

$ErrorActionPreference = "Stop"

function Write-ColoredOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Test-AzurePowerShell {
    try {
        $null = Get-Command Get-AzContext -ErrorAction Stop
        return $true
    }
    catch { return $false }
}

function Get-PublicIPAddress {
    try {
        $ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        if ($ip -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            return $ip
        }
        throw "Invalid IP format"
    }
    catch { 
        Write-ColoredOutput "Could not auto-detect IP" "Yellow"
        return $null
    }
}

function New-CompliantPassword {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure function: generates and returns a string, changes no system state.')]
    param([int]$Length = 16)
    
    $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    $lowercase = 'abcdefghijklmnopqrstuvwxyz'
    $numbers = '0123456789'
    $special = '!@#$%^&*+-='
    
    $password = @()
    $password += $uppercase[(Get-Random -Maximum $uppercase.Length)]
    $password += $lowercase[(Get-Random -Maximum $lowercase.Length)]
    $password += $numbers[(Get-Random -Maximum $numbers.Length)]
    $password += $special[(Get-Random -Maximum $special.Length)]
    
    $allChars = $uppercase + $lowercase + $numbers + $special
    for ($i = 4; $i -lt $Length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    return ($password | Sort-Object { Get-Random }) -join ''
}

function Save-CredentialsToFile {
    param(
        [string]$AdminUsername,
        [SecureString]$AdminPassword,
        [string]$VmPublicIP,
        [string]$OutputPath
    )
    
    # Decrypt SecureString just for writing to file.
    # PtrToStringBSTR, not PtrToStringAuto: SecureStringToBSTR returns UTF-16LE,
    # but on .NET Core/Unix 'Auto' marshals as ANSI and stops at the first NUL
    # byte, silently writing only the first character of the password.
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
    try {
        $plainTextPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }

    $credFile = Join-Path $OutputPath "credentials.txt"
    $content = @"
========================================
Adversary Lab Credentials
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
========================================

VM Public IP: $VmPublicIP
Admin Username: $AdminUsername
Admin Password: $plainTextPassword

RDP Command: mstsc /v:$VmPublicIP

========================================
KEEP THIS FILE SECURE AND DELETE AFTER USE
========================================
"@
    
    $content | Out-File -FilePath $credFile -Encoding UTF8
    return $credFile
}

function Get-InteractiveParameters {
    Write-Host "`n=== Adversary Lab Deployer ===" -ForegroundColor Cyan
    
    if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) {
        $ResourceGroupName = Read-Host "Enter Resource Group name (e.g., adversary-lab-rg)"
    }
    
    if ([string]::IsNullOrWhiteSpace($Location)) {
        $Location = Read-Host "Enter Azure region (e.g., eastus)"
    }
    
    if ([string]::IsNullOrWhiteSpace($SubscriptionId)) {
        $SubscriptionId = Read-Host "Enter Azure Subscription ID"
    }
    
    if ([string]::IsNullOrWhiteSpace($AdminUsername)) {
        $AdminUsername = Read-Host "Enter VM administrator username"
    }
    
    if ($null -eq $AdminPassword -or $AdminPassword.Length -eq 0) {
        $generateChoice = Read-Host "Generate password automatically? (y/n)"
        if ($generateChoice -eq 'y' -or $generateChoice -eq 'Y') {
            $plainPassword = New-CompliantPassword
            # Suppressed: ConvertTo-SecureString with plain text is unavoidable here
            # as we must generate the password as a string before securing it.
            # Plain text is cleared from memory immediately after conversion.
            $AdminPassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force
            $plainPassword = $null  # Clear plain text from memory immediately
            Write-Host "Password generated. It will be saved to a credentials file after deployment." -ForegroundColor Yellow
        } else {
            $AdminPassword = Read-Host "Enter password" -AsSecureString
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($MyIP)) {
        Write-Host "Detecting your public IP..." -ForegroundColor Yellow
        $MyIP = Get-PublicIPAddress
        if ($null -ne $MyIP) {
            Write-Host "Detected IP: $MyIP" -ForegroundColor Green
            $confirmIP = Read-Host "Use this IP for RDP access? (y/n)"
            if ($confirmIP -notmatch '^[Yy]') {
                $MyIP = Read-Host "Enter your public IP address"
            }
        } else {
            $MyIP = Read-Host "Enter your public IP address"
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($NotificationEmail) -and !$EnableShutdownNotificationEmails) {
        $emailChoice = Read-Host "Enable email notifications for VM shutdown and Billing Alarm? (y/n)"
        if ($emailChoice -eq 'y' -or $emailChoice -eq 'Y') {
            $EnableShutdownNotificationEmails = $true
            $NotificationEmail = Read-Host "Enter email address"
        }
    }
    
    Write-Host "`n=== Configuration Summary ===" -ForegroundColor Cyan
    Write-Host "Resource Group: $ResourceGroupName" -ForegroundColor White
    Write-Host "Location: $Location" -ForegroundColor White
    Write-Host "Admin Username: $AdminUsername" -ForegroundColor White
    Write-Host "VM Size: $VmSize" -ForegroundColor White
    Write-Host "Your IP: $MyIP" -ForegroundColor White
    Write-Host "Flow Logs: $(if($EnableFlowLogs){"Enabled"}else{"Disabled"})" -ForegroundColor White
    
    $confirm = Read-Host "`nProceed with deployment? (y/n)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Deployment cancelled." -ForegroundColor Yellow
        exit 0
    }
    
    return @{
        ResourceGroupName                = $ResourceGroupName
        Location                         = $Location
        SubscriptionId                   = $SubscriptionId
        AdminUsername                    = $AdminUsername
        AdminPassword                    = $AdminPassword
        MyIP                             = $MyIP
        namePrefix                       = $namePrefix
        VmSize                           = $VmSize
        RetentionInDays                  = $RetentionInDays
        EnableAzureActivity              = $EnableAzureActivity
        EnableAutoShutdown               = $EnableAutoShutdown
        ShutdownTime                     = $ShutdownTime
        ShutdownTimeZone                 = $ShutdownTimeZone
        EnableShutdownNotificationEmails = $EnableShutdownNotificationEmails
        NotificationEmail                = $NotificationEmail
        NotificationMinutesBefore        = $NotificationMinutesBefore
        EnableFlowLogs                   = $EnableFlowLogs
    }
}

function Initialize-AzureContext {
    param($SubscriptionId)
    
    $context = Get-AzContext
    if ($null -eq $context -or $ForceLogin) {
        Write-ColoredOutput "Connecting to Azure..." "Yellow"
        Connect-AzAccount | Out-Null
        Write-ColoredOutput "Connected to Azure!" "Green"
    }
    
    if ((Get-AzContext).Subscription.Id -ne $SubscriptionId) {
        Write-ColoredOutput "Setting subscription context..." "Yellow"
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
    
    $currentContext = Get-AzContext
    Write-ColoredOutput "`n=== Deploying Adversary Lab ===" "Cyan"
    Write-ColoredOutput "Using subscription: $($currentContext.Subscription.Name)" "Green"
}

function Test-AzurePermissions {
    param($ResourceGroupName, $Location)
    
    $resourceGroup = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
    if ($null -eq $resourceGroup) {
        Write-ColoredOutput "Creating resource group: $ResourceGroupName" "Yellow"
        New-AzResourceGroup -Name $ResourceGroupName -Location $Location | Out-Null
        Write-ColoredOutput "Resource group created!" "Green"
    } else {
        Write-ColoredOutput "Using existing resource group: $ResourceGroupName" "Green"
    }
}

function Test-NetworkWatcher {
    param($Location)
    
    $networkWatcherRG = "NetworkWatcherRG"
    $networkWatcherName = "NetworkWatcher_$Location"
    
    $nwRG = Get-AzResourceGroup -Name $networkWatcherRG -ErrorAction SilentlyContinue
    if ($null -eq $nwRG) {
        Write-ColoredOutput "Creating NetworkWatcherRG resource group..." "Yellow"
        New-AzResourceGroup -Name $networkWatcherRG -Location $Location | Out-Null
    }
    
    $nw = Get-AzNetworkWatcher -Name $networkWatcherName -ResourceGroupName $networkWatcherRG -ErrorAction SilentlyContinue
    if ($null -eq $nw) {
        Write-ColoredOutput "Creating Network Watcher in $Location..." "Yellow"
        New-AzNetworkWatcher -Name $networkWatcherName -ResourceGroupName $networkWatcherRG -Location $Location | Out-Null
        Write-ColoredOutput "Network Watcher created!" "Green"
    } else {
        Write-ColoredOutput "Network Watcher exists in $Location" "Green"
    }
}

function Test-VmMonitorAgent {
    <#
        The AMA extension reports provisioningState 'Succeeded' even when the
        agent on the box is not running, which lets host telemetry fail silently
        for weeks. Check the guest directly rather than trusting the extension.
    #>
    param([string]$ResourceGroupName, [string]$VmName)

    $probe = @'
$svc  = Get-Service -Name 'AzureMonitorAgent' -ErrorAction SilentlyContinue
$proc = @(Get-Process -Name 'MonAgentCore','MonAgentHost','MonAgentLauncher' -ErrorAction SilentlyContinue)
$pkg  = Get-ChildItem 'C:\Packages\Plugins\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent' -Directory -ErrorAction SilentlyContinue | Select-Object -First 1
if (($svc -and $svc.Status -eq 'Running') -or $proc.Count -gt 0) { "AGENT=RUNNING" }
elseif ($pkg) { "AGENT=INSTALLED_NOT_RUNNING" }
else { "AGENT=ABSENT" }
'@

    try {
        $result = Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName `
                                        -CommandId 'RunPowerShellScript' -ScriptString $probe -ErrorAction Stop
        $text = ($result.Value | ForEach-Object { $_.Message }) -join "`n"

        if ($text -match 'AGENT=RUNNING')               { return 'Running' }
        if ($text -match 'AGENT=INSTALLED_NOT_RUNNING') { return 'NotRunning' }
        return 'Absent'
    }
    catch {
        Write-ColoredOutput "  Could not probe the VM: $($_.Exception.Message)" "Yellow"
        return 'Unknown'
    }
}

function Wait-ForWorkspaceRows {
    <#
        The only proof that a pipeline works end to end is a row landing in the
        workspace. Poll until one arrives or the shared deadline passes. Always
        runs at least one query, so a caller with no time left still gets an
        answer instead of an automatic failure.
    #>
    param(
        [string]$WorkspaceCustomerId,
        [string]$Query,
        [string]$Label,
        [datetime]$Deadline
    )

    do {
        try {
            $r = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $Query -ErrorAction Stop
            $n = [int]($r.Results | Select-Object -First 1).N
            if ($n -gt 0) { return $n }
        }
        catch {
            # A newly created workspace can reject queries for the first minute
            # or two, and a table that has never received data does not exist
            # yet. Keep polling rather than treating either as fatal.
            Write-Verbose "$Label query not ready yet: $($_.Exception.Message)"
        }

        if ((Get-Date).AddSeconds(60) -ge $Deadline) { break }

        $remaining = [int]($Deadline - (Get-Date)).TotalMinutes
        Write-ColoredOutput "  No $Label yet; still waiting (~$remaining min left)..." "Yellow"
        Start-Sleep -Seconds 60
    } while ((Get-Date) -lt $Deadline)

    return 0
}

function Test-LabTelemetry {
    param(
        [string]$ResourceGroupName,
        [string]$VmName,
        [string]$WorkspaceCustomerId,
        [bool]$CheckActivityLogs,
        [int]$TimeoutMinutes
    )

    Write-ColoredOutput "`n=== Verifying Telemetry Pipeline ===" "Cyan"

    # One time budget for both checks so adding the activity log poll cannot
    # double how long the operator waits at the end of a deployment.
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $result   = [pscustomobject]@{ HostLogs = $false; ActivityLogs = $null }

    # --- Host telemetry: agent on the VM, then Heartbeat in the workspace ---
    $agent = Test-VmMonitorAgent -ResourceGroupName $ResourceGroupName -VmName $VmName

    switch ($agent) {
        'Running' {
            Write-ColoredOutput "Azure Monitor Agent is running on the VM" "Green"

            Write-ColoredOutput "Waiting for the first heartbeat to reach the workspace..." "Yellow"
            $beats = Wait-ForWorkspaceRows -WorkspaceCustomerId $WorkspaceCustomerId -Deadline $deadline `
                                           -Label 'heartbeat' `
                                           -Query "Heartbeat | where TimeGenerated > ago(30m) | summarize N = count()"

            if ($beats -gt 0) {
                Write-ColoredOutput "Host telemetry confirmed: $beats heartbeat(s) in the workspace" "Green"
                $result.HostLogs = $true
            }
            else {
                Write-ColoredOutput "NO HEARTBEAT after $TimeoutMinutes minutes" "Red"
                Write-ColoredOutput "  The agent is running but nothing is reaching Log Analytics." "Red"
                Write-ColoredOutput "  Check the DCR association and the VM's managed identity." "Yellow"
            }
        }
        'NotRunning' {
            Write-ColoredOutput "Azure Monitor Agent is INSTALLED BUT NOT RUNNING" "Red"
            Write-ColoredOutput "  The extension reports success but nothing is shipping logs." "Red"
            Write-ColoredOutput "  Repair with:" "Yellow"
            Write-ColoredOutput "    az vm extension set -g $ResourceGroupName --vm-name $VmName ``" "Yellow"
            Write-ColoredOutput "      --publisher Microsoft.Azure.Monitor --name AzureMonitorWindowsAgent --force-update" "Yellow"
        }
        'Absent' {
            Write-ColoredOutput "Azure Monitor Agent is NOT INSTALLED on the VM" "Red"
        }
        default {
            Write-ColoredOutput "Could not determine agent state; skipping heartbeat check" "Yellow"
        }
    }

    # --- Subscription telemetry: the activity log diagnostic setting is created
    #     by the subscription deployment above, which throws on failure, so the
    #     only open question is whether rows are actually landing. Activity logs
    #     do not depend on the VM, so check them even if the host pipeline is
    #     broken. ---
    if ($CheckActivityLogs) {
        Write-ColoredOutput "`nWaiting for activity logs to reach the workspace..." "Yellow"

        $rows = Wait-ForWorkspaceRows -WorkspaceCustomerId $WorkspaceCustomerId -Deadline $deadline `
                                      -Label 'activity log' `
                                      -Query "AzureActivity | where TimeGenerated > ago(1h) | summarize N = count()"

        if ($rows -gt 0) {
            Write-ColoredOutput "Activity logs confirmed: $rows record(s) in the last hour" "Green"
            $result.ActivityLogs = $true
        }
        else {
            # The diagnostic setting deployed successfully, so an empty table is
            # first-write latency far more often than a broken pipeline.
            Write-ColoredOutput "AzureActivity is still empty after $TimeoutMinutes minutes" "Yellow"
            Write-ColoredOutput "  The first write to a new diagnostic setting can take ~20 minutes." "Yellow"
            Write-ColoredOutput "  Re-check with: AzureActivity | where TimeGenerated > ago(1h)" "Yellow"
            $result.ActivityLogs = $false
        }
    }

    return $result
}

# Main execution
try {
    Write-ColoredOutput "Starting Adversary Lab deployment..." "Green"
    
    if (-not (Test-AzurePowerShell)) {
        throw "Azure PowerShell module not found. Install with: Install-Module -Name Az"
    }
    
    $params = Get-InteractiveParameters
    
    Initialize-AzureContext -SubscriptionId $params.SubscriptionId
    Test-AzurePermissions -ResourceGroupName $params.ResourceGroupName -Location $params.Location
    
    if ($params.EnableFlowLogs) {
        Test-NetworkWatcher -Location $params.Location
    }
    
    $mainTemplate = Join-Path $PSScriptRoot "main.bicep"
    $subscriptionTemplate = Join-Path $PSScriptRoot "main_subscription.bicep"
    
    Write-ColoredOutput "Checking Bicep templates..." "Yellow"
    if (-not (Test-Path $mainTemplate)) { 
        throw "main.bicep not found in script directory" 
    }
    if (-not (Test-Path $subscriptionTemplate)) { 
        throw "main_subscription.bicep not found in script directory" 
    }
    Write-ColoredOutput "Bicep templates found." "Green"
    
    Write-ColoredOutput "Deploying main infrastructure..." "Yellow"
    
    $deploymentParams = @{
        ResourceGroupName                = $params.ResourceGroupName
        TemplateFile                     = $mainTemplate
        namePrefix                       = $params.namePrefix
        location                         = $params.Location
        adminUsername                    = $params.AdminUsername
        adminPassword                    = $params.AdminPassword
        myIP                             = $params.MyIP
        vmSize                           = $params.VmSize
        retentionInDays                  = $params.RetentionInDays
        enableAutoShutdown               = $params.EnableAutoShutdown
        shutdownTime                     = $params.ShutdownTime
        shutdownTimeZone                 = $params.ShutdownTimeZone
        enableShutdownNotificationEmails = $params.EnableShutdownNotificationEmails
        notificationEmail                = $params.NotificationEmail
        notificationMinutesBefore        = $params.NotificationMinutesBefore
    }
    
    # Pin the suffix when adopting an existing deployment; otherwise the template
    # derives a stable one from the resource group id.
    if (-not [string]::IsNullOrWhiteSpace($ResourceSuffix)) {
        $deploymentParams['resourceSuffix'] = $ResourceSuffix
        Write-ColoredOutput "Using pinned resource suffix: $ResourceSuffix" "Yellow"
    }

    $deployment = New-AzResourceGroupDeployment @deploymentParams -ErrorAction Stop
    Write-ColoredOutput "Infrastructure deployment completed!" "Green"

    # Save credentials immediately. The VM now exists, and if the password was
    # auto-generated it lives only in memory - any later failure (activity logs,
    # flow logs, budget) would otherwise lose it permanently along with access
    # to a VM that is already running and billing.
    $credFile = Save-CredentialsToFile `
        -AdminUsername $params.AdminUsername `
        -AdminPassword $params.AdminPassword `
        -VmPublicIP $deployment.Outputs["vmPublicIP"].Value `
        -OutputPath $PSScriptRoot
    Write-ColoredOutput "Credentials saved to: $credFile" "Yellow"
    
    if ($params.EnableAzureActivity) {
        Write-ColoredOutput "Deploying Azure Activity logs..." "Yellow"
        
        $workspaceName = $deployment.Outputs["workspaceName"].Value
        
        $subTemplateParams = @{
            resourceGroupName   = $params.ResourceGroupName
            workspaceName       = $workspaceName
            enableAzureActivity = $params.EnableAzureActivity
        }
        
        $null = New-AzSubscriptionDeployment `
            -Location $params.Location `
            -TemplateFile $subscriptionTemplate `
            -TemplateParameterObject $subTemplateParams `
            -ErrorAction Stop
        Write-ColoredOutput "Activity logs deployment completed!" "Green"
    }
    
    if ($params.EnableFlowLogs) {
        Write-ColoredOutput "Deploying VNet Flow Logs..." "Yellow"
        
        $flowLogsTemplate = Join-Path $PSScriptRoot "modules/network_monitoring.bicep"
        
        $flowLogTemplateParams = @{
            location            = $params.Location
            vnetResourceId      = $deployment.Outputs["vnetResourceId"].Value
            storageAccountId    = $deployment.Outputs["storageAccountResourceId"].Value
            workspaceResourceId = $deployment.Outputs["workspaceResourceId"].Value
            retentionDays       = $params.RetentionInDays
            tags                = @{
                Environment = 'Development'
                Project     = $params.namePrefix
                Purpose     = 'AdversaryLab'
            }
        }
        
        $null = New-AzSubscriptionDeployment `
            -Location $params.Location `
            -TemplateFile $flowLogsTemplate `
            -TemplateParameterObject $flowLogTemplateParams `
            -ErrorAction Stop
        Write-ColoredOutput "VNet Flow Logs deployment completed!" "Green"
    }
    
    $telemetry = $null
    if (-not $SkipTelemetryCheck) {
        $telemetry = Test-LabTelemetry `
            -ResourceGroupName $params.ResourceGroupName `
            -VmName $deployment.Outputs["vmName"].Value `
            -WorkspaceCustomerId $deployment.Outputs["workspaceId"].Value `
            -CheckActivityLogs $params.EnableAzureActivity `
            -TimeoutMinutes $TelemetryTimeoutMinutes
    }

    
    Write-ColoredOutput "`n=== Deployment Summary ===" "Cyan"
    Write-ColoredOutput "✓ Resource Group: $($params.ResourceGroupName)" "Green"
    Write-ColoredOutput "✓ VM Name: $($deployment.Outputs["vmName"].Value)" "Green"
    Write-ColoredOutput "✓ VM Public IP: $($deployment.Outputs["vmPublicIP"].Value)" "Green"
    Write-ColoredOutput "✓ Log Analytics Workspace: $($deployment.Outputs["workspaceName"].Value)" "Green"
    Write-ColoredOutput "✓ Your IP (RDP Access): $($params.MyIP)" "Green"
    Write-ColoredOutput "✓ Auto-shutdown: $(if($params.EnableAutoShutdown){"Enabled at $($params.ShutdownTime)"}else{"Disabled"})" "Green"
    Write-ColoredOutput "✓ VNet Flow Logs: $(if($params.EnableFlowLogs){"Enabled"}else{"Disabled"})" "Green"
    
    if ($params.EnableAzureActivity) {
        Write-ColoredOutput "✓ Azure Activity Logs: Enabled" "Green"
    }

    if ($null -eq $telemetry) {
        Write-ColoredOutput "- Telemetry pipeline: not verified (-SkipTelemetryCheck)" "Yellow"
    }
    else {
        if ($telemetry.HostLogs) {
            Write-ColoredOutput "✓ Host telemetry (Heartbeat): verified end to end" "Green"
        }
        else {
            Write-ColoredOutput "✗ Host telemetry (Heartbeat): NOT WORKING - see above" "Red"
            Write-ColoredOutput "  Host logs will not reach Log Analytics until this is fixed." "Red"
        }

        if ($null -eq $telemetry.ActivityLogs) {
            Write-ColoredOutput "- Activity logs (AzureActivity): not verified" "Yellow"
        }
        elseif ($telemetry.ActivityLogs) {
            Write-ColoredOutput "✓ Activity logs (AzureActivity): verified end to end" "Green"
        }
        else {
            Write-ColoredOutput "- Activity logs (AzureActivity): no data yet - see above" "Yellow"
        }
    }
    
    Write-ColoredOutput "`n✓ Credentials saved to: $credFile" "Yellow"
    Write-ColoredOutput "  IMPORTANT: Delete this file after noting the credentials!" "Yellow"
    
    if ($deployment.Outputs.ContainsKey("sentinelUrl")) {
        Write-ColoredOutput "`n=== Useful Links ===" "Cyan"
        Write-ColoredOutput "Sentinel URL: $($deployment.Outputs["sentinelUrl"].Value)" "White"
    }
    
    Write-ColoredOutput "`nDeployment completed successfully!" "Green"
    Write-ColoredOutput "RDP command: mstsc /v:$($deployment.Outputs["vmPublicIP"].Value)" "Cyan"
    
}
catch {
    Write-ColoredOutput "Deployment failed: $($_.Exception.Message)" "Red"
    Write-ColoredOutput "Full error details:" "Yellow"
    Write-ColoredOutput $_.Exception.ToString() "Red"
    exit 1
}
finally {
    $params = $null
    [System.GC]::Collect()
}