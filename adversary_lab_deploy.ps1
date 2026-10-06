<#
.SYNOPSIS
    Deploys the Adversary Lab Windows + Linux logging environment.
.DESCRIPTION
    Deploys Windows and Ubuntu endpoints, Log Analytics, Sentinel, Azure Monitor
    Agent/DCR configuration, Azure Activity logging, VNet flow logs, budget and
    auto-shutdown resources. Host telemetry is validated for both endpoints.
#>

[CmdletBinding()]
param(
    [string]$ResourceGroupName = '',
    [string]$Location = '',
    [string]$SubscriptionId = '',
    [string]$AdminUsername = '',
    [SecureString]$AdminPassword = $null,
    [string]$MyIP = '',
    [string]$namePrefix = 'adversarylab',
    [string]$ResourceSuffix = '',
    [string]$VmSize = 'Standard_D2s_v4',
    [string]$LinuxVmSize = 'Standard_B2s',
    [int]$RetentionInDays = 30,
    [bool]$EnableAzureActivity = $true,
    [switch]$ForceLogin,
    [bool]$EnableAutoShutdown = $true,
    [string]$ShutdownTime = '2330',
    [string]$ShutdownTimeZone = 'Eastern Standard Time',
    [bool]$EnableShutdownNotificationEmails = $false,
    [string]$NotificationEmail = '',
    [int]$NotificationMinutesBefore = 15,
    [bool]$EnableFlowLogs = $true,
    [switch]$SkipTelemetryCheck,
    [int]$TelemetryTimeoutMinutes = 15
)

$ErrorActionPreference = 'Stop'

function Write-ColoredOutput { param([string]$Message,[string]$Color='White'); Write-Host $Message -ForegroundColor $Color }
function Read-YesNo { param([string]$Prompt); while($true){$answer=(Read-Host $Prompt).Trim();if($answer -match '^[Yy]$'){return $true};if($answer -match '^[Nn]$'){return $false};Write-ColoredOutput 'Please enter y or n.' 'Yellow'} }
function Test-IPv4Address { param([string]$Address);$parsed=$null;return [System.Net.IPAddress]::TryParse($Address,[ref]$parsed) -and $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
function Read-IPv4Address { param([string]$Prompt);while($true){$value=(Read-Host $Prompt).Trim();if(Test-IPv4Address $value){return $value};Write-ColoredOutput 'Please enter a valid IPv4 address.' 'Yellow'} }
function Read-EmailAddress { param([string]$Prompt);while($true){$value=(Read-Host $Prompt).Trim();if($value -match '^[^\s@]+@[^\s@]+\.[^\s@]+$'){return $value};Write-ColoredOutput 'Please enter a valid email address.' 'Yellow'} }
function Test-AzurePowerShell { try{$null=Get-Command Get-AzContext -ErrorAction Stop;return $true}catch{return $false} }
function Test-ResourceGroupName { param([string]$Name);if([string]::IsNullOrWhiteSpace($Name)){return $false};if($Name.Length -gt 90){return $false};if($Name.EndsWith('.')){return $false};return $Name -match '^[A-Za-z0-9_\-\.\(\)]+$' }
function Read-ResourceGroupName { param([string]$Prompt);while($true){$value=(Read-Host $Prompt).Trim();if(Test-ResourceGroupName $value){return $value};Write-ColoredOutput 'Please enter a valid Azure resource group name (1-90 characters; letters, numbers, _, -, ., (, ); cannot end with a period).' 'Yellow'} }
function Test-SubscriptionId { param([string]$Value);if([string]::IsNullOrWhiteSpace($Value)){return $false};$guid=[Guid]::Empty;return [Guid]::TryParse($Value,[ref]$guid) }
function Read-SubscriptionId { param([string]$Prompt);while($true){$value=(Read-Host $Prompt).Trim();if(Test-SubscriptionId $value){return $value};Write-ColoredOutput 'Please enter a valid Azure Subscription ID (GUID).' 'Yellow'} }
function Test-AdminUsername { param([string]$Value);if([string]::IsNullOrWhiteSpace($Value)){return $false};if($Value.Length -gt 20){return $false};if($Value.EndsWith('.')){return $false};if($Value -match '[\\/"\[\]:|<>+=;,?*@]'){return $false};$reserved=@('administrator','admin','user','user1','test','user2','test1','user3','admin1','1','123','a','actuser','adm','admin2','aspnet','backup','console','david','guest','john','owner','root','server','sql','support','support_388945a0','sys','test2','test3','user4','user5');return $reserved -notcontains $Value.ToLowerInvariant() }
function Read-AdminUsername { param([string]$Prompt);while($true){$value=(Read-Host $Prompt).Trim();if(Test-AdminUsername $value){return $value};Write-ColoredOutput 'Please enter a valid VM administrator username.' 'Yellow'} }
function Read-RequiredValue { param([string]$Prompt,[string]$FieldName);while($true){$value=(Read-Host $Prompt).Trim();if(-not[string]::IsNullOrWhiteSpace($value)){return $value};Write-ColoredOutput "$FieldName cannot be blank." 'Yellow'} }
function Get-PublicIPAddress { try{$ip=(Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 10).Trim();if(Test-IPv4Address $ip){return $ip};throw 'Invalid IP format'}catch{Write-ColoredOutput 'Could not auto-detect IP.' 'Yellow';return $null} }
function New-CompliantPassword { [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',Justification='Pure function.')][OutputType([string])]param([int]$Length=16);$uppercase='ABCDEFGHIJKLMNOPQRSTUVWXYZ';$lowercase='abcdefghijklmnopqrstuvwxyz';$numbers='0123456789';$special='!@#$%^&*+-=';$password=@();$password+=$uppercase[(Get-Random -Maximum $uppercase.Length)];$password+=$lowercase[(Get-Random -Maximum $lowercase.Length)];$password+=$numbers[(Get-Random -Maximum $numbers.Length)];$password+=$special[(Get-Random -Maximum $special.Length)];$allChars=$uppercase+$lowercase+$numbers+$special;for($i=4;$i -lt $Length;$i++){$password+=$allChars[(Get-Random -Maximum $allChars.Length)]};return ($password|Sort-Object{Get-Random}) -join '' }

function Save-CredentialsToFile {
    param([string]$AdminUsername,[SecureString]$AdminPassword,[string]$WindowsPublicIP,[string]$LinuxPublicIP,[string]$OutputPath)
    $bstr=[System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($AdminPassword)
    try{$plainTextPassword=[System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)}finally{[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)}
    $credFile=Join-Path $OutputPath 'credentials.txt'
@"
========================================
Adversary Lab Credentials
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
========================================

Admin Username: $AdminUsername
Admin Password: $plainTextPassword

Windows Endpoint
Public IP: $WindowsPublicIP
RDP: mstsc /v:$WindowsPublicIP

Linux Endpoint
Public IP: $LinuxPublicIP
SSH: ssh $AdminUsername@$LinuxPublicIP

========================================
KEEP THIS FILE SECURE AND DELETE AFTER USE
========================================
"@ | Out-File -FilePath $credFile -Encoding UTF8
    $plainTextPassword=$null;return $credFile
}

function Get-InteractiveParameters {
    Write-Host "`n=== Adversary Lab Deployer ===" -ForegroundColor Cyan
    if([string]::IsNullOrWhiteSpace($ResourceGroupName)){$ResourceGroupName=Read-ResourceGroupName 'Enter Resource Group name (e.g., adversary-lab-rg)'}elseif(-not(Test-ResourceGroupName $ResourceGroupName)){throw "Invalid ResourceGroupName value: $ResourceGroupName"}
    if([string]::IsNullOrWhiteSpace($Location)){$Location=Read-RequiredValue 'Enter Azure region (e.g., eastus)' 'Azure region'}
    if([string]::IsNullOrWhiteSpace($SubscriptionId)){$SubscriptionId=Read-SubscriptionId 'Enter Azure Subscription ID'}elseif(-not(Test-SubscriptionId $SubscriptionId)){throw "Invalid SubscriptionId value: $SubscriptionId"}
    if([string]::IsNullOrWhiteSpace($AdminUsername)){$AdminUsername=Read-AdminUsername 'Enter VM administrator username'}elseif(-not(Test-AdminUsername $AdminUsername)){throw "Invalid AdminUsername value: $AdminUsername"}
    if($null -eq $AdminPassword -or $AdminPassword.Length -eq 0){if(Read-YesNo 'Generate password automatically? (y/n)'){$plainPassword=New-CompliantPassword;$AdminPassword=ConvertTo-SecureString $plainPassword -AsPlainText -Force;$plainPassword=$null;Write-ColoredOutput 'Password generated. It will be saved to a credentials file after deployment.' 'Yellow'}else{$AdminPassword=Read-Host 'Enter password' -AsSecureString}}
    if([string]::IsNullOrWhiteSpace($MyIP)){Write-ColoredOutput 'Detecting your public IP...' 'Yellow';$detectedIP=Get-PublicIPAddress;if($detectedIP){Write-ColoredOutput "Detected IP: $detectedIP" 'Green';if(Read-YesNo 'Use this IP for RDP and SSH access? (y/n)'){$MyIP=$detectedIP}else{$MyIP=Read-IPv4Address 'Enter your public IP address'}}else{$MyIP=Read-IPv4Address 'Enter your public IP address'}}elseif(-not(Test-IPv4Address $MyIP)){throw "Invalid MyIP value: $MyIP"}
    if([string]::IsNullOrWhiteSpace($NotificationEmail) -and -not $EnableShutdownNotificationEmails){$EnableShutdownNotificationEmails=Read-YesNo 'Enable email notifications for VM shutdown and Billing Alarm? (y/n)';if($EnableShutdownNotificationEmails){$NotificationEmail=Read-EmailAddress 'Enter email address'}}elseif($EnableShutdownNotificationEmails -and [string]::IsNullOrWhiteSpace($NotificationEmail)){$NotificationEmail=Read-EmailAddress 'Enter email address'}
    Write-Host "`n=== Configuration Summary ===" -ForegroundColor Cyan
    Write-Host "Resource Group: $ResourceGroupName";Write-Host "Location: $Location";Write-Host "Admin Username: $AdminUsername";Write-Host 'Endpoints:';Write-Host "  Windows 11: $VmSize (RDP)";Write-Host "  Ubuntu 24.04 LTS: $LinuxVmSize (SSH)";Write-Host "Allowed Public IP: $MyIP";Write-Host "Auto-shutdown: $(if($EnableAutoShutdown){"Enabled at $ShutdownTime ($ShutdownTimeZone)"}else{'Disabled'})";Write-Host "Shutdown/Budget Email: $(if($EnableShutdownNotificationEmails){$NotificationEmail}else{'Disabled'})";Write-Host "Azure Activity Logs: $(if($EnableAzureActivity){'Enabled'}else{'Disabled'})";Write-Host "VNet Flow Logs: $(if($EnableFlowLogs){'Enabled'}else{'Disabled'})";Write-Host "Telemetry Validation: $(if($SkipTelemetryCheck){'Skipped'}else{"Enabled ($TelemetryTimeoutMinutes min timeout)"})"
    if(-not(Read-YesNo "`nProceed with deployment? (y/n)")){Write-ColoredOutput 'Deployment cancelled.' 'Yellow';exit 0}
    return @{ResourceGroupName=$ResourceGroupName;Location=$Location;SubscriptionId=$SubscriptionId;AdminUsername=$AdminUsername;AdminPassword=$AdminPassword;MyIP=$MyIP;namePrefix=$namePrefix;VmSize=$VmSize;LinuxVmSize=$LinuxVmSize;RetentionInDays=$RetentionInDays;EnableAzureActivity=$EnableAzureActivity;EnableAutoShutdown=$EnableAutoShutdown;ShutdownTime=$ShutdownTime;ShutdownTimeZone=$ShutdownTimeZone;EnableShutdownNotificationEmails=$EnableShutdownNotificationEmails;NotificationEmail=$NotificationEmail;NotificationMinutesBefore=$NotificationMinutesBefore;EnableFlowLogs=$EnableFlowLogs}
}

function Initialize-AzureContext { param([string]$SubscriptionId);$context=Get-AzContext;if($null -eq $context -or $ForceLogin){Write-ColoredOutput 'Connecting to Azure...' 'Yellow';Connect-AzAccount|Out-Null};if((Get-AzContext).Subscription.Id -ne $SubscriptionId){Write-ColoredOutput 'Setting subscription context...' 'Yellow';Set-AzContext -SubscriptionId $SubscriptionId|Out-Null};$currentContext=Get-AzContext;Write-ColoredOutput "`n=== Deploying Adversary Lab ===" 'Cyan';Write-ColoredOutput "Using subscription: $($currentContext.Subscription.Name)" 'Green' }
function Test-AzurePermissions { param([string]$ResourceGroupName,[string]$Location);$rg=Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue;if($null -eq $rg){Write-ColoredOutput "Creating resource group: $ResourceGroupName" 'Yellow';New-AzResourceGroup -Name $ResourceGroupName -Location $Location|Out-Null;Write-ColoredOutput 'Resource group created!' 'Green'}else{Write-ColoredOutput "Using existing resource group: $ResourceGroupName" 'Green'} }
function Test-NetworkWatcher { param([string]$Location);$rgName='NetworkWatcherRG';$name="NetworkWatcher_$Location";if($null -eq(Get-AzResourceGroup -Name $rgName -ErrorAction SilentlyContinue)){New-AzResourceGroup -Name $rgName -Location $Location|Out-Null};if($null -eq(Get-AzNetworkWatcher -Name $name -ResourceGroupName $rgName -ErrorAction SilentlyContinue)){Write-ColoredOutput "Creating Network Watcher in $Location..." 'Yellow';New-AzNetworkWatcher -Name $name -ResourceGroupName $rgName -Location $Location|Out-Null;Write-ColoredOutput 'Network Watcher created!' 'Green'}else{Write-ColoredOutput "Network Watcher exists in $Location" 'Green'} }

function Test-VmMonitorAgent {
    param([string]$ResourceGroupName,[string]$VmName,[ValidateSet('Windows','Linux')][string]$OS)
    if($OS -eq 'Windows'){$commandId='RunPowerShellScript';$probe=@'
$svc=Get-Service -Name 'AzureMonitorAgent' -ErrorAction SilentlyContinue
$proc=@(Get-Process -Name 'MonAgentCore','MonAgentHost','MonAgentLauncher' -ErrorAction SilentlyContinue)
if(($svc -and $svc.Status -eq 'Running') -or $proc.Count -gt 0){'AGENT=RUNNING'}else{'AGENT=NOT_RUNNING'}
'@}else{$commandId='RunShellScript';$probe=@'
if systemctl is-active --quiet azuremonitoragent 2>/dev/null || pgrep -f 'mdsd|azuremonitoragent|fluent-bit' >/dev/null 2>&1; then echo AGENT=RUNNING; else echo AGENT=NOT_RUNNING; fi
'@}
    try{$r=Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $VmName -CommandId $commandId -ScriptString $probe -ErrorAction Stop;$text=($r.Value|ForEach-Object{$_.Message}) -join "`n";if($text -match 'AGENT=RUNNING'){return 'Running'};return 'NotRunning'}catch{Write-ColoredOutput "  Could not probe $OS endpoint $VmName`: $($_.Exception.Message)" 'Yellow';return 'Unknown'}
}
function Invoke-LogAnalyticsCount {
    param(
        [string]$WorkspaceCustomerId,
        [string]$Query,
        [string]$Label
    )

    try {
        $response = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceCustomerId -Query $Query -ErrorAction Stop
        $row = $response.Results | Select-Object -First 1
        $count = if ($null -eq $row -or $null -eq $row.N) { 0 } else { [int]$row.N }

        return [pscustomobject]@{
            Success = $true
            Count   = $count
            Error   = $null
        }
    }
    catch {
        Write-ColoredOutput "  $Label query failed: $($_.Exception.Message)" 'Red'
        return [pscustomobject]@{
            Success = $false
            Count   = $null
            Error   = $_.Exception.Message
        }
    }
}

function Get-HeartbeatResult {
    param([string]$WorkspaceCustomerId,[string]$VmResourceId,[string]$Label)
    $escaped = $VmResourceId.Replace("'","''")
    $query = "Heartbeat | where TimeGenerated > ago(30m) | where _ResourceId =~ '$escaped' | summarize N=count()"
    return Invoke-LogAnalyticsCount -WorkspaceCustomerId $WorkspaceCustomerId -Query $query -Label $Label
}

function Get-EndpointTelemetryResult {
    param(
        [string]$WorkspaceCustomerId,
        [string]$VmResourceId,
        [ValidateSet('Event','Syslog')][string]$Table,
        [string]$Label
    )

    $escaped = $VmResourceId.Replace("'","''")
    $query = "$Table | where TimeGenerated > ago(30m) | where _ResourceId =~ '$escaped' | summarize N=count()"
    return Invoke-LogAnalyticsCount -WorkspaceCustomerId $WorkspaceCustomerId -Query $query -Label $Label
}

function Get-ValidationState {
    param([string]$AgentState,[object]$QueryResult)
    if ($AgentState -ne 'Running') { return 'Fail' }
    if (-not $QueryResult.Success) { return 'Fail' }
    if ($QueryResult.Count -gt 0) { return 'Pass' }
    return 'Pending'
}

function Write-ValidationStatus {
    param(
        [string]$Label,
        [ValidateSet('Pass','Pending','Fail','Skipped')][string]$State,
        [string]$Detail = ''
    )

    $suffix = if ([string]::IsNullOrWhiteSpace($Detail)) { '' } else { ": $Detail" }

    switch ($State) {
        'Pass'    { Write-ColoredOutput "✓ $Label$suffix" 'Green' }
        'Pending' { Write-ColoredOutput "- $Label$suffix" 'Yellow' }
        'Fail'    { Write-ColoredOutput "✗ $Label$suffix" 'Red' }
        'Skipped' { Write-ColoredOutput "- $Label$suffix" 'Yellow' }
    }
}

function Test-LabTelemetry {
    param(
        [string]$ResourceGroupName,
        [string]$WindowsVmName,
        [string]$LinuxVmName,
        [string]$WindowsVmResourceId,
        [string]$LinuxVmResourceId,
        [string]$WorkspaceCustomerId,
        [bool]$CheckActivityLogs,
        [int]$TimeoutMinutes
    )

    Write-ColoredOutput "`n=== Verifying Telemetry Pipeline ===" 'Cyan'

    $result = [ordered]@{
        WindowsAgent     = 'Fail'
        LinuxAgent       = 'Fail'
        WindowsHeartbeat = 'Skipped'
        LinuxHeartbeat   = 'Skipped'
        WindowsEvent     = 'Skipped'
        LinuxSyslog      = 'Skipped'
        ActivityLogs     = if ($CheckActivityLogs) { 'Pending' } else { 'Skipped' }
    }

    $windowsAgent = Test-VmMonitorAgent -ResourceGroupName $ResourceGroupName -VmName $WindowsVmName -OS Windows
    $linuxAgent = Test-VmMonitorAgent -ResourceGroupName $ResourceGroupName -VmName $LinuxVmName -OS Linux

    $result.WindowsAgent = if ($windowsAgent -eq 'Running') { 'Pass' } else { 'Fail' }
    $result.LinuxAgent = if ($linuxAgent -eq 'Running') { 'Pass' } else { 'Fail' }

    Write-ValidationStatus -Label 'Windows AMA' -State $result.WindowsAgent -Detail $windowsAgent
    Write-ValidationStatus -Label 'Linux AMA' -State $result.LinuxAgent -Detail $linuxAgent

    $windowsHeartbeat = [pscustomobject]@{ Success = $true; Count = 0; Error = $null }
    $linuxHeartbeat = [pscustomobject]@{ Success = $true; Count = 0; Error = $null }
    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)

    if ($windowsAgent -eq 'Running' -or $linuxAgent -eq 'Running') {
        Write-ColoredOutput 'Waiting for endpoint heartbeats to reach the workspace...' 'Yellow'

        do {
            if ($windowsAgent -eq 'Running' -and $windowsHeartbeat.Count -eq 0 -and $windowsHeartbeat.Success) {
                $windowsHeartbeat = Get-HeartbeatResult -WorkspaceCustomerId $WorkspaceCustomerId -VmResourceId $WindowsVmResourceId -Label 'Windows heartbeat'
            }
            if ($linuxAgent -eq 'Running' -and $linuxHeartbeat.Count -eq 0 -and $linuxHeartbeat.Success) {
                $linuxHeartbeat = Get-HeartbeatResult -WorkspaceCustomerId $WorkspaceCustomerId -VmResourceId $LinuxVmResourceId -Label 'Linux heartbeat'
            }

            $windowsDone = $windowsAgent -ne 'Running' -or -not $windowsHeartbeat.Success -or $windowsHeartbeat.Count -gt 0
            $linuxDone = $linuxAgent -ne 'Running' -or -not $linuxHeartbeat.Success -or $linuxHeartbeat.Count -gt 0

            if ($windowsDone -and $linuxDone) { break }
            if ((Get-Date).AddSeconds(60) -ge $deadline) { break }

            $remaining = [Math]::Max(0,[int]($deadline-(Get-Date)).TotalMinutes)
            Write-ColoredOutput "  Waiting: Windows=$($windowsHeartbeat.Count) Linux=$($linuxHeartbeat.Count) (~$remaining min left)..." 'Yellow'
            Start-Sleep 60
        }
        while ((Get-Date) -lt $deadline)
    }

    $result.WindowsHeartbeat = Get-ValidationState -AgentState $windowsAgent -QueryResult $windowsHeartbeat
    $result.LinuxHeartbeat = Get-ValidationState -AgentState $linuxAgent -QueryResult $linuxHeartbeat

    Write-ValidationStatus -Label 'Windows Heartbeat' -State $result.WindowsHeartbeat -Detail $(if ($result.WindowsHeartbeat -eq 'Pass') { "$($windowsHeartbeat.Count) row(s)" } elseif ($result.WindowsHeartbeat -eq 'Pending') { 'Pending ingestion' } else { 'Validation failed' })
    Write-ValidationStatus -Label 'Linux Heartbeat' -State $result.LinuxHeartbeat -Detail $(if ($result.LinuxHeartbeat -eq 'Pass') { "$($linuxHeartbeat.Count) row(s)" } elseif ($result.LinuxHeartbeat -eq 'Pending') { 'Pending ingestion' } else { 'Validation failed' })

    Write-ColoredOutput "`nChecking configured endpoint telemetry..." 'Yellow'

    $windowsEvent = Get-EndpointTelemetryResult -WorkspaceCustomerId $WorkspaceCustomerId -VmResourceId $WindowsVmResourceId -Table 'Event' -Label 'Windows Event'
    $linuxSyslog = Get-EndpointTelemetryResult -WorkspaceCustomerId $WorkspaceCustomerId -VmResourceId $LinuxVmResourceId -Table 'Syslog' -Label 'Linux Syslog'

    $result.WindowsEvent = Get-ValidationState -AgentState $windowsAgent -QueryResult $windowsEvent
    $result.LinuxSyslog = Get-ValidationState -AgentState $linuxAgent -QueryResult $linuxSyslog

    Write-ValidationStatus -Label 'Windows Event → LAW' -State $result.WindowsEvent -Detail $(if ($result.WindowsEvent -eq 'Pass') { "$($windowsEvent.Count) row(s)" } elseif ($result.WindowsEvent -eq 'Pending') { 'Pending ingestion' } else { 'Validation failed' })
    Write-ValidationStatus -Label 'Linux Syslog → LAW' -State $result.LinuxSyslog -Detail $(if ($result.LinuxSyslog -eq 'Pass') { "$($linuxSyslog.Count) row(s)" } elseif ($result.LinuxSyslog -eq 'Pending') { 'Pending ingestion' } else { 'Validation failed' })

    if ($CheckActivityLogs) {
        Write-ColoredOutput "`nChecking Azure Activity logs..." 'Yellow'
        $activity = Invoke-LogAnalyticsCount -WorkspaceCustomerId $WorkspaceCustomerId -Query 'AzureActivity | where TimeGenerated > ago(1h) | summarize N=count()' -Label 'Azure Activity'

        if (-not $activity.Success) { $result.ActivityLogs = 'Fail' }
        elseif ($activity.Count -gt 0) { $result.ActivityLogs = 'Pass' }
        else { $result.ActivityLogs = 'Pending' }

        Write-ValidationStatus -Label 'Azure Activity Logs' -State $result.ActivityLogs -Detail $(if ($result.ActivityLogs -eq 'Pass') { "$($activity.Count) row(s)" } elseif ($result.ActivityLogs -eq 'Pending') { 'Pending ingestion' } else { 'Validation failed' })
    }

    return [pscustomobject]$result
}

function Invoke-MainInfrastructureDeployment {
    param(
        [hashtable]$DeploymentParams,
        [int]$MaxAttempts = 5,
        [int]$RetryDelaySeconds = 15
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            return New-AzResourceGroupDeployment @DeploymentParams -ErrorAction Stop
        }
        catch {
            $message = $_.Exception.ToString()
            $isTransientSyslogTableError = $message -match 'InvalidOutputTable' -and $message -match 'Microsoft-Syslog'

            if (-not $isTransientSyslogTableError -or $attempt -eq $MaxAttempts) { throw }

            Write-ColoredOutput "Linux Syslog table is not ready yet. Retrying infrastructure deployment in $RetryDelaySeconds seconds (attempt $($attempt + 1)/$MaxAttempts)..." 'Yellow'
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

try{
    Write-ColoredOutput 'Starting Adversary Lab deployment...' 'Green';if(-not(Test-AzurePowerShell)){throw 'Azure PowerShell module not found. Install with: Install-Module -Name Az'};$params=Get-InteractiveParameters;Initialize-AzureContext -SubscriptionId $params.SubscriptionId;Test-AzurePermissions -ResourceGroupName $params.ResourceGroupName -Location $params.Location;if($params.EnableFlowLogs){Test-NetworkWatcher -Location $params.Location}
    $mainTemplate=Join-Path $PSScriptRoot 'main.bicep';$subscriptionTemplate=Join-Path $PSScriptRoot 'main_subscription.bicep';Write-ColoredOutput 'Checking Bicep templates...' 'Yellow';if(-not(Test-Path $mainTemplate)){throw 'main.bicep not found in script directory'};if(-not(Test-Path $subscriptionTemplate)){throw 'main_subscription.bicep not found in script directory'};Write-ColoredOutput 'Bicep templates found.' 'Green'
    Write-ColoredOutput 'Deploying main infrastructure...' 'Yellow';$deploymentParams=@{ResourceGroupName=$params.ResourceGroupName;TemplateFile=$mainTemplate;namePrefix=$params.namePrefix;location=$params.Location;adminUsername=$params.AdminUsername;adminPassword=$params.AdminPassword;myIP=$params.MyIP;vmSize=$params.VmSize;linuxVmSize=$params.LinuxVmSize;retentionInDays=$params.RetentionInDays;enableAutoShutdown=$params.EnableAutoShutdown;shutdownTime=$params.ShutdownTime;shutdownTimeZone=$params.ShutdownTimeZone;enableShutdownNotificationEmails=$params.EnableShutdownNotificationEmails;notificationEmail=$params.NotificationEmail;notificationMinutesBefore=$params.NotificationMinutesBefore};if(-not[string]::IsNullOrWhiteSpace($ResourceSuffix)){$deploymentParams['resourceSuffix']=$ResourceSuffix;Write-ColoredOutput "Using pinned resource suffix: $ResourceSuffix" 'Yellow'};$deployment=Invoke-MainInfrastructureDeployment -DeploymentParams $deploymentParams;Write-ColoredOutput 'Infrastructure deployment completed!' 'Green'
    $credFile=Save-CredentialsToFile -AdminUsername $params.AdminUsername -AdminPassword $params.AdminPassword -WindowsPublicIP $deployment.Outputs['vmPublicIP'].Value -LinuxPublicIP $deployment.Outputs['linuxVmPublicIP'].Value -OutputPath $PSScriptRoot;Write-ColoredOutput "Credentials saved to: $credFile" 'Yellow'
    if($params.EnableAzureActivity){Write-ColoredOutput 'Deploying Azure Activity logs...' 'Yellow';$subParams=@{resourceGroupName=$params.ResourceGroupName;workspaceName=$deployment.Outputs['workspaceName'].Value;enableAzureActivity=$true};$null=New-AzSubscriptionDeployment -Location $params.Location -TemplateFile $subscriptionTemplate -TemplateParameterObject $subParams -ErrorAction Stop;Write-ColoredOutput 'Activity logs deployment completed!' 'Green'}
    if($params.EnableFlowLogs){Write-ColoredOutput 'Deploying VNet Flow Logs...' 'Yellow';$flowTemplate=Join-Path $PSScriptRoot 'modules/network_monitoring.bicep';$flowParams=@{location=$params.Location;vnetResourceId=$deployment.Outputs['vnetResourceId'].Value;storageAccountId=$deployment.Outputs['storageAccountResourceId'].Value;workspaceResourceId=$deployment.Outputs['workspaceResourceId'].Value;retentionDays=$params.RetentionInDays;tags=@{Environment='Development';Project=$params.namePrefix;Purpose='AdversaryLab'}};$null=New-AzSubscriptionDeployment -Location $params.Location -TemplateFile $flowTemplate -TemplateParameterObject $flowParams -ErrorAction Stop;Write-ColoredOutput 'VNet Flow Logs deployment completed!' 'Green'}
    $telemetry=$null;if(-not $SkipTelemetryCheck){$telemetry=Test-LabTelemetry -ResourceGroupName $params.ResourceGroupName -WindowsVmName $deployment.Outputs['vmName'].Value -LinuxVmName $deployment.Outputs['linuxVmName'].Value -WindowsVmResourceId $deployment.Outputs['vmResourceId'].Value -LinuxVmResourceId $deployment.Outputs['linuxVmResourceId'].Value -WorkspaceCustomerId $deployment.Outputs['workspaceCustomerId'].Value -CheckActivityLogs $params.EnableAzureActivity -TimeoutMinutes $TelemetryTimeoutMinutes}
    Write-ColoredOutput "`n=== Deployment Summary ===" 'Cyan'
    Write-ColoredOutput "✓ Resource Group: $($params.ResourceGroupName)" 'Green'
    Write-ColoredOutput "✓ Windows: $($deployment.Outputs['vmName'].Value) | $($deployment.Outputs['vmPublicIP'].Value) | RDP" 'Green'
    Write-ColoredOutput "✓ Linux: $($deployment.Outputs['linuxVmName'].Value) | $($deployment.Outputs['linuxVmPublicIP'].Value) | SSH" 'Green'
    Write-ColoredOutput "✓ Log Analytics Workspace: $($deployment.Outputs['workspaceName'].Value)" 'Green'
    Write-ColoredOutput "✓ Allowed Public IP: $($params.MyIP)" 'Green'
    Write-ColoredOutput "✓ Auto-shutdown: $(if($params.EnableAutoShutdown){"Enabled at $($params.ShutdownTime)"}else{'Disabled'})" 'Green'
    Write-ColoredOutput "✓ VNet Flow Logs: $(if($params.EnableFlowLogs){'Enabled'}else{'Disabled'})" 'Green'
    Write-ColoredOutput "✓ Azure Activity Logs: $(if($params.EnableAzureActivity){'Enabled'}else{'Disabled'})" 'Green'

    $telemetryHasFailure = $false
    $telemetryHasPending = $false

    if ($null -eq $telemetry) {
        Write-ValidationStatus -Label 'Telemetry validation' -State 'Skipped' -Detail '-SkipTelemetryCheck'
    }
    else {
        Write-ValidationStatus -Label 'Windows AMA' -State $telemetry.WindowsAgent
        Write-ValidationStatus -Label 'Linux AMA' -State $telemetry.LinuxAgent
        Write-ValidationStatus -Label 'Windows Heartbeat' -State $telemetry.WindowsHeartbeat
        Write-ValidationStatus -Label 'Linux Heartbeat' -State $telemetry.LinuxHeartbeat
        Write-ValidationStatus -Label 'Windows Event → LAW' -State $telemetry.WindowsEvent
        Write-ValidationStatus -Label 'Linux Syslog → LAW' -State $telemetry.LinuxSyslog
        if ($params.EnableAzureActivity) {
            Write-ValidationStatus -Label 'Azure Activity Logs' -State $telemetry.ActivityLogs
        }

        $states = @(
            $telemetry.WindowsAgent,
            $telemetry.LinuxAgent,
            $telemetry.WindowsHeartbeat,
            $telemetry.LinuxHeartbeat,
            $telemetry.WindowsEvent,
            $telemetry.LinuxSyslog
        )
        if ($params.EnableAzureActivity) { $states += $telemetry.ActivityLogs }

        $telemetryHasFailure = $states -contains 'Fail'
        $telemetryHasPending = $states -contains 'Pending'
    }

    Write-ColoredOutput "`n✓ Credentials saved to: $credFile" 'Yellow'
    Write-ColoredOutput '  IMPORTANT: Delete this file after noting the credentials!' 'Yellow'

    if ($deployment.Outputs.ContainsKey('sentinelUrl')) {
        Write-ColoredOutput "`n=== Useful Links ===" 'Cyan'
        Write-ColoredOutput "Sentinel URL: $($deployment.Outputs['sentinelUrl'].Value)" 'White'
    }

    if ($telemetryHasFailure) {
        Write-ColoredOutput "`nInfrastructure deployment completed, but telemetry validation failed." 'Red'
    }
    elseif ($telemetryHasPending) {
        Write-ColoredOutput "`nDeployment completed. Some telemetry is still pending ingestion." 'Yellow'
    }
    else {
        Write-ColoredOutput "`nDeployment completed successfully!" 'Green'
    }

    Write-ColoredOutput "Windows RDP: mstsc /v:$($deployment.Outputs['vmPublicIP'].Value)" 'Cyan'
    Write-ColoredOutput "Linux SSH: ssh $($params.AdminUsername)@$($deployment.Outputs['linuxVmPublicIP'].Value)" 'Cyan'

    if ($telemetryHasFailure) { exit 2 }

}catch{Write-ColoredOutput "Deployment failed: $($_.Exception.Message)" 'Red';Write-ColoredOutput 'Full error details:' 'Yellow';Write-ColoredOutput $_.Exception.ToString() 'Red';exit 1}finally{$params=$null;[System.GC]::Collect()}
