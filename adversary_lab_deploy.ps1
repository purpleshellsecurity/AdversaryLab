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
    [string]$AdminPassword = "",
    [string]$MyIP = "",
    [string]$namePrefix = "adversarylab",
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
    [bool]$EnableFlowLogs = $true
)

$ErrorActionPreference = "Stop"

# Helper functions
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
        [string]$AdminPassword,
        [string]$VmPublicIP,
        [string]$OutputPath
    )
    
    $credFile = Join-Path $OutputPath "credentials.txt"
    $content = @"
========================================
Adversary Lab Credentials
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
========================================

VM Public IP: $VmPublicIP
Admin Username: $AdminUsername
Admin Password: $AdminPassword

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
    
    if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
        $generateChoice = Read-Host "Generate password automatically? (y/n)"
        if ($generateChoice -eq 'y' -or $generateChoice -eq 'Y') {
            $AdminPassword = New-CompliantPassword
            Write-Host "Password generated. It will be saved to a credentials file after deployment." -ForegroundColor Yellow
        } else {
            $AdminPassword = Read-Host "Enter password"
        }
    }
    
    if ([string]::IsNullOrWhiteSpace($MyIP)) {
        Write-Host "Detecting your public IP..." -ForegroundColor Yellow
        $MyIP = Get-PublicIPAddress
        if ($MyIP) {
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
        ResourceGroupName = $ResourceGroupName
        Location = $Location
        SubscriptionId = $SubscriptionId
        AdminUsername = $AdminUsername
        AdminPassword = $AdminPassword
        MyIP = $MyIP
        namePrefix = $namePrefix
        VmSize = $VmSize
        RetentionInDays = $RetentionInDays
        EnableAzureActivity = $EnableAzureActivity
        EnableAutoShutdown = $EnableAutoShutdown
        ShutdownTime = $ShutdownTime
        ShutdownTimeZone = $ShutdownTimeZone
        EnableShutdownNotificationEmails = $EnableShutdownNotificationEmails
        NotificationEmail = $NotificationEmail
        NotificationMinutesBefore = $NotificationMinutesBefore
        EnableFlowLogs = $EnableFlowLogs
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
    
    # Check if NetworkWatcherRG exists
    $nwRG = Get-AzResourceGroup -Name $networkWatcherRG -ErrorAction SilentlyContinue
    if ($null -eq $nwRG) {
        Write-ColoredOutput "Creating NetworkWatcherRG resource group..." "Yellow"
        New-AzResourceGroup -Name $networkWatcherRG -Location $Location | Out-Null
    }
    
    # Check if Network Watcher exists in the region
    $nw = Get-AzNetworkWatcher -Name $networkWatcherName -ResourceGroupName $networkWatcherRG -ErrorAction SilentlyContinue
    if ($null -eq $nw) {
        Write-ColoredOutput "Creating Network Watcher in $Location..." "Yellow"
        New-AzNetworkWatcher -Name $networkWatcherName -ResourceGroupName $networkWatcherRG -Location $Location | Out-Null
        Write-ColoredOutput "Network Watcher created!" "Green"
    } else {
        Write-ColoredOutput "Network Watcher exists in $Location" "Green"
    }
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
    
    # Ensure Network Watcher exists if flow logs are enabled
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
    
    $securePassword = ConvertTo-SecureString $params.AdminPassword -AsPlainText -Force
    
    $deploymentParams = @{
        ResourceGroupName = $params.ResourceGroupName
        TemplateFile = $mainTemplate
        namePrefix = $params.namePrefix
        location = $params.Location
        adminUsername = $params.AdminUsername
        adminPassword = $securePassword
        myIP = $params.MyIP
        vmSize = $params.VmSize
        retentionInDays = $params.RetentionInDays
        enableAutoShutdown = $params.EnableAutoShutdown
        shutdownTime = $params.ShutdownTime
        shutdownTimeZone = $params.ShutdownTimeZone
        enableShutdownNotificationEmails = $params.EnableShutdownNotificationEmails
        notificationEmail = $params.NotificationEmail
        notificationMinutesBefore = $params.NotificationMinutesBefore
    }
    
    $deployment = New-AzResourceGroupDeployment @deploymentParams -ErrorAction Stop
    Write-ColoredOutput "Infrastructure deployment completed!" "Green"
    
    if ($params.EnableAzureActivity) {
        Write-ColoredOutput "Deploying Azure Activity logs..." "Yellow"
        
        $workspaceName = $deployment.Outputs["workspaceName"].Value
        $vmName = $deployment.Outputs["vmName"].Value
        
        Write-ColoredOutput "Retrieving VM managed identity..." "Yellow"
        $vm = Get-AzVM -ResourceGroupName $params.ResourceGroupName -Name $vmName
        
        if ($vm.Identity -and $vm.Identity.PrincipalId) {
            $vmPrincipalId = $vm.Identity.PrincipalId
            Write-ColoredOutput "Found VM managed identity: $vmPrincipalId" "Green"
        } else {
            throw "VM '$vmName' does not have a system-assigned managed identity enabled."
        }
        
        $subTemplateParams = @{
            resourceGroupName = $params.ResourceGroupName
            workspaceName = $workspaceName
            enableAzureActivity = $params.EnableAzureActivity
            vmPrincipalId = $vmPrincipalId
            vmName = $vmName
        }
        
        $subscriptionDeployment = New-AzSubscriptionDeployment `
            -Location $params.Location `
            -TemplateFile $subscriptionTemplate `
            -TemplateParameterObject $subTemplateParams `
            -ErrorAction Stop
        Write-ColoredOutput "Activity logs deployment completed!" "Green"
    }
    
    # Deploy VNet Flow Logs (requires subscription scope for NetworkWatcherRG)
    if ($params.EnableFlowLogs) {
        Write-ColoredOutput "Deploying VNet Flow Logs..." "Yellow"
        
        $flowLogsTemplate = Join-Path $PSScriptRoot "modules/network_monitoring.bicep"
        
        $flowLogTemplateParams = @{
            location = $params.Location
            vnetResourceId = $deployment.Outputs["vnetResourceId"].Value
            storageAccountId = $deployment.Outputs["storageAccountResourceId"].Value
            workspaceResourceId = $deployment.Outputs["workspaceResourceId"].Value
            retentionDays = $params.RetentionInDays
        }
        
        $flowLogDeployment = New-AzSubscriptionDeployment `
            -Location $params.Location `
            -TemplateFile $flowLogsTemplate `
            -TemplateParameterObject $flowLogTemplateParams `
            -ErrorAction Stop
        Write-ColoredOutput "VNet Flow Logs deployment completed!" "Green"
    }
    
    # Save credentials to file
    $credFile = Save-CredentialsToFile `
        -AdminUsername $params.AdminUsername `
        -AdminPassword $params.AdminPassword `
        -VmPublicIP $deployment.Outputs["vmPublicIP"].Value `
        -OutputPath $PSScriptRoot
    
    # Deployment summary
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
    $securePassword = $null
    [System.GC]::Collect()
}
