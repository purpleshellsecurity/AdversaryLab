targetScope = 'resourceGroup'

// ============================================================================
// PARAMETERS
// ============================================================================

@description('Location for all resources')
param location string = resourceGroup().location

@description('Admin username for the VM')
param adminUsername string

@description('Admin password for the VM')
@secure()
param adminPassword string

@description('Base name prefix for resources')
param namePrefix string = 'adversarylab'

@description('VM size')
param vmSize string = 'Standard_D2s_v4'

@description('Your Public IP address to allow RDP access')
param myIP string = ''

@description('Log Analytics workspace retention in days')
param retentionInDays int = 30

@description('Enable automatic shutdown schedule')
param enableAutoShutdown bool = true

@description('Time to shutdown the VM daily (24-hour format, e.g., 2330 for 11:30 PM)')
param shutdownTime string = '2330'

@description('Timezone for the shutdown schedule')
param shutdownTimeZone string = 'Eastern Standard Time'

@description('Enable shutdown notifications')
param enableShutdownNotificationEmails bool = false

@description('Email for shutdown notifications')
param notificationEmail string = ''

@description('Minutes before shutdown to send notification')
param notificationMinutesBefore int = 15

@description('Start date for the budget (defaults to first day of current month)')
param budgetStartDate string = format('{0}-{1:D2}-01', utcNow('yyyy'), int(utcNow('MM')))

// ============================================================================
// VARIABLES
// ============================================================================

var resourceSuffix = substring(uniqueString(resourceGroup().id, deployment().name), 0, 3)
var uniqueNamePrefix = '${namePrefix}${resourceSuffix}'

// ============================================================================
// LAYER 1: FOUNDATION (no inter-dependencies)
// ============================================================================

module networking 'modules/networking.bicep' = {
  name: 'networking-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    myIP: myIP
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
  }
}

module logAnalytics 'modules/log_analytics.bicep' = {
  name: 'log-analytics-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    retentionInDays: retentionInDays
  }
}

// ============================================================================
// LAYER 2: COMPUTE (depends on Layer 1)
// ============================================================================

module vm 'modules/vm.bicep' = {
  name: 'vm-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    adminUsername: adminUsername
    adminPassword: adminPassword
    vmSize: vmSize
    subnetId: networking.outputs.subnetId
    publicIpId: networking.outputs.publicIpId
    enableAutoShutdown: enableAutoShutdown
    shutdownTime: shutdownTime
    shutdownTimeZone: shutdownTimeZone
    enableShutdownNotifications: enableShutdownNotificationEmails
    notificationEmail: notificationEmail
    notificationMinutesBefore: notificationMinutesBefore
  }
}

// ============================================================================
// LAYER 3: MONITORING (depends on Layer 1 + Layer 2)
// ============================================================================

module sentinel 'modules/sentinel.bicep' = {
  name: 'sentinel-${resourceSuffix}'
  params: {
    workspaceName: logAnalytics.outputs.workspaceName
  }
}

module vmMonitoring 'modules/vm_monitoring.bicep' = {
  name: 'vm-monitoring-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    vmResourceId: vm.outputs.vmResourceId
    workspaceResourceId: logAnalytics.outputs.workspaceResourceId
  }
}

// Note: Network monitoring is deployed separately via PowerShell as it requires subscription scope
// to deploy into NetworkWatcherRG. See adversary_lab_deploy.ps1

// ============================================================================
// LAYER 4: COST MANAGEMENT
// ============================================================================

resource budgetAlert 'Microsoft.Consumption/budgets@2023-05-01' = if (!empty(notificationEmail)) {
  name: '${uniqueNamePrefix}-dev-budget'
  scope: resourceGroup()
  properties: {
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
    }
    amount: 50
    category: 'Cost'
    notifications: {
      Actual: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        contactEmails: [
          notificationEmail
        ]
      }
    }
  }
}

// ============================================================================
// OUTPUTS
// ============================================================================

// Infrastructure
output vmName string = vm.outputs.vmName
output vmPublicIP string = networking.outputs.publicIpAddress
output vmResourceId string = vm.outputs.vmResourceId
output uniqueNamePrefix string = uniqueNamePrefix

// Networking
output vnetId string = networking.outputs.vnetId
output vnetResourceId string = networking.outputs.vnetResourceId
output vnetName string = networking.outputs.vnetName

// Monitoring
output workspaceName string = logAnalytics.outputs.workspaceName
output workspaceId string = logAnalytics.outputs.workspaceId
output workspaceResourceId string = logAnalytics.outputs.workspaceResourceId
output dcrId string = vmMonitoring.outputs.dcrId

// Note: flowLogId is output from the subscription-level deployment

// Storage
output storageAccountName string = storage.outputs.storageAccountName
output storageAccountResourceId string = storage.outputs.storageAccountResourceId

// Resource Group Info
output resourceGroupName string = resourceGroup().name

// Helpful URLs
output sentinelUrl string = 'https://portal.azure.com/#@${subscription().tenantId}/resource${logAnalytics.outputs.workspaceResourceId}/overview'
output vmConnectCommand string = 'mstsc /v:${networking.outputs.publicIpAddress}'

// Cost Management
output budgetCreated bool = !empty(notificationEmail)
