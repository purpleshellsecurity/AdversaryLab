targetScope = 'resourceGroup'

@description('Location for all resources')
param location string = resourceGroup().location
@description('Admin username for the VMs')
param adminUsername string
@description('Admin password for the VMs')
@secure()
param adminPassword string
@description('Base name prefix for resources')
param namePrefix string = 'adversarylab'
@description('Windows VM size')
param vmSize string = 'Standard_D2s_v4'
@description('Linux VM size')
param linuxVmSize string = 'Standard_B2s'
@description('Your Public IP address to allow RDP and SSH access')
param myIP string = ''
@description('Log Analytics workspace retention in days')
param retentionInDays int = 30
@description('Enable automatic shutdown schedule')
param enableAutoShutdown bool = true
@description('Time to shutdown the VMs daily')
param shutdownTime string = '2330'
@description('Timezone for shutdown schedules')
param shutdownTimeZone string = 'Eastern Standard Time'
@description('Enable Windows VM shutdown notifications')
param enableShutdownNotificationEmails bool = false
@description('Email for shutdown notifications')
param notificationEmail string = ''
@description('Minutes before shutdown to send notification')
param notificationMinutesBefore int = 15
@description('Tags applied to resources')
param tags object = {
  Environment: 'Development'
  Project: namePrefix
  Purpose: 'AdversaryLab'
}
@description('Stable resource-name suffix')
@minLength(3)
@maxLength(6)
param resourceSuffix string = substring(uniqueString(resourceGroup().id), 0, 4)
@description('Start date for the budget')
param budgetStartDate string = format('{0}-{1:D2}-01', utcNow('yyyy'), int(utcNow('MM')))

var uniqueNamePrefix = '${namePrefix}${resourceSuffix}'

module networking 'modules/networking.bicep' = {
  name: 'networking-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    myIP: myIP
    tags: tags
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    tags: tags
  }
}

module logAnalytics 'modules/log_analytics.bicep' = {
  name: 'log-analytics-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    retentionInDays: retentionInDays
    tags: tags
  }
}

module vm 'modules/vm.bicep' = {
  name: 'windows-vm-${resourceSuffix}'
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
    tags: tags
  }
}

module linuxVm 'modules/linux_vm.bicep' = {
  name: 'linux-vm-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    adminUsername: adminUsername
    adminPassword: adminPassword
    vmSize: linuxVmSize
    subnetId: networking.outputs.subnetId
    publicIpId: networking.outputs.linuxPublicIpId
    enableAutoShutdown: enableAutoShutdown
    shutdownTime: shutdownTime
    shutdownTimeZone: shutdownTimeZone
    tags: tags
  }
}

module sentinel 'modules/sentinel.bicep' = {
  name: 'sentinel-${resourceSuffix}'
  params: {
    workspaceName: logAnalytics.outputs.workspaceName
  }
}

module vmMonitoring 'modules/vm_monitoring.bicep' = {
  name: 'windows-monitoring-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    vmResourceId: vm.outputs.vmResourceId
    workspaceResourceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

module linuxVmMonitoring 'modules/linux_vm_monitoring.bicep' = {
  name: 'linux-monitoring-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    vmResourceId: linuxVm.outputs.vmResourceId
    workspaceResourceId: logAnalytics.outputs.workspaceResourceId
    tags: tags
  }
}

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

output vmName string = vm.outputs.vmName
output vmPublicIP string = networking.outputs.publicIpAddress
output vmResourceId string = vm.outputs.vmResourceId
output linuxVmName string = linuxVm.outputs.vmName
output linuxVmPublicIP string = networking.outputs.linuxPublicIpAddress
output linuxVmResourceId string = linuxVm.outputs.vmResourceId
output uniqueNamePrefix string = uniqueNamePrefix
output vnetId string = networking.outputs.vnetId
output vnetResourceId string = networking.outputs.vnetResourceId
output vnetName string = networking.outputs.vnetName
output workspaceName string = logAnalytics.outputs.workspaceName
output workspaceCustomerId string = logAnalytics.outputs.workspaceCustomerId
output workspaceResourceId string = logAnalytics.outputs.workspaceResourceId
output dcrId string = vmMonitoring.outputs.dcrId
output linuxDcrId string = linuxVmMonitoring.outputs.dcrId
output storageAccountName string = storage.outputs.storageAccountName
output storageAccountResourceId string = storage.outputs.storageAccountResourceId
output resourceGroupName string = resourceGroup().name
output sentinelUrl string = 'https://portal.azure.com/#@${subscription().tenantId}/resource${logAnalytics.outputs.workspaceResourceId}/overview'
output vmConnectCommand string = 'mstsc /v:${networking.outputs.publicIpAddress}'
output linuxConnectCommand string = 'ssh ${adminUsername}@${networking.outputs.linuxPublicIpAddress}'
output budgetCreated bool = !empty(notificationEmail)
