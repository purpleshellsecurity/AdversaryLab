// Layer 3: Monitoring - Network Monitoring (VNet Flow Logs)
// This module must be deployed at subscription scope to target NetworkWatcherRG
// Dependencies: networking (vnetResourceId), storage (storageAccountResourceId), log_analytics (workspaceResourceId)

targetScope = 'subscription'

param location string
param vnetResourceId string
param storageAccountId string
param workspaceResourceId string = ''
param retentionDays int = 30

// Network Watcher is auto-created as NetworkWatcher_<region> in NetworkWatcherRG
var networkWatcherName = 'NetworkWatcher_${location}'
var networkWatcherRG = 'NetworkWatcherRG'
var vnetName = last(split(vnetResourceId, '/'))
var flowLogName = '${vnetName}-flowlog'

// Reference existing NetworkWatcherRG
resource nwResourceGroup 'Microsoft.Resources/resourceGroups@2023-07-01' existing = {
  name: networkWatcherRG
}

// Deploy flow log to NetworkWatcherRG
module flowLogDeploy 'network_monitoring_flowlog.bicep' = {
  name: 'flowlog-${uniqueString(vnetResourceId)}'
  scope: nwResourceGroup
  params: {
    location: location
    networkWatcherName: networkWatcherName
    flowLogName: flowLogName
    vnetResourceId: vnetResourceId
    storageAccountId: storageAccountId
    workspaceResourceId: workspaceResourceId
    retentionDays: retentionDays
  }
}

// Outputs
output flowLogId string = flowLogDeploy.outputs.flowLogId
output flowLogName string = flowLogDeploy.outputs.flowLogName
