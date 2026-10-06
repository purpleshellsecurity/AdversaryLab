// Nested module for flow log deployment - runs within NetworkWatcherRG scope

param location string

@description('Tags applied to resources')
param tags object = {}
param networkWatcherName string
param flowLogName string
param vnetResourceId string
param storageAccountId string
param workspaceResourceId string = ''
param retentionDays int = 30

// Reference existing Network Watcher in this resource group
resource networkWatcher 'Microsoft.Network/networkWatchers@2024-01-01' existing = {
  name: networkWatcherName
}

// VNet Flow Log
resource flowLog 'Microsoft.Network/networkWatchers/flowLogs@2024-01-01' = {
  parent: networkWatcher
  name: flowLogName
  location: location
  tags: tags
  properties: {
    targetResourceId: vnetResourceId
    storageId: storageAccountId
    enabled: true
    retentionPolicy: {
      days: retentionDays
      enabled: true
    }
    format: {
      type: 'JSON'
      version: 2
    }
    flowAnalyticsConfiguration: !empty(workspaceResourceId) ? {
      networkWatcherFlowAnalyticsConfiguration: {
        enabled: true
        workspaceResourceId: workspaceResourceId
        trafficAnalyticsInterval: 10
      }
    } : null
  }
}

// Outputs
output flowLogId string = flowLog.id
output flowLogName string = flowLog.name
