// Layer 1: Foundation - Log Analytics Workspace
// No dependencies on other modules

param location string

@description('Tags applied to resources')
param tags object = {}
param namePrefix string
param retentionInDays int = 30

var workspaceName = '${namePrefix}-law'

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: retentionInDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
    workspaceCapping: {
      dailyQuotaGb: -1
    }
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

output workspaceName string = workspace.name
output workspaceId string = workspace.properties.customerId
output workspaceResourceId string = workspace.id
