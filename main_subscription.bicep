targetScope = 'subscription'

@description('Resource Group name where Log Analytics workspace is deployed')
param resourceGroupName string

@description('Log Analytics workspace name')
param workspaceName string

@description('Enable Azure Activity Logs connector')
param enableAzureActivity bool = true

// Reference the existing resource group
resource rg 'Microsoft.Resources/resourceGroups@2023-07-01' existing = {
  name: resourceGroupName
}

// Reference the existing Log Analytics workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspaceName
  scope: rg
}

// Diagnostic Settings for Azure Activity Logs (subscription scope)
resource activityLogDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableAzureActivity) {
  name: 'AzureActivity-Sentinel-${uniqueString(subscription().id, resourceGroupName)}'
  scope: subscription()
  properties: {
    workspaceId: workspace.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
        retentionPolicy: {
          enabled: false
          days: 0
        }
      }
    ]
  }
}

// Outputs
output activityLogDiagnosticsId string = enableAzureActivity ? activityLogDiagnostics.id : ''
output workspaceResourceId string = workspace.id
output resourceGroupName string = resourceGroupName
output workspaceName string = workspaceName
