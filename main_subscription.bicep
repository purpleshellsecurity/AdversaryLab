targetScope = 'subscription'

@description('Resource Group name where Log Analytics workspace is deployed')
param resourceGroupName string

@description('Log Analytics workspace name')
param workspaceName string

@description('Enable Azure Activity Logs connector')
param enableAzureActivity bool = true

@description('VM Principal ID for role assignment')
param vmPrincipalId string

@description('VM name for role assignment naming')
param vmName string

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

// Grant VM system-assigned identity contributor access to the subscription
// NOTE: This is intentionally subscription-scoped for Stratus Red Team attack simulations
// TODO: Scope down to resource group in production or when minimum permissions are determined
resource contributorRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' existing = {
  scope: subscription()
  name: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
}

resource vmContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().subscriptionId, vmName, 'contributor')
  properties: {
    roleDefinitionId: contributorRole.id
    principalId: vmPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Outputs
output activityLogDiagnosticsId string = enableAzureActivity ? activityLogDiagnostics.id : ''
output workspaceResourceId string = workspace.id
output resourceGroupName string = resourceGroupName
output workspaceName string = workspaceName
