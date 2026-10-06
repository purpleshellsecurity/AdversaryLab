// Layer 3: Monitoring - Microsoft Sentinel
// Dependencies: log_analytics (workspaceName)

@description('Log Analytics workspace to onboard to Sentinel')
param workspaceName string

@description('Deploy the full solution set. When false, only the core solution is installed.')
param enableAdvancedSolutions bool = true

// Solution catalogue. Adding a solution is a one-line data change; the resource
// loop below is what actually deploys them.
//   core = installed regardless of enableAdvancedSolutions
var solutions = [
  {
    id: 'azuresentinel.azure-sentinel-solution-securityevents'
    productId: 'azuresentinel.azure-sentinel-solution-securityeven-sl-exvlkfvbts35w'
    version: '3.0.9'
    displayName: 'Windows Security Events'
    sourceName: 'Windows Security Events'
    core: true
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-azureactivity'
    productId: 'azuresentinel.azure-sentinel-solution-azureactivit-sl-x6rxfrmsjp3pw'
    version: '3.0.3'
    displayName: 'Azure Activity'
    sourceName: 'Azure Activity'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-azureactivedirectory'
    productId: 'azuresentinel.azure-sentinel-solution-azureactived-sl-ysutelafuvsa2'
    version: '3.3.3'
    displayName: 'Microsoft Entra ID'
    sourceName: 'Microsoft Entra ID'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-azurestorageaccount'
    productId: 'azuresentinel.azure-sentinel-solution-azurestorage-sl-vrzhyzv5bq5mq'
    version: '2.0.2'
    displayName: 'Azure Storage'
    sourceName: 'Azure Storage'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-networksecuritygroup'
    productId: 'azuresentinel.azure-sentinel-solution-networksecur-sl-bdnl6w63teo7m'
    version: '2.0.2'
    displayName: 'Azure Network Security Groups'
    sourceName: 'Azure Network Security Groups'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-resourcegraph'
    productId: 'azuresentinel.azure-sentinel-solution-resourcegrap-sl-fe7yvf7mzxfgi'
    version: '3.0.0'
    displayName: 'Azure Resource Graph'
    sourceName: 'Azure Resource Graph'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark'
    productId: 'azuresentinel.azure-sentinel-solution-azuresecurit-sl-cbis4wtefs3lm'
    version: '3.0.2'
    displayName: 'Azure Security Benchmark'
    sourceName: 'AzureSecurityBenchmark'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-logicapps'
    productId: 'azuresentinel.azure-sentinel-solution-logicapps-sl-n3dubysksmgmc'
    version: '2.0.0'
    displayName: 'Azure Logic Apps'
    sourceName: 'Azure Logic Apps'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-azurekeyvault'
    productId: 'azuresentinel.azure-sentinel-solution-azurekeyvaul-sl-3m323kndkg22c'
    version: '3.0.2'
    displayName: 'Azure Key Vault'
    sourceName: 'Azure Key Vault'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-dns-domain'
    productId: 'azuresentinel.azure-sentinel-solution-dns-domain-sl-ekdkjxal4jlhc'
    version: '3.0.4'
    displayName: 'DNS Essentials'
    sourceName: 'DNS Essentials'
    core: false
  }
  {
    id: 'sentinel4azurefirewall.sentinel4azurefirewall'
    productId: 'sentinel4azurefirewall.sentinel4azurefirewall-sl-w7phvb6yjdpq2'
    version: '3.0.4'
    displayName: 'Azure Firewall'
    sourceName: 'Azure Firewall'
    core: false
  }
  {
    id: 'azuresentinel.azure-sentinel-solution-windowsfirewall'
    productId: 'azuresentinel.azure-sentinel-solution-windowsfirew-sl-i3cua5qtmecle'
    version: '3.0.2'
    displayName: 'Windows Firewall'
    sourceName: 'Windows Firewall'
    core: false
  }
]

var selectedSolutions = [for s in solutions: s.core || enableAdvancedSolutions ? s.displayName : '']

// Reference existing workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2025-02-01' existing = {
  name: workspaceName
}

resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-09-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

resource sentinelSolutions 'Microsoft.SecurityInsights/contentPackages@2024-09-01' = [
  for s in solutions: if (s.core || enableAdvancedSolutions) {
    scope: workspace
    name: s.id
    properties: {
      version: s.version
      contentSchemaVersion: '3.0.0'
      contentId: s.id
      contentProductId: s.productId
      contentKind: 'Solution'
      displayName: s.displayName
      source: {
        kind: 'Solution'
        name: s.sourceName
        sourceId: s.id
      }
    }
    dependsOn: [
      sentinelOnboarding
    ]
  }
]

// Outputs
output workspaceId string = workspace.id
output solutionsDeployed array = filter(selectedSolutions, s => !empty(s))
output solutionCount int = length(filter(selectedSolutions, s => !empty(s)))
