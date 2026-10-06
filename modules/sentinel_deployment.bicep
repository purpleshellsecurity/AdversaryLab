@description('Azure Workspace Name')
param workspaceName string

@description('Enable additional security solutions')
param enableAdvancedSolutions bool = true

// Reference existing workspace
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

// Sentinel Onboarding
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = {
  scope: workspace
  name: 'default'
  properties: {}
}

// Windows Security Events Solution
resource windowsSecurityEvents 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-securityevents'
  properties: {
    version: '3.0.9'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-securityevents'
    contentProductId: 'azuresentinel.azure-sentinel-solution-securityeven-sl-exvlkfvbts35w'
    contentKind: 'Solution'
    displayName: 'Windows Security Events'
    source: {
      kind: 'Solution'
      name: 'Windows Security Events'
      sourceId: 'azuresentinel.azure-sentinel-solution-securityevents'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Activity Solution
resource azureActivitySolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azureactivity'
  properties: {
    version: '3.0.3'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azureactivity'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azureactivit-sl-x6rxfrmsjp3pw'
    contentKind: 'Solution'
    displayName: 'Azure Activity'
    source: {
      kind: 'Solution'
      name: 'Azure Activity'
      sourceId: 'azuresentinel.azure-sentinel-solution-azureactivity'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Microsoft Entra ID Solution
resource entraIdSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azureactivedirectory'
  properties: {
    version: '3.3.3'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azureactivedirectory'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azureactived-sl-ysutelafuvsa2'
    contentKind: 'Solution'
    displayName: 'Microsoft Entra ID'
    source: {
      kind: 'Solution'
      name: 'Microsoft Entra ID'
      sourceId: 'azuresentinel.azure-sentinel-solution-azureactivedirectory'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Storage Solution
resource azureStorageSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azurestorageaccount'
  properties: {
    version: '2.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azurestorageaccount'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azurestorage-sl-vrzhyzv5bq5mq'
    contentKind: 'Solution'
    displayName: 'Azure Storage'
    source: {
      kind: 'Solution'
      name: 'Azure Storage'
      sourceId: 'azuresentinel.azure-sentinel-solution-azurestorageaccount'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Network Security Groups Solution
resource networkSecurityGroupsSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-networksecuritygroup'
  properties: {
    version: '2.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-networksecuritygroup'
    contentProductId: 'azuresentinel.azure-sentinel-solution-networksecur-sl-bdnl6w63teo7m'
    contentKind: 'Solution'
    displayName: 'Azure Network Security Groups'
    source: {
      kind: 'Solution'
      name: 'Azure Network Security Groups'
      sourceId: 'azuresentinel.azure-sentinel-solution-networksecuritygroup'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Resource Graph Solution
resource azureResourceGraphSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-resourcegraph'
  properties: {
    version: '3.0.0'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-resourcegraph'
    contentProductId: 'azuresentinel.azure-sentinel-solution-resourcegrap-sl-fe7yvf7mzxfgi'
    contentKind: 'Solution'
    displayName: 'Azure Resource Graph'
    source: {
      kind: 'Solution'
      name: 'Azure Resource Graph'
      sourceId: 'azuresentinel.azure-sentinel-solution-resourcegraph'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Security Benchmark Solution
resource azureSecurityBenchmarkSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark'
  properties: {
    version: '3.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azuresecurit-sl-cbis4wtefs3lm'
    contentKind: 'Solution'
    displayName: 'Azure Security Benchmark'
    source: {
      kind: 'Solution'
      name: 'AzureSecurityBenchmark'
      sourceId: 'azuresentinel.azure-sentinel-solution-azuresecuritybenchmark'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Logic Apps Solution
resource azureLogicAppsSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-logicapps'
  properties: {
    version: '2.0.0'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-logicapps'
    contentProductId: 'azuresentinel.azure-sentinel-solution-logicapps-sl-n3dubysksmgmc'
    contentKind: 'Solution'
    displayName: 'Azure Logic Apps'
    source: {
      kind: 'Solution'
      name: 'Azure Logic Apps'
      sourceId: 'azuresentinel.azure-sentinel-solution-logicapps'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Key Vault Solution
resource azureKeyVaultSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-azurekeyvault'
  properties: {
    version: '3.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-azurekeyvault'
    contentProductId: 'azuresentinel.azure-sentinel-solution-azurekeyvaul-sl-3m323kndkg22c'
    contentKind: 'Solution'
    displayName: 'Azure Key Vault'
    source: {
      kind: 'Solution'
      name: 'Azure Key Vault'
      sourceId: 'azuresentinel.azure-sentinel-solution-azurekeyvault'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// DNS Essentials Solution
resource dnsEssentialsSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-dns-domain'
  properties: {
    version: '3.0.4'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-dns-domain'
    contentProductId: 'azuresentinel.azure-sentinel-solution-dns-domain-sl-ekdkjxal4jlhc'
    contentKind: 'Solution'
    displayName: 'DNS Essentials'
    source: {
      kind: 'Solution'
      name: 'DNS Essentials'
      sourceId: 'azuresentinel.azure-sentinel-solution-dns-domain'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Azure Firewall Solution
resource azureFirewallSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'sentinel4azurefirewall.sentinel4azurefirewall'
  properties: {
    version: '3.0.4'
    contentSchemaVersion: '3.0.0'
    contentId: 'sentinel4azurefirewall.sentinel4azurefirewall'
    contentProductId: 'sentinel4azurefirewall.sentinel4azurefirewall-sl-w7phvb6yjdpq2'
    contentKind: 'Solution'
    displayName: 'Azure Firewall'
    source: {
      kind: 'Solution'
      name: 'Azure Firewall'
      sourceId: 'sentinel4azurefirewall.sentinel4azurefirewall'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}

// Windows Firewall Solution
resource windowsFirewallSolution 'Microsoft.SecurityInsights/contentPackages@2024-03-01' = if (enableAdvancedSolutions) {
  scope: workspace
  name: 'azuresentinel.azure-sentinel-solution-windowsfirewall'
  properties: {
    version: '3.0.2'
    contentSchemaVersion: '3.0.0'
    contentId: 'azuresentinel.azure-sentinel-solution-windowsfirewall'
    contentProductId: 'azuresentinel.azure-sentinel-solution-windowsfirew-sl-i3cua5qtmecle'
    contentKind: 'Solution'
    displayName: 'Windows Firewall'
    source: {
      kind: 'Solution'
      name: 'Windows Firewall'
      sourceId: 'azuresentinel.azure-sentinel-solution-windowsfirewall'
    }
  }
  dependsOn: [
    sentinelOnboarding
  ]
}



// Outputs
output sentinelOnboarded bool = true
output workspaceId string = workspace.id
output solutionsDeployed array = enableAdvancedSolutions ? [
  'Windows Security Events'
  'Azure Activity'
  'Microsoft Entra ID'
  'Azure Storage'
  'Azure Network Security Groups'
  'Azure Resource Graph'
  'Azure Security Benchmark'
  'Azure Logic Apps'
  'Azure Key Vault'
  'DNS Essentials'
  'Azure Firewall'
  'Windows Firewall'
] : [
  'Windows Security Events'
]
output analyticsRulesDeployed int = enableAdvancedSolutions ? 1 : 0
