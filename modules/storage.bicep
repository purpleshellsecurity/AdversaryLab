// Layer 1: Foundation - Storage
// No dependencies on other modules

@description('Location for all resources')
param location string

@description('Name prefix for resources')
param namePrefix string

@description('Storage account SKU')
param storageAccountSku string = 'Standard_LRS'

var storageAccountName = '${take(toLower(namePrefix), 10)}fl${substring(uniqueString(resourceGroup().id), 0, 8)}'

// Storage Account for Flow Logs
resource storageAccount 'Microsoft.Storage/storageAccounts@2024-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: storageAccountSku
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    encryption: {
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      defaultAction: 'Allow'
    }
  }
  tags: {
    Environment: 'Development'
    Project: namePrefix
    Purpose: 'FlowLogs'
  }
}

// Outputs
output storageAccountName string = storageAccount.name
output storageAccountResourceId string = storageAccount.id
output storageAccountPrimaryEndpoints object = storageAccount.properties.primaryEndpoints
