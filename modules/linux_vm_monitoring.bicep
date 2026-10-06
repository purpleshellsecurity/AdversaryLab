// Layer 3: Monitoring - Linux AMA + Syslog DCR
// Sysmon for Linux writes through syslog. AMA collects the configured facilities
// and sends them to the Log Analytics Syslog table.

param location string
param tags object = {}
param namePrefix string
param vmResourceId string
param workspaceResourceId string

var vmName = last(split(vmResourceId, '/'))
var dcrName = '${namePrefix}-linux-dcr'

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: vmName
}

resource amaExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dcrName
  location: location
  tags: tags
  properties: {
    dataSources: {
      syslog: [
        {
          name: 'LinuxSyslogDataSource'
          streams: [
            'Microsoft-Syslog'
          ]
          // Broad during lab validation. Tighten facilities/severities after
          // observing Sysmon for Linux on the deployed Ubuntu image.
          facilityNames: [
            '*'
          ]
          logLevels: [
            '*'
          ]
        }
      ]
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: 'la-workspace'
        }
      ]
    }
    dataFlows: [
      {
        streams: [
          'Microsoft-Syslog'
        ]
        destinations: [
          'la-workspace'
        ]
      }
    ]
  }
}

resource dcrAssociation 'Microsoft.Insights/dataCollectionRuleAssociations@2023-03-11' = {
  name: '${dcrName}-association'
  scope: vm
  properties: {
    dataCollectionRuleId: dcr.id
    description: 'Linux Syslog collection rule for Sysmon validation'
  }
  dependsOn: [
    amaExtension
  ]
}

output amaExtensionId string = amaExtension.id
output dcrId string = dcr.id
output dcrName string = dcr.name
output dcrAssociationId string = dcrAssociation.id
