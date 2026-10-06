// Layer 1: Foundation - Networking
// No dependencies on other modules

@description('Location for all resources')
param location string

@description('Tags applied to resources')
param tags object = {}

@description('Name prefix for resources')
param namePrefix string

@description('Your Public IP address to allow RDP access')
param myIP string

var vnetName = '${namePrefix}-vnet'
var subnetName = '${namePrefix}-subnet'
var nsgName = '${namePrefix}-nsg'
var pipName = '${namePrefix}-pip'

// Network Security Group
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: nsgName
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowRDP'
        properties: {
          priority: 1000
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: myIP
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
    ]
  }
}

// Virtual Network
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: vnetName
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: '10.0.0.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

// Public IP
resource pip 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: pipName
  location: location
  tags: tags
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// Outputs
output subnetId string = '${vnet.id}/subnets/${subnetName}'
output publicIpId string = pip.id
output publicIpAddress string = pip.properties.ipAddress
output vnetId string = vnet.id
output vnetName string = vnet.name
output vnetResourceId string = vnet.id
output nsgId string = nsg.id
output nsgName string = nsg.name
