param location string
param namePrefix string
param adminUsername string

@description('Admin password for the VM (retrieved from Key Vault by PowerShell)')
@secure()
param adminPassword string

param vmSize string
param subnetId string
param publicIpId string

// Shutdown schedule parameters
@description('Enable automatic shutdown schedule')
param enableAutoShutdown bool = true

@description('Time to shutdown the VM daily (24-hour format, e.g., 1900 for 7:00 PM)')
param shutdownTime string = '1900'

@description('Timezone for the shutdown schedule')
param shutdownTimeZone string = 'Eastern Standard Time'

@description('Enable shutdown notifications')
param enableShutdownNotifications bool = false

@description('Email for shutdown notifications (required if notifications enabled)')
param notificationEmail string = ''

@description('Minutes before shutdown to send notification')
param notificationMinutesBefore int = 15

var vmName = '${namePrefix}-vm'
var nicName = '${namePrefix}-nic'
var computerName = take('${replace(namePrefix, '-', '')}vm', 15) // Windows computer name limit

resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIpId
          }
          subnet: {
            id: subnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: computerName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
        provisionVMAgent: true
        patchSettings: {
          patchMode: 'AutomaticByOS'
          assessmentMode: 'ImageDefault'
          enableHotpatching: false
        }
        winRM: {
          listeners: [
            {
              protocol: 'Http'
            }
          ]
        }
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'microsoftwindowsdesktop'
        offer: 'windows-11'
        sku: 'win11-24h2-pro'
        version: 'latest'
      }
      osDisk: {
        name: '${vmName}-osdisk'
        caching: 'ReadWrite'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Premium_LRS'
        }
        diskSizeGB: 128
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// Auto-shutdown schedule
resource vmShutdownSchedule 'Microsoft.DevTestLab/schedules@2018-09-15' = if (enableAutoShutdown) {
  name: 'shutdown-computevm-${vmName}'
  location: location
  properties: {
    status: 'Enabled'
    taskType: 'ComputeVmShutdownTask'
    dailyRecurrence: {
      time: shutdownTime
    }
    timeZoneId: shutdownTimeZone
    targetResourceId: vm.id
    notificationSettings: enableShutdownNotifications ? {
      status: 'Enabled'
      timeInMinutes: notificationMinutesBefore
      emailRecipient: notificationEmail
      notificationLocale: 'en'
    } : {
      status: 'Disabled'
    }
  }
}

// Azure Monitor Agent Extension
resource amaExtension 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'AzureMonitorWindowsAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorWindowsAgent'
    typeHandlerVersion: '1.22'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {
      workspaceId: ''
    }
  }
}

// Outputs
output vmName string = vm.name
output vmResourceId string = vm.id
output vmPrincipalId string = vm.identity.principalId
output nicId string = nic.id
output computerName string = computerName
output vmPrivateIP string = nic.properties.ipConfigurations[0].properties.privateIPAddress

// Shutdown schedule outputs
output shutdownScheduleEnabled bool = enableAutoShutdown
output shutdownTime string = enableAutoShutdown ? shutdownTime : 'Not configured'
output shutdownTimeZone string = enableAutoShutdown ? shutdownTimeZone : 'Not configured'
