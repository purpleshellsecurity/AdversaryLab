# Contributing to Adversary Lab

Thanks for your interest in contributing! This document covers the architecture and guidelines for making changes.

## Architecture Overview

The lab is a dual-endpoint Azure environment orchestrated by `adversary_lab_deploy.ps1`.

```text
adversary_lab_deploy.ps1
    │
    ├── main.bicep                         # Resource-group scope
    │   ├── networking.bicep              # VNet, NSG, Windows/Linux public IPs
    │   ├── storage.bicep                 # Flow-log storage
    │   ├── log_analytics.bicep           # Shared Log Analytics workspace
    │   ├── vm.bicep                      # Windows 11 endpoint
    │   ├── linux_vm.bicep                # Ubuntu 24.04 endpoint
    │   ├── vm_monitoring.bicep           # Windows AMA + DCR
    │   ├── linux_vm_monitoring.bicep     # Linux AMA + Syslog DCR
    │   └── sentinel.bicep                # Microsoft Sentinel
    │
    ├── main_subscription.bicep           # Azure Activity diagnostic settings
    │
    └── modules/network_monitoring.bicep  # Subscription-scope flow-log orchestration
        └── network_monitoring_flowlog.bicep
            # Flow-log resource in NetworkWatcherRG
```

The endpoint monitoring paths are intentionally separate:

- Windows AMA uses a Windows DCR and sends `Microsoft-Event` and `Microsoft-Perf` to Log Analytics.
- Linux AMA uses a Linux DCR and sends `Microsoft-Syslog` to Log Analytics.
- Sysmon for Linux is collected through syslog.
- Azure Activity is configured at subscription scope.
- VNet Flow Logs are hosted under Network Watcher and use the lab storage account plus Traffic Analytics.

## Module Dependency Layers

```text
Layer 4: Cost Management
  └── Budget alert

Layer 3: Monitoring
  ├── sentinel.bicep ───────────────► log_analytics
  ├── vm_monitoring.bicep ──────────► Windows VM + log_analytics
  ├── linux_vm_monitoring.bicep ────► Linux VM + log_analytics
  └── network_monitoring.bicep ─────► VNet + storage + log_analytics

Layer 2: Compute
  ├── vm.bicep ─────────────────────► networking
  └── linux_vm.bicep ───────────────► networking

Layer 1: Foundation
  ├── networking.bicep
  ├── storage.bicep
  └── log_analytics.bicep
```

### Layer Rules

| Layer | Can Depend On | Examples |
|-------|---------------|----------|
| 1 | Nothing | VNet, storage, Log Analytics |
| 2 | Layer 1 | Windows/Linux VMs |
| 3 | Layers 1-2 | AMA, DCRs, Sentinel, flow logs |
| 4 | Layers 1-3 | Cost controls and alerting |

## Adding a New Module

### 1. Determine the layer

Ask: "What existing resources does this need?"
- Needs nothing → Layer 1
- Needs networking/storage → Layer 2
- Needs VM or workspace → Layer 3

### 2. Create the module

```
modules/
└── your_module.bicep
```

Standard module structure:
```bicep
// Layer N: Category - Description
// Dependencies: list what it needs

param location string
param namePrefix string
// ... other params

// Resources
resource myResource 'Microsoft.Something/resource@version' = {
  // ...
}

// Outputs (anything other modules or the user needs)
output resourceId string = myResource.id
```

### 3. Wire it up in main.bicep

```bicep
module yourModule 'modules/your_module.bicep' = {
  name: 'your-module-${resourceSuffix}'
  params: {
    location: location
    namePrefix: uniqueNamePrefix
    // Pass outputs from dependencies
    someDependency: otherModule.outputs.something
  }
}
```

### 4. Add outputs if needed

If the deployment script or users need values from your module, add them to the outputs section in `main.bicep`.

## Subscription-Scope Resources

Some resources must deploy at subscription scope. Azure Activity diagnostic settings are deployed by `main_subscription.bicep`; VNet Flow Logs are orchestrated separately through `modules/network_monitoring.bicep`, which targets `NetworkWatcherRG`.

Example: `network_monitoring.bicep` deploys to NetworkWatcherRG, so it's called as a separate subscription-level deployment in `adversary_lab_deploy.ps1`.

## Scripts Guidelines

Scripts in `/scripts` run on the deployed VM, not during infrastructure deployment.

### Script Organization
- `AdversaryLab-BlueTeam.ps1` owns Windows defensive tooling lifecycle with `-Action Install|Remove|Test`.
- `AdversaryLab-RedTeam.ps1` owns offensive-tool lifecycle with the same action model.
- `Install-SysmonLinux.sh` bootstraps Sysmon for Linux on the Ubuntu endpoint.

### Script Standards
- Include comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`, `.EXAMPLE`)
- Support `-WhatIf` for destructive operations
- Require admin: `#Requires -RunAsAdministrator`
- Use consistent status output functions

## Testing Changes

1. **Validate Bicep syntax:**
   ```powershell
   az bicep build --file main.bicep
   ```

2. **What-if deployment:**
   ```powershell
   New-AzResourceGroupDeployment -ResourceGroupName "test-rg" `
     -TemplateFile main.bicep -WhatIf
   ```

3. **Test in isolated subscription** before submitting PR

## Pull Request Checklist

- [ ] Module placed in correct layer
- [ ] Dependencies explicitly passed as parameters (not hardcoded)
- [ ] Outputs added for values other modules/users need
- [ ] README updated if user-facing behavior changes
- [ ] Tested deployment end-to-end