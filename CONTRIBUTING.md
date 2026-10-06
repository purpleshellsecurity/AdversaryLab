# Contributing to Adversary Lab

Thanks for your interest in contributing! This document covers the architecture and guidelines for making changes.

## Architecture Overview

The lab deploys across two Azure scopes using Bicep templates orchestrated by PowerShell.

```
adversary_lab_deploy.ps1          # Orchestrates everything
    │
    ├── main.bicep                # Resource Group scope
    │   └── modules/*.bicep
    │
    └── main_subscription.bicep   # Subscription scope (Activity logs, RBAC)
        └── modules/network_monitoring.bicep  # Flow logs (NetworkWatcherRG)
```

## Module Dependency Layers

Modules are organized in layers based on their dependencies. This determines deployment order and helps identify where new modules should go.

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Cost Management                                    │
│   └── Budget alerts (conditional on email parameter)        │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Monitoring                                         │
│   ├── sentinel.bicep ──────────────► log_analytics          │
│   ├── vm_monitoring.bicep ─────────► vm, log_analytics      │
│   └── network_monitoring.bicep ────► networking, storage,   │
│                                      log_analytics          │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Compute                                            │
│   └── vm.bicep ────────────────────► networking             │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: Foundation (no dependencies - deploy in parallel)  │
│   ├── networking.bicep                                      │
│   ├── storage.bicep                                         │
│   └── log_analytics.bicep                                   │
└─────────────────────────────────────────────────────────────┘
```

### Layer Rules

| Layer | Can Depend On | Examples |
|-------|---------------|----------|
| 1 | Nothing | VNet, storage accounts, Log Analytics |
| 2 | Layer 1 | VMs, App Services (need networking) |
| 3 | Layers 1-2 | Monitoring, extensions (need compute + destinations) |
| 4 | Layers 1-3 | Cost controls, alerting (need resources to monitor) |

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

Some resources must deploy at subscription scope (Activity logs, role assignments, NetworkWatcherRG resources). These go in `main_subscription.bicep` or are called separately from the PowerShell script.

Example: `network_monitoring.bicep` deploys to NetworkWatcherRG, so it's called as a separate subscription-level deployment in `adversary_lab_deploy.ps1`.

## Scripts Guidelines

Scripts in `/scripts` run on the deployed VM, not during infrastructure deployment.

### Naming Convention
- `Install-*.ps1` - Installs tools/configurations
- `Uninstall-*.ps1` - Removes tools/configurations (should mirror Install)

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