# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Components declare their prerequisites** - `Requires` entries in the component table let `-Action Test` and `-WhatIf` report `skip (needs choco (from Chocolatey))` instead of a bare `absent`. The check probes the capability (is git on PATH?) rather than the providing component's completeness, so a git or Python installed by other means is not reported as blocked. Reporting only: the checks inside each Install remain the real gate.
- **`-Yes` switch** - skips the confirmation prompt without changing any other behaviour. `-Force` also skips it but additionally reinstalls present components and removes ones that pre-dated the script, so unattended runs previously had no way to opt out of the destructive semantics.
- **`-Action Test` verb** - Both tooling scripts can now report whether components are configured *and* whether events are actually being produced, without changing anything. Exits `2` when unhealthy so automation can gate on it.
- **Install manifests** - `C:\ProgramData\AdversaryLab\{blue,red}team-state.json` record what each install actually changed. `-Action Remove` reverses only those changes, restoring prior audit settings and registry values instead of guessing at Windows defaults.
- **Deploy-time telemetry verification** - `adversary_lab_deploy.ps1` now verifies both halves of the pipeline before declaring success: it probes the guest for a running Azure Monitor Agent and waits for a real `Heartbeat` row, and it waits for a real `AzureActivity` row from the subscription diagnostic setting. Both waits share one time budget. Opt out with `-SkipTelemetryCheck`; tune with `-TelemetryTimeoutMinutes`.
- **Plan mode** - `-WhatIf` renders the intended per-component change set before gating every mutation.

### Changed
- **Module installs use `Install-PSResource`** - `AdversaryLab-RedTeam.ps1` now installs PowerShell modules through PSResourceGet (bootstrapping it when absent, falling back to `Install-Module` if that fails). `Az` pulls 102 dependent modules and `Microsoft.Graph` another 39, and PowerShellGet v2 resolved all 141 serially behind a progress bar that `$ProgressPreference` could not suppress, because PackageManagement writes it from a child runspace. The `Az` and `Microsoft.Graph` meta-modules are kept rather than swapped for sub-modules: MicroBurst gates its whole Az function set on `Get-InstalledModule -Name Az`, which matches only the meta-module.
- **Retired modules are opt-in** - `AzureADPreview` and `MSOnline` are skipped unless `-IncludeRetired` is passed. Azure AD Graph is decommissioned, so installing them by default spent minutes on cmdlets that fail at runtime; the script already printed a warning saying so.
- **Blue/Red team scripts merged** - `Install-*`/`Uninstall-*` pairs replaced by `AdversaryLab-BlueTeam.ps1` and `AdversaryLab-RedTeam.ps1`, each with `-Action Install|Remove|Test`. Components declare Test/Install/Remove once in a table; the three verbs are three walks over it, so they cannot drift apart. Red team's Remove walks the table in reverse.
- **Credentials are saved immediately after the VM is created**, not after every subsequent deployment step. Previously a failure in the activity-log, flow-log or budget step lost an auto-generated password permanently, along with access to a VM that was already running.
- **AzureHound is added to the machine PATH** - previously only `$env:Path` was modified, so it was never actually available after a restart despite the installer claiming otherwise.
- **TLS 1.2 is set before the first PSGallery call** rather than midway through installation.
- **CI lint rules tightened** - `PSShouldProcess`, `PSUseShouldProcessForStateChangingFunctions` and `PSUseApprovedVerbs` are now enforced; per-function exceptions use targeted `[SuppressMessageAttribute]` with justifications.

### Fixed
- **`-Action Remove` deleted an AzureHound it never installed.** Every other component records whether it found the thing already present and leaves it alone on removal; `Install-AzureHoundComponent` returned early without writing state, and `Remove-AzureHoundComponent` deleted the directory unconditionally. It now records `PreExisting`, and removal leaves alone anything with no manifest entry or one marked pre-existing unless `-Force` is passed.
- **The credentials file recorded only the first character of the password** when deploying from macOS or Linux. `Save-CredentialsToFile` decrypted the SecureString with `Marshal::PtrToStringAuto`, which resolves to the ANSI marshaller on .NET Core and stops at the first NUL byte of the UTF-16LE buffer `SecureStringToBSTR` returns. An auto-generated password was therefore unrecoverable, requiring a VMAccess password reset to get into a VM that was already running. Now uses `PtrToStringBSTR`, and frees the buffer with `ZeroFreeBSTR` instead of leaving the plaintext in unmanaged memory.
- **`-Force` was silently ignored** when Sysmon was already running. `if (Test-SysmonRunning -and -not $Force)` binds `-and`/`-not` as arguments to the function and discards the check, so Sysmon could never be reinstalled or reconfigured in place.
- **`-WhatIf` was advertised but not honored** by either installer. Both declared `SupportsShouldProcess` with zero `ShouldProcess` calls, so `-WhatIf` installed a kernel driver and rewrote audit policy while appearing to preview. The blue-team uninstaller also deleted Sysmon driver files outside its `ShouldProcess` guard.
- **`Install-BlueTeamTools` could not run unattended** - the confirmation prompt was not gated by `-Force`, which blocked Custom Script Extension and `Invoke-AzVMRunCommand` use.
- **Array unrolling under StrictMode** - `return @()` unrolls to `$null`, so `.Count` threw and broke `-Action Remove` whenever no state file existed.
- **Remove-then-reinstall deadlock** - a removed-but-locked `Sysmon64.exe` blocked reinstall and aborted the whole run. The existing binary is now reused and its queued reboot-deletion cancelled.
- **One failing component no longer aborts the others** - components are independent; failures are collected and surfaced in the exit code.
- **Elevation used a hardcoded `pwsh.exe`** that does not exist on a fresh Windows 11 image. Now uses the running host.
- **Azure Monitor Agent detection** - AMA does not always register a Windows service; a service-only probe reported a false negative on a healthy agent. Now checks service, processes and extension package, and distinguishes "running" from "installed but not running".
- **Profile and shortcuts targeted the SYSTEM account** under Custom Script Extension / `Invoke-AzVMRunCommand`. `$env:USERPROFILE` resolves to `C:\Windows\system32\config\systemprofile` and `GetFolderPath('Desktop')` returns an empty string, so the install reported success while the interactive admin got nothing. Profiles now target the machine-wide AllUsersAllHosts locations and shortcuts fall back to the all-users desktop.
- **`Test` used a stale PATH** - a freshly spawned host inherits the PATH from whatever started it, so `pip` installed moments earlier appeared missing. The environment is now refreshed before any probe.
- **Nested-array returns** - the `return , @(...)` idiom keeps the array wrapped, so `@(f).Count` returned 1 regardless of contents. This made `-Action Remove` iterate over a single array object instead of each item, and made the empty case report 1 rather than 0.
- **Uninstall no longer removes software it did not install** - `-KeepPython`/`-KeepGit` are unnecessary; pre-existing git, Python and Defender exclusions are left alone.

### Fixed
- **Resource names depended on the deployment name.** `resourceSuffix` was seeded on `uniqueString(resourceGroup().id, deployment().name)`, so deploying the same template under a different deployment name produced an entirely new set of resources rather than updating the existing ones. Confirmed with `what-if` against a live lab: a redeploy proposed creating a parallel VM, VNet, workspace and NIC alongside the running ones. The suffix is now a stable hash of the resource group id, exposed as an overridable `resourceSuffix` parameter (and `-ResourceSuffix` on the deploy script) so an existing deployment can be adopted.
- **NIC and OS disk are now deleted with the VM** (`deleteOption: 'Delete'`). Previously both were orphaned on teardown and kept billing.

### Changed
- **Tags are applied to every resource that supports them**, driven by a single `tags` parameter threaded through all modules. The README advertised Environment/Project/Purpose tagging; only the storage account actually carried tags.
- **`sentinel.bicep` rewritten as a data-driven loop** - 12 near-identical resource blocks became one array plus one resource loop (253 lines to 151). Adding a solution is now a one-line change.

### Removed
- `modules/vm_ama.bicep` and `modules/vm_data_collection.bicep` - unreferenced duplicates of `vm.bicep` and `vm_monitoring.bicep` that CI kept compiling while they drifted. `vm_ama.bicep` additionally enabled an unencrypted WinRM HTTP listener that the live template does not.

### Security
- **Removed the subscription-scoped Contributor grant** to the VM's system-assigned managed identity. Combined with internet-facing RDP, a Defender exclusion, and preinstalled offensive tooling, any code execution on the lab VM became subscription Contributor via a single `Connect-AzAccount -Identity`. The identity is still enabled; it simply holds no role assignments. Attack simulations that need Azure permissions should be granted an explicit, scoped role.

### Removed
- `Install-BlueTeamTools.ps1`, `Uninstall-BlueTeamTools.ps1`, `Install-RedTeamTools.ps1`, `Uninstall-RedTeamTools.ps1` - superseded by the merged scripts.

## [2.0.0] - 2025-12-28

### Added
- **Automated VNet Flow Logs** - Flow logs now deploy automatically via `network_monitoring.bicep` (previously required manual portal configuration)
- **Storage module** - New `storage.bicep` for flow log storage account
- **Blue Team Tools installer** - `Install-BlueTeamTools.ps1` combines Sysmon, PowerShell logging, and Windows audit policies into a single configurable script
- **Red Team Tools installer** - `Install-RedTeamTools.ps1` installs Azure/Entra ID security assessment tools (AADInternals, GraphRunner, AzureHound, etc.)
- **Uninstall scripts** - `Uninstall-BlueTeamTools.ps1` and `Uninstall-RedTeamTools.ps1` for clean removal
- **CONTRIBUTING.md** - Architecture documentation and contributor guidelines
- **CHANGELOG.md** - Version history tracking

### Changed
- **Module reorganization** - All Bicep modules moved to `modules/` directory with clear separation of concerns
- **VM size** - Updated default from `Standard_D2s_v3` to `Standard_D2s_v4`
- **README overhaul** - Cleaner structure, GitHub alert callouts, removed redundant sections
- **Scripts consolidated** - Individual scripts (`Enable-PSLogging.ps1`, `Install-Sysmon.ps1`) replaced by unified BlueTeam/RedTeam installers

### Removed
- **Stratus Red Team** - Removed from deployment and documentation
- **Manual flow log setup** - No longer needed (now automated)
- **Individual setup scripts** - Replaced by consolidated installers

### Fixed
- Network Watcher creation now handled automatically before flow log deployment

## [1.0.0] - 2025-07-29

### Added
- Initial release
- Windows 11 Pro VM with Azure Monitor Agent
- Microsoft Sentinel with 12+ security solutions
- Log Analytics Workspace
- Data Collection Rules for VM monitoring
- Azure Activity Logs integration
- Network Security Groups with RDP restriction
- Auto-shutdown scheduling
- Budget alerts
- Manual setup scripts for Sysmon, PowerShell logging, and Stratus Red Team