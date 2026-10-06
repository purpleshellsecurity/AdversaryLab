# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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