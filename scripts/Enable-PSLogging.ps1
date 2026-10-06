 function Confirm-Administrator {
    [CmdletBinding()]
    param(
        [string]$Message = "This script requires Administrator privileges"
    )
    
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        
        if (-not $isAdmin) {
            Write-Host "[ERROR] $Message" -ForegroundColor Red
            Write-Host "[INFO] To fix this:" -ForegroundColor Yellow
            Write-Host "   1. Right-click PowerShell" -ForegroundColor Cyan
            Write-Host "   2. Select 'Run as Administrator'" -ForegroundColor Cyan
            Write-Host "   3. Re-run this script" -ForegroundColor Cyan
            
            # Optionally try to restart as admin
            $reply = Read-Host "Would you like to restart as Administrator? (y/n)"
            if ($reply -match '^[Yy]') {
                Start-Process powershell -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
            }
            
            exit 1
        }
        
        Write-Host "[OK] Administrator privileges confirmed" -ForegroundColor Green
        Write-Host "Enabling PowerShell Script Block Logging..." -ForegroundColor Green
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1

        Write-Host "Enabling PowerShell Module Logging for security modules..." -ForegroundColor Green
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1
        Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "Microsoft.PowerShell.Security" -Value "Microsoft.PowerShell.Security"

        Write-Host "PowerShell logging enabled. Settings will take effect for new PowerShell sessions." -ForegroundColor Yellow
    }
    catch {
        Write-Error "Failed to check administrator privileges: $($_.Exception.Message)"
        exit 1
    }
}

Confirm-Administrator 
