 # Azure CLI and Stratus Red Team Setup Script
# This script checks for Azure CLI, installs it if needed, downloads Stratus Red Team v2.21.0, and sets up Azure subscription

# Function to check if a command exists
function Test-CommandExists {
    param($command)
    try {
        if (Get-Command $command -ErrorAction Stop) {
            return $true
        }
    }
    catch {
        return $false
    }
}

# Function to install Azure CLI
function Install-AzureCLI {
    Write-Host "Azure CLI not found. Installing Azure CLI..." -ForegroundColor Yellow
    
    try {
        # Download and install Azure CLI using the official installer
        $installerUrl = "https://aka.ms/installazurecliwindows"
        $installerPath = "$env:TEMP\AzureCLI.msi"
        
        Write-Host "Downloading Azure CLI installer..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath
        
        Write-Host "Installing Azure CLI..." -ForegroundColor Yellow
        Start-Process msiexec.exe -Wait -ArgumentList "/I $installerPath /quiet"
        
        # Clean up installer
        Remove-Item $installerPath -Force
        
        # Refresh environment variables
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        
        Write-Host "Azure CLI installed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to install Azure CLI: $_"
        exit 1
    }
}

# Function to download and install Stratus Red Team
function Install-StratusRedTeam {
    Write-Host "Installing Stratus Red Team v2.21.0..." -ForegroundColor Yellow
    
    try {
        $stratusUrl = "https://github.com/datadog/stratus-red-team/releases/download/v2.21.0/stratus-red-team_Windows_x86_64.tar.gz"
        $downloadPath = "$env:TEMP\stratus-red-team_Windows_x86_64.tar.gz"
        $extractPath = "$env:TEMP\stratus-red-team"
        $installPath = "$env:LOCALAPPDATA\stratus-red-team"
        
        Write-Host "Downloading Stratus Red Team v2.21.0..." -ForegroundColor Blue
        Invoke-WebRequest -Uri $stratusUrl -OutFile $downloadPath
        
        # Extract tar.gz file (requires tar command available in Windows 10+)
        Write-Host "Extracting Stratus Red Team..." -ForegroundColor Blue
        if (Test-CommandExists "tar") {
            tar -xzf $downloadPath -C $env:TEMP
        } else {
            Write-Error "tar command not available. Please extract $downloadPath manually."
            return
        }
        
        # Create installation directory
        if (!(Test-Path $installPath)) {
            New-Item -ItemType Directory -Path $installPath -Force | Out-Null
        }
        
        # Move executable to installation directory
        $exePath = Get-ChildItem -Path $env:TEMP -Name "stratus*.exe" -Recurse | Select-Object -First 1
        if ($exePath) {
            $sourceFile = Join-Path $env:TEMP $exePath
            Copy-Item $sourceFile -Destination "$installPath\stratus.exe" -Force
            
            # Add to PATH if not already there
            $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
            if ($userPath -notlike "*$installPath*") {
                [System.Environment]::SetEnvironmentVariable("Path", "$userPath;$installPath", "User")
                $env:Path += ";$installPath"
            }
            
            Write-Host "Stratus Red Team installed to: $installPath" -ForegroundColor Green
        } else {
            Write-Error "Could not find stratus executable after extraction."
        }
        
        # Clean up
        Remove-Item $downloadPath -Force -ErrorAction SilentlyContinue
        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
        
    }
    catch {
        Write-Error "Failed to install Stratus Red Team: $_"
    }
}

# Function to set up Azure subscription ID
function Set-AzureSubscriptionID {
    Write-Host "`nSetting up Azure Subscription ID..." -ForegroundColor Yellow
    
    # Check if environment variable is already set
    if ($env:AZURE_SUBSCRIPTION_ID) {
        Write-Host "Current Azure Subscription ID: $env:AZURE_SUBSCRIPTION_ID" -ForegroundColor Green
        $response = Read-Host "Do you want to change it? (y/N)"
        if ($response -notmatch '^[Yy]') {
            return
        }
    }
    
    # Prompt user for subscription ID
    do {
        $subscriptionId = Read-Host "Please enter your Azure Subscription ID"
        if ($subscriptionId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            break
        } else {
            Write-Host "Invalid subscription ID format. Please enter a valid GUID." -ForegroundColor Red
        }
    } while ($true)
    
    # Set environment variable for current session
    $env:AZURE_SUBSCRIPTION_ID = $subscriptionId
    
    # Set environment variable permanently for user
    [System.Environment]::SetEnvironmentVariable("AZURE_SUBSCRIPTION_ID", $subscriptionId, "User")
    
    Write-Host "Azure Subscription ID set successfully: $subscriptionId" -ForegroundColor Green
}

# Main script execution
Write-Host "=== Azure CLI and Stratus Red Team Setup ===" -ForegroundColor Cyan
Write-Host ""

# Check for Azure CLI
Write-Host "Checking for Azure CLI..." -ForegroundColor Green
if (Test-CommandExists "az") {
    $azVersion = (az version --output tsv --query '"azure-cli"') 2>$null
    Write-Host "Azure CLI found: $azVersion" -ForegroundColor Green
} else {
    Install-AzureCLI
}

# Check for Stratus Red Team
Write-Host "`nChecking for Stratus Red Team..." -ForegroundColor Green
if (Test-CommandExists "stratus") {
    $stratusVersion = (stratus version) 2>$null
    Write-Host "Stratus Red Team found: $stratusVersion" -ForegroundColor Green
} else {
    Install-StratusRedTeam
}

# Set up Azure subscription ID
Set-AzureSubscriptionID

Write-Host "`n=== Setup Complete ===" -ForegroundColor Cyan
Write-Host "You can now use:" -ForegroundColor White
Write-Host "  - az (Azure CLI)" -ForegroundColor Gray
Write-Host "  - stratus (Stratus Red Team)" -ForegroundColor Gray
Write-Host "  - `$env:AZURE_SUBSCRIPTION_ID is set" -ForegroundColor Gray
Write-Host "WARNING: Please open a new shell to refresh your PATH variable." -ForegroundColor Red 
