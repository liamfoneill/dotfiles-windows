[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "A name from 3 to 15 characters for your Windows PC.")]
    [ValidateLength(3, 15)]
    [string]$ComputerName = "liam-desktop",


    [Parameter(HelpMessage = "A list of linux distributions you wish to enable")]
    [ValidateSet("Ubuntu", "Debian", "kali-linux", "openSUSE-42", "SLES-12", "Ubuntu-16.04", "Ubuntu-18.04", "Ubuntu-20.04")]
    [string[]]$WSLDistributions = @("Ubuntu", "Debian"),
    
    [Parameter(HelpMessage = "Install Packages?")]
    [switch]$InstallPackages,

    [Parameter(HelpMessage = "Path to Winget Import JSON file")]
    [string]$WingetImportFile = ".\winget-packages\winget-common.json",

    [Parameter(HelpMessage= "Computer Type - acceptable values are 'Physical' or 'Virtual'")]
    [ValidateSet("Physical", "Virtual")]
    [string]$ComputerType = "Physical"

)

Write-Host "Checking for elevated permissions..."
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
    Break
}
else {
    Write-Host "Code is running as administrator, go on executing the script..." -ForegroundColor "Green"
}

Write-Host "Configuring System..." -ForegroundColor "Yellow"
Write-Host "Setting PC name to $ComputerName" -ForegroundColor "Yellow"
Rename-Computer -NewName $ComputerName

if ($ComputerName -eq "Physical") {
    Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart

    if (!(Test-Path -Path 'V:\Virtual Hard Disks')) { 
        New-Item -ItemType Directory -Path 'V:\Virtual Hard Disks' -Force
        Set-VMHost -VirtualHardDiskPath 'V:\Virtual Hard Disks'
    }

    if (!(Test-Path -Path 'V:\Virtual Machines')) { 
        New-Item -ItemType Directory -Path 'V:\Virtual Machines' -Force
        Set-VMHost -VirtualMachinePath 'V:\Virtual Machines'
    }
}

###############################################################################
### Developer Settings                                                        #
###############################################################################
Write-Host "Enabling Developer Mode..." -ForegroundColor "Yellow"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowDevelopmentWithoutDevLicense" /d "1"

# Explorer: Show hidden files by default: Show Files: 1, Hide Files: 2
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1

# Explorer: Show file extensions by default Show Extensions: 0 Hide Extensions: 1
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0

# Explorer: Show path in title bar: Hide Path: 0 Show Path: 1 
Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" "FullPath" 1

# Create a folder for source code
if (!(Test-Path -Path '~\Repositories')) { 
    New-Item -ItemType Directory -Path '~\Repositories' -Force 
}

.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\Pictures"
.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\Videos"
.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\Repositories"
.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\Documents"
.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\Downloads"
.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\Desktop"
.\powershell-helper-scripts\Set-QuickAccess.ps1 -Action "Pin" -Path "c:\Users\$env:USERNAME\"

#Clean Up Desktop
Remove-Item -path ~\Desktop -include *.lnk -Recurse

###############################################################################
### SSH Settings                                                        #
###############################################################################
# Create a folder for .ssh
if (!(Test-Path -Path "C:\Users\$env:USERNAME\.ssh")) { 
    New-Item -ItemType Directory -Path "C:\Users\$env:USERNAME\.ssh" -Force 
}

# Create SSH Key
& "ssh-keygen" -t ed25519  -f "C:\Users\$env:USERNAME\.ssh\ed25519" -C $ComputerName -q -N '""'

# Setup Windows Service for SSH Agent
Get-Service ssh-agent | Set-Service -StartupType Automatic -PassThru | Start-Service
# & "start-ssh-agent.cmd"


###############################################################################
### Windows Subsystem for Linux                                               #
###############################################################################
Write-Host "Enable Hyper-V" -ForegroundColor "Yellow"
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All -NoRestart

Write-Host "Enable Windows Subsystem for Linux" -ForegroundColor "Yellow"
Write-Host "Setting WSL Default Distribution to 2..." -ForegroundColor "Yellow"
& "wsl" --set-default-version 2

Write-Host "Updating WSL (only if there are updates available)" -ForegroundColor "Yellow"
& "wsl" --update

Write-Host "Installing WSL Distribtion(s)" -ForegroundColor "Yellow"
foreach ($WSLDistribution in $WSLDistributions) {
    Write-Host "Enabling $WSLDistribution..." -ForegroundColor "Yellow"
    & "wsl" --install --distribution $WSLDistribution
}

###############################################################################
### Software Installation                                                     #
###############################################################################

if ($InstallPackages) {
Write-Host "Installing Chocolately..." -ForegroundColor "Yellow"
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
Set-ExecutionPolicy Unrestricted -Scope Process -Force
choco feature enable -n allowGlobalConfirmation

& "choco" install cascadiacode terraform starship #These packages are unfortunately still not on Winget as Winget

Write-Host "Importing Winget Packages..." -ForegroundColor "Yellow"
& "winget" import --import-file $WingetImportFile --accept-package-agreements --accept-source-agreements

# DAPR
powershell -Command "iwr -useb https://raw.githubusercontent.com/dapr/cli/master/install/install.ps1 | iex"
}
###############################################################################
### Default Windows Applications                                              #
###############################################################################

# Uninstall Bing News
Get-AppxPackage "Microsoft.BingNews" -AllUsers | Remove-AppxPackage
Get-AppXProvisionedPackage -Online | Where-Object DisplayName -like "Microsoft.BingNews" | Remove-AppxProvisionedPackage -Online

# Uninstall Microsoft Teams (Personal)
Get-AppxPackage "MicrosoftTeams" -AllUsers | Remove-AppxPackage
Get-AppXProvisionedPackage -Online | Where-Object DisplayName -like "MicrosoftTeams" | Remove-AppxProvisionedPackage -Online

# Uninstall Solitaire
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" -AllUsers | Remove-AppxPackage
Get-AppXProvisionedPackage -Online | Where-Object DisplayName -like "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxProvisionedPackage -Online

# Uninstall Groove (Formerly Zune) Music 
Get-AppxPackage "Microsoft.ZuneMusic" -AllUsers | Remove-AppxPackage
Get-AppXProvisionedPackage -Online | Where-Object DisplayName -like "Microsoft.ZuneMusic" | Remove-AppxProvisionedPackage -Online

# Prevent "Suggested Applications" from returning
if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent")) { New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Type Folder | Out-Null }
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

###############################################################################
### Windows Update & Application Updates                                      #
###############################################################################
Write-Host "Configuring Windows Update..." -ForegroundColor "Yellow"

# Ensure Windows Update registry paths
if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate")) { New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" -Type Folder | Out-Null }
if (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU")) { New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -Type Folder | Out-Null }

# Enable Automatic Updates
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0

# Configure to Auto-Download but not Install: NotConfigured: 0, Disabled: 1, NotifyBeforeDownload: 2, NotifyBeforeInstall: 3, ScheduledInstall: 4
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 3

# Include Recommended Updates
Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "IncludeRecommendedUpdates" 1

# Opt-In to Microsoft Update
$MU = New-Object -ComObject Microsoft.Update.ServiceManager -Strict
$MU.AddService2("7971f918-a847-4430-9279-4a52d1efe18d", 7, "") | Out-Null
Remove-Variable MU

# Copy Windows Terminal Settings
Copy-Item -Path ".\windows-terminal\settings.json" -Destination "C:\Users\$env:UserName\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json" 

# Create PowerShell Profile Symlink
New-Item -ItemType SymbolicLink -Path "C:\Users\$env:USERNAME\Documents\PowerShell\Microsoft.PowerShell_profile.ps1" -Target "C:\Users\$env:USERNAME\.dotfiles-windows\powershell-profile\Microsoft.PowerShell_profile.ps1" 

# Create Personal Profile for Edge
profilePath = "profile-personal"
Start-Process -FilePath "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "--profile-directory=$profilePath --no-first-run --no-default-browser-check"

# Create Work Profile for Edge
profilePath = "profile-work"
Start-Process -FilePath "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ArgumentList "--profile-directory=$profilePath --no-first-run --no-default-browser-check"

# Starship Configuration
New-Item -Path '~\' -ItemType Directory -Name '.starship'
New-Item -ItemType SymbolicLink -Path "C:\Users\$env:USERNAME\.starship\starship.toml" -Target "C:\Users\$env:USERNAME\.dotfiles-windows\starship.toml" 

# Log Into Github
gh auth login

# Log in to Azure CLI
az login

### MANUAL TASKS ###
<#
I should be creating Symlinks rather than copying items!!

Install Visio x64
Install MS Project x64
Log into Cloud Shell
Create Unix User(s)
Move-Location of Videos Folder to .\OneDrive
Move-location of Pictures Folder to .\OneDrive
Set Visual Studio to open blank project by default
Change Visual Studio save folder to be ~\Repositories
Add git.ico Logo to ~\Repositories folder
Configure OneDrive + OneDrive for Business
Disable Recycle Bin Icon
Remove suggested items from Quick Access
Install Post-Git, oh-my-posh etc on PowerShell 7
#>
