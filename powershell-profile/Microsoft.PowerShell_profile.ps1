#$env:AZ_ENABLED = $true
$ENV:STARSHIP_CONFIG = "$HOME\.starship\starship.toml"
if ($PSVersionTable.PSVersion.Minor -gt 1) {
    Import-Module Az.Tools.Predictor
    Set-PSReadLineOption -PredictionSource Plugin
    Set-PSReadLineOption -PredictionViewStyle ListView
}
oh-my-posh --init --shell pwsh --config "C:\Users\Liam\Documents\PowerShell\liamfoneill.omp.json" | Invoke-Expression
Import-Module -Name Terminal-Icons
Import-Module -Name PSReadline

# The below modules slow down loading profile too much
#Import-Module -Name Az
#Import-Module -Name BurntToast
#Import-Module -Name Microsoft.PowerShell.SecretManagement
#Import-Module -Name Microsoft.PowerShell.SecretStore
#Import-Module -Name MicrosoftTeams
#Import-Module -Name Plaster
#Import-Module -Name posh-git
#Import-Module -Name PSWriteColor
#Import-Module -Name PSWriteHTML
#Import-Module -Name SHiPS
#Import-Module -Name Trackyon.Utils
#Import-Module -Name VSTeam
#Import-Module -Name AutomatedLab
