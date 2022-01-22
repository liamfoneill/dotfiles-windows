# Liam's Windows Dotfiles

Get a new Windows machine up and running in no time at all with all of the programs and tools you would need as a developer.


## Pre-Reqs:

Make sure you are able to run scripts by running this command in a PowerShell admin prompt 
```posh
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

## 5 Step Plan for Success:

1. Go to the Windows Store and get the 'App Installer' app from Microsoft. Once installed open up a shell and run ```winget --version``` to make sure it installed correctly and is on your PATH

2. Clone this repo into your user folder (even if you normally clone repos into a different folder like ~\Repositories). You can do this without needing GIT installed by running these PowerShell command in an admin window:

```posh
$url = "https://github.com/liamfoneill/dotfiles-windows/archive/main.zip"
$tempfile = "c:\dotfiles-windows.zip"
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($url, $tempfile)
expand-archive -LiteralPath $tempfile -DestinationPath "C:\Users\$env:USERNAME\"
rename-item -Path "C:\Users\$env:USERNAME\dotfiles-windows-main" -NewName ".dotfiles-windows"
remove-Item -Path $tempfile -Force
```
3. Open a Powershell window as Administrator. Make sure the current working directory is the same as the repo you just cloned. You can do that by running:
```
cd C:\Users\$env:USERNAME\.dotfiles-windows
```
4. Run the install.ps1 script making sure to pass in parameters that make sense for you. 
```
.\install.ps1
```

5. RELAX!

## Next Steps:

I have another repo at https://github.com/liamfoneill/dotfiles which you can also use to configure your Windows Subsystem for Linux (WSL) installation(s).
