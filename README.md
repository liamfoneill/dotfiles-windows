# Pre-Reqs:

This script can be run on a vanilla Windows 10 or 11 machine but as it relies on Winget you need to install that manually first before you execute the script. WinGet is available from: https://www.microsoft.com/en-gb/p/app-installer/9nblggh4nns1?activetab=pivot:overviewtab

# Steps:

0. Go to the Windows Store and get the 'App Installer' app from Microsoft. Once installed open up a shell and run 'winget' to make sure it installed correctly and is on your PATH
1. Clone this repo into your user folder (even if you normally clone repos into a different folder like ~\Repositories).
2. Open a Powershell window as Administrator. Make sure the current working directory is the same as the repo you just cloned.
3. Run the install.ps1 script making sure to pass in parameters that make sense for you.
4. RELAX!

# Next Steps:

I have another repo at https://github.com/liamfoneill/dotfiles which you can also use to configure your WSL installation(s)

NOTE: If you have any trouble running the script use Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser