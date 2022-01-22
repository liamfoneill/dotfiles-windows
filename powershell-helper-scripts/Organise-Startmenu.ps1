    $paths = @("C:\ProgramData\Microsoft\Windows\Start Menu\Programs", "~\AppData\Roaming\Microsoft\Windows\Start Menu\Programs")
    ForEach($path in $paths){
        $Rootfolder = Get-ChildItem $path -Directory
        # The following loop flattens all subfolders and places them at the root directories defined above
        ForEach($folder in $Rootfolder)
        {
            $shortcut = Get-ChildItem $folder.fullname -Recurse -File
            Move-Item -Path $shortcut.FullName -Destination $path -Force
            Remove-Item $folder.FullName -Force -Recurse
        }
    }






