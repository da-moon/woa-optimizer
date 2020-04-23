Function DisableOneDrive {
	info "Disabling OneDrive..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" DWord 1
	success "Disabling OneDrive..."
}
Function UninstallOneDrive {
	info "Uninstalling OneDrive..."
	Stop-Process -Name OneDrive -ErrorAction SilentlyContinue
	Start-Sleep -s 3
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 3
	Stop-Process -Name explorer -ErrorAction SilentlyContinue
	Start-Sleep -s 3
	Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	success "Uninstalling OneDrive..."
}
Function UninstallBloat {
    info "Removing Windows Bloatware ..."
    info "Uninstalling default Microsoft applications..."
    foreach($app in $microsoft_apps_to_remove) {
        Safe-Uninstall "Microsoft.$app"
    }
    success "Uninstalling default Microsoft applications..."
    
    info "Uninstalling default third party applications..."
    foreach($app in $thirdparty_apps_to_remove) {
        Safe-Uninstall "$app"
    }
    success "Uninstalling default third party applications..."
    info "Disabling Xbox ..."
    # xbox ....
    Safe-Set-ItemProperty "HKCU:\System\GameConfigStore" "GameDVR_Enabled" DWord 0
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" DWord 0
    success "Disabling Xbox ..."
    success "Removing Windows Bloatware ..."
}
Function UninstallWindowsStore {
	info "Uninstalling Windows Store..."
	Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
	success "Uninstalling Windows Store..."
}
Function InstallWindowsStore {
	info "Installing Windows Store..."
	Get-AppxPackage -AllUsers "Microsoft.DesktopAppInstaller" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	Get-AppxPackage -AllUsers "Microsoft.WindowsStore" | ForEach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
	success "Installing Windows Store..."
}
Function DisableAdobeFlash {
	info "Disabling built-in Adobe Flash in IE and Edge..."
    Create-Path-If-Not-Exists "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons"
    Safe-Set-ItemProperty "HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Addons" "FlashPlayerEnabled" DWord 0
    Create-Path-If-Not-Exists "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}"
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Ext\Settings\{D27CDB6E-AE6D-11CF-96B8-444553540000}" "Flags" DWord 1
	success "Disabling built-in Adobe Flash in IE and Edge..."
}
Function UninstallMediaPlayer {
	info "Uninstalling Windows Media Player..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	success "Uninstalling Windows Media Player..."
}
# Install Windows Media Player
Function InstallMediaPlayer {
	info "Installing Windows Media Player..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
	success "Installing Windows Media Player..."
}
Function UninstallWorkFolders {
	info "Uninstalling Work Folders Client..."
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	success "Uninstalling Work Folders Client..."
}
Function InstallLinuxSubsystem {
    info "Installing Linux Subsystem..."
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowDevelopmentWithoutDevLicense" DWord 1
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" "AllowAllTrustedApps" DWord 1
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
    C:\windows\system32\wsl.exe --set-default-version 2
    $url="https://aka.ms/wsl-ubuntu-1804-arm"
    $dir=pwd
    $file="ubuntu.appx"
    aria2_dl "$url" "$dir" "$file"
    Add-AppxPackage"$dir\$file"
    success "Installing Linux Subsystem..."
}
Function AddPhotoViewerOpenWith {
	info "Adding Photo Viewer to `"Open with...`""
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\command" -Force | Out-Null
	New-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" -Force | Out-Null
    Safe-Set-ItemProperty "HKCR:\Applications\photoviewer.dll\shell\open" "MuiVerb" String "@photoviewer.dll,-3043"
    Safe-Set-ItemProperty "HKCR:\Applications\photoviewer.dll\shell\open\command" "(Default)"  ExpandString   "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1"
    Safe-Set-ItemProperty "HKCR:\Applications\photoviewer.dll\shell\open\DropTarget" "Clsid"  String "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}"
	info "Adding Photo Viewer to `"Open with...`""
}
Function DisableSearchAppInStore {
	info "Disabling search for app in store for unknown extensions..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith" DWord 1
	success "Disabling search for app in store for unknown extensions..."
}
Function EnableSearchAppInStore {
	info "Enabling search for app in store for unknown extensions..."
	Safe-Remove-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith"
	success "Enabling search for app in store for unknown extensions..."
}
Function DisableNewAppPrompt {
	info "Disabling 'How do you want to open this file?' prompt..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoNewAppAlert" DWord 1
	success "Disabling 'How do you want to open this file?' prompt..."
}
Function EnableNewAppPrompt {
	info "Enabling 'How do you want to open this file?' prompt..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "NoNewAppAlert" -ErrorAction SilentlyContinue
	success "Enabling 'How do you want to open this file?' prompt..."
}
Function DeleteTempFiles {
    info "Cleaning up temporary files..."
    $tempfolders = @("C:\Windows\Temp\*", "C:\Windows\Prefetch\*", "C:\Documents and Settings\*\Local Settings\temp\*", "C:\Users\*\Appdata\Local\Temp\*")
    Remove-Item $tempfolders -force -recurse 2>&1 | Out-Null
    success "Cleaning up temporary files..."
}
# Clean WinSXS folder (WARNING: this takes a while!)
Function CleanWinSXS {
    info "Cleaning WinSXS folder, this may take a while, please wait..."
    Dism.exe /online /Cleanup-Image /StartComponentCleanup
    success "Cleaning WinSXS folder, this may take a while, please wait..."
}
Function DownloadShutup10 {
    info "Downloading Shutup10 & putting it on C drive..."
    $url = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    $dir=pwd
    $file="Shutup10.exe"
    aria2_dl "$url" "$dir" "$file"
    success "Downloading Shutup10 & putting it on C drive..."
}
Function InstallScoop {
    info "Installing and conifiguring Scoop  ..."
    info "Installing Up Scoop ..."
    iwr -useb get.scoop.sh | iex
    success "Installing Up Scoop ..."
    info "Installing git ..."
    scoop install git
    success "Installing git ..."
    info "adding scoop extras bucket ..."
    scoop bucket add extras
    success "adding scoop extras bucket ..."
    success "Installing and conifiguring Scoop  ..."
}
function InstallScoopPackages{
    info "Installing Requested Software WIth Scoop ..."
    foreach($app in $scoop_software) {
        scoop install -s -a 32bit $app
    }
    success "Installing Requested Software WIth Scoop ..."
}
Function InstallChocolatey {
    info "Installing Up Chocolatey ..."
    iwr -useb https://chocolatey.org/install.ps1 | iex
    success "Installing Up Chocolatey ..."
}
Function DisableWindowsSearch {
	info "Stopping and disabling Windows Search Service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
	success "Stopping and disabling Windows Search Service..."
}
Function EnableWindowsSearch {
	info "Enabling and starting Windows Search Service..."
	Set-Service "WSearch" -StartupType Automatic
	Start-Service "WSearch" -WarningAction SilentlyContinue
	success "Enabling and starting Windows Search Service..."
}
Function DisableCompatibilityAppraiser {
	info "Stopping and disabling Microsoft Compatibility Appraiser..."
	info "Disable compattelrunner.exe launched by scheduled tasks..."
    'Microsoft Compatibility Appraiser',
    'ProgramDataUpdater' | ForEach-Object {
        Get-ScheduledTask -TaskName $_ -TaskPath '\Microsoft\Windows\Application Experience\' |
        Disable-ScheduledTask | Out-Null
    }
	success "Disable compattelrunner.exe launched by scheduled tasks..."
	info "Disable the Autologger session at the next computer restart"
    del C:\ProgramData\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl -ErrorAction SilentlyContinue
    Set-AutologgerConfig -Name 'AutoLogger-Diagtrack-Listener' -Start 0
	success "Disable the Autologger session at the next computer restart"
	success "Stopping and disabling Microsoft Compatibility Appraiser..."
}
Function DisableConnectedStandby {
    info "Disabling Connected Standby..."
    Safe-Set-ItemProperty "HKLM:\SYSTEM\\CurrentControlSet\Control\Power" "CSEnabled" DWord 0
    success "Disabling Connected Standby..."
}
Function EnableBigDesktopIcons {
    info "Enabling Big Desktop Icons..."
    Set-ItemProperty -path HKCU:\Software\Microsoft\Windows\Shell\Bags\1\Desktop -name IconSize -value 100
    success "Enabling Big Desktop Icons..."
}
Function RemoveUnneededComponents {
    info "Disabling Optional Feature..."
    foreach ($feature in $optional_features_to_remove) {
        info "Disabling: $feature"
        disable-windowsoptionalfeature -online -featureName $feature -NoRestart 
        success "Disabling: $feature"
    }
    success "Disabling Optional Feature..."
}
Function DisableGPDWinServices {
	info "Disabling extra services ..."
    $service="Spooler"
        if (Get-Service $service -ErrorAction SilentlyContinue)
        {
            info "Stopping and disabling $service"
            Stop-Service -Name $service
            Get-Service -Name $service | Set-Service -StartupType Disabled
        } else {
            warn "Skipping $service (does not exist)"
        }
	success "Disabling extra services ..."
}
