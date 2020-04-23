Function SetUACLow {
    info "Lowering UAC level..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Safe-Set-ItemProperty "$path"  "ConsentPromptBehaviorAdmin"  DWord  0
    Safe-Set-ItemProperty "$path"  "PromptOnSecureDesktop"  DWord  0
    success "Lowering UAC level..."
}
Function DisableAdminShares {
	info "Disabling implicit administrative shares..."
    $path="HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    Safe-Set-ItemProperty "$path"  "AutoShareWks"  DWord  0
	success "Disabling implicit administrative shares..."
}
Function EnableCtrldFolderAccess {
	info "Enabling Controlled Folder Access..."
	Set-MpPreference -EnableControlledFolderAccess Enabled
	success "Enabling Controlled Folder Access..."
}
Function DisableFirewall {
	info "Disabling Firewall..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"  "EnableFirewall"  DWord  0
	success "Disabling Firewall..."
}
Function EnableFirewall {
	info "Enabling Firewall..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile" -Name "EnableFirewall" -ErrorAction SilentlyContinue
	success "Enabling Firewall..."
}
Function DisableDefender {
	info "Disabling Windows Defender..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"  "DisableAntiSpyware"  DWord  1
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	success "Disabling Windows Defender..."
}
Function DisableDefenderCloud {
    info "Disabling Windows Defender Cloud..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"  "SpynetReporting"  DWord  0
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet"  "SubmitSamplesConsent"  DWord  2
    success "Disabling Windows Defender Cloud..."
}
Function DisableUpdateMSRT {
	info "Disabling Malicious Software Removal Tool offering..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\MRT"  "DontOfferThroughWUAU"  DWord  1
	success "Disabling Malicious Software Removal Tool offering..."
}
Function DisableUpdateDriver {
    info "Disabling driver offering through Windows Update..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching"
    Safe-Set-ItemProperty "$path"  "SearchOrderConfig"  DWord  0
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"  "ExcludeWUDriversInQualityUpdate"  DWord  1
	success "Disabling driver offering through Windows Update..."
}
Function DisableUpdateRestart {
	info "Disabling Windows Update automatic restart..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"  "NoAutoRebootWithLoggedOnUsers"  DWord  1
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"  "AUPowerManagement"  DWord  0
	success "Disabling Windows Update automatic restart..."
}
Function DisableSharedExperiences {
    info "Disabling Shared Experiences..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDP"
    Safe-Set-ItemProperty "$path"  "RomeSdkChannelUserAuthzPolicy"  DWord  0
    success "Disabling Shared Experiences..."
}
Function DisableRemoteAssistance {
    info "Disabling Remote Assistance..."
    $path="HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
    Safe-Set-ItemProperty "$path"  "fAllowToGetHelp"  DWord  0
    success "Disabling Remote Assistance..."
}
Function DisableAutoplay {
    info "Disabling Autoplay..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
    Safe-Set-ItemProperty "$path"  "DisableAutoplay"  DWord  1
    success "Disabling Autoplay..."
}
Function EnableRemoteDesktop {
    info "Enabling Remote Desktop w/o Network Level Authentication..."
    $paths = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' = 'fDenyTSConnections'
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' = 'UserAuthentication'
    }
    $paths.GetEnumerator() | ForEach-Object {
        $path=$_.Key
        Safe-Set-ItemProperty "$path"  $_.Value  DWord  0
    }
    success "Enabling Remote Desktop w/o Network Level Authentication..."
}
Function DisableRemoteDesktop {
    info "Disabling Remote Desktop..."
    $paths = @{
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' = 'fDenyTSConnections'
        'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' = 'UserAuthentication'
    }
    $paths.GetEnumerator() | ForEach-Object {
        $path=$_.Key
        Safe-Set-ItemProperty "$path"  $_.Value  DWord  1
    }
    success "Disabling Remote Desktop..."
}
Function EnableStorageSense {
    info "Enabling Storage Sense..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
    Safe-Set-ItemProperty "$path"  "01"  DWord  1 
    success "Enabling Storage Sense..."
}
Function DisableStorageSense {
	info "Disabling Storage Sense..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy"
    Safe-Set-ItemProperty "$path"  "01"  DWord  0 
	success "Disabling Storage Sense..."
}
Function DisableDefragmentation {
	info "Disabling scheduled defragmentation..."
	Disable-ScheduledTask -TaskName "\Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
	success "Disabling scheduled defragmentation..."
}
Function DisableSuperfetch {
	info "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled
	success "Stopping and disabling Superfetch service..."
}
Function DisableIndexing {
	info "Stopping and disabling Windows Search indexing service..."
	Stop-Service "WSearch" -WarningAction SilentlyContinue
	Set-Service "WSearch" -StartupType Disabled
	success "Stopping and disabling Windows Search indexing service..."
}
Function SetBIOSTimeLocal {
	info "Setting BIOS time to Local time..."
    $path="HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    If (Test-Path "$path") {
        Remove-ItemProperty -Path "$path" -Name "RealTimeIsUniversal" -ErrorAction SilentlyContinue
    }
	success "Setting BIOS time to Local time..."
}
Function SetBIOSTimeUTC {
    info "Setting BIOS time to UTC..."
    $path="HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation"
    Safe-Set-ItemProperty "$path"  "RealTimeIsUniversal"  DWord  1
    success "Setting BIOS time to UTC..."
}
Function DisableHibernation {
    info "Disabling Hibernation..."
    $path="HKLM:\System\CurrentControlSet\Control\Session Manager\Power"
    Safe-Set-ItemProperty "$path"  "HibernteEnabled"  Dword  0
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"  "ShowHibernateOption"  Dword  0
    Start-Process 'powercfg.exe' -Verb runAs -ArgumentList '/h off'
    success "Disabling Hibernation..."
}
Function DisableFastStartup {
    info "Disabling Fast Startup..."
    $path="HKLM:\System\CurrentControlSet\Control\Session Manager\Power"
    Safe-Set-ItemProperty "$path" "HiberbootEnabled"  DWord  0
    success "Disabling Fast Startup..."
}
Function DisableExtraServices {
	info "Disabling extra services ..."
    foreach ($service in $services_to_disable) {
        if (Get-Service $service -ErrorAction SilentlyContinue)
        {
            info "Stopping and disabling $service"
            Stop-Service -Name $service
            Get-Service -Name $service | Set-Service -StartupType Disabled
        } else {
            warn "Skipping $service (does not exist)"
        }
    }
	success "Disabling extra services ..."
}
Function DisableAutorun {
	info "Disabling Autorun for all drives..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"  "NoDriveTypeAutoRun"  DWord  255
	success "Disabling Autorun for all drives..."
}
