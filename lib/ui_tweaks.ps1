Function DisableLockScreen {
	info "Disabling Lock screen..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Safe-Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen" DWord 1
	success "Disabling Lock screen..."
}
Function EnableLockScreen {
    info "Enabling Lock screen..."
    $path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    Safe-Remove-ItemProperty "$path" "NoLockScreen"
    success "Enabling Lock screen..."
}
Function DisableLockScreenRS1 {
	info "Disabling Lock screen using scheduler workaround..."
	$service = New-Object -com Schedule.Service
	$service.Connect()
	$task = $service.NewTask(0)
	$task.Settings.DisallowStartIfOnBatteries = $false
	$trigger = $task.Triggers.Create(9)
	$trigger = $task.Triggers.Create(11)
	$trigger.StateChange = 8
	$action = $task.Actions.Create(0)
	$action.Path = "reg.exe"
	$action.Arguments = "add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData /t REG_DWORD /v AllowLockScreen /d 0 /f"
	$service.GetFolder("\").RegisterTaskDefinition("Disable LockScreen", $task, 6, "NT AUTHORITY\SYSTEM", $null, 4) | Out-Null
	success "Disabling Lock screen using scheduler workaround..."
}
Function EnableLockScreenRS1 {
	info "Enabling Lock screen (removing scheduler workaround)..."
	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
	success "Enabling Lock screen (removing scheduler workaround)..."
}
Function HideShutdownFromLockScreen {
    info "Hiding shutdown options from Lock Screen..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Safe-Set-ItemProperty "$path" "ShutdownWithoutLogon" DWord 0
    success "Hiding shutdown options from Lock Screen..."
}
Function ShowShutdownOnLockScreen {
    info "Showing shutdown options on Lock Screen..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Safe-Set-ItemProperty "$path" "ShutdownWithoutLogon" DWord 1
    success "Showing shutdown options on Lock Screen..."
}
Function DisableStickyKeys {
    info "Disabling Sticky keys prompt..."
    $path="HKCU:\Control Panel\Accessibility\StickyKeys"
    Safe-Set-ItemProperty "$path" "Flags" String "506"
    success "Disabling Sticky keys prompt..."
}
Function EnableStickyKeys {
    info "Enabling Sticky keys prompt..."
    $path="HKCU:\Control Panel\Accessibility\StickyKeys"
    Safe-Set-ItemProperty "$path" "Flags" String "510"
    success "Enabling Sticky keys prompt..."
}
Function HideTaskbarSearchBox {
    info "Hiding Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    Safe-Set-ItemProperty "$path" "SearchboxTaskbarMode" DWord 0
    success "Hiding Taskbar Search box / button..."
}
Function ShowTaskbarSearchBox {
    info "Showing Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    Safe-Remove-ItemProperty "$path" "SearchboxTaskbarMode"
    success "Showing Taskbar Search box / button..."
}
Function HideTaskView {
    info "Hiding Task View button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "ShowTaskViewButton" DWord 0
    success "Hiding Task View button..."
}
Function ShowTaskView {
    info "Showing Task View button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Remove-ItemProperty "$path" "ShowTaskViewButton"
    success "Showing Task View button..."
}
Function ShowSmallTaskbarIcons {
    info "Showing small icons in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "TaskbarSmallIcons" DWord 1
    success "Showing small icons in taskbar..."
}
Function ShowLargeTaskbarIcons {
    info "Showing large icons in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Remove-ItemProperty "$path" "TaskbarSmallIcons"
    success "Showing large icons in taskbar..."
}
Function ShowTaskbarTitles {
    info "Showing titles in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "TaskbarGlomLevel" DWord 1
    success "Showing titles in taskbar..."
}
Function HideTaskbarTitles {
    info "Hiding titles in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Remove-ItemProperty "$path" "TaskbarGlomLevel"
    success "Hiding titles in taskbar..."
}
Function ShowTaskManagerDetails {
	info "Showing task manager details..."
    Create-Path-If-Not-Exists "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager"
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If (!($preferences)) {
		$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
		While (!($preferences)) {
			Start-Sleep -m 250
			$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
		}
		Stop-Process $taskmgr
	}
	$preferences.Preferences[28] = 0
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences" Binary $preferences.Preferences
	success "Showing task manager details..."
}
Function HideTaskManagerDetails {
	info "Hiding task manager details..."
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If ($preferences) {
		$preferences.Preferences[28] = 1
        Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" "Preferences" Binary $preferences.Preferences
	}
	success "Hiding task manager details..."
}
Function ShowFileOperationsDetails {
	info "Showing file operations details..."
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    Safe-Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" "EnthusiastMode" DWord 1
	success "Showing file operations details..."
}
Function HideFileOperationsDetails {
    info "Hiding file operations details..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    Safe-Remove-ItemProperty "$path" "EnthusiastMode"
    success "Hiding file operations details..."
}
Function Hide3DObjectsFromThisPC {
    info "Hiding 3D Objects icon from This PC..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    # If (Test-Path "$path") {
        Remove-Item  -Path "$path" -Recurse -ErrorAction SilentlyContinue
    # }
    success "Hiding 3D Objects icon from This PC..."
}
Function HideTaskbarPeopleIcon {
	info "Hiding People icon..."
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People"
    Safe-Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" DWord 0
	success "Hiding People icon..."
}
Function ShowTrayIcons {
    info "Showing all tray icons..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    Safe-Set-ItemProperty "$path" "EnableAutoTray" DWord 0
    success "Showing all tray icons..."
}
Function ShowKnownExtensions {
    info "Showing known file extensions..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "HideFileExt" DWord 0
    success "Showing known file extensions..."
}
Function ShowHiddenFiles {
    info "Showing hidden files..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "Hidden" DWord 1
    success "Showing hidden files..."
}
Function HideSyncNotifications {
    info "Hiding sync provider notifications..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "ShowSyncProviderNotifications" DWord 0
    success "Hiding sync provider notifications..."
}
Function HideRecentShortcuts {
    info "Hiding recent shortcuts..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $names=@(
        "ShowRecent", 
        "ShowFrequent"
    )
    foreach($name in $names) {
        Safe-Set-ItemProperty "$path" "$name" DWord 0
    }
    success "Hiding recent shortcuts..."
}
Function SetExplorerThisPC {
    info "Changing default Explorer view to This PC..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "LaunchTo" DWord 1
    success "Changing default Explorer view to This PC..."
}
Function ShowThisPCOnDesktop {
    info "Showing This PC shortcut on desktop..."
    $paths = @{
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' = '{20D04FE0-3AEA-1069-A2D8-08002B30309D}'
    }
    $paths.GetEnumerator() | ForEach-Object {
        $path=$_.Key
        Create-Path-If-Not-Exists "$path"
        Safe-Set-ItemProperty "$path"  $_.Value DWord 0
    }
	success "Showing This PC shortcut on desktop..."
}
Function ShowUserFolderOnDesktop {
	info "Showing User Folder shortcut on desktop..."
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
    Safe-Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" DWord 0
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
    Safe-Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" DWord 0
	success "Showing User Folder shortcut on desktop..."
}
# Adjusts visual effects for performance - 
# Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	info "Adjusting visual effects for performance..."
    Safe-Set-ItemProperty "HKCU:\Control Panel\Desktop" "DragFullWindows" String 0
    Safe-Set-ItemProperty "HKCU:\Control Panel\Desktop" "MenuShowDelay" String 0
    Safe-Set-ItemProperty "HKCU:\Control Panel\Desktop\WindowMetrics" "MinAnimate" String 0
    Safe-Set-ItemProperty "HKCU:\Control Panel\Desktop" "UserPreferencesMask" Binary ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
    Safe-Set-ItemProperty "HKCU:\Control Panel\Keyboard" "KeyboardDelay" DWord 0
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewAlphaSelect" DWord 0
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ListviewShadow" DWord 0
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarAnimations" DWord 0
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" "VisualFXSetting" DWord 3
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\DWM" "EnableAeroPeek" DWord 0
	success "Adjusting visual effects for performance..."
}
Function DisableThumbnails {
    info "Disabling thumbnails..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "IconsOnly" DWord 1
    success "Disabling thumbnails..."
}
Function DisableThumbsDB {
    info "Disabling creation of Thumbs.db..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    Safe-Set-ItemProperty "$path" "DisableThumbnailCache" DWord 1
    Safe-Set-ItemProperty "$path" "DisableThumbsDBOnNetworkFolders" DWord 1
    success "Disabling creation of Thumbs.db..."
}
Function EnableNumlock {
	info "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    $path="HKU:\.DEFAULT\Control Panel\Keyboard"
    Safe-Set-ItemProperty "$path" "InitialKeyboardIndicators" DWord 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
	success "Enabling NumLock after startup..."
}
Function EnableFileDeleteConfirm {
	info "Enabling file delete confirmation dialog..."
    Create-Path-If-Not-Exists "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ConfirmFileDelete" DWord 1
	success "Enabling file delete confirmation dialog..."
}
Function DisableFileDeleteConfirm {
    info "Disabling file delete confirmation dialog..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Safe-Remove-ItemProperty "$path" "ConfirmFileDelete"
    success "Disabling file delete confirmation dialog..."
}
Function HideTaskbarSearchBox {
    info "Hiding Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    Safe-Set-ItemProperty "$path" "SearchboxTaskbarMode" DWord 0
    success "Hiding Taskbar Search box / button..."
}
Function ShowTaskbarSearchBox {
    info "Showing Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    Safe-Remove-ItemProperty "$path" "SearchboxTaskbarMode"
    success "Showing Taskbar Search box / button..."
}
Function EnableFileDeleteConfirm {
	info "Enabling file delete confirmation dialog..."
    Create-Path-If-Not-Exists "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Safe-Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ConfirmFileDelete" DWord 1
	success "Enabling file delete confirmation dialog..."
}
Function SetDEPOptOut {
    info "Setting Data Execution Prevention (DEP) policy to OptOut..."
    try {
        bcdedit /set `{current`} nx OptOut | Out-Null
        success "Setting Data Execution Prevention (DEP) policy to OptOut..."
    }
    catch{
        warn "could not ser Data Execution Prevention (DEP) policy to OptOut. Possibly, bcdedit was not present in path"
    }
}
