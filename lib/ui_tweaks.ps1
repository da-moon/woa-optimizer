Function DisableLockScreen {
	info "Disabling Lock screen..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "NoLockScreen" -Type DWord -Value 1
	success "[DONE] Disabling Lock screen..."
}
Function EnableLockScreen {
    info "Enabling Lock screen..."
    $path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "NoLockScreen" -ErrorAction SilentlyContinue
    }
    success "[DONE] Enabling Lock screen..."
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
	success "[DONE] Disabling Lock screen using scheduler workaround..."
}
Function EnableLockScreenRS1 {
	info "Enabling Lock screen (removing scheduler workaround)..."
	Unregister-ScheduledTask -TaskName "Disable LockScreen" -Confirm:$false -ErrorAction SilentlyContinue
	success "[DONE] Enabling Lock screen (removing scheduler workaround)..."
}
Function HideShutdownFromLockScreen {
    info "Hiding shutdown options from Lock Screen..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "ShutdownWithoutLogon" -Type DWord -Value 0
    }
    success "[DONE] Hiding shutdown options from Lock Screen..."

}
Function ShowShutdownOnLockScreen {
    info "Showing shutdown options on Lock Screen..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "ShutdownWithoutLogon" -Type DWord -Value 1
    }
    success "[DONE] Showing shutdown options on Lock Screen..."
}
Function DisableStickyKeys {
    info "Disabling Sticky keys prompt..."
    $path="HKCU:\Control Panel\Accessibility\StickyKeys"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "Flags" -Type String -Value "506"
    }
    success "[DONE] Disabling Sticky keys prompt..."
}
Function EnableStickyKeys {
    info "Enabling Sticky keys prompt..."
    $path="HKCU:\Control Panel\Accessibility\StickyKeys"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "Flags" -Type String -Value "510"
    }
    success "[DONE] Enabling Sticky keys prompt..."
}
Function HideTaskbarSearchBox {
    info "Hiding Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    }
    success "[DONE] Hiding Taskbar Search box / button..."
}
Function ShowTaskbarSearchBox {
    info "Showing Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue
    }
    success "[DONE] Showing Taskbar Search box / button..."
}
Function HideTaskView {
    info "Hiding Task View button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "ShowTaskViewButton" -Type DWord -Value 0
    }
    success "[DONE] Hiding Task View button..."
}
Function ShowTaskView {
    info "Showing Task View button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "ShowTaskViewButton" -ErrorAction SilentlyContinue
    }
    success "[DONE] Showing Task View button..."
}
Function ShowSmallTaskbarIcons {
    info "Showing small icons in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "TaskbarSmallIcons" -Type DWord -Value 1
    }
    success "[DONE] Showing small icons in taskbar..."
}
Function ShowLargeTaskbarIcons {
    info "Showing large icons in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path"  -Name "TaskbarSmallIcons" -ErrorAction SilentlyContinue
    }
    success "[DONE] Showing large icons in taskbar..."
}
Function ShowTaskbarTitles {
    info "Showing titles in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "TaskbarGlomLevel" -Type DWord -Value 1
    }
    success "[DONE] Showing titles in taskbar..."
}
Function HideTaskbarTitles {
    info "Hiding titles in taskbar..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "TaskbarGlomLevel" -ErrorAction SilentlyContinue
    }
    success "[DONE] Hiding titles in taskbar..."
}
Function ShowTaskManagerDetails {
	info "Showing task manager details..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Force | Out-Null
	}
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
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	success "[DONE] Showing task manager details..."
}
Function HideTaskManagerDetails {
	info "Hiding task manager details..."
	$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	If ($preferences) {
		$preferences.Preferences[28] = 1
		Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
	}
	success "[DONE] Hiding task manager details..."
}
Function ShowFileOperationsDetails {
	info "Showing file operations details..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1
	success "[DONE] Showing file operations details..."
}
Function HideFileOperationsDetails {
    info "Hiding file operations details..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "EnthusiastMode" -ErrorAction SilentlyContinue
    }
    success "[DONE] Hiding file operations details..."
}
Function Hide3DObjectsFromThisPC {
    info "Hiding 3D Objects icon from This PC..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
    If (Test-Path "$path") {
        Remove-Item  -Path "$path" -Recurse -ErrorAction SilentlyContinue
    }
    success "[DONE] Hiding 3D Objects icon from This PC..."
}
Function HideTaskbarPeopleIcon {
	info "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
	success "[DONE] Hiding People icon..."
}
Function ShowTrayIcons {
    info "Showing all tray icons..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "EnableAutoTray" -Type DWord -Value 0
    }
    success "[DONE] Showing all tray icons..."
}
Function ShowKnownExtensions {
    info "Showing known file extensions..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "HideFileExt" -Type DWord -Value 0
    }
    success "[DONE] Showing known file extensions..."
}
Function ShowHiddenFiles {
    info "Showing hidden files..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "Hidden" -Type DWord -Value 1
    }
    success "[DONE] Showing hidden files..."
}
Function HideSyncNotifications {
    info "Hiding sync provider notifications..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "ShowSyncProviderNotifications" -Type DWord -Value 0
    }
    success "[DONE] Hiding sync provider notifications..."
}
Function HideRecentShortcuts {
    info "Hiding recent shortcuts..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "ShowRecent" -Type DWord -Value 0
        Set-ItemProperty -Path "$path" -Name "ShowFrequent" -Type DWord -Value 0
    }
    success "[DONE] Hiding recent shortcuts..."
}
Function SetExplorerThisPC {
    info "Changing default Explorer view to This PC..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "LaunchTo" -Type DWord -Value 1
    }
    success "[DONE] Changing default Explorer view to This PC..."
}
Function ShowThisPCOnDesktop {
	info "Showing This PC shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Type DWord -Value 0
	success "[DONE] Showing This PC shortcut on desktop..."
}
Function ShowUserFolderOnDesktop {
	info "Showing User Folder shortcut on desktop..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Type DWord -Value 0
	success "[DONE] Showing User Folder shortcut on desktop..."
}
# Adjusts visual effects for performance - 
# Disables animations, transparency etc. but leaves font smoothing and miniatures enabled
Function SetVisualFXPerformance {
	info "Adjusting visual effects for performance..."
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Type String -Value 0
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Type String -Value 0
	Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Type Binary -Value ([byte[]](0x90,0x12,0x03,0x80,0x10,0x00,0x00,0x00))
	Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "KeyboardDelay" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Type DWord -Value 3
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Type DWord -Value 0
	success "[DONE] Adjusting visual effects for performance..."
}
Function DisableThumbnails {
    info "Disabling thumbnails..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "IconsOnly" -Type DWord -Value 1
    }
    success "[DONE] Disabling thumbnails..."
}
Function DisableThumbsDB {
    info "Disabling creation of Thumbs.db..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "DisableThumbnailCache" -Type DWord -Value 1
        Set-ItemProperty -Path "$path" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value 1
    }
    success "[DONE] Disabling creation of Thumbs.db..."

}
Function EnableNumlock {
	info "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    $path="HKU:\.DEFAULT\Control Panel\Keyboard"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    }

	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}
	success "[DONE] Enabling NumLock after startup..."
}
Function EnableFileDeleteConfirm {
	info "Enabling file delete confirmation dialog..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
	success "[DONE] Enabling file delete confirmation dialog..."
}
Function DisableFileDeleteConfirm {
    info "Disabling file delete confirmation dialog..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
    }
    success "[DONE] Disabling file delete confirmation dialog..."
}
Function HideTaskbarSearchBox {
    info "Hiding Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "SearchboxTaskbarMode" -Type DWord -Value 0
    }
    success "[DONE] Hiding Taskbar Search box / button..."
}
Function ShowTaskbarSearchBox {
    info "Showing Taskbar Search box / button..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    If (Test-Path "$path") {
        Remove-ItemProperty  -Path "$path" -Name "SearchboxTaskbarMode" -ErrorAction SilentlyContinue
    }
    success "[DONE] Showing Taskbar Search box / button..."
}
Function EnableFileDeleteConfirm {
	info "Enabling file delete confirmation dialog..."
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
		New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1
	success "[DONE] Enabling file delete confirmation dialog..."
}
Function SetDEPOptOut {
	info "Setting Data Execution Prevention (DEP) policy to OptOut..."
	bcdedit /set `{current`} nx OptOut | Out-Null
	success "[DONE] Setting Data Execution Prevention (DEP) policy to OptOut..."
}