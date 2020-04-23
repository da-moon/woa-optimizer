Function DisableTelemetry {
    info "Disabling Telemetry..."
    $paths=@(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    )
    foreach($path in $paths) {
        Safe-Set-ItemProperty "$path" "AllowTelemetry" DWord 0
    }
    success "Disabling Telemetry..."
}
Function DisableWiFiSense {
	info "Disabling Wi-Fi Sense..."
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $paths=@(
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting",
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    )
    foreach($path in $paths) {
        Safe-Set-ItemProperty  "$path" "Value" DWord 0
    }
	success "Disabling Wi-Fi Sense..."
}
Function DisableSmartScreen {
    info "Disabling SmartScreen Filter..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "SmartScreenEnabled" -Type String -Value "Off"
    }
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "EnableWebContentEvaluation" -Type DWord -Value 0
    }
	$edge = (Get-AppxPackage -AllUsers "Microsoft.MicrosoftEdge").PackageFamilyName
    $path="HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\$edge\MicrosoftEdge\PhishingFilter"
    Create-Path-If-Not-Exists "$path"
    $names=@(
        "EnabledV9" , 
        "PreventOverride"
    )
    foreach($name in $names) {
        Set-ItemProperty -Path "$path" -Name "$name" -Type DWord -Value 0
    }
    success "Disabling SmartScreen Filter..."
}
Function DisableWebSearch {
    info "Disabling Bing Search in Start Menu..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "BingSearchEnabled" -Type DWord -Value 0
    }
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -Type DWord -Value 1
    success "Disabling Bing Search in Start Menu..."
}
Function DisableBackgroundApps {
    info "Disabling Background application access..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications"
    If (Test-Path "$path") {
        Get-ChildItem "$path" | ForEach-Object {
            Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
            Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
        }
    }
    success "Disabling Background application access..."
}
Function DisableLockScreenSpotlight {
    info "Disabling Lock screen spotlight..."
    $path="HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name 'RotatingLockScreenEnabled' -Type DWord -Value 0
        Set-ItemProperty -Path "$path" -Name 'RotatingLockScreenOverlayEnabled' -Type DWord -Value 0
        Set-ItemProperty -Path "$path" -Name 'SubscribedContent-338387Enabled' -Type DWord -Value 0
    }
    success "Disabling Lock screen spotlight..."
}
Function DisableLocationTracking {
    info "Disabling Location Tracking..."
    $paths = @{
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' = 'SensorPermissionState'
        'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' = 'Status'
    }
    $paths.GetEnumerator() | ForEach-Object {
        $path=$_.Key
        If (Test-Path "$path") {
            Set-ItemProperty -Path "$path" -Name $_.Value -Type DWord -Value 0
        }
    }
    success "Disabling Location Tracking..."
}
Function DisableMapUpdates {
    info "Disabling automatic Maps updates..."
    $path="HKLM:\SYSTEM\Maps"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    }
    success "Disabling automatic Maps updates..."
}
Function DisableFeedback {
	info "Disabling Feedback..."
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	success "Disabling Feedback..."
}
Function DisableAdvertisingID {
    info "Disabling Advertising ID..."
    $paths = @{
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' = 'Enabled'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' = 'TailoredExperiencesWithDiagnosticDataEnabled'
    }
    $paths.GetEnumerator() | ForEach-Object {
        $path=$_.Key
        Create-Path-If-Not-Exists "$path"
        If (Test-Path "$path") {
            Set-ItemProperty -Path "$path" -Name $_.Value -Type DWord -Value 0
        }
    }
	success "Disabling Advertising ID..."
}
Function DisableCortana {
    info "Disabling Cortana..."
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    Create-Path-If-Not-Exists "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"	
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0
    success "Disabling Cortana..."
}
Function DisableErrorReporting {
    info "Disabling Error reporting..."
    $path="HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting"
    If (Test-Path "$path") {
        Set-ItemProperty -Path "$path" -Name "Disabled" -Type DWord -Value 1
    }
    success "Disabling Error reporting..."
}
Function DisableAutoLogger {
	info "Removing AutoLogger file and restricting directory..."
	$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
	If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
		Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
	}
	icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null
	success "Removing AutoLogger file and restricting directory..."
}
Function DisableDiagTrack {
	info "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled
	success "Stopping and disabling Diagnostics Tracking Service..."
}
Function DisableWAPPush {
	info "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled
	success "Stopping and disabling WAP Push Service..."
}
# Disable Application suggestions and automatic installation
Function DisableAppSuggestions {
    info "Disabling Application suggestions..."
    $path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (Test-Path "$path") {
        $names=@(
            "ContentDeliveryAllowed",
            "OemPreInstalledAppsEnabled" ,
            "PreInstalledAppsEnabled",
            "PreInstalledAppsEverEnabled" ,
            "SilentInstalledAppsEnabled" ,
            "SubscribedContent-338389Enabled" ,
            "SystemPaneSuggestionsEnabled" ,
            "SubscribedContent-338388Enabled" 
        )
        foreach($name in $names) {
            Set-ItemProperty -Path "$path" -Name "$name" -Type DWord -Value 0
        }
    }
    Create-Path-If-Not-Exists "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
}
