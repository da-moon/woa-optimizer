#Requires -Version 5
# Tweaks
$package_managers = @(
    "InstallScoop",
    "InstallChocolatey"
)
$scoop_software = @(
    "7zip",
    "Lessmsi",
    "Innounp", 
    "Dark",
    "wget",
    "curl",
    "unzip",
    "zip",
    "unrar",
    "aria2",
    "axel",
    "cygwin",
    "jq",
    "memreduct",
    "bulk-crap-uninstaller",
    "yarn",
    "nodejs",
    "vcxsrv",
    "vscode-insiders",
    "shasum",
    "coreutils",
    "dd",
    "win32-openssh",
    "nano",
    "vim"
)
$optional_features_to_remove = @(
    'Printing-PrintToPDFServices-Features',
    'Printing-XPSServices-Features',
    'Xps-Foundation-Xps-Viewer',
    'WorkFolders-Client',
    'MediaPlayback',
    'SMB1Protocol',
    'WCF-Services45',
    'MSRDC-Infrastructure',
    'Internet-Explorer-Optional-amd64'
)
$tweaks = @(
	# ---------------------------------------- privacy -----------------------------------------
	"DisableTelemetry",
    # ------------------------------------------------------------------------------------------
    "DisableWiFiSense",             
    # "EnableWiFiSense",
    # ------------------------------------------------------------------------------------------
    "DisableSmartScreen",           
    # "EnableSmartScreen",
    # ------------------------------------------------------------------------------------------
    "DisableWebSearch",             
    # "EnableWebSearch",
    # ------------------------------------------------------------------------------------------
    "DisableAppSuggestions",        
    # "EnableAppSuggestions",
    # ------------------------------------------------------------------------------------------
    "DisableBackgroundApps",        
    # "EnableBackgroundApps",
    # ------------------------------------------------------------------------------------------
    "DisableLockScreenSpotlight",   
    # "EnableLockScreenSpotlight",
    # ------------------------------------------------------------------------------------------
    "DisableLocationTracking",      
    # "EnableLocationTracking",
    # ------------------------------------------------------------------------------------------
    "DisableMapUpdates",            
    # "EnableMapUpdates",
    # ------------------------------------------------------------------------------------------
    "DisableFeedback",              
    # "EnableFeedback",
    # ------------------------------------------------------------------------------------------
    # "EnableAdvertisingID",
    "DisableAdvertisingID",
    # ------------------------------------------------------------------------------------------
    # "EnableCortana",
    "DisableCortana",        
    # ------------------------------------------------------------------------------------------
    # "EnableErrorReporting",
    "DisableErrorReporting", 
    # ------------------------------------------------------------------------------------------
    # "SetP2PUpdateInternet",
    # REMOVED this --- caused script to fail
    # "SetP2PUpdateLocal", 
    # ------------------------------------------------------------------------------------------
    # "EnableAutoLogger",
    "DisableAutoLogger",
    # ------------------------------------------------------------------------------------------
    # "EnableDiagTrack",
    "DisableDiagTrack",
    # ------------------------------------------------------------------------------------------
    # "EnableWAPPush",
    "DisableWAPPush",               
    # ------------------------------------------------------------------------------------------
    # ---------------------------------------- Service ----------------------------------------
    "SetUACLow",                    
    # "SetUACHigh",
    # ------------------------------------------------------------------------------------------
    "DisableAdminShares",         
    # "EnableAdminShares",
    # ------------------------------------------------------------------------------------------
    # "DisableCtrldFolderAccess",
    "EnableCtrldFolderAccess",     
    # ------------------------------------------------------------------------------------------
    # "EnableFirewall",
    # "DisableFirewall",            
    # ------------------------------------------------------------------------------------------
    "DisableDefender",            
    # "EnableDefender",
    # ------------------------------------------------------------------------------------------
    "DisableDefenderCloud",       
    # "EnableDefenderCloud",
    # ------------------------------------------------------------------------------------------
    "DisableUpdateMSRT",          
    # "EnableUpdateMSRT",
    # ------------------------------------------------------------------------------------------
    "DisableUpdateDriver",       
    # ------------------------------------------------------------------------------------------
    "DisableUpdateRestart",         
    # "EnableUpdateRestart",
    # ------------------------------------------------------------------------------------------
    "DisableSharedExperiences",     
    # "EnableSharedExperiences",
    # ------------------------------------------------------------------------------------------
    "DisableRemoteAssistance",      
    # "EnableRemoteAssistance",
    # ------------------------------------------------------------------------------------------
    "EnableRemoteDesktop",          
    # "DisableRemoteDesktop",
    # ------------------------------------------------------------------------------------------
    "DisableAutoplay",              
    # "EnableAutoplay",
    # ------------------------------------------------------------------------------------------
    "DisableAutorun",               
    # ------------------------------------------------------------------------------------------
    "DisableStorageSense",          
    # "EnableStorageSense",
    # ------------------------------------------------------------------------------------------
    "DisableDefragmentation",       
    # "EnableDefragmentation",
    # ------------------------------------------------------------------------------------------
    "DisableSuperfetch",            
    # "EnableSuperfetch",
    # ------------------------------------------------------------------------------------------
    "DisableIndexing",              
    # "EnableIndexing",
    # ------------------------------------------------------------------------------------------
    "DisableHibernation",           
    # ------------------------------------------------------------------------------------------
    "DisableFastStartup",           
    # "EnableFastStartup",
    # ------------------------------------------------------------------------------------------
    "SetBIOSTimeLocal",             
    # "SetBIOSTimeUTC",
    # ------------------------------------------------------------------------------------------
    # ---------------------------------------- UI Tweaks ----------------------------------------
    "DisableLockScreen",            
    # "EnableLockScreen",
    # ------------------------------------------------------------------------------------------
    "DisableLockScreenRS1",         
    # "EnableLockScreenRS1",
    # ------------------------------------------------------------------------------------------
    "ShowShutdownOnLockScreen",     
    # "HideShutdownFromLockScreen",
    # ------------------------------------------------------------------------------------------
    "DisableStickyKeys",            
    # "EnableStickyKeys",
    # ------------------------------------------------------------------------------------------
    "ShowTaskManagerDetails"        
    # "HideTaskManagerDetails",
    # ------------------------------------------------------------------------------------------
    "ShowFileOperationsDetails",    
    # "HideFileOperationsDetails",
    # ------------------------------------------------------------------------------------------
    "DisableFileDeleteConfirm",  
    # ------------------------------------------------------------------------------------------
    "ShowTaskbarSearchBox",         
    # "HideTaskbarSearchBox",
    # ------------------------------------------------------------------------------------------
    "ShowTaskView",                 
    # "HideTaskView",
    # ------------------------------------------------------------------------------------------
    "ShowLargeTaskbarIcons",        
    # "ShowSmallTaskbarIcons",
    # ------------------------------------------------------------------------------------------
    "HideTaskbarTitles",            
    # "ShowTaskbarTitles",
    # ------------------------------------------------------------------------------------------
    "HideTaskbarPeopleIcon",        
    # "ShowTaskbarPeopleIcon",
    # ------------------------------------------------------------------------------------------
    "ShowTrayIcons",                
    # "HideTrayIcons",
    # ------------------------------------------------------------------------------------------
    "ShowKnownExtensions",          
    # "HideKnownExtensions",
    # ------------------------------------------------------------------------------------------
    "ShowHiddenFiles",              
    # "HideHiddenFiles",
    # ------------------------------------------------------------------------------------------
    "HideSyncNotifications"         
    # "ShowSyncNotifications",
    # ------------------------------------------------------------------------------------------
    "HideRecentShortcuts",          
    # "ShowRecentShortcuts",
    # ------------------------------------------------------------------------------------------
    "SetExplorerThisPC",            
    # "SetExplorerQuickAccess",
    # ------------------------------------------------------------------------------------------
    "ShowThisPCOnDesktop",          
    # "HideThisPCFromDesktop",
    # ------------------------------------------------------------------------------------------
    "ShowUserFolderOnDesktop",   
    # ------------------------------------------------------------------------------------------
    "Hide3DObjectsFromThisPC",    
    # ------------------------------------------------------------------------------------------
    "SetVisualFXPerformance",       
    # "SetVisualFXAppearance",
    # ------------------------------------------------------------------------------------------
    "DisableThumbnails",            
    # "EnableThumbnails",
    # ------------------------------------------------------------------------------------------
    "DisableThumbsDB",              
    # "EnableThumbsDB",
    # ------------------------------------------------------------------------------------------
    "EnableNumlock",                
    # "DisableNumlock",
    # ------------------------------------------------------------------------------------------
	#---------------------------------------- Application Tweaks ----------------------------------------
    "DisableOneDrive",             
    # "EnableOneDrive",
    # ------------------------------------------------------------------------------------------
    "UninstallOneDrive",           
    # "InstallOneDrive",
    # ------------------------------------------------------------------------------------------
    "UninstallBloat",              
    # "InstallMsftBloat",
    # ------------------------------------------------------------------------------------------
    # "UninstallWindowsStore", 
    # "InstallWindowsStore",
    # ------------------------------------------------------------------------------------------
    "DisableAdobeFlash",        
    # ------------------------------------------------------------------------------------------
    "UninstallMediaPlayer",         
    # "InstallMediaPlayer",
    # ------------------------------------------------------------------------------------------
    "UninstallWorkFolders",         
    # "InstallWorkFolders",
    # ------------------------------------------------------------------------------------------
    "InstallLinuxSubsystem",        
    # "UninstallLinuxSubsystem",
    # ------------------------------------------------------------------------------------------
    "AddPhotoViewerOpenWith",       
    # "RemovePhotoViewerOpenWith",
    # ------------------------------------------------------------------------------------------
    "DisableSearchAppInStore",      
    # "EnableSearchAppInStore",
    # ------------------------------------------------------------------------------------------
    "DisableNewAppPrompt",          
    # "EnableNewAppPrompt",
    # ------------------------------------------------------------------------------------------
    "SetDEPOptOut",                 
    # ------------------------------------------------------------------------------------------
    "DisableExtraServices",
    # ------------------------------------------------------------------------------------------
    "SetupDependancies",
    # ------------------------------------------------------------------------------------------
    "DeleteTempFiles",
    # ------------------------------------------------------------------------------------------
    "CleanWinSXS",
    # ------------------------------------------------------------------------------------------
    "DownloadShutup10",
    # ------------------------------------------------------------------------------------------
    "RemoveUnneededComponents",
    # ------------------------------------------------------------------------------------------
    "EnableWindowsSearch",          
    #DisableWindowsSearch     
    # ------------------------------------------------------------------------------------------
    "DisableCompatibilityAppraiser",
    # ------------------------------------------------------------------------------------------
    # "DisableConnectedStandby",
    # ------------------------------------------------------------------------------------------
    "EnableBigDesktopIcons",
    # ------------------------------------------------------------------------------------------
    "DisableGPDWinServices"
    # ------------------------------------------------------------------------------------------
)
# comment out apps you want to keep
$microsoft_apps_to_remove = @(
    # "Office.OneNote",
	# "indowsSoundRecorder",
    # "MSPaint",
    # "RemoteDesktop",
    # "Windows.Photos",
    # "WindowsAlarms",
    # "People",
    # "MicrosoftStickyNotes",
    "3DBuilder",
    "BingFinance",
    "BingNews",
    "BingSports",
    "BingWeather",
    "Getstarted",
    "MicrosoftOfficeHub",
    "MicrosoftSolitaireCollection",
    "SkypeApp",
    "WindowsCamera",
    "windowscommunicationsapps",
    "WindowsMaps",
    "WindowsPhone",
    "ZuneMusic",
    "ZuneVideo",
    "AppConnector",
    "ConnectivityStore",
    "Office.Sway",
    "Messaging",
    "CommsPhone",
    "OneConnect",
    "WindowsFeedbackHub",
    "MinecraftUWP",
    "MicrosoftPowerBIForWindows",
    "NetworkSpeedTest",
    "Microsoft3DViewer",
    "Print3D",
    # xbox
    "XboxApp",
    "XboxIdentityProvider",
    "XboxSpeechToTextOverlay",
    "XboxGameOverlay",
    "Xbox.TCUI"
)
$thirdparty_apps_to_remove= @(
    "9E2F88E3.Twitter",
    "king.com.CandyCrushSodaSaga",
    "4DF9E0F8.Netflix",
    "Drawboard.DrawboardPDF",
    "D52A8D61.FarmVille2CountryEscape",
    "GAMELOFTSA.Asphalt8Airborne",
    "flaregamesGmbH.RoyalRevolt2",
    "AdobeSystemsIncorporated.AdobePhotoshopExpress",
    "ActiproSoftwareLLC.562882FEEB491",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "Facebook.Facebook",
    "46928bounde.EclipseManager",
    "A278AB0D.MarchofEmpires",
    "KeeperSecurityInc.Keeper",
    "king.com.BubbleWitch3Saga",
    "89006A2E.AutodeskSketchBook",
    "CAF9E577.Plex"
)
$services_to_disable = @(
    # Microsoft (R) Diagnostics Hub Standard Collector Service
    "diagnosticshub.standardcollector.service",
    # Downloaded Maps Manager
    "MapsBroker",
    # Net.Tcp Port Sharing Service					
    "NetTcpPortSharing",
    # Distributed Link Tracking Client     
    "TrkWks",
    # Windows Biometric Service                      	
    "WbioSrvc",
    # Windows Media Player Network Sharing Service                       	
    "WMPNetworkSvc",
    "AppVClient",
    "RemoteRegistry",
    "CDPSvc",
    "shpamsvc",
    "SCardSvr",
    "UevAgentService",
    "PeerDistSvc",
    "lfsvc",
    "HvHost",
    "vmickvpexchange",
    "vmicguestinterface",
    "vmicshutdown",
    "vmicheartbeat",
    "vmicvmsession",
    "vmicrdv",
    "vmictimesync",
    "vmicvss",
    "irmon",
    "SharedAccess",
    "SmsRouter",
    "CscService",
    "SEMgrSvc",
    "PhoneSvc",
    "RpcLocator",
    "RetailDemo",
    "SensorDataService",
    "SensrSvc",
    "SensorService",
    "ScDeviceEnum",
    "SCPolicySvc",
    "SNMPTRAP",
    "WFDSConSvc",
    "FrameServer",
    "wisvc",
    "icssvc",
    "WwanSvc"
)
# WARNING : Do not modify any values below this line
# vars-consts
$script_name='woa-optimizer'
$base_url = 'https://raw.githubusercontent.com/da-moon/woa-optimizer/master'
Write-Output "$script_name Loading lib/log.ps1"
Invoke-Expression (new-object net.webclient).downloadstring("$base_url/lib/log.ps1")
$libs= @(
    'lib/utils.ps1',
    'lib/privacy.ps1',
    'lib/ui_tweaks.ps1',
    'lib/service.ps1',
    'lib/app.ps1'
)
foreach($lib in $libs) {
    info "$script_name Loading $lib"
    Invoke-Expression (new-object net.webclient).downloadstring("$base_url/$lib")
    success "[DONE] $script_name Loading $lib"
}
$old_erroractionpreference = $erroractionpreference
$erroractionpreference = 'stop' # quit if anything goes wrong
if (($PSVersionTable.PSVersion.Major) -lt 5) {
    Write-Output "PowerShell 5 or later is required to run woa-optimizer script."
    Write-Output "Upgrade PowerShell: https://docs.microsoft.com/en-us/powershell/scripting/setup/installing-windows-powershell"
    break
}
# show notification to change execution policy:
$allowedExecutionPolicy = @('Unrestricted', 'RemoteSigned', 'ByPass')
if ((Get-ExecutionPolicy).ToString() -notin $allowedExecutionPolicy) {
    Write-Output "PowerShell requires an execution policy in [$($allowedExecutionPolicy -join ", ")] to run $script_name script."
    Write-Output "For example, to set the execution policy to 'RemoteSigned' please run :"
    Write-Output "'Set-ExecutionPolicy RemoteSigned -scope CurrentUser'"
    break
}
RequireAdmin
# parsing flags
$opt, $apps, $err = getopt $args 'dv' 'dependancies,verbose'
if ($err) {
    error "$err"
    exit 1
}
$dependancies = $opt.d -or $opt.dependancies
$verbose = $opt.v -or $opt.verbose
if ((Get-Command "scoop" -ErrorAction SilentlyContinue) -eq $null) 
{ 
	warn "Unable to find scoop in your PATH"
	info "installing scoop"
	InstallScoop
}
if ((Get-Command "choco" -ErrorAction SilentlyContinue) -eq $null) 
{ 
	warn "Unable to find choco in your PATH"
	info "installing chocolatey"
	InstallScoop
	InstallChocolatey
}
if ($dependancies) {
    info "installing dependancies"
    InstallScoopPackages
}
$preset = ""
$PSCommandArgs = $args
If ($args -And $args[0].ToLower() -eq "-preset") {
	$preset = Resolve-Path $($args | Select-Object -Skip 1)
	$PSCommandArgs = "-preset `"$preset`""
}
# Load function names from command line arguments or a preset file
If ($args) {
	$tweaks = $args
	If ($preset) {
		$tweaks = Get-Content $preset -ErrorAction Stop | ForEach { $_.Trim() } | Where { $_ -ne "" -and $_[0] -ne "#" }
	}
}
foreach($tweak in $tweaks) {
	Invoke-Expression $tweak
}
success "[DONE] $script_name ran wirhout any issues successfully!"
$erroractionpreference = $old_erroractionpreference # Reset $erroractionpreference to original value
WaitForKey
Restart
