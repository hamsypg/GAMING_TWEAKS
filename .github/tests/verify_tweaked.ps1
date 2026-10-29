# Checks that the EN menu (menu_tweaks.txt) and Frame Booster really applied their tweaks.
$fail = 0
function Check($What, $Actual, $Expected) {
    $ok = "$Actual" -eq "$Expected"
    if (-not $ok) { $script:fail++ }
    '{0,-6} {1,-45} actual={2,-12} expected={3}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $What, "$Actual", "$Expected"
}
function Reg($Path, $Name) { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
function Svc($Name) { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name").Start }

$mm = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
$mem = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$gc = 'HKCU:\System\GameConfigStore'
# Optimize Windows
Check 'Store AutoDownload'          (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload') 2
Check 'SearchOrderConfig'           (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig') 0
Check 'GlobalUserDisabled'          (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled') 1
Check 'DiagTrack start'             (Svc 'DiagTrack') 4
Check 'SysMain start'               (Svc 'SysMain') 4
Check 'MapsBroker start'            (Svc 'MapsBroker') 4
Check 'FeatureSettingsOverride'     (Reg $mem 'FeatureSettingsOverride') 3
Check 'FeatureSettingsOverrideMask' (Reg $mem 'FeatureSettingsOverrideMask') 3
Check 'EnableTransparency'          (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency') 0
# Gaming Boost
Check 'AllowGameDVR'                (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR') 0
Check 'GameDVR_FSEBehaviorMode'     (Reg $gc 'GameDVR_FSEBehaviorMode') 2
Check 'DXGIHonorFSEWindowsCompatible' (Reg $gc 'GameDVR_DXGIHonorFSEWindowsCompatible') 1
Check 'UseNexusForGameBarEnabled'   (Reg 'HKCU:\Software\Microsoft\GameBar' 'UseNexusForGameBarEnabled') 0
Check 'Games Priority'              (Reg "$mm\Tasks\Games" 'Priority') 6
Check 'Games Scheduling Category'   (Reg "$mm\Tasks\Games" 'Scheduling Category') 'High'
Check 'Games SFIO Priority'         (Reg "$mm\Tasks\Games" 'SFIO Priority') 'High'
Check 'Win32PrioritySeparation'     (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation') 38
$ramKb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB)
Check 'SvcHostSplitThresholdInKB'   (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB') $ramKb
Check 'MouseSpeed'                  (Reg 'HKCU:\Control Panel\Mouse' 'MouseSpeed') 0
Check 'MouseThreshold1'             (Reg 'HKCU:\Control Panel\Mouse' 'MouseThreshold1') 0
# Network
Check 'StopThrottling rule'         (@(Get-NetFirewallRule -DisplayName 'StopThrottling' -ErrorAction SilentlyContinue).Count) 1
# Frame Booster
Check 'AutoGameModeEnabled'         (Reg 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled') 1
Check 'HwSchMode'                   (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode') 2
Check 'Windowed games'              ((Reg 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' 'DirectXUserGlobalSettings') -like '*SwapEffectUpgradeEnable=1;*') 'True'
Check 'SystemResponsiveness'        (Reg $mm 'SystemResponsiveness') 10
Check 'NetworkThrottlingIndex'      (Reg $mm 'NetworkThrottlingIndex') 4294967295
Check 'PowerThrottlingOff'          (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff') 1
Check 'GameDVR_Enabled'             (Reg $gc 'GameDVR_Enabled') 0
Check 'AppCaptureEnabled'           (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled') 0
Check 'GlobalTimerResolutionRequests' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'GlobalTimerResolutionRequests') 1
Check 'Active plan is GAMING TWEAKS' ([bool]((powercfg /getactivescheme | Out-String) -match 'GAMING TWEAKS Ultimate')) 'True'
Check 'Only one GAMING TWEAKS plan' (@(powercfg /list | Where-Object { $_ -match 'GAMING TWEAKS' }).Count) 1
powercfg /getactivescheme

"`n$fail check(s) failed"
exit $fail
