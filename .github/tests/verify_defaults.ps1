# Checks that every setting GAMING TWEAKS changes is back to the Windows default.
$fail = 0
function Check($What, $Actual, $Expected) {
    $ok = "$Actual" -eq "$Expected"
    if (-not $ok) { $script:fail++ }
    '{0,-6} {1,-45} actual={2,-12} expected={3}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $What, "$Actual", "$Expected"
}
function Reg($Path, $Name) { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
function Svc($Name) { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$Name").Start }

$mm = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
Check 'NoAutoUpdate'            (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate') ''
Check 'SearchOrderConfig'       (Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig') 1
Check 'GlobalUserDisabled'      (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled') ''
Check 'FeatureSettingsOverride' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride') ''
Check 'EnableTransparency'      (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency') 1
Check 'GameDVR_Enabled'         (Reg 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled') 1
Check 'GameDVR_FSEBehaviorMode' (Reg 'HKCU:\System\GameConfigStore' 'GameDVR_FSEBehaviorMode') 1
Check 'NetworkThrottlingIndex'  (Reg $mm 'NetworkThrottlingIndex') 10
Check 'SystemResponsiveness'    (Reg $mm 'SystemResponsiveness') 20
Check 'GPU Priority'            (Reg "$mm\Tasks\Games" 'GPU Priority') 8
Check 'SvcHostSplitThresholdInKB' (Reg 'HKLM:\SYSTEM\ControlSet001\Control' 'SvcHostSplitThresholdInKB') 3670016
Check 'CursorSensitivity'       (Reg 'HKLM:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed' 'CursorSensitivity') 100
Check 'Win32PrioritySeparation' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation') 2
Check 'DefaultTTL'              (Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DefaultTTL') ''
$gc = 'HKCU:\System\GameConfigStore'
$gb = 'HKCU:\Software\Microsoft\GameBar'
Check 'Store AutoDownload'      (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload') ''
Check 'FeatureSettingsOverrideMask' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverrideMask') ''
Check 'GameDVR_FSEBehavior'     (Reg $gc 'GameDVR_FSEBehavior') ''
Check 'HonorUserFSEBehaviorMode' (Reg $gc 'GameDVR_HonorUserFSEBehaviorMode') 0
Check 'DXGIHonorFSEWindowsCompatible' (Reg $gc 'GameDVR_DXGIHonorFSEWindowsCompatible') 0
Check 'AppCaptureEnabled'       (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled') ''
Check 'HistoricalCaptureEnabled' (Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'HistoricalCaptureEnabled') ''
Check 'AllowGameDVR'            (Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR') ''
Check 'UseNexusForGameBarEnabled' (Reg $gb 'UseNexusForGameBarEnabled') ''
Check 'AutoGameModeEnabled'     (Reg $gb 'AutoGameModeEnabled') ''
Check 'AllowAutoGameMode'       (Reg $gb 'AllowAutoGameMode') ''
Check 'HwSchMode'               (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode') ''
Check 'DirectXUserGlobalSettings' (Reg 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' 'DirectXUserGlobalSettings') ''
Check 'PowerThrottlingOff'      (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff') ''
Check 'GlobalTimerResolutionRequests' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'GlobalTimerResolutionRequests') ''
Check 'Games Priority'          (Reg "$mm\Tasks\Games" 'Priority') 2
Check 'Games Scheduling Category' (Reg "$mm\Tasks\Games" 'Scheduling Category') 'Medium'
Check 'Games SFIO Priority'     (Reg "$mm\Tasks\Games" 'SFIO Priority') 'Normal'
Check 'SvcHostSplit (current)'  (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB') 3670016
Check 'MouseSpeed'              (Reg 'HKCU:\Control Panel\Mouse' 'MouseSpeed') 1
Check 'MouseThreshold1'         (Reg 'HKCU:\Control Panel\Mouse' 'MouseThreshold1') 6
Check 'MouseThreshold2'         (Reg 'HKCU:\Control Panel\Mouse' 'MouseThreshold2') 10
Check 'DiagTrack start'         (Svc 'DiagTrack') 2
Check 'SysMain start'           (Svc 'SysMain') 2
Check 'MapsBroker start'        (Svc 'MapsBroker') 2
Check 'MapsBroker delayed'      (Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker' 'DelayedAutostart') 1
# Memory compression only changes state after a reboot, which CI can't do: shown, not counted
'INFO   {0,-45} actual={1,-12} expected=True (after reboot)' -f 'Memory compression', (Get-MMAgent).MemoryCompression
Check 'bcdedit numproc'         ([bool]((bcdedit /enum '{current}') -match '^\s*numproc')) 'False'
Check 'Active power plan'       ([bool]((powercfg /getactivescheme) -match '381b4222-f694-41f0-9685-ff5bb260df2e')) 'True'
Check 'GAMING TWEAKS plans left' (@(powercfg /list | Where-Object { $_ -match 'GAMING TWEAKS' }).Count) 0
Check 'Ultimate copies left'    (@(powercfg /list | Where-Object { $_ -match 'Ultimate' }).Count) 0
Check 'StopThrottling rule'     ([bool](Get-NetFirewallRule -DisplayName 'StopThrottling' -ErrorAction SilentlyContinue)) 'False'
Check 'TCP autotuning'          ([bool]((netsh int tcp show global | Out-String) -match '(?im)Auto-Tuning Level\s*:\s*normal')) 'True'

"`n$fail check(s) failed"
exit $fail
