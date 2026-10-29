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
Check 'CursorSensitivity'       (Reg 'HKLM:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed' 'CursorSensitivity') ''
Check 'Win32PrioritySeparation' (Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation') 2
Check 'DefaultTTL'              (Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'DefaultTTL') ''
Check 'DiagTrack start'         (Svc 'DiagTrack') 2
Check 'SysMain start'           (Svc 'SysMain') 2
Check 'MapsBroker start'        (Svc 'MapsBroker') 2
Check 'MapsBroker delayed'      (Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker' 'DelayedAutostart') 1
Check 'Memory compression'      ((Get-MMAgent).MemoryCompression) 'True'
Check 'bcdedit numproc'         ([bool]((bcdedit /enum '{current}') -match '^\s*numproc')) 'False'
Check 'Active power plan'       ([bool]((powercfg /getactivescheme) -match '381b4222-f694-41f0-9685-ff5bb260df2e')) 'True'
Check 'Ultimate copies left'    (@(powercfg /list | Where-Object { $_ -match 'Ultimate' }).Count) 0
Check 'StopThrottling rule'     ([bool](Get-NetFirewallRule -DisplayName 'StopThrottling' -ErrorAction SilentlyContinue)) 'False'
Check 'TCP autotuning'          ([bool]((netsh int tcp show global | Out-String) -match '(?im)Auto-Tuning Level\s*:\s*normal')) 'True'

"`n$fail check(s) failed"
exit $fail
