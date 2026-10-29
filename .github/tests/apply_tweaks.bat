@echo off
:: Applies the same system changes as Core_EN.bat (non-interactive) so the
:: restore can be tested against a fully tweaked system.
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t reg_dword /d "1" /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching /v SearchOrderConfig /t reg_dword /d "0" /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
sc config DiagTrack start= disabled
sc config SysMain start= disabled
sc config MapsBroker start= disabled
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize /v EnableTransparency /t reg_dword /d "0" /f
PowerShell "Disable-MMAgent -MemoryCompression"
reg add HKCU\System\GameConfigStore /v GameDVR_Enabled /t reg_dword /d "0" /f
reg add HKCU\System\GameConfigStore /v GameDVR_FSEBehaviorMode /t reg_dword /d "2" /f
reg add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t reg_dword /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
bcdedit /set numproc 2
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0 /f
reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "16777216" /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t reg_dword /d "10000" /f
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
for /f "tokens=4" %%G in ('powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61') do powercfg /setactive %%G
netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes
reg add HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl /v Win32PrioritySeparation /t REG_DWORD /d 38 /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v DefaultTTL /t REG_DWORD /d 64 /f
netsh int tcp set global autotuninglevel=disabled
exit /b 0
