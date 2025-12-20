@echo off
title GAMING TWEAKS v0.5.7 (English)
cls
color b

:enmain
cls
echo.
echo                        MAIN MENU
echo.
echo                  Choose Any Number
echo             ----------------------------------------
echo             [1] Optimize Windows
echo             [2] Gaming Boost
echo             [3] Optimize Network
echo             [4] Latest Components Updates
echo.
echo             [L] View Log
echo             [F] Follow Me
echo             [X] Exit
echo             ----------------------------------------
echo.
set /p "enmain=Write Here: "

if /i "%enmain%"=="L" goto enlog
if /i "%enmain%"=="F" goto followme
if /i "%enmain%"=="X" exit
if "%enmain%"=="1" goto optimizewindows
if "%enmain%"=="2" goto gamingboost
if "%enmain%"=="3" goto optimizenetwork
if "%enmain%"=="4" goto componetsupdate
goto enmain

:: --------------------------------------------------
:: OPTIMIZE WINDOWS
:: --------------------------------------------------
:optimizewindows
title Optimize Windows & color a
cls
echo.
echo                              Optimize Windows
echo             ----------------------------------------------------------
echo             [1]  Cache, Temporary, Logs Cleaner
echo             [2]  Disable Automatic App Updates
echo             [3]  Disable Automatic Driver Updates
echo             [4]  Disable or Restore Background Apps
echo             [5]  Disable or Restore Unnecessary Services
echo             [6]  Disable Spectre and Meltdown Protection
echo             [7]  Disable Transparency Effects
echo             [8]  Disable Memory Compression
echo             [9]  Prevent Unnecessary Apps Auto Starting
echo             [10] Optimize Hard Drive
echo             [B]  Back
echo             ----------------------------------------------------------
echo.
set /p "optw=Choice: "
if /i "%optw%"=="B" goto enmain
if "%optw%"=="1" goto tempcleaner
if "%optw%"=="2" goto disableappupd
if "%optw%"=="3" goto disabledriverupd
if "%optw%"=="4" goto backapps
if "%optw%"=="5" goto unnservices
if "%optw%"=="6" goto spectre
if "%optw%"=="7" goto trans
if "%optw%"=="8" goto memcomp
if "%optw%"=="9" goto autostart
if "%optw%"=="10" goto defrag
goto optimizewindows

:tempcleaner
cls
echo Cleaning Cache and Temp files...
:: Commands hidden for cleaner UI
del /s /f /q "%temp%\*" >nul 2>&1
del /s /f /q "C:\Windows\Temp\*" >nul 2>&1
del /s /f /q "%localappdata%\NVIDIA\DXCache\*" >nul 2>&1
del /s /f /q "%localappdata%\D3DSCache\*" >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo.
echo [OK] Done. Running Disk Cleanup...
cleanmgr.exe /D C
goto optimizewindows

:disableappupd
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t reg_dword /d "1" /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:disabledriverupd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching /v SearchOrderConfig /t reg_dword /d "0" /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:backapps
cls
echo [1] Disable Background Apps
echo [2] Restore Background Apps
set /p "ba=Choice: "
if "%ba%"=="1" (
    Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f >nul
    echo [OK] Disabled.
)
if "%ba%"=="2" (
    Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f >nul
    echo [OK] Restored.
)
timeout /t 2 >nul
goto optimizewindows

:unnservices
:: Example logic
cls
echo Disabling Unnecessary Services (DiagTrack, SysMain...)...
sc config DiagTrack start= disabled >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
sc config MapsBroker start= disabled >nul 2>&1
echo [OK] Done.
pause
goto optimizewindows

:spectre
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:trans
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize /v EnableTransparency /t reg_dword /d "0" /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:memcomp
PowerShell "Disable-MMAgent -MemoryCompression"
echo [OK] Done.
pause
goto optimizewindows

:autostart
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t reg_dword /d "1" /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:defrag
defrag.exe C: /O
pause
goto optimizewindows

:: --------------------------------------------------
:: GAMING BOOST
:: --------------------------------------------------
:gamingboost
cls
color a
title Gaming Boost
echo.
echo                            Gaming Boost
echo             -----------------------------------------------------
echo             [1] Disable Game DVR (Registry)
echo             [2] Disable FSO and Game Bar
echo             [3] Remove Windows Delay
echo             [4] Boost CPU
echo             [5] Boost RAM (Auto Detect)
echo             [6] Boost GPU (MSI Utility)
echo             [7] Remove KBM Delay
echo             [8] Change Power Config
echo             [B] Back
echo             -----------------------------------------------------
set /p "gb=Choice: "
if /i "%gb%"=="B" goto enmain
if "%gb%"=="1" goto gamedvr
if "%gb%"=="2" goto fso
if "%gb%"=="3" goto delay
if "%gb%"=="4" goto cpu
if "%gb%"=="5" goto ram
if "%gb%"=="6" goto gpu
if "%gb%"=="7" goto kbm
if "%gb%"=="8" goto power
goto gamingboost

:gamedvr
cls
echo Applying Registry Tweaks...
:: Applying key GameDVR tweaks
reg add HKCU\System\GameConfigStore /v GameDVR_Enabled /t reg_dword /d "0" /f >nul
reg add HKCU\System\GameConfigStore /v GameDVR_FSEBehaviorMode /t reg_dword /d "2" /f >nul
echo [OK] Game DVR Disabled.
pause
goto gamingboost

:fso
reg add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t reg_dword /d "0" /f >nul
echo [OK] FSO Disabled.
timeout /t 2 >nul
goto gamingboost

:delay
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul
echo Opening Info...
if exist "%RES%\System Properties Performance\INFO.png" start "" "%RES%\System Properties Performance\INFO.png"
start SystemPropertiesPerformance.exe
pause
goto gamingboost

:cpu
cls
echo Select CPU: [1] AMD  [2] INTEL
set /p "cputype=Type: "
:: Use PowerShell instead of WMIC to count cores
for /f "usebackq tokens=*" %%A in (`powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).NumberOfLogicalProcessors"`) do set "cores=%%A"
echo Detected Logical Cores: %cores%
bcdedit /set numproc %cores% >nul
if "%cputype%"=="1" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
)
if "%cputype%"=="2" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0 /f >nul
)
echo [OK] CPU Optimized.
pause
goto gamingboost

:ram
cls
echo Detecting RAM using PowerShell (No WMIC)...
:: PowerShell RAM Detection
for /f "usebackq tokens=*" %%A in (`powershell -NoProfile -Command "[math]::round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)"`) do set "ram_gb=%%A"

echo You have approx: %ram_gb% GB RAM
echo Applying optimization for %ram_gb% GB...

:: Logic based on detected RAM
if %ram_gb% LEQ 4 reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "4194304" /f >nul
if %ram_gb% GEQ 8 reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "8388608" /f >nul
if %ram_gb% GEQ 16 reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "16777216" /f >nul

echo [OK] RAM Optimized.
pause
goto gamingboost

:gpu
cls
echo Opening MSI Utility...
if exist "%RES%\MSI Utility v3\MSI_util_v3.exe" start "" "%RES%\MSI Utility v3\MSI_util_v3.exe"
pause
goto gamingboost

:kbm
cls
echo [1] Mouse Delay [2] Keyboard Delay
set /p "k=Choice: "
if "%k%"=="1" reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t reg_dword /d "10000" /f >nul
if "%k%"=="2" if exist "%RES%\Filter Keys Setter\FilterKeysSetter.exe" start "" "%RES%\Filter Keys Setter\FilterKeysSetter.exe"
pause
goto gamingboost

:power
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul
echo [OK] Ultimate Power Plan Added.
start powercfg.cpl
pause
goto gamingboost

:: --------------------------------------------------
:: NETWORK
:: --------------------------------------------------
:optimizenetwork
cls
echo [1] Fix Network Spikes
echo [2] Clear DNS
echo [3] TCP Optimizer
echo [B] Back
set /p "n=Choice: "
if /i "%n%"=="B" goto enmain
if "%n%"=="1" goto fixnet
if "%n%"=="2" goto cleardns
if "%n%"=="3" goto tcpopt
goto optimizenetwork

:fixnet
netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizenetwork

:cleardns
ipconfig /flushdns >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizenetwork

:tcpopt
if exist "%RES%\TCP Optimizer\TCPOptimizer.exe" start "" "%RES%\TCP Optimizer\TCPOptimizer.exe"
pause
goto optimizenetwork

:: --------------------------------------------------
:: EXTRAS
:: --------------------------------------------------
:componetsupdate
cls
echo [1] Visual C++ [2] DirectX [B] Back
set /p "c=Choice: "
if "%c%"=="1" start "" "https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/"
if "%c%"=="2" start "" "https://www.microsoft.com/en-us/download/details.aspx?id=35"
if /i "%c%"=="B" goto enmain
goto componetsupdate

:enlog
if exist "%RES%\Log\EN_log.txt" start "" "%RES%\Log\EN_log.txt"
goto enmain

:followme
start "" "http://www.instagram.com/hamsypg"
goto enmain