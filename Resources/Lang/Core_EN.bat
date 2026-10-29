@echo off
setlocal EnableExtensions
title GAMING TWEAKS beta 0.6.5 (English)
color b

:: Resources folder (tools, info pictures, log, scripts), found from this file's
:: own folder so it works from any path (Desktop, USB, Temp)
for %%I in ("%~dp0..") do set "RES=%%~fI"
set "PS=powershell -NoProfile -ExecutionPolicy Bypass"

:enmain
cls
color b
title GAMING TWEAKS beta 0.6.5 (English)
echo.
echo                        MAIN MENU
echo.
echo                  Choose Any Number
echo             ----------------------------------------
echo             [1] Optimize Windows
echo             [2] Gaming Boost
echo             [3] Optimize Network
echo             [4] Latest Components Updates
echo             [5] Frame Booster (Max FPS)
echo.
echo             [R] Restore Windows Defaults
echo             [L] View Log
echo             [F] Follow Me
echo             [X] Exit
echo             ----------------------------------------
echo.
set "enmain="
set /p "enmain=Write Here: "

if /i "%enmain%"=="R" goto restoredefaults
if /i "%enmain%"=="L" goto enlog
if /i "%enmain%"=="F" goto followme
if /i "%enmain%"=="X" exit
if "%enmain%"=="1" goto optimizewindows
if "%enmain%"=="2" goto gamingboost
if "%enmain%"=="3" goto optimizenetwork
if "%enmain%"=="4" goto componetsupdate
if "%enmain%"=="5" goto frameboost
goto enmain

:: --------------------------------------------------
:: OPTIMIZE WINDOWS
:: --------------------------------------------------
:optimizewindows
cls
color a
title Optimize Windows
echo.
echo                              Optimize Windows
echo             ----------------------------------------------------------
echo             [1]  Cache, Temporary, Logs Cleaner
echo             [2]  Disable Automatic App Updates (Microsoft Store)
echo             [3]  Disable Automatic Driver Updates
echo             [4]  Disable or Restore Background Apps
echo             [5]  Disable or Restore Unnecessary Services
echo             [6]  Disable Spectre and Meltdown Protection
echo             [7]  Disable Transparency Effects
echo             [8]  Disable or Restore Memory Compression
echo             [9]  Prevent Unnecessary Apps Auto Starting
echo             [10] Optimize Hard Drive
echo             [B]  Back
echo             ----------------------------------------------------------
echo.
set "optw="
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
del /s /f /q "%temp%\*" >nul 2>&1
for /d %%D in ("%temp%\*") do rd /s /q "%%D" >nul 2>&1
del /s /f /q "%SystemRoot%\Temp\*" >nul 2>&1
for /d %%D in ("%SystemRoot%\Temp\*") do rd /s /q "%%D" >nul 2>&1
del /s /f /q "%localappdata%\NVIDIA\DXCache\*" >nul 2>&1
del /s /f /q "%localappdata%\D3DSCache\*" >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo.
echo [OK] Done. Running Disk Cleanup...
cleanmgr.exe /D %SystemDrive:~0,1%
goto optimizewindows

:disableappupd
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f >nul
echo [OK] Microsoft Store apps no longer update by themselves.
timeout /t 2 >nul
goto optimizewindows

:disabledriverupd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:backapps
cls
echo [1] Disable Background Apps
echo [2] Restore Background Apps
set "ba="
set /p "ba=Choice: "
if "%ba%"=="1" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f >nul
    echo [OK] Disabled.
)
if "%ba%"=="2" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f >nul
    echo [OK] Restored.
)
timeout /t 2 >nul
goto optimizewindows

:unnservices
cls
echo Services: DiagTrack (telemetry), SysMain (Superfetch), MapsBroker (offline maps)
echo [1] Disable Unnecessary Services
echo [2] Restore Services
set "us="
set /p "us=Choice: "
if "%us%"=="1" (
    for %%S in (DiagTrack SysMain MapsBroker) do (
        sc stop %%S >nul 2>&1
        sc config %%S start= disabled >nul 2>&1
    )
    echo [OK] Disabled.
)
if "%us%"=="2" (
    sc config DiagTrack start= auto >nul 2>&1
    sc config SysMain start= auto >nul 2>&1
    sc config MapsBroker start= delayed-auto >nul 2>&1
    for %%S in (DiagTrack SysMain MapsBroker) do sc start %%S >nul 2>&1
    echo [OK] Restored.
)
pause
goto optimizewindows

:spectre
cls
color e
echo [WARNING] This turns off the CPU protection against Spectre and Meltdown.
echo           It can give more FPS on old CPUs, but makes your PC less safe.
echo           Undo it any time with [R] Restore Windows Defaults.
echo.
set "sp="
set /p "sp=Disable the protection? (Y/N): "
if /i "%sp%"=="Y" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f >nul
    echo [OK] Done. Restart your PC to apply.
    timeout /t 3 >nul
)
color a
goto optimizewindows

:trans
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f >nul
echo [OK] Done.
timeout /t 2 >nul
goto optimizewindows

:memcomp
cls
echo Memory Compression saves RAM but costs CPU time. Disable it only with 16 GB RAM or more.
echo [1] Disable Memory Compression
echo [2] Restore Memory Compression
set "mc="
set /p "mc=Choice: "
if "%mc%"=="1" (
    %PS% -Command "Disable-MMAgent -MemoryCompression" <nul
    echo [OK] Disabled. Restart your PC to apply.
)
if "%mc%"=="2" (
    %PS% -Command "Enable-MMAgent -MemoryCompression" <nul
    echo [OK] Restored. Restart your PC to apply.
)
pause
goto optimizewindows

:autostart
echo Opening Startup Apps: turn off the apps you don't need at startup...
start "" ms-settings:startupapps
timeout /t 2 >nul
goto optimizewindows

:defrag
defrag.exe %SystemDrive% /O
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
echo             [8] Change Power Config (Ultimate Performance)
echo             [B] Back
echo             -----------------------------------------------------
echo.
set "gb="
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
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f >nul
echo [OK] Game DVR Disabled.
pause
goto gamingboost

:fso
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f >nul
echo [OK] FSO and Game Bar Disabled.
timeout /t 2 >nul
goto gamingboost

:delay
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
echo [OK] Done. Opening Info...
call :open "System Properties Performance\INFO.png"
start "" SystemPropertiesPerformance.exe
pause
goto gamingboost

:cpu
cls
echo Giving games the CPU first (MMCSS + foreground boost)...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f >nul
echo [OK] CPU Optimized.
pause
goto gamingboost

:ram
cls
echo Detecting RAM using PowerShell (No WMIC)...
set "ram_kb="
for /f "usebackq tokens=*" %%A in (`%PS% -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB)" ^<nul`) do set "ram_kb=%%A"
if not defined ram_kb (
    echo [ERROR] Could not detect the RAM size.
    pause
    goto gamingboost
)
set /a ram_gb=(ram_kb + 524288) / 1048576
echo You have approx: %ram_gb% GB RAM
echo Applying optimization for %ram_gb% GB...
:: One svchost process per service group up to the RAM size: fewer processes
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d %ram_kb% /f >nul
echo [OK] RAM Optimized.
pause
goto gamingboost

:gpu
cls
echo Opening MSI Utility...
echo Tick "msi" for your GPU, set its priority to High, then click Apply.
call :open "MSI Utility v3\MSI_util_v3.exe"
pause
goto gamingboost

:kbm
cls
echo [1] Mouse Delay (turn off mouse acceleration)
echo [2] Keyboard Delay (fastest repeat + Filter Keys Setter)
set "k="
set /p "k=Choice: "
if "%k%"=="1" (
    reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f >nul
    reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f >nul
    reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f >nul
    echo [OK] Mouse acceleration off. Sign out or restart to apply.
)
if "%k%"=="2" (
    reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f >nul
    reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f >nul
    echo [OK] Keyboard repeat delay set to the shortest.
    call :open "Filter Keys Setter\FilterKeysSetter.exe"
    call :open "Filter Keys Setter\INFO.png"
)
pause
goto gamingboost

:power
cls
%PS% -File "%RES%\Scripts\GT_FrameBooster.ps1" -Only Power -Lang EN <nul
start "" powercfg.cpl
pause
goto gamingboost

:: --------------------------------------------------
:: NETWORK
:: --------------------------------------------------
:optimizenetwork
cls
color a
title Optimize Network
echo.
echo                           Optimize Network
echo             -----------------------------------------------------
echo             [1] Fix Network Spikes
echo             [2] Clear DNS
echo             [3] TCP Optimizer
echo             [B] Back
echo             -----------------------------------------------------
echo.
set "n="
set /p "n=Choice: "
if /i "%n%"=="B" goto enmain
if "%n%"=="1" goto fixnet
if "%n%"=="2" goto cleardns
if "%n%"=="3" goto tcpopt
goto optimizenetwork

:fixnet
netsh advfirewall firewall delete rule name="StopThrottling" >nul 2>&1
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
echo Opening TCP Optimizer: choose your speed, then "Optimal" and "Apply changes".
call :open "TCP Optimizer\TCPOptimizer.exe"
call :open "TCP Optimizer\STEP1.png"
call :open "TCP Optimizer\STEP2.png"
pause
goto optimizenetwork

:: --------------------------------------------------
:: FRAME BOOSTER
:: --------------------------------------------------
:frameboost
cls
color d
title Frame Booster
echo.
echo                        Frame Booster (Max FPS)
echo             ----------------------------------------------------------
echo             One click, safe and reversible:
echo              - Power plan "GAMING TWEAKS Ultimate" (CPU 100%%, no
echo                core parking, no USB/PCIe sleep)
echo              - Game Mode on
echo              - Hardware-accelerated GPU scheduling
echo              - Optimizations for windowed games
echo              - Games get high CPU, GPU and disk priority
echo              - CPU time goes to the game in the foreground
echo              - Power throttling off
echo              - Background game recording (Game DVR) off
echo              - Precise timer for games (Windows 11)
echo.
echo             Security and Windows Update are not touched.
echo             Undo it any time with [R] Restore Windows Defaults.
echo             ----------------------------------------------------------
echo.
set "fb="
set /p "fb=Apply Frame Booster? (Y/N): "
if /i not "%fb%"=="Y" goto enmain
%PS% -File "%RES%\Scripts\GT_FrameBooster.ps1" -Only All -Lang EN <nul
echo.
pause
goto enmain

:: --------------------------------------------------
:: EXTRAS
:: --------------------------------------------------
:componetsupdate
cls
echo [1] Visual C++  [2] DirectX  [B] Back
set "c="
set /p "c=Choice: "
if "%c%"=="1" start "" "https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/"
if "%c%"=="2" start "" "https://www.microsoft.com/en-us/download/details.aspx?id=35"
if /i "%c%"=="B" goto enmain
goto componetsupdate

:restoredefaults
cls
color e
echo.
echo             Restore Windows Defaults
echo             ----------------------------------------------------------
echo             Undo every tweak of this tool: registry, services, power
echo             plans, network, boot options, firewall rule, memory
echo             compression and Frame Booster.
echo.
echo             [0] 000 - Fresh Windows defaults
echo             [1] My PC backup (values before the first tweak)
echo             [B] Back
echo             ----------------------------------------------------------
echo.
set "rdm="
set /p "rdm=Choice: "
set "rdmode="
if "%rdm%"=="0" set "rdmode=Defaults"
if "%rdm%"=="1" set "rdmode=PCBackup"
if not defined rdmode goto enmain
set "rd="
set /p "rd=Continue? (Y/N): "
if /i not "%rd%"=="Y" goto enmain
%PS% -File "%RES%\Restore\GT_Restore.ps1" -Mode %rdmode% -Lang EN <nul
echo.
pause
goto enmain

:enlog
call :open "Log\EN_log.txt"
goto enmain

:followme
start "" "https://www.instagram.com/hamsypg"
goto enmain

:: --------------------------------------------------
:: Opens a file of the Resources folder: call :open "Folder\File.exe"
:: --------------------------------------------------
:open
if not exist "%RES%\%~1" (
    echo [ERROR] File not found: Resources\%~1
    exit /b 1
)
start "" "%RES%\%~1"
exit /b 0
