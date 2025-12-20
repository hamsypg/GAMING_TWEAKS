@echo off
:: دعم الحروف الفرنسية
chcp 65001 >nul
title GAMING TWEAKS v0.5.7 (Francais)
cls
color b

:frmain
cls
echo.
echo                        MENU PRINCIPAL
echo.
echo                  Choisissez un numero
echo             ----------------------------------------
echo             [1] Optimiser Windows
echo             [2] Boost Jeux (Gaming)
echo             [3] Optimiser Reseau (Network)
echo             [4] Mises a jour composants
echo.
echo             [L] Voir le Journal (Log)
echo             [F] Me Suivre
echo             [X] Quitter
echo             ----------------------------------------
echo.
set /p "frmain=Votre choix : "

if /i "%frmain%"=="L" goto frlog
if /i "%frmain%"=="F" goto followme
if /i "%frmain%"=="X" exit
if "%frmain%"=="1" goto optimizewindows
if "%frmain%"=="2" goto gamingboost
if "%frmain%"=="3" goto optimizenetwork
if "%frmain%"=="4" goto componetsupdate
goto frmain

:: --------------------------------------------------
:: OPTIMISER WINDOWS
:: --------------------------------------------------
:optimizewindows
cls
echo.
echo                              Optimiser Windows
echo             ----------------------------------------------------------
echo             [1]  Nettoyer Cache et Fichiers Temporaires
echo             [2]  Desactiver Mises a jour Auto (Apps)
echo             [3]  Desactiver Mises a jour Auto (Drivers)
echo             [4]  Apps en Arriere-plan (Desactiver/Restaurer)
echo             [5]  Services Inutiles (Desactiver)
echo             [6]  Desactiver Protection Spectre/Meltdown
echo             [7]  Desactiver Transparence
echo             [8]  Desactiver Compression Memoire
echo             [9]  Empecher demarrage auto des apps
echo             [10] Optimiser Disque Dur (Defrag)
echo             [B]  Retour
echo             ----------------------------------------------------------
echo.
set /p "optw=Choix : "
if /i "%optw%"=="B" goto frmain
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
echo Nettoyage en cours...
del /s /f /q "%temp%\*" >nul 2>&1
del /s /f /q "C:\Windows\Temp\*" >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo.
echo [OK] Fait. Lancement Nettoyage Disque...
cleanmgr.exe /D C
goto optimizewindows

:disableappupd
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t reg_dword /d "1" /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:disabledriverupd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching /v SearchOrderConfig /t reg_dword /d "0" /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:backapps
cls
echo [1] Desactiver Apps Arriere-plan
echo [2] Restaurer Apps Arriere-plan
set /p "ba=Choix : "
if "%ba%"=="1" (
    Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f >nul
    echo [OK] Desactive.
)
if "%ba%"=="2" (
    Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 0 /f >nul
    echo [OK] Restaure.
)
timeout /t 2 >nul
goto optimizewindows

:unnservices
cls
echo Desactivation Services Inutiles...
sc config DiagTrack start= disabled >nul 2>&1
sc config SysMain start= disabled >nul 2>&1
echo [OK] Fait.
pause
goto optimizewindows

:spectre
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:trans
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize /v EnableTransparency /t reg_dword /d "0" /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:memcomp
PowerShell "Disable-MMAgent -MemoryCompression"
echo [OK] Fait.
pause
goto optimizewindows

:autostart
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t reg_dword /d "1" /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:defrag
defrag.exe C: /O
pause
goto optimizewindows

:: --------------------------------------------------
:: BOOST JEUX
:: --------------------------------------------------
:gamingboost
cls
color a
title Boost Jeux
echo.
echo                            Boost Jeux
echo             -----------------------------------------------------
echo             [1] Desactiver Game DVR (Registre)
echo             [2] Desactiver FSO et Game Bar
echo             [3] Supprimer Delai Windows
echo             [4] Boost CPU
echo             [5] Boost RAM (Auto Detection)
echo             [6] Boost GPU (MSI Utility)
echo             [7] Supprimer Delai Clavier/Souris
echo             [8] Plan d'alimentation (Ultimate)
echo             [B] Retour
echo             -----------------------------------------------------
set /p "gb=Choix : "
if /i "%gb%"=="B" goto frmain
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
echo Application des tweaks registre...
reg add HKCU\System\GameConfigStore /v GameDVR_Enabled /t reg_dword /d "0" /f >nul
echo [OK] Game DVR Desactive.
pause
goto gamingboost

:fso
reg add HKCU\System\GameConfigStore /v GameDVR_DXGIHonorFSEWindowsCompatible /t reg_dword /d "0" /f >nul
echo [OK] FSO Desactive.
timeout /t 2 >nul
goto gamingboost

:delay
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f >nul
echo Ouverture Infos...
if exist "%RES%\System Properties Performance\INFO.png" start "" "%RES%\System Properties Performance\INFO.png"
start SystemPropertiesPerformance.exe
pause
goto gamingboost

:cpu
cls
echo Selection CPU: [1] AMD  [2] INTEL
set /p "cputype=Type : "
:: استبدال WMIC بـ PowerShell
for /f "usebackq tokens=*" %%A in (`powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).NumberOfLogicalProcessors"`) do set "cores=%%A"
echo Coeurs Logiques Detectes: %cores%
bcdedit /set numproc %cores% >nul
if "%cputype%"=="1" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
)
if "%cputype%"=="2" (
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 0 /f >nul
)
echo [OK] CPU Optimise.
pause
goto gamingboost

:ram
cls
echo Detection RAM via PowerShell (Sans WMIC)...
:: استبدال systeminfo و wmic
for /f "usebackq tokens=*" %%A in (`powershell -NoProfile -Command "[math]::round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)"`) do set "ram_gb=%%A"

echo Vous avez environ : %ram_gb% Go RAM
echo Application optimisation pour %ram_gb% Go...

if %ram_gb% LEQ 4 reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "4194304" /f >nul
if %ram_gb% GEQ 8 reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "8388608" /f >nul
if %ram_gb% GEQ 16 reg add HKLM\SYSTEM\ControlSet001\Control /v SvcHostSplitThresholdInKB /t reg_dword /d "16777216" /f >nul

echo [OK] RAM Optimisee.
pause
goto gamingboost

:gpu
cls
echo Ouverture MSI Utility...
if exist "%RES%\MSI Utility v3\MSI_util_v3.exe" start "" "%RES%\MSI Utility v3\MSI_util_v3.exe"
pause
goto gamingboost

:kbm
cls
echo [1] Delai Souris [2] Delai Clavier
set /p "k=Choix : "
if "%k%"=="1" reg add "HKLM\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed" /v "CursorSensitivity" /t reg_dword /d "10000" /f >nul
if "%k%"=="2" if exist "%RES%\Filter Keys Setter\FilterKeysSetter.exe" start "" "%RES%\Filter Keys Setter\FilterKeysSetter.exe"
pause
goto gamingboost

:power
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 >nul
echo [OK] Plan d'alimentation ajoute.
start powercfg.cpl
pause
goto gamingboost

:: --------------------------------------------------
:: RESEAU (NETWORK)
:: --------------------------------------------------
:optimizenetwork
cls
echo [1] Fixer pics reseau (Spikes)
echo [2] Vider DNS
echo [3] TCP Optimizer
echo [B] Retour
set /p "n=Choix : "
if /i "%n%"=="B" goto frmain
if "%n%"=="1" goto fixnet
if "%n%"=="2" goto cleardns
if "%n%"=="3" goto tcpopt
goto optimizenetwork

:fixnet
netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizenetwork

:cleardns
ipconfig /flushdns >nul
echo [OK] Fait.
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
echo [1] Visual C++ [2] DirectX [B] Retour
set /p "c=Choix : "
if "%c%"=="1" start "" "https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/"
if "%c%"=="2" start "" "https://www.microsoft.com/en-us/download/details.aspx?id=35"
if /i "%c%"=="B" goto frmain
goto componetsupdate

:frlog
:: تأكد من وجود ملف Log خاص بالفرنسية أو استعمل الإنجليزي
if exist "%RES%\Log\EN_log.txt" start "" "%RES%\Log\EN_log.txt"
goto frmain

:followme
start "" "http://www.instagram.com/hamsypg"
goto frmain