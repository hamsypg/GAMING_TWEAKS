@echo off
setlocal EnableExtensions
:: دعم الحروف الفرنسية
chcp 65001 >nul
title GAMING TWEAKS beta 0.7.0 (Francais)
color b

:: Dossier Resources (outils, images d'info, journal, scripts), trouve depuis le
:: dossier de ce fichier pour marcher depuis n'importe ou (Bureau, USB, Temp)
for %%I in ("%~dp0..") do set "RES=%%~fI"
set "PS=powershell -NoProfile -ExecutionPolicy Bypass"

:frmain
cls
color b
title GAMING TWEAKS beta 0.7.0 (Francais)
echo.
echo                        MENU PRINCIPAL
echo.
echo                  Choisissez un numero
echo             ----------------------------------------
echo             [1] Optimiser Windows
echo             [2] Boost Jeux (Gaming)
echo             [3] Optimiser Reseau (Network)
echo             [4] Mises a jour composants
echo             [5] Frame Booster (FPS Max)
echo.
echo             [R] Restaurer les parametres par defaut de Windows
echo             [L] Voir le Journal (Log)
echo             [F] Me Suivre
echo             [X] Quitter
echo             ----------------------------------------
echo.
set "frmain="
set /p "frmain=Votre choix : "

if /i "%frmain%"=="R" goto restoredefaults
if /i "%frmain%"=="L" goto frlog
if /i "%frmain%"=="F" goto followme
if /i "%frmain%"=="X" exit
if "%frmain%"=="1" goto optimizewindows
if "%frmain%"=="2" goto gamingboost
if "%frmain%"=="3" goto optimizenetwork
if "%frmain%"=="4" goto componetsupdate
if "%frmain%"=="5" goto frameboost
goto frmain

:: --------------------------------------------------
:: OPTIMISER WINDOWS
:: --------------------------------------------------
:optimizewindows
cls
color a
title Optimiser Windows
echo.
echo                              Optimiser Windows
echo             ----------------------------------------------------------
echo             [1]  Nettoyer Cache et Fichiers Temporaires
echo             [2]  Desactiver Mises a jour Auto (Apps Microsoft Store)
echo             [3]  Desactiver Mises a jour Auto (Drivers)
echo             [4]  Apps en Arriere-plan (Desactiver/Restaurer)
echo             [5]  Services Inutiles (Desactiver/Restaurer)
echo             [6]  Desactiver Protection Spectre/Meltdown
echo             [7]  Desactiver Transparence
echo             [8]  Compression Memoire (Desactiver/Restaurer)
echo             [9]  Empecher demarrage auto des apps
echo             [10] Optimiser Disque Dur (Defrag)
echo             [B]  Retour
echo             ----------------------------------------------------------
echo.
set "optw="
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
for /d %%D in ("%temp%\*") do rd /s /q "%%D" >nul 2>&1
del /s /f /q "%SystemRoot%\Temp\*" >nul 2>&1
for /d %%D in ("%SystemRoot%\Temp\*") do rd /s /q "%%D" >nul 2>&1
del /s /f /q "%localappdata%\NVIDIA\DXCache\*" >nul 2>&1
del /s /f /q "%localappdata%\D3DSCache\*" >nul 2>&1
ipconfig /flushdns >nul 2>&1
echo.
echo [OK] Fait. Lancement Nettoyage Disque...
cleanmgr.exe /D %SystemDrive:~0,1%
goto optimizewindows

:disableappupd
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f >nul
echo [OK] Les apps du Microsoft Store ne se mettent plus a jour seules.
timeout /t 2 >nul
goto optimizewindows

:disabledriverupd
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 0 /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:backapps
cls
echo [1] Desactiver Apps Arriere-plan
echo [2] Restaurer Apps Arriere-plan
set "ba="
set /p "ba=Choix : "
if "%ba%"=="1" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f >nul
    echo [OK] Desactive.
)
if "%ba%"=="2" (
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 0 /f >nul
    echo [OK] Restaure.
)
timeout /t 2 >nul
goto optimizewindows

:unnservices
cls
echo Services : DiagTrack (telemetrie), SysMain (Superfetch), MapsBroker (cartes hors ligne)
echo [1] Desactiver Services Inutiles
echo [2] Restaurer Services
set "us="
set /p "us=Choix : "
if "%us%"=="1" (
    for %%S in (DiagTrack SysMain MapsBroker) do (
        sc stop %%S >nul 2>&1
        sc config %%S start= disabled >nul 2>&1
    )
    echo [OK] Desactive.
)
if "%us%"=="2" (
    sc config DiagTrack start= auto >nul 2>&1
    sc config SysMain start= auto >nul 2>&1
    sc config MapsBroker start= delayed-auto >nul 2>&1
    for %%S in (DiagTrack SysMain MapsBroker) do sc start %%S >nul 2>&1
    echo [OK] Restaure.
)
pause
goto optimizewindows

:spectre
cls
color e
echo [ATTENTION] Ceci desactive la protection CPU contre Spectre et Meltdown.
echo             Plus de FPS sur les vieux CPU, mais votre PC est moins protege.
echo             Annulez a tout moment avec [R] Restaurer les parametres par defaut.
echo.
set "sp="
set /p "sp=Desactiver la protection ? (O/N) : "
if /i "%sp%"=="O" (
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 3 /f >nul
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f >nul
    echo [OK] Fait. Redemarrez votre PC pour appliquer.
    timeout /t 3 >nul
)
color a
goto optimizewindows

:trans
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f >nul
echo [OK] Fait.
timeout /t 2 >nul
goto optimizewindows

:memcomp
cls
echo La Compression Memoire economise la RAM mais coute du CPU. A desactiver seulement avec 16 Go de RAM ou plus.
echo [1] Desactiver Compression Memoire
echo [2] Restaurer Compression Memoire
set "mc="
set /p "mc=Choix : "
if "%mc%"=="1" (
    %PS% -Command "Disable-MMAgent -MemoryCompression" <nul
    echo [OK] Desactive. Redemarrez votre PC pour appliquer.
)
if "%mc%"=="2" (
    %PS% -Command "Enable-MMAgent -MemoryCompression" <nul
    echo [OK] Restaure. Redemarrez votre PC pour appliquer.
)
pause
goto optimizewindows

:autostart
echo Ouverture Apps au demarrage : desactivez les apps inutiles au demarrage...
start "" ms-settings:startupapps
timeout /t 2 >nul
goto optimizewindows

:defrag
defrag.exe %SystemDrive% /O
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
echo             [8] Plan d'alimentation (Performances optimales)
echo             [B] Retour
echo             -----------------------------------------------------
echo.
set "gb="
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
reg add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f >nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f >nul
echo [OK] Game DVR Desactive.
pause
goto gamingboost

:fso
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehaviorMode /t REG_DWORD /d 2 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f >nul
reg add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\GameBar" /v UseNexusForGameBarEnabled /t REG_DWORD /d 0 /f >nul
echo [OK] FSO et Game Bar Desactives.
timeout /t 2 >nul
goto gamingboost

:delay
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 4294967295 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f >nul
echo [OK] Fait. Ouverture Infos...
call :open "System Properties Performance\INFO.png"
start "" SystemPropertiesPerformance.exe
pause
goto gamingboost

:cpu
cls
echo Priorite CPU aux jeux (MMCSS + boost premier plan)...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f >nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f >nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v Win32PrioritySeparation /t REG_DWORD /d 38 /f >nul
echo [OK] CPU Optimise.
pause
goto gamingboost

:ram
cls
echo Detection RAM via PowerShell (Sans WMIC)...
set "ram_kb="
for /f "usebackq tokens=*" %%A in (`%PS% -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB)" ^<nul`) do set "ram_kb=%%A"
if not defined ram_kb (
    echo [ERREUR] Impossible de detecter la taille de la RAM.
    pause
    goto gamingboost
)
set /a ram_gb=(ram_kb + 524288) / 1048576
echo Vous avez environ : %ram_gb% Go RAM
echo Application optimisation pour %ram_gb% Go...
:: Un processus svchost par groupe de services jusqu'a la taille de la RAM : moins de processus
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v SvcHostSplitThresholdInKB /t REG_DWORD /d %ram_kb% /f >nul
echo [OK] RAM Optimisee.
pause
goto gamingboost

:gpu
cls
echo Ouverture MSI Utility...
echo Cochez "msi" pour votre GPU, mettez sa priorite sur High, puis cliquez Apply.
call :open "MSI Utility v3\MSI_util_v3.exe"
pause
goto gamingboost

:kbm
cls
echo [1] Delai Souris (desactiver l'acceleration)
echo [2] Delai Clavier (repetition la plus rapide + Filter Keys Setter)
set "k="
set /p "k=Choix : "
if "%k%"=="1" (
    reg add "HKCU\Control Panel\Mouse" /v MouseSpeed /t REG_SZ /d 0 /f >nul
    reg add "HKCU\Control Panel\Mouse" /v MouseThreshold1 /t REG_SZ /d 0 /f >nul
    reg add "HKCU\Control Panel\Mouse" /v MouseThreshold2 /t REG_SZ /d 0 /f >nul
    echo [OK] Acceleration souris desactivee. Deconnectez-vous ou redemarrez pour appliquer.
)
if "%k%"=="2" (
    reg add "HKCU\Control Panel\Keyboard" /v KeyboardDelay /t REG_SZ /d 0 /f >nul
    reg add "HKCU\Control Panel\Keyboard" /v KeyboardSpeed /t REG_SZ /d 31 /f >nul
    echo [OK] Delai de repetition clavier au minimum.
    call :open "Filter Keys Setter\FilterKeysSetter.exe"
    call :open "Filter Keys Setter\INFO.png"
)
pause
goto gamingboost

:power
cls
%PS% -File "%RES%\Scripts\GT_FrameBooster.ps1" -Only Power -Lang FR <nul
start "" powercfg.cpl
pause
goto gamingboost

:: --------------------------------------------------
:: RESEAU (NETWORK)
:: --------------------------------------------------
:optimizenetwork
cls
color a
title Optimiser Reseau
echo.
echo                           Optimiser Reseau
echo             -----------------------------------------------------
echo             [1] Fixer pics reseau (Spikes)
echo             [2] Vider DNS
echo             [3] TCP Optimizer
echo             [B] Retour
echo             -----------------------------------------------------
echo.
set "n="
set /p "n=Choix : "
if /i "%n%"=="B" goto frmain
if "%n%"=="1" goto fixnet
if "%n%"=="2" goto cleardns
if "%n%"=="3" goto tcpopt
goto optimizenetwork

:fixnet
netsh advfirewall firewall delete rule name="StopThrottling" >nul 2>&1
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
echo Ouverture TCP Optimizer : choisissez votre debit, puis "Optimal" et "Apply changes".
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
echo                        Frame Booster (FPS Max)
echo             ----------------------------------------------------------
echo             Un clic, sans risque et reversible :
echo              - Plan d'alimentation "GAMING TWEAKS Ultimate" (CPU 100%%,
echo                pas de core parking, pas de veille USB/PCIe)
echo              - Mode Jeu active
echo              - Planification GPU acceleree materiellement
echo              - Optimisations des jeux en fenetre
echo              - Priorite CPU, GPU et disque haute pour les jeux
echo              - Le temps CPU va au jeu au premier plan
echo              - Limitation de l'alimentation desactivee
echo              - Enregistrement des jeux en arriere-plan (Game DVR) desactive
echo              - Minuterie precise pour les jeux (Windows 11)
echo.
echo             La securite et Windows Update ne sont pas modifies.
echo             Annulez a tout moment avec [R] Restaurer les parametres par defaut.
echo             ----------------------------------------------------------
echo.
set "fb="
set /p "fb=Appliquer Frame Booster ? (O/N) : "
if /i not "%fb%"=="O" goto frmain
%PS% -File "%RES%\Scripts\GT_FrameBooster.ps1" -Only All -Lang FR <nul
echo.
pause
goto frmain

:: --------------------------------------------------
:: EXTRAS
:: --------------------------------------------------
:componetsupdate
cls
echo [1] Visual C++  [2] DirectX  [B] Retour
set "c="
set /p "c=Choix : "
if "%c%"=="1" start "" "https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/"
if "%c%"=="2" start "" "https://www.microsoft.com/en-us/download/details.aspx?id=35"
if /i "%c%"=="B" goto frmain
goto componetsupdate

:restoredefaults
cls
color e
echo.
echo             Restaurer les parametres par defaut de Windows
echo             ----------------------------------------------------------
echo             Annule chaque tweak de cet outil : registre, services,
echo             plans d'alimentation, reseau, demarrage, regle pare-feu,
echo             compression memoire et Frame Booster.
echo.
echo             [0] 000 - Valeurs par defaut d'un Windows neuf
echo             [1] Sauvegarde de mon PC (avant le premier tweak)
echo             [B] Retour
echo             ----------------------------------------------------------
echo.
set "rdm="
set /p "rdm=Choix : "
set "rdmode="
if "%rdm%"=="0" set "rdmode=Defaults"
if "%rdm%"=="1" set "rdmode=PCBackup"
if not defined rdmode goto frmain
set "rd="
set /p "rd=Continuer ? (O/N) : "
if /i not "%rd%"=="O" goto frmain
%PS% -File "%RES%\Restore\GT_Restore.ps1" -Mode %rdmode% -Lang FR <nul
echo.
pause
goto frmain

:frlog
call :open "Log\EN_log.txt"
goto frmain

:followme
start "" "https://www.instagram.com/hamsypg"
goto frmain

:: --------------------------------------------------
:: Ouvre un fichier du dossier Resources : call :open "Dossier\Fichier.exe"
:: --------------------------------------------------
:open
if not exist "%RES%\%~1" (
    echo [ERREUR] Fichier introuvable : Resources\%~1
    exit /b 1
)
start "" "%RES%\%~1"
exit /b 0
