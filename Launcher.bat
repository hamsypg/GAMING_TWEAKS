@echo off
setlocal EnableDelayedExpansion
title GAMING TWEAKS Launcher (v0.5.7)

:: ==========================================
:: 1. ADMIN CHECK & PATH DEFINITION
:: ==========================================
cd /d "%~dp0"
fsutil dirty query %systemdrive% >nul 2>&1
if %errorLevel% NEQ 0 (
    echo.
    echo    Requesting Administrator Privileges...
    echo.
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0"" %*", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B
)

:: تعريف المتغيرات العامة
set "ROOT=%~dp0"
set "RES=%ROOT%Resources"
set "LANG_DIR=%RES%\Lang"

:: التحقق من سلامة الملفات
if not exist "%LANG_DIR%" (
    color c
    cls
    echo.
    echo [ERROR] Resources folder is missing or incorrect!
    echo Please ensure 'Resources' folder is next to this script.
    pause
    exit
)

:: ==========================================
:: 2. LANGUAGE SELECTION
:: ==========================================
:LangMenu
cls
color b
echo.
echo    ===============================================
echo       GAMING TWEAKS by HAMSYPG (beta v0.5.7)
echo    ===============================================
echo.
echo    [1] English (For English Systems)
echo    [2] Francais (Pour Systemes Francais)
echo.
set /p "lang_choice=Choice / Choix : "

if "%lang_choice%"=="1" set "TARGET_SCRIPT=Core_EN.bat" & goto CreatePoint
if "%lang_choice%"=="2" set "TARGET_SCRIPT=Core_FR.bat" & goto CreatePoint
goto LangMenu

:: ==========================================
:: 3. SILENT RESTORE POINT (PowerShell)
:: ==========================================
:CreatePoint
cls
if "%lang_choice%"=="1" echo    Creating System Restore Point... Please Wait...
if "%lang_choice%"=="2" echo    Creation du point de restauration... Veuillez patienter...

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'GAMING TWEAKS v0.5.7 Auto' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop } catch { exit 1 }" >nul 2>&1

:: ==========================================
:: 4. LAUNCH CORE SCRIPT
:: ==========================================
if exist "%LANG_DIR%\%TARGET_SCRIPT%" (
    call "%LANG_DIR%\%TARGET_SCRIPT%"
) else (
    cls
    color c
    echo.
    echo [ERROR] Core Script missing: %LANG_DIR%\%TARGET_SCRIPT%
    pause
    exit
)
exit