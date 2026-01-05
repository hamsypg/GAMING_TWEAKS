@echo off
setlocal EnableDelayedExpansion
title GAMING TWEAKS Cloud Console (v0.6.0)
color b

:: ==========================================
:: 1. INITIALIZATION & CHECKS
:: ==========================================
cd /d "%~dp0"

:: التحقق من Admin (سريع وخفيف لأن الـ Loader قام بالمهمة)
fsutil dirty query %systemdrive% >nul 2>&1
if %errorLevel% NEQ 0 (
    color c
    cls
    echo.
    echo [ERROR] Administrator privileges required!
    echo Please run the Cloud Loader as Administrator.
    pause
    exit
)

:: تعريف المسارات
set "ROOT=%~dp0"
set "RES=%ROOT%Resources"
set "LANG_DIR=%RES%\Lang"

:: التحقق من أن الملفات تحملات بشكل صحيح
if not exist "%LANG_DIR%" (
    color c
    cls
    echo.
    echo [FATAL ERROR] Cloud Resources Incomplete!
    echo The downloaded package seems corrupted or empty.
    echo Path searched: %LANG_DIR%
    pause
    exit
)

:: ==========================================
:: 2. CLOUD DASHBOARD
:: ==========================================
:LangMenu
cls
color b
echo.
echo    ===============================================
echo       GAMING TWEAKS CLOUD (v0.6.0) - Connected
echo    ===============================================
echo    Status: Online | Session: Temporary
echo    ===============================================
echo.
echo    [1] English (Global)
echo    [2] Francais (Europe/Afrique)
echo.
echo    [X] Close Session
echo.
set /p "lang_choice=Command : "

if /i "%lang_choice%"=="X" exit
if "%lang_choice%"=="1" set "TARGET_SCRIPT=Core_EN.bat" & goto CloudInit
if "%lang_choice%"=="2" set "TARGET_SCRIPT=Core_FR.bat" & goto CloudInit
goto LangMenu

:: ==========================================
:: 3. SAFEGUARD & LAUNCH
:: ==========================================
:CloudInit
cls
echo.
echo    [CLOUD SYNC] Initializing Environment...

:: نقطة استعادة النظام (ضرورية للأمان)
if "%lang_choice%"=="1" echo    [SAFETY] Creating System Restore Point...
if "%lang_choice%"=="2" echo    [SECURITE] Creation du point de restauration...

powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Checkpoint-Computer -Description 'GT Cloud v0.6.0 Pre-Tweak' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop } catch { exit 1 }" >nul 2>&1

:: ==========================================
:: 4. EXECUTE CORE ENGINE
:: ==========================================
if exist "%LANG_DIR%\%TARGET_SCRIPT%" (
    cls
    :: تشغيل الكود الأساسي
    call "%LANG_DIR%\%TARGET_SCRIPT%"
) else (
    cls
    color c
    echo.
    echo [ERROR] Core Script Not Found!
    echo Target: %TARGET_SCRIPT%
    pause
    exit
)

:: النهاية (التحكم كيرجع للـ Loader باش يمسح)
exit
