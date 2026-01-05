@echo off
setlocal EnableDelayedExpansion
title GAMING TWEAKS Launcher (beta 0.6.0)
color b

:: ==========================================
:: 1. SETUP PATHS (إعداد المسارات)
:: ==========================================
:: أهم سطر: كيخلي السكريبت يعرف بلي راه وسط المجلد المؤقت
cd /d "%~dp0"

:: التحقق من وجود ملفات اللغة
if not exist "Resources\Lang" (
    cls
    color c
    echo.
    echo [ERROR] Resources folder missing!
    echo Current Path: %CD%
    pause
    exit
)

:: ==========================================
:: 2. MENU (القائمة)
:: ==========================================
:LangMenu
cls
echo.
echo    ===============================================
echo       GAMING TWEAKS Cloud (beta 0.6.0)
echo    ===============================================
echo.
echo    [1] English
echo    [2] Francais
echo.
echo    [X] Exit
echo.
set /p "lang_choice=Choice: "

if /i "%lang_choice%"=="X" exit

:: هنا كان المشكل، دابا مصلح باستعمال الأقواس
if "%lang_choice%"=="1" (
    set "TARGET_SCRIPT=Core_EN.bat"
    goto RunScript
)

if "%lang_choice%"=="2" (
    set "TARGET_SCRIPT=Core_FR.bat"
    goto RunScript
)

:: إلا كتب شي حاجة غالطة يرجع
goto LangMenu

:: ==========================================
:: 3. EXECUTE (التشغيل)
:: ==========================================
:RunScript
cls
echo.
echo    [CLOUD] Initializing beta 0.6.0...

:: نقطة استعادة النظام
powershell -NoProfile -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'GT beta 0.6.0 Cloud' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue"

:: تشغيل السكريبت النهائي
if exist "Resources\Lang\%TARGET_SCRIPT%" (
    call "Resources\Lang\%TARGET_SCRIPT%"
) else (
    color c
    echo.
    echo [ERROR] Script not found: Resources\Lang\%TARGET_SCRIPT%
    pause
)
exit
