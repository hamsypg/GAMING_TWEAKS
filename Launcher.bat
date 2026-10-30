@echo off
:: ==========================================
:: GAMING TWEAKS by HAMSYPG - Launcher
:: Copyright (c) 2024-2026 HAMSYPG - HamzaPG. All rights reserved.
:: Licensed under the Apache License 2.0 (see LICENSE).
:: ==========================================
setlocal
title GAMING TWEAKS (beta 0.6.5)
color 0b

:: ==========================================
:: 1. SETUP PATHS (إعداد المسارات)
:: ==========================================
:: أهم سطر: كيخلي السكريبت يعرف بلي راه وسط المجلد ديالو
cd /d "%~dp0"

:: Administrator rights: the tweaks write to HKLM, services and power plans
fltmc >nul 2>&1 && goto IsAdmin
echo.
echo    Requesting Administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" <nul
exit /b
:IsAdmin

:: التحقق من وجود الملفات
if exist "Resources\GamingTweaks.ps1" goto Start
color 0c
echo.
echo    [ERROR] Resources folder missing! Extract the whole zip first.
echo    Current Path: %CD%
pause
exit /b 1

:: ==========================================
:: 2. START (التشغيل)
:: ==========================================
:Start
cls
echo.
echo    GAMING TWEAKS by HAMSYPG  -  beta 0.6.5
echo    Copyright (c) 2024-2026 HAMSYPG - HamzaPG. All rights reserved.
echo.
echo    Preparing...

:: Backup ديال القيم الأصلية ديال البيسي (كيتدار غير أول مرة)
powershell -NoProfile -ExecutionPolicy Bypass -File "Resources\Restore\GT_Restore.ps1" -Mode Backup <nul

:: نقطة استعادة النظام
powershell -NoProfile -ExecutionPolicy Bypass -Command "Checkpoint-Computer -Description 'GAMING TWEAKS beta 0.6.5' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction SilentlyContinue" <nul

:: الواجهة (PowerShell): القوائم كتخدم بالفلاش و بالضغط على حرف واحد
powershell -NoProfile -ExecutionPolicy Bypass -File "Resources\GamingTweaks.ps1"
exit /b 0
