# ==========================================
# GAMING TWEAKS - Frame Booster
# ==========================================
# -Only All   : every Frame Booster tweak (Main Menu [5] Frame Booster)
# -Only Power : just the "GAMING TWEAKS Ultimate" power plan (Gaming Boost [8])
# Every change here is undone by GT_Restore.ps1 (000 and PC backup).
param(
    [ValidateSet('All', 'Power')][string]$Only = 'All',
    [ValidateSet('EN', 'FR')][string]$Lang = 'EN'
)

$ErrorActionPreference = 'SilentlyContinue'
$PlanName = 'GAMING TWEAKS Ultimate'

# Messages
$T = @{
    EN = @{
        NoAdmin   = 'Please run GAMING TWEAKS as Administrator.'
        Power     = 'Power plan "GAMING TWEAKS Ultimate" active (CPU 100%, no core parking, no USB/PCIe sleep)'
        NoPower   = 'Could not create the power plan (not supported on this PC)'
        GameMode  = 'Game Mode on'
        Hags      = 'Hardware-accelerated GPU scheduling on (if your GPU supports it)'
        Windowed  = 'Optimizations for windowed games on (lower latency, like fullscreen)'
        Mmcss     = 'Games get high CPU, GPU and disk priority (MMCSS)'
        Foreground = 'CPU time goes to the game in the foreground'
        Throttle  = 'Power throttling off (Windows no longer slows down apps)'
        Dvr       = 'Background game recording (Game DVR) off'
        Timer     = 'Precise timer for games (Windows 11)'
        Done      = 'Frame Booster applied. Restart your PC to get the full boost.'
        Undo      = 'To undo: Main Menu [R] Restore Windows Defaults.'
    }
    FR = @{
        NoAdmin   = 'Lancez GAMING TWEAKS en tant qu''Administrateur.'
        Power     = 'Plan d''alimentation "GAMING TWEAKS Ultimate" actif (CPU 100%, pas de core parking, pas de veille USB/PCIe)'
        NoPower   = 'Impossible de creer le plan d''alimentation (non supporte sur ce PC)'
        GameMode  = 'Mode Jeu active'
        Hags      = 'Planification GPU acceleree materiellement activee (si votre GPU la supporte)'
        Windowed  = 'Optimisations des jeux en fenetre activees (latence plus basse, comme en plein ecran)'
        Mmcss     = 'Les jeux ont une priorite CPU, GPU et disque haute (MMCSS)'
        Foreground = 'Le temps CPU va au jeu au premier plan'
        Throttle  = 'Limitation de l''alimentation desactivee (Windows ne ralentit plus les apps)'
        Dvr       = 'Enregistrement des jeux en arriere-plan (Game DVR) desactive'
        Timer     = 'Minuterie precise pour les jeux (Windows 11)'
        Done      = 'Frame Booster applique. Redemarrez votre PC pour le boost complet.'
        Undo      = 'Pour annuler : Menu Principal [R] Restaurer les parametres par defaut.'
    }
}[$Lang]

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] $($T.NoAdmin)" -ForegroundColor Red
    exit 1
}

function Set-Reg($Path, $Name, $Type, $Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Get-Guid($Text) {
    if ("$Text" -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { return $Matches[0].ToLower() }
    return $null
}

# Makes (once) a copy of Ultimate Performance, or High Performance when
# Ultimate is not available, named "GAMING TWEAKS Ultimate", and activates it.
# The Restore deletes this plan and goes back to the PC's own plan.
function Set-PowerPlan {
    $plan = $null
    foreach ($line in (powercfg /list)) {
        if ($line -like "*($PlanName)*") { $plan = Get-Guid $line }
    }
    if (-not $plan) {
        $plan = Get-Guid (powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-String)
        if (-not $plan) { $plan = Get-Guid (powercfg -duplicatescheme 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c | Out-String) }
        if (-not $plan) { return $false }
        powercfg /changename $plan $PlanName 'Max performance plan made by GAMING TWEAKS' | Out-Null
    }
    $cpu = '54533251-82be-4824-96c1-47b60b740d00'
    powercfg /setacvalueindex $plan $cpu 893dee8e-2bef-41e0-89c6-b55d0929964c 100 | Out-Null   # Minimum processor state
    powercfg /setacvalueindex $plan $cpu 0cc5b647-c1df-4637-891a-dec35c318583 100 | Out-Null   # Core parking: keep all cores
    powercfg /setacvalueindex $plan 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 | Out-Null   # USB selective suspend
    powercfg /setacvalueindex $plan 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 0 | Out-Null   # PCIe link state power management
    powercfg /setactive $plan | Out-Null
    return ((powercfg /getactivescheme | Out-String) -match $plan)
}

function Write-Step($Ok, $Text) {
    if ($Ok) { Write-Host "[OK] $Text" } else { Write-Host "[!] $Text" -ForegroundColor Yellow }
}

Write-Host ''
if (Set-PowerPlan) { Write-Step $true $T.Power } else { Write-Step $false $T.NoPower }
if ($Only -eq 'Power') { exit 0 }

# Game Mode
Set-Reg 'HKCU:\Software\Microsoft\GameBar' 'AutoGameModeEnabled' DWord 1
Set-Reg 'HKCU:\Software\Microsoft\GameBar' 'AllowAutoGameMode' DWord 1
Write-Step $true $T.GameMode

# Hardware-accelerated GPU scheduling (ignored by GPUs that don't support it)
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode' DWord 2
Write-Step $true $T.Hags

# Optimizations for windowed games: keep the user's other DirectX settings
$dx = 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences'
$current = (Get-ItemProperty -Path $dx -Name 'DirectXUserGlobalSettings').DirectXUserGlobalSettings
$parts = @("$current" -split ';' | Where-Object { $_ -and $_ -notlike 'SwapEffectUpgradeEnable=*' }) + 'SwapEffectUpgradeEnable=1'
Set-Reg $dx 'DirectXUserGlobalSettings' String (($parts -join ';') + ';')
Write-Step $true $T.Windowed

# MMCSS: games get the CPU, GPU and disk first
$mm = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
Set-Reg $mm 'SystemResponsiveness' DWord 10
Set-Reg $mm 'NetworkThrottlingIndex' DWord 0xFFFFFFFF
Set-Reg "$mm\Tasks\Games" 'GPU Priority' DWord 8
Set-Reg "$mm\Tasks\Games" 'Priority' DWord 6
Set-Reg "$mm\Tasks\Games" 'Scheduling Category' String 'High'
Set-Reg "$mm\Tasks\Games" 'SFIO Priority' String 'High'
Write-Step $true $T.Mmcss

# Foreground boost: short, variable quantums, 3x for the foreground app
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation' DWord 0x26
Write-Step $true $T.Foreground

# Power throttling (EcoQoS) off
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' 'PowerThrottlingOff' DWord 1
Write-Step $true $T.Throttle

# Game DVR background recording off (Game Bar stays available)
Set-Reg 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' DWord 0
Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' DWord 0
Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'HistoricalCaptureEnabled' DWord 0
Write-Step $true $T.Dvr

# Windows 11: a game's timer request applies system wide again
Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' 'GlobalTimerResolutionRequests' DWord 1
Write-Step $true $T.Timer

Write-Host ''
Write-Host "[OK] $($T.Done)" -ForegroundColor Green
Write-Host "     $($T.Undo)"
exit 0
