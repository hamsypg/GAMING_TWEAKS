# ==========================================
# GAMING TWEAKS by HAMSYPG
# Copyright (c) 2024-2026 HAMSYPG - HamzaPG. All rights reserved.
# Licensed under the Apache License 2.0 (see LICENSE).
# ==========================================
# Menus: arrow keys + Enter, or the item's key. No typing.
# When the input is redirected (tests), each line of input is one key press:
# a character, an empty line for Enter, or UP / DOWN / ESC.
param(
    [ValidateSet('', 'EN', 'FR')][string]$Lang = ''
)

$ErrorActionPreference = 'SilentlyContinue'
$Version = 'beta 0.6.5'
$Res = $PSScriptRoot
$Ps = Join-Path $PSHOME 'powershell.exe'
$Redirected = [Console]::IsInputRedirected

# ------------------------------------------
# Look
# ------------------------------------------
$W = 66
$Frame = 'DarkCyan'
$C = @{
    TL = [char]0x2554; TR = [char]0x2557; BL = [char]0x255A; BR = [char]0x255D
    H = [char]0x2550; V = [char]0x2551; ML = [char]0x255F; MR = [char]0x2562; h = [char]0x2500
    Dot = [char]0x2022; Arrow = [char]0x25BA
}

function Write-Edge($Left, $Fill, $Right) {
    Write-Host (' ' + $Left + ([string]$Fill * $W) + $Right) -ForegroundColor $Frame
}

function Write-Row([string]$Text = '', [string]$Fg = 'Gray', [string]$Bg = '', [switch]$Center) {
    if ($Text.Length -gt $W - 2) { $Text = $Text.Substring(0, $W - 2) }
    if ($Center) { $Text = (' ' * [math]::Floor(($W - $Text.Length) / 2)) + $Text }
    else { $Text = '  ' + $Text }
    $Text = $Text.PadRight($W)
    Write-Host (' ' + $C.V) -NoNewline -ForegroundColor $Frame
    if ($Bg) { Write-Host $Text -NoNewline -ForegroundColor $Fg -BackgroundColor $Bg }
    else { Write-Host $Text -NoNewline -ForegroundColor $Fg }
    Write-Host $C.V -ForegroundColor $Frame
}

function Show-Header([string]$Title) {
    Clear-Host
    $Host.UI.RawUI.WindowTitle = "GAMING TWEAKS $Version  |  $([char]0xA9) HAMSYPG"
    Write-Host ''
    Write-Edge $C.TL $C.H $C.TR
    Write-Row ''
    Write-Row 'G A M I N G   T W E A K S' 'Cyan' -Center
    Write-Row "by HAMSYPG  $($C.Dot)  $Version" 'DarkGray' -Center
    Write-Row $S.Tagline 'DarkGray' -Center
    Write-Row ''
    Write-Edge $C.ML $C.h $C.MR
    Write-Row $Title 'White' -Center
    Write-Edge $C.ML $C.h $C.MR
}

function Show-Footer {
    Write-Edge $C.ML $C.h $C.MR
    Write-Row $S.Hints 'DarkGray' -Center
    Write-Edge $C.BL $C.H $C.BR
    Write-Host ('  ' + $S.Rights) -ForegroundColor DarkGray
    Write-Host ('  ' + $S.License + '  ' + $C.Dot + '  github.com/hamsypg/GAMING_TWEAKS') -ForegroundColor DarkGray
}

# ------------------------------------------
# Input
# ------------------------------------------
function Read-Choice {
    if ($Redirected) {
        $line = [Console]::In.ReadLine()
        if ($null -eq $line) { exit 0 }   # end of the test input
        $line = $line.Trim().ToUpper()
        switch ($line) {
            ''     { return @{ Key = 'Enter'; Char = '' } }
            'UP'   { return @{ Key = 'UpArrow'; Char = '' } }
            'DOWN' { return @{ Key = 'DownArrow'; Char = '' } }
            'ESC'  { return @{ Key = 'Escape'; Char = '' } }
        }
        return @{ Key = 'Char'; Char = $line.Substring(0, 1) }
    }
    $k = [Console]::ReadKey($true)
    return @{ Key = "$($k.Key)"; Char = "$($k.KeyChar)".ToUpper() }
}

# Items: @{ Key; Text; Color; Do = { ... } }, or @{ Sep = $true } for a blank row.
# Returns the chosen item; Esc returns the B (Back) or X (Exit) item.
$LastSel = @{}
function Show-Menu([string]$Title, [array]$Items, [string[]]$Info = @()) {
    $pick = @(for ($i = 0; $i -lt $Items.Count; $i++) { if (-not $Items[$i].Sep) { $i } })
    $sel = [int]$LastSel[$Title]
    if ($sel -ge $pick.Count) { $sel = 0 }
    while ($true) {
        Show-Header $Title
        Write-Row ''
        foreach ($line in $Info) { Write-Row $line 'DarkGray' }
        if ($Info) { Write-Row '' }
        for ($i = 0; $i -lt $Items.Count; $i++) {
            $it = $Items[$i]
            if ($it.Sep) { Write-Row ''; continue }
            $label = "[$($it.Key)]  $($it.Text)"
            if ($i -eq $pick[$sel]) { Write-Row ("$($C.Arrow) " + $label) 'Black' 'Cyan' }
            else {
                $fg = if ($it.Color) { $it.Color } else { 'Gray' }
                Write-Row ('  ' + $label) $fg
            }
        }
        Write-Row ''
        Show-Footer
        $c = Read-Choice
        switch ($c.Key) {
            'UpArrow'   { $sel = ($sel - 1 + $pick.Count) % $pick.Count; continue }
            'DownArrow' { $sel = ($sel + 1) % $pick.Count; continue }
            'Home'      { $sel = 0; continue }
            'End'       { $sel = $pick.Count - 1; continue }
            'Enter'     { $LastSel[$Title] = $sel; return $Items[$pick[$sel]] }
            'Escape'    { return ($Items | Where-Object { $_.Key -eq 'B' -or $_.Key -eq 'X' } | Select-Object -First 1) }
        }
        if ($c.Char) {
            for ($j = 0; $j -lt $pick.Count; $j++) {
                if ($Items[$pick[$j]].Key -eq $c.Char) { $LastSel[$Title] = $j; return $Items[$pick[$j]] }
            }
        }
    }
}

# Runs a menu until Back / Exit. Each item's Do block runs on its own screen.
function Invoke-Menu([string]$Title, [array]$Items, [string[]]$Info = @()) {
    while ($true) {
        $it = Show-Menu $Title $Items $Info
        if (-not $it -or $it.Key -eq 'B') { return }
        if ($it.Key -eq 'X') { Exit-App }
        if ($it.Menu) { & $it.Do; continue }
        Show-Header $it.Text
        Write-Host ''
        & $it.Do
        Wait-Key
    }
}

# A small menu that runs one choice, then goes back (Disable / Restore...)
function Invoke-Choice([string]$Title, [array]$Items, [string[]]$Info = @()) {
    $it = Show-Menu $Title ($Items + @(@{ Sep = $true }, @{ Key = 'B'; Text = $S.Back }) ) $Info
    if (-not $it -or $it.Key -eq 'B') { return }
    Show-Header $it.Text
    Write-Host ''
    & $it.Do
    Wait-Key
}

function Confirm-Step([string]$Question) {
    Write-Host ''
    Write-Host "  $Question   " -NoNewline -ForegroundColor Yellow
    Write-Host "[$($S.YesKey)] $($S.Yes)   [$($S.NoKey)] $($S.No)" -ForegroundColor White
    while ($true) {
        $c = Read-Choice
        if ($c.Char -eq $S.YesKey -or $c.Char -eq 'Y') { return $true }
        if ($c.Char -eq $S.NoKey -or $c.Key -eq 'Escape') { Write-Info $S.Cancelled; return $false }
    }
}

function Wait-Key {
    Write-Host ''
    Write-Host "  $($S.AnyKey)" -ForegroundColor DarkGray
    Read-Choice | Out-Null
}

function Exit-App {
    Clear-Host
    exit 0
}

# ------------------------------------------
# Output and helpers
# ------------------------------------------
function Write-Ok($Text)   { Write-Host '  [OK] ' -NoNewline -ForegroundColor Green; Write-Host $Text }
function Write-Info($Text) { Write-Host "  $Text" -ForegroundColor Gray }
function Write-Warn($Text) { Write-Host '  [!] ' -NoNewline -ForegroundColor Yellow; Write-Host $Text -ForegroundColor Yellow }
function Write-Err($Text)  { Write-Host '  [ERROR] ' -NoNewline -ForegroundColor Red; Write-Host $Text }

function Set-Reg($Path, $Name, $Type, $Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Open-Resource([string]$Rel) {
    $p = Join-Path $Res $Rel
    if (Test-Path -LiteralPath $p) { Start-Process -FilePath $p }
    else { Write-Err "$($S.NotFound) Resources\$Rel" }
}

# Child scripts get an empty input: they must never eat the menu's key presses
function Invoke-Script([string]$Rel, [string[]]$Arguments) {
    $null | & $Ps -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Res $Rel) @Arguments
}

$MM    = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
$Games = "$MM\Tasks\Games"
$GameCfg = 'HKCU:\System\GameConfigStore'
$Svc = 'DiagTrack', 'SysMain', 'MapsBroker'

# ------------------------------------------
# OPTIMIZE WINDOWS
# ------------------------------------------
function Show-OptimizeWindows {
    Invoke-Menu $S.OptimizeWindows @(
        @{ Key = '1'; Text = $S.Clean; Do = {
            Write-Info $S.Cleaning
            foreach ($d in $env:TEMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\NVIDIA\DXCache", "$env:LOCALAPPDATA\D3DSCache") {
                Get-ChildItem -LiteralPath $d -Force | Remove-Item -Recurse -Force
            }
            ipconfig /flushdns | Out-Null
            Write-Ok $S.CleanDone
            Start-Process cleanmgr.exe -ArgumentList "/D $($env:SystemDrive.Substring(0, 1))"
        } }
        @{ Key = '2'; Text = $S.StoreUpdates; Do = {
            Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' 'AutoDownload' DWord 2
            Write-Ok $S.StoreDone
        } }
        @{ Key = '3'; Text = $S.DriverUpdates; Do = {
            Set-Reg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig' DWord 0
            Write-Ok $S.Done
        } }
        @{ Key = '4'; Text = $S.BgApps; Menu = $true; Do = {
            $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'
            Invoke-Choice $S.BgApps @(
                @{ Key = '1'; Text = $S.Disable; Do = { Set-Reg $k 'GlobalUserDisabled' DWord 1; Write-Ok $S.Disabled } }
                @{ Key = '2'; Text = $S.RestoreIt; Do = { Set-Reg $k 'GlobalUserDisabled' DWord 0; Write-Ok $S.Restored } }
            )
        } }
        @{ Key = '5'; Text = $S.Services; Menu = $true; Do = {
            Invoke-Choice $S.Services @(
                @{ Key = '1'; Text = $S.Disable; Do = {
                    foreach ($n in $Svc) { Stop-Service -Name $n -Force; sc.exe config $n start= disabled | Out-Null }
                    Write-Ok $S.Disabled
                } }
                @{ Key = '2'; Text = $S.RestoreIt; Do = {
                    sc.exe config DiagTrack start= auto | Out-Null
                    sc.exe config SysMain start= auto | Out-Null
                    sc.exe config MapsBroker start= delayed-auto | Out-Null
                    foreach ($n in $Svc) { Start-Service -Name $n }
                    Write-Ok $S.Restored
                } }
            ) @($S.ServicesInfo)
        } }
        @{ Key = '6'; Text = $S.Spectre; Do = {
            Write-Warn $S.SpectreWarn
            Write-Info $S.Undo
            if (Confirm-Step $S.Continue) {
                $mem = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
                Set-Reg $mem 'FeatureSettingsOverride' DWord 3
                Set-Reg $mem 'FeatureSettingsOverrideMask' DWord 3
                Write-Ok "$($S.Done) $($S.Restart)"
            }
        } }
        @{ Key = '7'; Text = $S.Transparency; Do = {
            Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency' DWord 0
            Write-Ok $S.Done
        } }
        @{ Key = '8'; Text = $S.MemComp; Menu = $true; Do = {
            Invoke-Choice $S.MemComp @(
                @{ Key = '1'; Text = $S.Disable; Do = { Disable-MMAgent -MemoryCompression; Write-Ok "$($S.Disabled) $($S.Restart)" } }
                @{ Key = '2'; Text = $S.RestoreIt; Do = { Enable-MMAgent -MemoryCompression; Write-Ok "$($S.Restored) $($S.Restart)" } }
            ) @($S.MemCompInfo)
        } }
        @{ Key = '9'; Text = $S.Startup; Do = {
            Write-Info $S.StartupInfo
            Start-Process 'ms-settings:startupapps'
        } }
        @{ Key = '0'; Text = $S.Defrag; Do = { defrag.exe $env:SystemDrive /O } }
        @{ Sep = $true }
        @{ Key = 'B'; Text = $S.Back }
    )
}

# ------------------------------------------
# GAMING BOOST
# ------------------------------------------
function Show-GamingBoost {
    Invoke-Menu $S.GamingBoost @(
        @{ Key = '1'; Text = $S.GameDvr; Do = {
            Set-Reg $GameCfg 'GameDVR_Enabled' DWord 0
            Set-Reg 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR' 'AppCaptureEnabled' DWord 0
            Set-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR' DWord 0
            Write-Ok $S.GameDvrDone
        } }
        @{ Key = '2'; Text = $S.Fso; Do = {
            Set-Reg $GameCfg 'GameDVR_FSEBehaviorMode' DWord 2
            Set-Reg $GameCfg 'GameDVR_FSEBehavior' DWord 2
            Set-Reg $GameCfg 'GameDVR_HonorUserFSEBehaviorMode' DWord 1
            Set-Reg $GameCfg 'GameDVR_DXGIHonorFSEWindowsCompatible' DWord 1
            Set-Reg 'HKCU:\Software\Microsoft\GameBar' 'UseNexusForGameBarEnabled' DWord 0
            Write-Ok $S.FsoDone
        } }
        @{ Key = '3'; Text = $S.Delay; Do = {
            Set-Reg $MM 'NetworkThrottlingIndex' DWord 0xFFFFFFFF
            Set-Reg $MM 'SystemResponsiveness' DWord 0
            Write-Ok $S.DelayDone
            Open-Resource 'System Properties Performance\INFO.png'
            Start-Process SystemPropertiesPerformance.exe
        } }
        @{ Key = '4'; Text = $S.Cpu; Do = {
            Write-Info $S.CpuInfo
            Set-Reg $Games 'GPU Priority' DWord 8
            Set-Reg $Games 'Priority' DWord 6
            Set-Reg $Games 'Scheduling Category' String 'High'
            Set-Reg $Games 'SFIO Priority' String 'High'
            Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation' DWord 0x26
            Write-Ok $S.CpuDone
        } }
        @{ Key = '5'; Text = $S.Ram; Do = {
            Write-Info $S.RamDetect
            $kb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1KB)
            if (-not $kb) { Write-Err $S.RamFail; return }
            # One svchost process per service group up to the RAM size: fewer processes
            Set-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB' DWord $kb
            Write-Ok ($S.RamDone -f [math]::Round($kb / 1MB))
        } }
        @{ Key = '6'; Text = $S.Gpu; Do = {
            Write-Info $S.GpuInfo
            Open-Resource 'MSI Utility v3\MSI_util_v3.exe'
        } }
        @{ Key = '7'; Text = $S.Kbm; Menu = $true; Do = {
            Invoke-Choice $S.Kbm @(
                @{ Key = '1'; Text = $S.Mouse; Do = {
                    foreach ($n in 'MouseSpeed', 'MouseThreshold1', 'MouseThreshold2') { Set-Reg 'HKCU:\Control Panel\Mouse' $n String '0' }
                    Write-Ok "$($S.MouseDone) $($S.SignOut)"
                } }
                @{ Key = '2'; Text = $S.Keyboard; Do = {
                    Set-Reg 'HKCU:\Control Panel\Keyboard' 'KeyboardDelay' String '0'
                    Set-Reg 'HKCU:\Control Panel\Keyboard' 'KeyboardSpeed' String '31'
                    Write-Ok $S.KeyboardDone
                    Open-Resource 'Filter Keys Setter\FilterKeysSetter.exe'
                    Open-Resource 'Filter Keys Setter\INFO.png'
                } }
            )
        } }
        @{ Key = '8'; Text = $S.Power; Do = {
            Invoke-Script 'Scripts\GT_FrameBooster.ps1' @('-Only', 'Power', '-Lang', $Lang)
            Start-Process powercfg.cpl
        } }
        @{ Sep = $true }
        @{ Key = 'B'; Text = $S.Back }
    )
}

# ------------------------------------------
# NETWORK
# ------------------------------------------
function Show-Network {
    Invoke-Menu $S.OptimizeNetwork @(
        @{ Key = '1'; Text = $S.FixNet; Do = {
            netsh advfirewall firewall delete rule name="StopThrottling" | Out-Null
            netsh advfirewall firewall add rule name="StopThrottling" dir=in action=block remoteip=173.194.55.0/24,206.111.0.0/16 enable=yes | Out-Null
            Write-Ok $S.Done
        } }
        @{ Key = '2'; Text = $S.Dns; Do = { ipconfig /flushdns | Out-Null; Write-Ok $S.Done } }
        @{ Key = '3'; Text = $S.TcpOpt; Do = {
            Write-Info $S.TcpInfo
            Open-Resource 'TCP Optimizer\TCPOptimizer.exe'
            Open-Resource 'TCP Optimizer\STEP1.png'
            Open-Resource 'TCP Optimizer\STEP2.png'
        } }
        @{ Sep = $true }
        @{ Key = 'B'; Text = $S.Back }
    )
}

# ------------------------------------------
# COMPONENTS
# ------------------------------------------
function Show-Components {
    Invoke-Menu $S.Components @(
        @{ Key = '1'; Text = $S.Vcpp; Do = { Start-Process 'https://www.techpowerup.com/download/visual-c-redistributable-runtime-package-all-in-one/'; Write-Ok $S.Done } }
        @{ Key = '2'; Text = $S.DirectX; Do = { Start-Process 'https://www.microsoft.com/en-us/download/details.aspx?id=35'; Write-Ok $S.Done } }
        @{ Sep = $true }
        @{ Key = 'B'; Text = $S.Back }
    )
}

# ------------------------------------------
# FRAME BOOSTER
# ------------------------------------------
function Show-FrameBooster {
    Show-Header $S.FrameBooster
    Write-Row ''
    Write-Row $S.FbIntro 'White'
    foreach ($line in ($S.FbItems -split "`r?`n")) { if ($line) { Write-Row "  $($C.Dot) $line" 'Gray' } }
    Write-Row ''
    Write-Row $S.FbSafe 'DarkGray'
    Write-Row $S.Undo 'DarkGray'
    Write-Row ''
    Write-Edge $C.BL $C.H $C.BR
    if (Confirm-Step $S.FbApply) {
        Invoke-Script 'Scripts\GT_FrameBooster.ps1' @('-Only', 'All', '-Lang', $Lang)
    }
    Wait-Key
}

# ------------------------------------------
# RESTORE
# ------------------------------------------
function Show-Restore {
    $run = {
        param($Mode)
        if (Confirm-Step $S.Continue) { Invoke-Script 'Restore\GT_Restore.ps1' @('-Mode', $Mode, '-Lang', $Lang) }
    }
    Invoke-Choice $S.Restore @(
        @{ Key = '0'; Text = $S.Restore000; Do = { & $run 'Defaults' } }
        @{ Key = '1'; Text = $S.RestoreBackup; Do = { & $run 'PCBackup' } }
    ) @($S.RestoreInfo)
}

# ------------------------------------------
# START
# ------------------------------------------
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
$S = Import-PowerShellDataFile (Join-Path $Res 'Lang\EN.psd1')
if (-not $Lang) {
    $pickLang = Show-Menu $S.LanguageTitle @(
        @{ Key = '1'; Text = 'English' }
        @{ Key = '2'; Text = 'Francais' }
        @{ Sep = $true }
        @{ Key = 'X'; Text = 'Exit / Quitter' }
    )
    if (-not $pickLang -or $pickLang.Key -eq 'X') { Exit-App }
    $Lang = if ($pickLang.Key -eq '2') { 'FR' } else { 'EN' }
}
$S = Import-PowerShellDataFile (Join-Path $Res "Lang\$Lang.psd1")

Invoke-Menu $S.MainMenu @(
    @{ Key = '1'; Text = $S.OptimizeWindows; Menu = $true; Do = { Show-OptimizeWindows } }
    @{ Key = '2'; Text = $S.GamingBoost; Menu = $true; Do = { Show-GamingBoost } }
    @{ Key = '3'; Text = $S.OptimizeNetwork; Menu = $true; Do = { Show-Network } }
    @{ Key = '4'; Text = $S.Components; Menu = $true; Do = { Show-Components } }
    @{ Key = '5'; Text = $S.FrameBooster; Color = 'Magenta'; Menu = $true; Do = { Show-FrameBooster } }
    @{ Sep = $true }
    @{ Key = 'R'; Text = $S.Restore; Color = 'Yellow'; Menu = $true; Do = { Show-Restore } }
    @{ Key = 'L'; Text = $S.Log; Menu = $true; Do = { Open-Resource 'Log\EN_log.txt' } }
    @{ Key = 'F'; Text = $S.Follow; Menu = $true; Do = { Start-Process 'https://www.instagram.com/hamsypg' } }
    @{ Key = 'X'; Text = $S.Exit }
)
Exit-App
