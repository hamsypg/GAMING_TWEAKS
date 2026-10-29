# ==========================================
# GAMING TWEAKS - Restore Windows Defaults
# ==========================================
# Puts back the Windows default value of everything GAMING TWEAKS changes.
# It does not need a backup: every value below is the stock Windows 10/11
# default ($null = the value does not exist on a clean Windows install).
param(
    [ValidateSet('EN', 'FR')][string]$Lang = 'EN'
)

$ErrorActionPreference = 'SilentlyContinue'

# Messages
$T = @{
    EN = @{
        NoAdmin  = 'Please run GAMING TWEAKS as Administrator.'
        Registry = 'Registry tweaks (Windows, Gaming, Delay, CPU, RAM, Mouse)'
        Visual   = 'Visual effects and processor scheduling'
        Keyboard = 'Keyboard delay (Filter Keys)'
        Services = 'Services (DiagTrack, SysMain, MapsBroker)'
        MemComp  = 'Memory Compression'
        Boot     = 'Boot options (CPU cores)'
        Power    = 'Power plans (Balanced)'
        Firewall = 'Firewall rule StopThrottling'
        Network  = 'TCP/IP and Winsock (TCP Optimizer)'
        Gpu      = 'GPU interrupt priority (MSI Utility)'
        Done     = 'Done. Restart your PC to apply everything.'
        Manual   = 'MSI mode (MSISupported) depends on each driver and is not changed: reinstall the GPU driver to reset it.'
    }
    FR = @{
        NoAdmin  = 'Lancez GAMING TWEAKS en tant qu''Administrateur.'
        Registry = 'Tweaks du registre (Windows, Jeux, Delai, CPU, RAM, Souris)'
        Visual   = 'Effets visuels et planification du processeur'
        Keyboard = 'Delai clavier (Filter Keys)'
        Services = 'Services (DiagTrack, SysMain, MapsBroker)'
        MemComp  = 'Compression memoire'
        Boot     = 'Options de demarrage (coeurs CPU)'
        Power    = 'Plans d''alimentation (Utilisation normale)'
        Firewall = 'Regle pare-feu StopThrottling'
        Network  = 'TCP/IP et Winsock (TCP Optimizer)'
        Gpu      = 'Priorite des interruptions GPU (MSI Utility)'
        Done     = 'Termine. Redemarrez votre PC pour tout appliquer.'
        Manual   = 'Le mode MSI (MSISupported) depend de chaque pilote et n''est pas modifie: reinstallez le pilote GPU pour le reinitialiser.'
    }
}[$Lang]

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] $($T.NoAdmin)" -ForegroundColor Red
    exit 1
}

# Writes a DWORD, or deletes the value when $Value is $null.
function Set-Dword($Path, $Name, $Value) {
    if ($null -eq $Value) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

function Set-String($Path, $Name, $Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force | Out-Null
}

Write-Host ''

# ------------------------------------------
# Registry tweaks from the menus
# ------------------------------------------
$MMProfile = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
# Optimize Windows [2] Disable Automatic App Updates
Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' $null
# Optimize Windows [3] Disable Automatic Driver Updates
Set-Dword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' 'SearchOrderConfig' 1
# Optimize Windows [4] Background Apps / [9] Prevent Apps Auto Starting
Set-Dword 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications' 'GlobalUserDisabled' $null
# Optimize Windows [6] Disable Spectre and Meltdown Protection
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' 'FeatureSettingsOverride' $null
# Optimize Windows [7] Disable Transparency Effects
Set-Dword 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize' 'EnableTransparency' 1
# Gaming Boost [1] Disable Game DVR / [2] Disable FSO
Set-Dword 'HKCU:\System\GameConfigStore' 'GameDVR_Enabled' 1
Set-Dword 'HKCU:\System\GameConfigStore' 'GameDVR_FSEBehaviorMode' 1
Set-Dword 'HKCU:\System\GameConfigStore' 'GameDVR_DXGIHonorFSEWindowsCompatible' 0
# Gaming Boost [3] Remove Windows Delay
Set-Dword $MMProfile 'NetworkThrottlingIndex' 10
Set-Dword $MMProfile 'SystemResponsiveness' 20
# Gaming Boost [4] Boost CPU
Set-Dword "$MMProfile\Tasks\Games" 'GPU Priority' 8
# Gaming Boost [5] Boost RAM (380000 hex)
Set-Dword 'HKLM:\SYSTEM\ControlSet001\Control' 'SvcHostSplitThresholdInKB' 3670016
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control' 'SvcHostSplitThresholdInKB' 3670016
# Gaming Boost [7] Remove Mouse Delay
Set-Dword 'HKLM:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed' 'CursorSensitivity' $null
Write-Host "[OK] $($T.Registry)"

# ------------------------------------------
# Gaming Boost [3] opens System Properties > Performance:
# visual effects back to "Let Windows choose", processor scheduling to "Programs"
# ------------------------------------------
Set-Dword 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' 'VisualFXSetting' 0
New-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -PropertyType Binary -Value ([byte[]](0x9E, 0x1E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00)) -Force | Out-Null
Set-String 'HKCU:\Control Panel\Desktop' 'DragFullWindows' '1'
Set-String 'HKCU:\Control Panel\Desktop\WindowMetrics' 'MinAnimate' '1'
Set-Dword 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ListviewAlphaSelect' 1
Set-Dword 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'ListviewShadow' 1
Set-Dword 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' 'TaskbarAnimations' 1
Set-Dword 'HKCU:\Software\Microsoft\Windows\DWM' 'EnableAeroPeek' 1
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' 'Win32PrioritySeparation' 2
Write-Host "[OK] $($T.Visual)"

# ------------------------------------------
# Gaming Boost [7] Keyboard Delay (Filter Keys Setter)
# ------------------------------------------
$KeyResp = 'HKCU:\Control Panel\Accessibility\Keyboard Response'
Set-String $KeyResp 'Flags' '126'
Set-String $KeyResp 'DelayBeforeAcceptance' '1000'
Set-String $KeyResp 'AutoRepeatRate' '500'
Set-String $KeyResp 'AutoRepeatDelay' '1000'
Set-String $KeyResp 'BounceTime' '0'
Set-String 'HKCU:\Control Panel\Keyboard' 'KeyboardDelay' '1'
Set-String 'HKCU:\Control Panel\Keyboard' 'KeyboardSpeed' '31'
Write-Host "[OK] $($T.Keyboard)"

# ------------------------------------------
# Optimize Windows [5] Unnecessary Services (Windows default: Automatic)
# ------------------------------------------
sc.exe config DiagTrack start= auto | Out-Null
sc.exe config SysMain start= auto | Out-Null
sc.exe config MapsBroker start= delayed-auto | Out-Null
Start-Service -Name DiagTrack, SysMain
Write-Host "[OK] $($T.Services)"

# ------------------------------------------
# Optimize Windows [8] Memory Compression (Windows default: enabled)
# ------------------------------------------
Enable-MMAgent -MemoryCompression
Write-Host "[OK] $($T.MemComp)"

# ------------------------------------------
# Gaming Boost [4] bcdedit numproc (Windows default: not set)
# ------------------------------------------
bcdedit /deletevalue '{current}' numproc | Out-Null
Write-Host "[OK] $($T.Boot)"

# ------------------------------------------
# Gaming Boost [8] Ultimate Performance plan: reset the Windows power plans
# and switch back to Balanced
# ------------------------------------------
powercfg -restoredefaultschemes | Out-Null
powercfg /setactive 381b4222-f694-41f0-9685-ff5bb260df2e | Out-Null
Write-Host "[OK] $($T.Power)"

# ------------------------------------------
# Network [1] Fix Network Spikes (rule does not exist on Windows by default)
# ------------------------------------------
netsh advfirewall firewall delete rule name="StopThrottling" | Out-Null
Write-Host "[OK] $($T.Firewall)"

# ------------------------------------------
# Network [3] TCP Optimizer: TCP globals, TCP/IP tuning values and Winsock
# ------------------------------------------
netsh int tcp reset | Out-Null
netsh int tcp set global autotuninglevel=normal | Out-Null
netsh winsock reset | Out-Null
$TcpParams = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
foreach ($n in 'DefaultTTL', 'Tcp1323Opts', 'TcpMaxDupAcks', 'SackOpts', 'MaxUserPort', 'TcpTimedWaitDelay', 'GlobalMaxTcpWindowSize', 'TcpWindowSize') {
    Set-Dword $TcpParams $n $null
}
Get-ChildItem "$TcpParams\Interfaces" | ForEach-Object {
    foreach ($n in 'TcpAckFrequency', 'TCPNoDelay', 'TcpDelAckTicks') { Set-Dword $_.PSPath $n $null }
}
Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched' 'NonBestEffortLimit' $null
Set-Dword 'HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters' 'TCPNoDelay' $null
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'Size' $null
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' 'LocalPriority' 499
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' 'HostsPriority' 500
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' 'DnsPriority' 2000
Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider' 'NetbtPriority' 2001
Write-Host "[OK] $($T.Network)"

# ------------------------------------------
# Gaming Boost [6] MSI Utility: interrupt priority (Windows default: undefined)
# ------------------------------------------
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -Recurse |
    Where-Object { $_.PSChildName -eq 'Affinity Policy' } |
    ForEach-Object { Set-Dword $_.PSPath 'DevicePriority' $null }
Write-Host "[OK] $($T.Gpu)"

Write-Host ''
Write-Host "[!] $($T.Manual)" -ForegroundColor Yellow
Write-Host ''
Write-Host "[OK] $($T.Done)" -ForegroundColor Green
exit 0
