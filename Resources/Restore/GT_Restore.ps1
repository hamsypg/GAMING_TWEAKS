# ==========================================
# GAMING TWEAKS - Restore
# ==========================================
# -Mode Defaults : "000" restore. Puts back the fresh Windows 10/11 default of
#                  everything GAMING TWEAKS changes. Needs no backup.
# -Mode Backup   : saves this PC's own values of the same settings, once,
#                  before the first tweak (Launcher runs it automatically).
# -Mode PCBackup : puts back the values saved by -Mode Backup. Anything the
#                  backup does not have falls back to the Windows default.
param(
    [ValidateSet('Defaults', 'Backup', 'PCBackup')][string]$Mode = 'Defaults',
    [ValidateSet('EN', 'FR')][string]$Lang = 'EN',
    [string]$BackupFile = (Join-Path $env:ProgramData 'GamingTweaks\pc_backup.json')
)

$ErrorActionPreference = 'SilentlyContinue'
$BalancedGuid = '381b4222-f694-41f0-9685-ff5bb260df2e'

# Messages
$T = @{
    EN = @{
        NoAdmin  = 'Please run GAMING TWEAKS as Administrator.'
        Use000   = 'Restoring 000: fresh Windows default values'
        UsePC    = 'Restoring your PC backup from'
        NoPC     = 'No PC backup found: using the fresh Windows defaults (000) instead'
        Registry = 'Registry (Windows, Gaming, Delay, CPU, RAM, Mouse, Keyboard, Visual effects, TCP)'
        Services = 'Services (DiagTrack, SysMain, MapsBroker)'
        MemComp  = 'Memory Compression'
        Boot     = 'Boot options (CPU cores)'
        Power    = 'Power plans'
        Firewall = 'Firewall rule StopThrottling'
        Network  = 'TCP/IP and Winsock'
        Done     = 'Done. Restart your PC to apply everything.'
        Manual   = 'MSI mode (MSISupported) depends on each driver and is not changed: reinstall the GPU driver to reset it.'
    }
    FR = @{
        NoAdmin  = 'Lancez GAMING TWEAKS en tant qu''Administrateur.'
        Use000   = 'Restauration 000 : valeurs par defaut d''un Windows neuf'
        UsePC    = 'Restauration de la sauvegarde du PC du'
        NoPC     = 'Pas de sauvegarde du PC : utilisation des valeurs Windows par defaut (000)'
        Registry = 'Registre (Windows, Jeux, Delai, CPU, RAM, Souris, Clavier, Effets visuels, TCP)'
        Services = 'Services (DiagTrack, SysMain, MapsBroker)'
        MemComp  = 'Compression memoire'
        Boot     = 'Options de demarrage (coeurs CPU)'
        Power    = 'Plans d''alimentation'
        Firewall = 'Regle pare-feu StopThrottling'
        Network  = 'TCP/IP et Winsock'
        Done     = 'Termine. Redemarrez votre PC pour tout appliquer.'
        Manual   = 'Le mode MSI (MSISupported) depend de chaque pilote et n''est pas modifie : reinstallez le pilote GPU pour le reinitialiser.'
    }
}[$Lang]

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] $($T.NoAdmin)" -ForegroundColor Red
    exit 1
}

# ------------------------------------------
# Every registry value GAMING TWEAKS changes, with its fresh Windows default.
# Default $null = the value does not exist on a fresh Windows install.
# ------------------------------------------
$MM       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
$Desktop  = 'HKCU:\Control Panel\Desktop'
$Advanced = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$KeyResp  = 'HKCU:\Control Panel\Accessibility\Keyboard Response'
$Tcp      = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
$SvcProv  = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider'
$Reg = @(
    # Optimize Windows [2] [3] [4] [6] [7] [9]
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Name = 'NoAutoUpdate'; Type = 'DWord'; Default = $null }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching'; Name = 'SearchOrderConfig'; Type = 'DWord'; Default = 1 }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications'; Name = 'GlobalUserDisabled'; Type = 'DWord'; Default = $null }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'; Name = 'FeatureSettingsOverride'; Type = 'DWord'; Default = $null }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'EnableTransparency'; Type = 'DWord'; Default = 1 }
    # Gaming Boost [1] [2] Game DVR / FSO
    @{ Path = 'HKCU:\System\GameConfigStore'; Name = 'GameDVR_Enabled'; Type = 'DWord'; Default = 1 }
    @{ Path = 'HKCU:\System\GameConfigStore'; Name = 'GameDVR_FSEBehaviorMode'; Type = 'DWord'; Default = 1 }
    @{ Path = 'HKCU:\System\GameConfigStore'; Name = 'GameDVR_DXGIHonorFSEWindowsCompatible'; Type = 'DWord'; Default = 0 }
    # Gaming Boost [3] Remove Windows Delay, [4] CPU, [5] RAM (0x380000), [7] Mouse
    @{ Path = $MM; Name = 'NetworkThrottlingIndex'; Type = 'DWord'; Default = 10 }
    @{ Path = $MM; Name = 'SystemResponsiveness'; Type = 'DWord'; Default = 20 }
    @{ Path = "$MM\Tasks\Games"; Name = 'GPU Priority'; Type = 'DWord'; Default = 8 }
    @{ Path = 'HKLM:\SYSTEM\ControlSet001\Control'; Name = 'SvcHostSplitThresholdInKB'; Type = 'DWord'; Default = 3670016 }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control'; Name = 'SvcHostSplitThresholdInKB'; Type = 'DWord'; Default = 3670016 }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\Input\Settings\ControllerProcessor\CursorSpeed'; Name = 'CursorSensitivity'; Type = 'DWord'; Default = 100 }
    # Gaming Boost [3] System Properties > Performance (visual effects, processor scheduling)
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects'; Name = 'VisualFXSetting'; Type = 'DWord'; Default = 0 }
    @{ Path = $Desktop; Name = 'UserPreferencesMask'; Type = 'Binary'; Default = [byte[]](0x9E, 0x1E, 0x07, 0x80, 0x12, 0x00, 0x00, 0x00) }
    @{ Path = $Desktop; Name = 'DragFullWindows'; Type = 'String'; Default = '1' }
    @{ Path = "$Desktop\WindowMetrics"; Name = 'MinAnimate'; Type = 'String'; Default = '1' }
    @{ Path = $Advanced; Name = 'ListviewAlphaSelect'; Type = 'DWord'; Default = 1 }
    @{ Path = $Advanced; Name = 'ListviewShadow'; Type = 'DWord'; Default = 1 }
    @{ Path = $Advanced; Name = 'TaskbarAnimations'; Type = 'DWord'; Default = 1 }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\DWM'; Name = 'EnableAeroPeek'; Type = 'DWord'; Default = 1 }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'; Name = 'Win32PrioritySeparation'; Type = 'DWord'; Default = 2 }
    # Gaming Boost [7] Keyboard Delay (Filter Keys Setter)
    @{ Path = $KeyResp; Name = 'Flags'; Type = 'String'; Default = '126' }
    @{ Path = $KeyResp; Name = 'DelayBeforeAcceptance'; Type = 'String'; Default = '1000' }
    @{ Path = $KeyResp; Name = 'AutoRepeatRate'; Type = 'String'; Default = '500' }
    @{ Path = $KeyResp; Name = 'AutoRepeatDelay'; Type = 'String'; Default = '1000' }
    @{ Path = $KeyResp; Name = 'BounceTime'; Type = 'String'; Default = '0' }
    @{ Path = 'HKCU:\Control Panel\Keyboard'; Name = 'KeyboardDelay'; Type = 'String'; Default = '1' }
    @{ Path = 'HKCU:\Control Panel\Keyboard'; Name = 'KeyboardSpeed'; Type = 'String'; Default = '31' }
    # Network [3] TCP Optimizer
    @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Psched'; Name = 'NonBestEffortLimit'; Type = 'DWord'; Default = $null }
    @{ Path = 'HKLM:\SOFTWARE\Microsoft\MSMQ\Parameters'; Name = 'TCPNoDelay'; Type = 'DWord'; Default = $null }
    @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'Size'; Type = 'DWord'; Default = $null }
    @{ Path = $SvcProv; Name = 'LocalPriority'; Type = 'DWord'; Default = 499 }
    @{ Path = $SvcProv; Name = 'HostsPriority'; Type = 'DWord'; Default = 500 }
    @{ Path = $SvcProv; Name = 'DnsPriority'; Type = 'DWord'; Default = 2000 }
    @{ Path = $SvcProv; Name = 'NetbtPriority'; Type = 'DWord'; Default = 2001 }
)
foreach ($n in 'DefaultTTL', 'Tcp1323Opts', 'TcpMaxDupAcks', 'SackOpts', 'MaxUserPort', 'TcpTimedWaitDelay', 'GlobalMaxTcpWindowSize', 'TcpWindowSize') {
    $Reg += @{ Path = $Tcp; Name = $n; Type = 'DWord'; Default = $null }
}
foreach ($k in Get-ChildItem "$Tcp\Interfaces") {
    foreach ($n in 'TcpAckFrequency', 'TCPNoDelay', 'TcpDelAckTicks') {
        $Reg += @{ Path = "$Tcp\Interfaces\$($k.PSChildName)"; Name = $n; Type = 'DWord'; Default = $null }
    }
}
# Gaming Boost [6] MSI Utility: interrupt priority
foreach ($k in Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\PCI' -Recurse | Where-Object { $_.PSChildName -eq 'Affinity Policy' }) {
    $Reg += @{ Path = $k.PSPath -replace '^.*::HKEY_LOCAL_MACHINE', 'HKLM:'; Name = 'DevicePriority'; Type = 'DWord'; Default = $null }
}

# Services the tool disables, with their fresh Windows start type
$Services = @(
    @{ Name = 'DiagTrack';  Default = 'auto' }
    @{ Name = 'SysMain';    Default = 'auto' }
    @{ Name = 'MapsBroker'; Default = 'delayed-auto' }
)

function Get-RegValue($Path, $Name) {
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

# Writes a value, or deletes it when $Value is $null.
function Set-RegValue($Path, $Name, $Type, $Value) {
    if ($null -eq $Value) {
        Remove-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        return
    }
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    if ($Type -eq 'DWord') {
        # 0xFFFFFFFF reads back as -1: store it as the matching signed Int32
        $n = [long]$Value
        if ($n -gt [int]::MaxValue) { $n -= 4294967296 }
        $Value = [int]$n
    }
    if ($Type -eq 'Binary') { $Value = [byte[]]@($Value) }
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $Value -Force | Out-Null
}

function Get-StartType($Name) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $key)) { return $null }
    switch (Get-RegValue $key 'Start') {
        2 { if ((Get-RegValue $key 'DelayedAutostart') -eq 1) { 'delayed-auto' } else { 'auto' } }
        3 { 'demand' }
        4 { 'disabled' }
        default { $null }
    }
}

function Get-NumProc {
    foreach ($line in (bcdedit /enum '{current}')) {
        if ($line -match '^\s*numproc\s+(\d+)') { return [int]$Matches[1] }
    }
    return $null
}

function Get-ActiveScheme {
    if ((powercfg /getactivescheme | Out-String) -match '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}') { return $Matches[0].ToLower() }
    return $null
}

# ==========================================
# BACKUP (this PC's own values, kept from the first run only)
# ==========================================
if ($Mode -eq 'Backup') {
    if (Test-Path $BackupFile) { exit 0 }
    $reg = foreach ($i in $Reg) {
        $v = Get-RegValue $i.Path $i.Name
        if ($v -is [byte[]]) { $v = [int[]]$v }
        @{ Path = $i.Path; Name = $i.Name; Exists = ($null -ne $v); Value = $v }
    }
    $svc = foreach ($s in $Services) { @{ Name = $s.Name; Start = (Get-StartType $s.Name) } }
    $backup = @{
        Created           = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Registry          = @($reg)
        Services          = @($svc)
        MemoryCompression = [bool](Get-MMAgent).MemoryCompression
        NumProc           = Get-NumProc
        PowerScheme       = Get-ActiveScheme
    }
    New-Item -ItemType Directory -Path (Split-Path $BackupFile) -Force | Out-Null
    $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $BackupFile -Encoding UTF8
    exit 0
}

# ==========================================
# RESTORE (000 defaults or PC backup)
# ==========================================
$backup = $null
Write-Host ''
if ($Mode -eq 'PCBackup') {
    if (Test-Path $BackupFile) { $backup = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json }
    if ($backup) { Write-Host "[*] $($T.UsePC) $($backup.Created)" -ForegroundColor Cyan }
    else { Write-Host "[*] $($T.NoPC)" -ForegroundColor Yellow }
} else {
    Write-Host "[*] $($T.Use000)" -ForegroundColor Cyan
}
Write-Host ''

# Registry
foreach ($i in $Reg) {
    $value = $i.Default
    if ($backup) {
        $b = $backup.Registry | Where-Object { $_.Path -eq $i.Path -and $_.Name -eq $i.Name } | Select-Object -First 1
        if ($b) { $value = if ($b.Exists) { $b.Value } else { $null } }
    }
    Set-RegValue $i.Path $i.Name $i.Type $value
}
Write-Host "[OK] $($T.Registry)"

# Memory compression (fresh Windows: enabled). Done before the services:
# Enable-MMAgent turns SysMain back on, which would undo a SysMain restore.
if ($backup -and $backup.MemoryCompression -eq $false) { Disable-MMAgent -MemoryCompression }
else { Enable-MMAgent -MemoryCompression }
Write-Host "[OK] $($T.MemComp)"

# Services
foreach ($s in $Services) {
    if ($null -eq (Get-StartType $s.Name)) { continue }
    $start = $s.Default
    if ($backup) {
        $b = $backup.Services | Where-Object { $_.Name -eq $s.Name } | Select-Object -First 1
        if ($b -and $b.Start) { $start = $b.Start }
    }
    sc.exe config $s.Name start= $start | Out-Null
    if ($start -like '*auto') { Start-Service -Name $s.Name }
}
Write-Host "[OK] $($T.Services)"

# Boot: numproc (fresh Windows: not set)
if ($backup -and $backup.NumProc) { bcdedit /set '{current}' numproc $backup.NumProc | Out-Null }
else { bcdedit /deletevalue '{current}' numproc | Out-Null }
Write-Host "[OK] $($T.Boot)"

# Power plans: reset to the Windows plans, then go back to the PC's plan
# (or Balanced). A custom plan of this PC is kept active when it still exists.
$scheme = $BalancedGuid
if ($backup -and $backup.PowerScheme) { $scheme = $backup.PowerScheme }
if ($backup) {
    powercfg /setactive $scheme | Out-Null
    if ((Get-ActiveScheme) -ne $scheme) { powercfg /setactive $BalancedGuid | Out-Null }
    # Remove the Ultimate Performance copies the tool added
    foreach ($line in (powercfg /list)) {
        if ($line -match '([0-9a-fA-F-]{36}).*\((Ultimate Performance|Performances optimales)\)') {
            $g = $Matches[1].ToLower()
            if ($g -ne $scheme) { powercfg /delete $g | Out-Null }
        }
    }
} else {
    powercfg -restoredefaultschemes | Out-Null
    powercfg /setactive $BalancedGuid | Out-Null
}
Write-Host "[OK] $($T.Power)"

# Firewall rule added by "Fix Network Spikes" (not on a fresh Windows)
netsh advfirewall firewall delete rule name="StopThrottling" | Out-Null
Write-Host "[OK] $($T.Firewall)"

# TCP globals and Winsock (fresh Windows)
netsh int tcp reset | Out-Null
netsh int tcp set global autotuninglevel=normal | Out-Null
netsh winsock reset | Out-Null
Write-Host "[OK] $($T.Network)"

Write-Host ''
Write-Host "[!] $($T.Manual)" -ForegroundColor Yellow
Write-Host ''
Write-Host "[OK] $($T.Done)" -ForegroundColor Green
exit 0
