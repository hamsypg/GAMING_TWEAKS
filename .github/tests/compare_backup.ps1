# Compares two backups made by GT_Restore.ps1 -Mode Backup (before tweaks vs after restore).
param([string]$Before, [string]$After)
$b = Get-Content $Before -Raw | ConvertFrom-Json
$a = Get-Content $After -Raw | ConvertFrom-Json
$fail = 0
function Check($What, $x, $y) {
    $ok = ($x | ConvertTo-Json -Compress) -eq ($y | ConvertTo-Json -Compress)
    if (-not $ok) { $script:fail++ }
    '{0,-6} {1,-70} before={2} after={3}' -f $(if ($ok) { 'PASS' } else { 'FAIL' }), $What, ($x | ConvertTo-Json -Compress), ($y | ConvertTo-Json -Compress)
}
foreach ($r in $b.Registry) {
    $m = $a.Registry | Where-Object { $_.Path -eq $r.Path -and $_.Name -eq $r.Name } | Select-Object -First 1
    Check "$($r.Path)\$($r.Name)" @($r.Exists, $r.Value) @($m.Exists, $m.Value)
}
foreach ($s in $b.Services) {
    $m = $a.Services | Where-Object { $_.Name -eq $s.Name } | Select-Object -First 1
    Check "Service $($s.Name)" $s.Start $m.Start
}
Check 'MemoryCompression' $b.MemoryCompression $a.MemoryCompression
Check 'NumProc' $b.NumProc $a.NumProc
Check 'PowerScheme' $b.PowerScheme $a.PowerScheme
"`n$fail check(s) failed"
exit $fail
