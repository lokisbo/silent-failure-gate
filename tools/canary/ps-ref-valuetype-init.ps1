$d = $null
$ok = [datetime]::TryParseExact('x', 'yyyy', $null, 0, [ref]$d)
Write-Output $ok
