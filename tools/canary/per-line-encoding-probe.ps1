$lines = Get-Content 'sample.log' -Encoding Unicode
Write-Output $lines.Count
