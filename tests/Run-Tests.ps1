[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$packageRoot = Split-Path -Parent $PSScriptRoot
$sourceTool = Join-Path $packageRoot 'tools\sfg-lint.ps1'
$powerShellExe = Join-Path $PSHOME $(if ($PSVersionTable.PSEdition -eq 'Core') { 'pwsh.exe' } else { 'powershell.exe' })
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('sfg-test-' + [guid]::NewGuid().ToString('N'))
$toolCopy = Join-Path $tempRoot 'tools'
$fixtures = Join-Path $toolCopy 'canary'
$counterexamples = Join-Path $fixtures 'counterexamples'
$workspace = Join-Path $tempRoot 'workspace'
$output = Join-Path $tempRoot 'output'

function Assert([bool]$condition, [string]$message) {
  if (-not $condition) { throw "FAIL: $message" }
  Write-Output "PASS: $message"
}

function Invoke-Scanner([string]$root, [string]$baseline, [string]$report, [switch]$canaryOnly) {
  $args = @('-NoProfile', '-NonInteractive', '-File', $sourceTool,
            '-Root', $root, '-GateDir', $toolCopy,
            '-BaselinePath', $baseline, '-ReportPath', $report, '-Quiet')
  if ($canaryOnly) { $args += '-CanaryOnly' }
  $proc = Start-Process -FilePath $powerShellExe -ArgumentList $args -Wait -PassThru -NoNewWindow
  return [int]$proc.ExitCode
}

try {
  New-Item -ItemType Directory -Path $toolCopy, $fixtures, $counterexamples, $workspace, $output -Force | Out-Null
  Copy-Item -LiteralPath $sourceTool -Destination (Join-Path $toolCopy 'sfg-lint.ps1')
  Get-ChildItem -LiteralPath (Join-Path $packageRoot 'tools\canary') -File -Recurse |
    ForEach-Object {
      $relative = $_.FullName.Substring((Join-Path $packageRoot 'tools\canary').Length).TrimStart('\')
      $destination = Join-Path $fixtures $relative
      $parent = Split-Path -Parent $destination
      if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
      Copy-Item -LiteralPath $_.FullName -Destination $destination
    }

  $baseline = Join-Path $output 'baseline.json'
  $report = Join-Path $output 'report.json'
  Set-Content -LiteralPath $baseline -Value '{"fingerprints":[]}' -Encoding UTF8

  $rc = Invoke-Scanner $workspace $baseline $report -CanaryOnly
  $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
  Assert ($rc -eq 0) 'all positive controls and safe counterexamples pass'
  Assert ($result.canary.expected -eq 19 -and $result.canary.satisfied -eq 19) 'every packaged rule has a working positive control'
  Assert ($result.canary.counterexamples.expected -eq 3 -and $result.canary.counterexamples.satisfied -eq 3) 'safe counterexamples remain clean'

  $rc = Invoke-Scanner $workspace $baseline $report
  Assert ($rc -eq 0) 'empty synthetic workspace returns clean'

  Set-Content -LiteralPath (Join-Path $workspace 'new-pattern.ps1') -Value "Add-Content -Path 'sample.jsonl' -Value `$line -Encoding UTF8"
  $rc = Invoke-Scanner $workspace $baseline $report
  $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
  Assert (($rc -band 1) -ne 0 -and $result.counts.newViolations -gt 0) 'new synthetic finding sets exit bit 1'

  Set-Content -LiteralPath (Join-Path $workspace 'broken.ps1') -Value '$value = if ($true) {'
  $rc = Invoke-Scanner $workspace $baseline $report
  $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
  Assert (($rc -band 4) -ne 0 -and $result.errors.Count -gt 0) 'PowerShell parse error sets checker-error bit 4'

  Remove-Item -LiteralPath (Join-Path $fixtures 'heartbeat-in-finally.ps1')
  $rc = Invoke-Scanner $workspace $baseline $report -CanaryOnly
  Assert (($rc -band 2) -ne 0) 'missing positive-control fixture sets canary bit 2'

  Write-Output 'ALL TESTS PASSED'
}
finally {
  if (Test-Path -LiteralPath $tempRoot) { Remove-Item -LiteralPath $tempRoot -Recurse -Force }
}
