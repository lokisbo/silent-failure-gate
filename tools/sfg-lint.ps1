<#
.SYNOPSIS
  Static checks for selected failure-prone patterns in PowerShell, Python, and VBScript automation.
.DESCRIPTION
  Read-only source scanner with positive controls, safe counterexamples, fail-closed checker errors,
  and an optional fingerprint baseline. Heuristic rules can produce false positives and false negatives.
#>
[CmdletBinding()]
param(
  [string]$Root = (Split-Path -Parent $PSScriptRoot),
  [string]$GateDir = $PSScriptRoot,
  [string]$BaselinePath,
  [string]$ReportPath,
  [switch]$WriteBaseline,
  [switch]$CanaryOnly,
  [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
try {
  $OutputEncoding = New-Object System.Text.UTF8Encoding($false)
  [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
} catch {}

if (-not $BaselinePath) { $BaselinePath = Join-Path $GateDir 'baseline.json' }
if (-not $ReportPath)   { $ReportPath   = Join-Path $GateDir 'lint-report.json' }
$CanaryDir = Join-Path $GateDir 'canary'

$script:AstNS = 'System.Management.Automation.Language'

function Get-LineNo([string]$text, [int]$index) {
  if ($index -le 0) { return 1 }
  $n = 1
  for ($i = 0; $i -lt $index -and $i -lt $text.Length; $i++) {
    if ($text[$i] -eq "`n") { $n++ }
  }
  return $n
}

function New-Hit([int]$line, [string]$evidence) {
  if ($null -eq $evidence) { $evidence = '' }
  if ($evidence.Length -gt 240) { $evidence = $evidence.Substring(0, 240) }
  return @{ line = $line; evidence = $evidence.Trim() }
}

function Find-Line($ctx, [string]$pattern) {
  $out = @()
  for ($i = 0; $i -lt $ctx.Lines.Count; $i++) {
    if ([regex]::IsMatch($ctx.CodeLines[$i], $pattern, 'IgnoreCase')) {
      $out += (New-Hit ($i + 1) $ctx.Lines[$i])
    }
  }
  return $out
}

function Get-Fingerprint([string]$ruleId, [string]$rel, [string]$evidence) {
  $norm = [regex]::Replace($evidence, '\s+', ' ').Trim()
  $raw  = "$ruleId|$rel|$norm"
  $sha  = [System.Security.Cryptography.SHA1]::Create()
  try {
    $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($raw))
  } finally { $sha.Dispose() }
  return (($bytes | ForEach-Object { $_.ToString('x2') }) -join '').Substring(0, 20)
}

function Get-AstNodes($ctx, [string]$typeName) {
  if (-not $ctx.Ast) { return @() }
  $t = [type]"$script:AstNS.$typeName"
  return @($ctx.Ast.FindAll({ param($a) $a -is $t }.GetNewClosure(), $true))
}

function Test-ArrayOutputStatement($statement) {
  if ($statement -is [type]"$script:AstNS.PipelineAst") {
    foreach ($element in $statement.PipelineElements) {
      if (-not ($element -is [type]"$script:AstNS.CommandExpressionAst")) { continue }
      $expr = $element.Expression
      if ($expr -is [type]"$script:AstNS.ArrayExpressionAst" -or
          $expr -is [type]"$script:AstNS.ArrayLiteralAst") { return $true }
    }
  }
  if ($statement -is [type]"$script:AstNS.AssignmentStatementAst") {
    $expr = $statement.Right
    if ($expr -is [type]"$script:AstNS.ArrayExpressionAst" -or
        $expr -is [type]"$script:AstNS.ArrayLiteralAst") { return $true }
  }
  return $false
}

function Test-IfBlockArrayOutput($block) {
  if (-not $block) { return $false }
  foreach ($statement in $block.Statements) {
    if (Test-ArrayOutputStatement $statement) { return $true }
  }
  return $false
}

function Test-InFinally($node) {
  $p = $node.Parent
  while ($p) {
    if ($p -is [type]"$script:AstNS.TryStatementAst") {
      $fin = $p.Finally
      if ($fin -and $node.Extent.StartOffset -ge $fin.Extent.StartOffset -and
          $node.Extent.EndOffset -le $fin.Extent.EndOffset) { return $true }
    }
    $p = $p.Parent
  }
  return $false
}

$script:Rules = @(


  @{ Id='default-arg-frozen-global'; Severity='warn'; Exts=@('.py'); Canary='default-arg-frozen-global.py'
     Fn = { param($ctx)
       $out = @()
       $reassigned = New-Object 'System.Collections.Generic.HashSet[string]'
       foreach ($m in [regex]::Matches($ctx.Text, '(?m)^\s*global\s+([A-Za-z_][\w\s,]*)$')) {
         foreach ($n in ($m.Groups[1].Value -split ',')) { [void]$reassigned.Add($n.Trim()) }
       }
       $modAssign = @{}
       foreach ($m in [regex]::Matches($ctx.Text, '(?m)^([A-Za-z_]\w*)\s*=[^=]')) {
         $n = $m.Groups[1].Value
         if ($modAssign.ContainsKey($n)) { $modAssign[$n]++ } else { $modAssign[$n] = 1 }
       }
       foreach ($k in $modAssign.Keys) { if ($modAssign[$k] -ge 2) { [void]$reassigned.Add($k) } }
       if ($reassigned.Count -eq 0) { return @() }
       foreach ($d in [regex]::Matches($ctx.Text, '(?s)\bdef\s+\w+\s*\((.*?)\)\s*(?:->[^:\r\n]*)?:')) {
         foreach ($p in [regex]::Matches($d.Groups[1].Value, '=\s*([A-Za-z_]\w*)\s*(?:,|$)')) {
           $name = $p.Groups[1].Value
           if ($reassigned.Contains($name)) {
             $ln = Get-LineNo $ctx.Text $d.Index
             $out += (New-Hit $ln ("默认参数 =$name 冻结了会被重赋值的模块级全局量: " + ($d.Value -split "`n")[0]))
           }
         }
       }
       return $out } }

  @{ Id='checker-error-must-fail'; Severity='block'; Exts=@('.py'); Canary='checker-error-must-fail.py'; Counterexample='checker-error-must-fail-safe.py'
     Fn = { param($ctx)
       $out = @()
       foreach ($m in [regex]::Matches($ctx.Code, '(?:return|sys\.exit\(|exit\()\s*1\s+if\s+([^\r\n]*?)\s+else\s+0')) {
         $lineNo = Get-LineNo $ctx.Text $m.Index
         $lineIndex = $lineNo - 1
         $returnIndent = [regex]::Match($ctx.CodeLines[$lineIndex], '^\s*').Length
         $fnIndex = -1; $fnIndent = -1
         for ($j = 0; $j -le $lineIndex; $j++) {
           $fm = [regex]::Match($ctx.CodeLines[$j], '^( *)(?:async\s+)?def\s+\w+')
           if ($fm.Success -and $fm.Groups[1].Length -lt $returnIndent -and $fm.Groups[1].Length -ge $fnIndent) {
             $fnIndex = $j; $fnIndent = $fm.Groups[1].Length
           }
         }
         $scopeStart = 0; $scopeEnd = $ctx.CodeLines.Count - 1
         if ($fnIndex -ge 0) {
           $scopeStart = $fnIndex
           for ($j = $fnIndex + 1; $j -lt $ctx.CodeLines.Count; $j++) {
             $fm = [regex]::Match($ctx.CodeLines[$j], '^( *)(?:async\s+)?def\s+\w+')
             if ($fm.Success -and $fm.Groups[1].Length -le $fnIndent) { $scopeEnd = $j - 1; break }
           }
         }
         $scopeLines = @($ctx.CodeLines[$scopeStart..$scopeEnd])
         $scope = $scopeLines -join "`n"
         $tracked = @()
         if ($fnIndex -ge 0) {
           for ($j = 0; $j -lt $fnIndex; $j++) {
             $globalDecl = [regex]::Match($ctx.CodeLines[$j], '^([A-Za-z_]\w*)\s*(?::[^=\r\n]+)?\s*=\s*(?:\[\s*\]|0|false)\s*$')
             if ($globalDecl.Success -and $globalDecl.Groups[1].Value -match '(?i)(errors?|failures?|failed)') {
               $tracked += $globalDecl.Groups[1].Value
             }
           }
         }
         foreach ($decl in [regex]::Matches($scope, '(?im)^\s*([A-Za-z_]\w*)\s*(?::[^=\r\n]+)?\s*=\s*(?:\[\s*\]|0|false)\s*$')) {
           $name = $decl.Groups[1].Value
           if ($name -match '(?i)(errors?|failures?|failed)') { $tracked += $name }
         }
         foreach ($alias in [regex]::Matches($scope, '(?im)^\s*([A-Za-z_]\w*)\s*=\s*(?:list\s*\(\s*)?([A-Za-z_]\w*)\s*\)?\s*$')) {
           if ($tracked -contains $alias.Groups[2].Value) { $tracked += $alias.Groups[1].Value }
         }
         if ($tracked.Count -eq 0) { continue }
         $condition = $m.Groups[1].Value
         $checksTracked = $false
         foreach ($name in ($tracked | Select-Object -Unique)) {
           if ([regex]::IsMatch($condition, ('\b' + [regex]::Escape($name) + '\b'), 'IgnoreCase')) { $checksTracked = $true; break }
         }
         if (-not $checksTracked) {
           $out += (New-Hit $lineNo ("收尾返回值未检查当前作用域内的 errors/failures 累积器: " + $m.Value))
         }
       }
       return $out } }
  @{ Id='heartbeat-in-finally'; Severity='block'; Exts=@('.ps1'); Canary='heartbeat-in-finally.ps1'; NeedAst=$true
     Fn = { param($ctx)
       $out = @()
       $eapContinue = @()
       foreach ($a in (Get-AstNodes $ctx 'AssignmentStatementAst')) {
         if ($a.Left.Extent.Text -match '(?i)ErrorActionPreference' -and $a.Right.Extent.Text -match "(?i)Continue") {
           $eapContinue += $a.Extent.StartOffset
         }
       }
       foreach ($c in (Get-AstNodes $ctx 'CommandAst')) {
         $name = $null
         try { $name = $c.GetCommandName() } catch {}
         if (-not $name) { continue }
         if ($name -notmatch '(?i)^(beat|write-beat|write-heartbeat|set-beat|invoke-beat)$') { continue }
         if (Test-InFinally $c) { continue }
         $downgraded = $false
         foreach ($o in $eapContinue) { if ($o -lt $c.Extent.StartOffset) { $downgraded = $true; break } }
         if ($downgraded) { continue }
         $out += (New-Hit $c.Extent.StartLineNumber ("心跳/落账调用不在 finally 且上文未把 EAP 降为 Continue: " + $c.Extent.Text))
       }
       return $out } }

  @{ Id='ps-ref-valuetype-init'; Severity='block'; Exts=@('.ps1'); Canary='ps-ref-valuetype-init.ps1'; NeedAst=$true
     Fn = { param($ctx)
       $out = @()
       $valueTypes = '(?i)^\[\s*(system\.)?(datetime|int|int16|int32|int64|uint32|double|single|float|decimal|bool|boolean|guid|timespan|byte|char|datetimeoffset)\s*\]$'
       $assigns = @(Get-AstNodes $ctx 'AssignmentStatementAst')
       foreach ($cv in (Get-AstNodes $ctx 'ConvertExpressionAst')) {
         if ($cv.Type.TypeName.Name -ne 'ref') { continue }
         if (-not ($cv.Child -is [type]"$script:AstNS.VariableExpressionAst")) { continue }
         $vname = $cv.Child.VariablePath.UserPath
         $inv = $cv.Parent
         while ($inv -and -not ($inv -is [type]"$script:AstNS.InvokeMemberExpressionAst")) { $inv = $inv.Parent }
         if (-not $inv) { continue }
         if ($inv.Expression.Extent.Text -notmatch $valueTypes) { continue }
         $last = $null
         foreach ($a in $assigns) {
           if ($a.Extent.StartOffset -ge $cv.Extent.StartOffset) { continue }
           if ($a.Left.Extent.Text -match ('(?i)^\$' + [regex]::Escape($vname) + '$')) { $last = $a }
         }
         if (-not $last) {
           $out += (New-Hit $cv.Extent.StartLineNumber ("[ref]`$$vname 绑值类型 out 形参而该变量此前从未赋值: " + $inv.Extent.Text))
         } elseif ($last.Right.Extent.Text -match '(?i)^\$null$') {
           $out += (New-Hit $cv.Extent.StartLineNumber ("[ref]`$$vname 绑值类型 out 形参而最近一次赋值是 `$null: " + $inv.Extent.Text))
         }
       }
       return $out } }

  @{ Id='system-acp-probe'; Severity='warn'; Exts=@('.ps1','.py'); Canary='system-acp-probe.ps1'
     Fn = { param($ctx) Find-Line $ctx 'TextInfo\.ANSICodePage' } }

  @{ Id='per-line-encoding-probe'; Severity='block'; Exts=@('.ps1','.py'); Canary='per-line-encoding-probe.ps1'
     Fn = { param($ctx)
       if ($ctx.Ext -eq '.py') { return (Find-Line $ctx 'open\s*\([^\r\n]*\.log[^\r\n]*encoding\s*=') }
       return (Find-Line $ctx '(Get-Content|ReadAllText|ReadAllLines)[^\r\n]*\.log[^\r\n]*-Encoding|(-Encoding[^\r\n]*(Get-Content|ReadAllText)[^\r\n]*\.log)') } }

  @{ Id='vbs-exit-code-passthrough'; Severity='block'; Exts=@('.vbs'); Canary='vbs-exit-code-passthrough.vbs'
     Fn = { param($ctx)
       if (-not [regex]::IsMatch($ctx.Text, '(?i)\.Run\s*[\("]')) { return @() }
       $capturesRc = [regex]::IsMatch($ctx.Text, '(?i)=\s*[\w\.]+\.Run\s*\(')
       $quitsRc    = [regex]::IsMatch($ctx.Text, '(?i)WScript\.Quit')
       if ($capturesRc -and $quitsRc) { return @() }
       $m = [regex]::Match($ctx.Text, '(?i)[\w\.]*\.Run\s*[\("]')
       return @(New-Hit (Get-LineNo $ctx.Text $m.Index) ('vbs 包装器吞退出码(缺 rc = sh.Run(...) 或 WScript.Quit rc): ' + $m.Value)) } }


  @{ Id='no-schtasks-change'; Severity='block'; Exts=@('.ps1','.py','.vbs'); Canary='no-schtasks-change.ps1'
     Fn = { param($ctx) Find-Line $ctx 'schtasks[^\r\n]*\s/change\b' } }

  @{ Id='escapes-via-write-tool'; Severity='block'; Exts=@('.ps1','.py','.vbs'); Canary='escapes-via-write-tool.py'
     Fn = { param($ctx)
       $out = @()
       $ms = [regex]::Matches($ctx.Text, '[\x00-\x08\x0B\x0C\x0E-\x1F]')
       $n = 0
       foreach ($m in $ms) {
         $n++
         if ($n -gt 3) { break }
         $code = [int][char]$m.Value[0]
         $out += (New-Hit (Get-LineNo $ctx.Text $m.Index) ("产物含裸控制字符 0x{0:X2}(本该是转义序列),偏移 {1}" -f $code, $m.Index))
       }
       return $out } }


  @{ Id='regex-ascii-boundary-cjk'; Severity='block'; Exts=@('.ps1','.py'); Canary='regex-ascii-boundary-cjk.py'; Counterexample='regex-ascii-boundary-cjk-safe.py'
     Fn = { param($ctx)
       if (-not $ctx.HasCjk) { return @() }
       $out = @()
       for ($i = 0; $i -lt $ctx.Lines.Count; $i++) {
         $l = $ctx.CodeLines[$i]
         $probe = [regex]::Replace($l, '[A-Za-z]:\\[^''"\s)]*', ' ')
         $probe = [regex]::Replace($probe, '(?i)\[regex\]::Escape\([^)]*\)', ' ')
         if ($probe -notmatch '\\[wWbB]') { continue }
         if ($l -notmatch '(?i)(-match|-notmatch|-replace|-split|\[regex\]|Select-String|re\.(search|match|fullmatch|sub|subn|findall|finditer|compile|split))') { continue }
         $unicodeLookaround = [regex]::IsMatch($probe, '(?s)\(\?(?:<=|<!|=|!)[^\r\n]{0,120}\\[wW]')
         $asciiWordBoundary = [regex]::IsMatch($probe, '\\[bB][A-Za-z_][A-Za-z0-9_]*')
         $escapedVariableBoundary = [regex]::IsMatch($probe, '\\[bB]"\s*\+\s*re\.escape\(var\)')
         $unicodeIdentifierExtraction = [regex]::IsMatch($ctx.Code, '(?s)ident\s*=\s*r"\(\?:\[\^\\W\\d\]\|_\)\\w\*".*path_assign\s*=.*ident.*str_assign\s*=.*ident')
         if ($escapedVariableBoundary -and $unicodeIdentifierExtraction) { continue }
         if (-not ($unicodeLookaround -or $asciiWordBoundary)) { continue }
         $out += (New-Hit ($i + 1) $ctx.Lines[$i])
       }
       return $out } }


  @{ Id='no-grep-multibyte-charclass'; Severity='block'; Exts=@('.ps1','.py'); Canary='no-grep-multibyte-charclass.ps1'
     Fn = { param($ctx) Find-Line $ctx 'grep[^\r\n]*\[[^\]\r\n]*[^\x00-\x7F][^\]\r\n]*\]' } }

  @{ Id='delete-exact-whitelist'; Severity='block'; Exts=@('.ps1'); Canary='delete-exact-whitelist.ps1'
     Fn = { param($ctx)
       if ($ctx.Code -notmatch '(?i)Remove-Item') { return @() }
       return (Find-Line $ctx '-Filter\s+["''][^"'']*\*') } }

  @{ Id='acp-dependency-guard'; Severity='block'; Exts=@('.ps1'); Canary='acp-dependency-guard.ps1'
     Fn = { param($ctx)
       if ($ctx.HasBom) { return @() }
       if (-not $ctx.HasCjk) { return @() }
       $m = [regex]::Match($ctx.Text, '[\u4e00-\u9fff]')
       return @(New-Hit (Get-LineNo $ctx.Text $m.Index) '无 BOM 且含 CJK 字面量的 .ps1(ACP 一旦不是 65001 就会静默乱码)') } }

  @{ Id='ps-array-null-concat'; Severity='warn'; Exts=@('.ps1'); Canary='ps-array-null-concat.ps1'; NeedAst=$true
     Fn = { param($ctx)
       $init = New-Object 'System.Collections.Generic.HashSet[string]'
       foreach ($a in (Get-AstNodes $ctx 'AssignmentStatementAst')) {
         if ($a.Right.Extent.Text -match '^@\(' -and $a.Left.Extent.Text -match '^\$(\w+)$') {
           [void]$init.Add($matches[1].ToLower())
         }
       }
       $out = @()
       foreach ($b in (Get-AstNodes $ctx 'BinaryExpressionAst')) {
         if ("$($b.Operator)" -ne 'Plus') { continue }
         $arrayT = @([type]"$script:AstNS.ArrayExpressionAst", [type]"$script:AstNS.ArrayLiteralAst")
         $lIsArr = ($arrayT | Where-Object { $b.Left  -is $_ }).Count -gt 0
         $rIsArr = ($arrayT | Where-Object { $b.Right -is $_ }).Count -gt 0
         if (-not ($lIsArr -or $rIsArr)) { continue }
         $other = if ($lIsArr) { $b.Right } else { $b.Left }
         if (-not ($other -is [type]"$script:AstNS.VariableExpressionAst")) { continue }
         $n = $other.VariablePath.UserPath
         if ($init.Contains($n.ToLower())) { continue }
         $out += (New-Hit $b.Extent.StartLineNumber ("数组拼接的 `$$n 没有无条件的 = @() 初始化(@() + `$null 会得到 Count=1): " + $b.Extent.Text))
       }
       return $out } }

  @{ Id='jsonl-no-bom'; Severity='block'; Exts=@('.ps1'); Canary='jsonl-no-bom.ps1'
     Fn = { param($ctx) Find-Line $ctx 'Add-Content[^\r\n]*-Encoding\s+UTF8' } }

  @{ Id='ps-if-expression-unwrap'; Severity='warn'; Exts=@('.ps1'); Canary='ps-if-expression-unwrap.ps1'; Counterexample='ps-if-expression-unwrap-safe.ps1'; NeedAst=$true
     Fn = { param($ctx)
       $out = @()
       foreach ($a in (Get-AstNodes $ctx 'AssignmentStatementAst')) {
         if (-not ($a.Right -is [type]"$script:AstNS.IfStatementAst")) { continue }
         $arrayOutput = $false
         foreach ($clause in $a.Right.Clauses) {
           if (Test-IfBlockArrayOutput $clause.Item2) { $arrayOutput = $true; break }
         }
         if (-not $arrayOutput -and $a.Right.ElseClause) {
           $arrayOutput = Test-IfBlockArrayOutput $a.Right.ElseClause
         }
         if (-not $arrayOutput) { continue }
         $out += (New-Hit $a.Extent.StartLineNumber ('if 表达式赋值且分支返回数组(单元素会被 unwrap 成标量): ' + (($a.Extent.Text -split "`n")[0])))
       }
       return $out } }

  @{ Id='ps-format-in-arglist'; Severity='warn'; Exts=@('.ps1'); Canary='ps-format-in-arglist.ps1'
     Fn = { param($ctx) Find-Line $ctx '[\.:]\w+\([^()\r\n]*\s-f\s[^()\r\n]*,' } }

  @{ Id='ps-eap-stop-stderr'; Severity='warn'; Exts=@('.ps1'); Canary='ps-eap-stop-stderr.ps1'
     Fn = { param($ctx)
       if ($ctx.Code -notmatch '(?i)\$ErrorActionPreference\s*=\s*[''"]Stop[''"]') { return @() }
       $out = @()
       for ($i = 0; $i -lt $ctx.Lines.Count; $i++) {
         if ($ctx.CodeLines[$i] -notmatch '2>&1') { continue }
         $downgraded = $false
         for ($j = [Math]::Max(0, $i - 5); $j -lt $i; $j++) {
           if ($ctx.CodeLines[$j] -match '(?i)\$ErrorActionPreference\s*=\s*[''"]Continue[''"]') { $downgraded = $true; break }
         }
         if ($downgraded) { continue }
         $out += (New-Hit ($i + 1) ('EAP=Stop 下对原生命令用 2>&1 且未临时降级: ' + $ctx.Lines[$i]))
       }
       return $out } }

  @{ Id='ps-param-name-collision'; Severity='warn'; Exts=@('.ps1'); Canary='ps-param-name-collision.ps1'; NeedAst=$true
     Fn = { param($ctx)
       $out = @()
       foreach ($pb in (Get-AstNodes $ctx 'ParamBlockAst')) {
         $guarded = New-Object 'System.Collections.Generic.HashSet[string]'
         foreach ($p in $pb.Parameters) {
           $isGuarded = $false
           foreach ($at in $p.Attributes) {
             $tn = $at.TypeName.Name
             if ($tn -match '(?i)^(switch|bool|boolean|int|int32|int64|ValidateSet|ValidateRange)$') { $isGuarded = $true }
           }
           if ($isGuarded) { [void]$guarded.Add($p.Name.VariablePath.UserPath.ToLower()) }
         }
         if ($guarded.Count -eq 0) { continue }
         foreach ($a in (Get-AstNodes $ctx 'AssignmentStatementAst')) {
           if ($a.Extent.StartOffset -lt $pb.Extent.EndOffset) { continue }
           if ($a.Left.Extent.Text -notmatch '^\$(\w+)$') { continue }
           $n = $matches[1].ToLower()
           if (-not $guarded.Contains($n)) { continue }
           $out += (New-Hit $a.Extent.StartLineNumber ("局部赋值与带类型约束的 param 参数同名(大小写不敏感): " + (($a.Extent.Text -split "`n")[0])))
         }
       }
       return $out } }

)

$script:ExcludePattern = '(?i)(\\\.bak|\.bak\\|\.bak$|\\node_modules\\|\\\.git\\|\\\.venv\\|\\__pycache__\\|\\runs\\|\\logs\\)'
$script:Exts = @('.ps1', '.py', '.vbs')

function Get-Candidates([string]$root, [ref]$errors) {
  $files = @()
  $enumErr = @()
  try {
    $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue -ErrorVariable enumErr |
               Where-Object { $script:Exts -contains $_.Extension.ToLower() })
  } catch {
    throw "枚举失败: $root : $($_.Exception.Message)"
  }
  foreach ($ee in @($enumErr)) {
    $ep = if ($ee.TargetObject) { [string]$ee.TargetObject } else { $root }
    if ($ee.TargetObject -and (($ep.TrimEnd('\') + '\') -match $script:ExcludePattern)) { $script:cExcludedEnumErr++; continue }
    $errors.Value += @{ path = $ep; stage = 'enumerate'; rule = ''; message = $ee.Exception.Message }
  }
  return $files
}

function Invoke-ScanFile($path, [string]$rel, $rules, [ref]$errors) {
  $ctx = @{ Path = $path; Rel = $rel; Ext = ([IO.Path]::GetExtension($path)).ToLower() }

  try {
    $ctx.Text = [IO.File]::ReadAllText($path)
  } catch {
    $errors.Value += @{ path = $rel; stage = 'read'; rule = ''; message = $_.Exception.Message }
    return $null
  }
  if ($null -eq $ctx.Text) {
    $errors.Value += @{ path = $rel; stage = 'read'; rule = ''; message = 'ReadAllText 返回 null' }
    return $null
  }

  try {
    $head = New-Object byte[] 3
    $fs = [IO.File]::OpenRead($path)
    try { [void]$fs.Read($head, 0, 3) } finally { $fs.Dispose() }
    $ctx.HasBom = ($head[0] -eq 0xEF -and $head[1] -eq 0xBB -and $head[2] -eq 0xBF)
  } catch {
    $errors.Value += @{ path = $rel; stage = 'bom'; rule = ''; message = $_.Exception.Message }
    return $null
  }

  $ctx.Lines  = [regex]::Split($ctx.Text, '\r?\n')
  $ctx.HasCjk = [regex]::IsMatch($ctx.Text, '[\u4e00-\u9fff]')
  $ctx.Ast    = $null
  $ctx.Code = [regex]::Replace($ctx.Text, '(?m)^([ \t]*)#[^\r\n]*', {
      param($m) $m.Groups[1].Value + (' ' * ($m.Value.Length - $m.Groups[1].Value.Length)) })
  $ctx.CodeLines = [regex]::Split($ctx.Code, '\r?\n')

  $needAst = @($rules | Where-Object { $_.NeedAst -and $_.Exts -contains $ctx.Ext }).Count -gt 0
  if ($needAst -and $ctx.Ext -eq '.ps1') {
    $tokens = $null; $perr = $null
    try {
      $ctx.Ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$perr)
    } catch {
      $errors.Value += @{ path = $rel; stage = 'parse'; rule = ''; message = $_.Exception.Message }
      $ctx.Ast = $null
    }
    if ($perr -and @($perr).Count -gt 0) {
      $ctx.Ast = $null
      $errors.Value += @{ path = $rel; stage = 'parse'; rule = ''
                          message = ("ParseFile 报 {0} 个语法错误,首条: {1}" -f @($perr).Count, @($perr)[0].Message) }
    }
  }

  $hits = @()
  foreach ($r in $rules) {
    if ($r.Exts -notcontains $ctx.Ext) { continue }
    if ($r.NeedAst -and -not $ctx.Ast) {
      $errors.Value += @{ path = $rel; stage = 'rule-skipped'; rule = $r.Id; message = 'AST 不可用,该规则未能在此文件上执行' }
      continue
    }
    try {
      $res = @(& $r.Fn $ctx)
    } catch {
      $errors.Value += @{ path = $rel; stage = 'rule'; rule = $r.Id; message = $_.Exception.Message }
      continue
    }
    foreach ($h in $res) {
      if (-not $h) { continue }
      $hits += @{
        rule        = $r.Id
        severity    = $r.Severity
        path        = $rel
        line        = $h.line
        evidence    = $h.evidence
        fingerprint = (Get-Fingerprint $r.Id $rel $h.evidence)
      }
    }
  }
  return @{ hits = $hits }
}

$canaryErrors = @()
$canaryHits   = @()
$canaryMissingFiles = @()
$counterexampleFailures = @()
$counterexamplePerRule = @()

if (-not (Test-Path -LiteralPath $CanaryDir)) {
  $canaryErrors += @{ path = $CanaryDir; stage = 'canary'; rule = ''; message = 'canary 目录不存在,阳性对照无法执行' }
} else {
  foreach ($r in $script:Rules) {
    $cf = Join-Path $CanaryDir $r.Canary
    if (-not (Test-Path -LiteralPath $cf)) {
      $canaryMissingFiles += "$($r.Id) -> $($r.Canary)"
      continue
    }
    $e = @()
    $res = Invoke-ScanFile $cf $r.Canary $script:Rules ([ref]$e)
    foreach ($x in $e) { $canaryErrors += $x }
    if ($res) { $canaryHits += @($res.hits) }
  }

  foreach ($r in @($script:Rules | Where-Object { $_.Counterexample })) {
    $cf = Join-Path (Join-Path $CanaryDir 'counterexamples') $r.Counterexample
    if (-not (Test-Path -LiteralPath $cf)) {
      $counterexampleFailures += @{ rule = $r.Id; canary = $r.Counterexample; reason = '安全反例样本缺失' }
      $counterexamplePerRule += @{ rule = $r.Id; canary = $r.Counterexample; passed = $false; hits = 0 }
      continue
    }
    $e = @()
    $res = Invoke-ScanFile $cf (Join-Path 'counterexamples' $r.Counterexample) $script:Rules ([ref]$e)
    foreach ($x in $e) { $canaryErrors += $x }
    $targetHits = @()
    if ($res) { $targetHits = @($res.hits | Where-Object { $_.rule -eq $r.Id }) }
    if ($targetHits.Count -gt 0) {
      $counterexampleFailures += @{ rule = $r.Id; canary = $r.Counterexample; reason = '安全反例仍触发规则'; hits = $targetHits }
      $counterexamplePerRule += @{ rule = $r.Id; canary = $r.Counterexample; passed = $false; hits = $targetHits.Count }
    } else {
      $counterexamplePerRule += @{ rule = $r.Id; canary = $r.Counterexample; passed = $true; hits = 0 }
    }
  }
}

$canaryByRule = @{}
foreach ($h in $canaryHits) {
  $k = "$($h.rule)|$($h.path)"
  if (-not $canaryByRule.ContainsKey($k)) { $canaryByRule[$k] = 0 }
  $canaryByRule[$k]++
}
$canaryFailures = @()
foreach ($r in $script:Rules) {
  $k = "$($r.Id)|$($r.Canary)"
  if ($canaryByRule.ContainsKey($k)) { continue }
  $reason = '规则在自己的 canary 上零命中(规则很可能根本没在匹配)'
  foreach ($mf in $canaryMissingFiles) { if ($mf -like "$($r.Id) ->*") { $reason = 'canary 样本文件缺失' } }
  $canaryFailures += @{ rule = $r.Id; canary = $r.Canary; reason = $reason }
}
$positiveCanaryFailureCount = $canaryFailures.Count
foreach ($failure in $counterexampleFailures) { $canaryFailures += $failure }
$canarySatisfied = $script:Rules.Count - $positiveCanaryFailureCount
$counterexamplesSatisfied = $counterexamplePerRule.Count - $counterexampleFailures.Count

$canaryPerRule = @()
foreach ($r in $script:Rules) {
  $k = "$($r.Id)|$($r.Canary)"
  $n = 0
  if ($canaryByRule.ContainsKey($k)) { $n = $canaryByRule[$k] }
  $canaryPerRule += @{ rule = $r.Id; canary = $r.Canary; hits = $n }
}

$scanErrors   = @()
$violations   = @()
$cScanned = 0; $cExcluded = 0; $cExempt = 0
$script:cExcludedEnumErr = 0   # 排除范围内的枚举错误数,只计数不进 errors
$gateFull = (Resolve-Path -LiteralPath $GateDir -ErrorAction SilentlyContinue)
$gatePrefix = if ($gateFull) { $gateFull.Path.TrimEnd('\') + '\' } else { $GateDir.TrimEnd('\') + '\' }

if (-not $CanaryOnly) {
  $candidates = @()
  $enumErrs = @()
  try {
    $candidates = Get-Candidates $Root ([ref]$enumErrs)
  } catch {
    $scanErrors += @{ path = $Root; stage = 'enumerate'; rule = ''; message = $_.Exception.Message }
  }
  foreach ($x in $enumErrs) { $scanErrors += $x }
  $rootPrefix = (Resolve-Path -LiteralPath $Root).Path.TrimEnd('\') + '\'
  foreach ($f in $candidates) {
    $full = $f.FullName
    if ($full -match $script:ExcludePattern) { $cExcluded++; continue }
    if ($full.StartsWith($gatePrefix, [StringComparison]::OrdinalIgnoreCase)) { $cExempt++; continue }
    $rel = $full
    if ($full.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { $rel = $full.Substring($rootPrefix.Length) }
    $e = @()
    $res = Invoke-ScanFile $full $rel $script:Rules ([ref]$e)
    foreach ($x in $e) { $scanErrors += $x }
    if ($res) { $cScanned++; $violations += @($res.hits) }
  }
}

$acpRuleId = 'acp-dependency-guard'
$systemAcp = 0
try {
  $systemAcp = [int](Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name 'ACP' -ErrorAction Stop).ACP
} catch {
  $scanErrors += @{ path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage'; stage = 'acp-probe'; rule = $acpRuleId
                    message = "读不到系统 ACP($($_.Exception.Message));按 fail-closed 计入 errors,不假定它是 65001" }
}
$latentAcp = @()
if ($systemAcp -eq 65001) {
  $latentAcp   = @($violations | Where-Object { $_.rule -eq $acpRuleId })
  $violations  = @($violations | Where-Object { $_.rule -ne $acpRuleId })
}

$baseSet = New-Object 'System.Collections.Generic.HashSet[string]'
$baseExists = Test-Path -LiteralPath $BaselinePath
if ($baseExists) {
  try {
    $bj = Get-Content -LiteralPath $BaselinePath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($fp in $bj.fingerprints) { [void]$baseSet.Add([string]$fp) }
  } catch {
    $scanErrors += @{ path = $BaselinePath; stage = 'baseline'; rule = ''
                      message = "baseline 读不开或不是合法 JSON($($_.Exception.Message));按 fail-closed 计入 errors,不当作空 baseline" }
  }
}
$newViolations = @($violations | Where-Object { $_.rule -eq $acpRuleId -or -not $baseSet.Contains($_.fingerprint) })

if ($WriteBaseline) {
  $fps = @($violations | Where-Object { $_.rule -ne $acpRuleId } | ForEach-Object { $_.fingerprint } | Sort-Object -Unique)
  $perRule = @{}
  foreach ($v in $violations) { if ($perRule.ContainsKey($v.rule)) { $perRule[$v.rule]++ } else { $perRule[$v.rule] = 1 } }
  $bl = [ordered]@{
    generatedAt  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    root         = $Root
    note         = '存量违规快照。指纹 = sha1(规则id|相对路径|归一化后的违规内容) 前 20 位,不含行号。'
    ruleCount    = $script:Rules.Count
    total        = $violations.Count
    perRule      = $perRule
    fingerprints = $fps
  }
  $dir = Split-Path -Parent $BaselinePath
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  [IO.File]::WriteAllText($BaselinePath, ($bl | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
  $newViolations = @($violations | Where-Object { $_.rule -eq $acpRuleId })
}

$allErrors = @($canaryErrors) + @($scanErrors)
$rc = 0
if ($newViolations.Count -gt 0)  { $rc = $rc -bor 1 }
if ($canaryFailures.Count -gt 0) { $rc = $rc -bor 2 }
if ($allErrors.Count -gt 0)      { $rc = $rc -bor 4 }

$perRuleNew = @{}
foreach ($v in $newViolations) { if ($perRuleNew.ContainsKey($v.rule)) { $perRuleNew[$v.rule]++ } else { $perRuleNew[$v.rule] = 1 } }

$report = [ordered]@{
  generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
  root        = $Root
  ruleCount   = $script:Rules.Count
  files       = [ordered]@{
    scanned  = $cScanned
    excluded = $cExcluded
    exempt   = $cExempt          # silent-failure-gate 自身,规则自述豁免,单独计数不静默丢弃
    skipped  = $cExcluded + $cExempt
    errored  = @($allErrors | ForEach-Object { $_.path } | Sort-Object -Unique).Count
    excludedEnumErrors = $script:cExcludedEnumErr   # 落在排除范围内的枚举错误,只计数不计入 errors
  }
  canary      = [ordered]@{
    expected  = $script:Rules.Count
    satisfied = $canarySatisfied
    hits      = $canaryHits.Count
    perRule   = $canaryPerRule
    failures  = $canaryFailures
    counterexamples = [ordered]@{
      expected = $counterexamplePerRule.Count
      satisfied = $counterexamplesSatisfied
      perRule = $counterexamplePerRule
    }
  }
  baseline    = [ordered]@{ path = $BaselinePath; exists = $baseExists; count = $baseSet.Count; written = [bool]$WriteBaseline }
  errors      = $allErrors
  counts      = [ordered]@{ violations = $violations.Count; newViolations = $newViolations.Count; perRuleNew = $perRuleNew }
  acpGate     = [ordered]@{ systemAcp = $systemAcp; latentCount = $latentAcp.Count
                            state = $(if ($systemAcp -eq 65001) { 'dormant(ACP=65001,前置条件不成立,潜伏不报也不入 baseline)' }
                                      elseif ($systemAcp -eq 0) { 'unknown(读不到 ACP,已计入 errors,命中全部保留)' }
                                      else { "active(ACP=$systemAcp≠65001,命中全部上报且绕过 baseline)" }) }
  latentAcp   = @($latentAcp | Sort-Object path, line)
  newViolations = @($newViolations | Sort-Object rule, path, line)
  violations  = @($violations | Sort-Object rule, path, line)
  exitCode    = $rc
}

try {
  $dir = Split-Path -Parent $ReportPath
  if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  [IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))
} catch {
  Write-Output "报告写盘失败: $($_.Exception.Message)"
  $rc = $rc -bor 4
}

$summary = ("静默失败静态断言: 规则={0} 扫描={1} 跳过={2}(排除{3}/自述豁免{4}) 出错={5} canary={6}/{7} 反例={8}/{9} 违规={10} 新增={11} 退出码={12}" -f `
  $script:Rules.Count, $cScanned, ($cExcluded + $cExempt), $cExcluded, $cExempt, $allErrors.Count,
  $canarySatisfied, $script:Rules.Count, $counterexamplesSatisfied, $counterexamplePerRule.Count, $violations.Count, $newViolations.Count, $rc)
if ($latentAcp.Count -gt 0) {
  $summary += (" | acp潜伏={0}(ACP=65001,前置条件不成立;代码页一旦变更这些会立刻转为违规)" -f $latentAcp.Count)
}

if ($canaryFailures.Count -gt 0) {
  Write-Output '闸没能执行:以下规则在自己的阳性对照上没命中,本次结果不可采信(绝不是全仓干净):'
  foreach ($cf in $canaryFailures) { Write-Output ("  [canary失效] {0}  {1}  ({2})" -f $cf.rule, $cf.canary, $cf.reason) }
}
if ($allErrors.Count -gt 0) {
  Write-Output ("闸没能执行:{0} 处检查器自身出错(fail-closed,不当通过):" -f $allErrors.Count)
  foreach ($e in ($allErrors | Select-Object -First 15)) {
    Write-Output ("  [错误] {0} [{1}] {2} {3}" -f $e.path, $e.stage, $e.rule, $e.message)
  }
  if ($allErrors.Count -gt 15) { Write-Output ("  ...另有 {0} 处未列出,详见 {1}" -f ($allErrors.Count - 15), $ReportPath) }
}
if ($newViolations.Count -gt 0) {
  Write-Output ("新增违规 {0} 条(baseline 之外):" -f $newViolations.Count)
  foreach ($v in ($newViolations | Sort-Object severity, rule, path | Select-Object -First 15)) {
    Write-Output ("  [{0}] {1}  {2}:{3}  {4}" -f $v.severity, $v.rule, $v.path, $v.line, $v.evidence)
  }
  if ($newViolations.Count -gt 15) { Write-Output ("  ...另有 {0} 条未列出,详见 {1}" -f ($newViolations.Count - 15), $ReportPath) }
}
if ($CanaryOnly -and -not $Quiet) {
  Write-Output '阳性对照逐条点名(规则 / canary 样本 / 命中数):'
  foreach ($c in $canaryPerRule) { Write-Output ("  {0,-30} {1,-34} hits={2}" -f $c.rule, $c.canary, $c.hits) }
}
if (-not $Quiet -and $rc -eq 0) { Write-Output '干净:canary 全命中,无新增违规,无 errors。' }

Write-Output $summary
exit $rc


