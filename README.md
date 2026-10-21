# Silent Failure Gate

A read-only static scanner for selected failure-prone patterns in PowerShell, Python, and VBScript automation.

The scanner checks its own rules against positive-control fixtures before scanning a target tree. Safe counterexamples guard selected rules against known false positives. Read, parse, enumeration, baseline, and rule errors are included in the result instead of being treated as a clean scan. An optional fingerprint baseline lets a maintainer focus on newly introduced findings.

This is a small heuristic checker, not a general-purpose static analyzer. A clean result does not prove that a program is correct. Rules can miss defects or report patterns that are safe in a particular context. Review findings before changing code.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.
- No modules, model account, network connection, or API key are required.

PowerShell source files are parsed with the PowerShell AST for rules that need syntax information. Python and VBScript checks are text-based heuristics.

## Run

From PowerShell, in the project directory:

```powershell
.\tools\sfg-lint.ps1 -Root . -ReportPath .\out\report.json
```

Run only the rule controls:

```powershell
.\tools\sfg-lint.ps1 -CanaryOnly
```

The scanner reads source text. It does not execute scanned files or fixture files. Canary fixtures intentionally contain code-shaped examples and are test data; do not run them as scripts.

## Exit codes

The process exit code is a bit mask:

| Bit | Meaning |
| ---: | --- |
| 1 | New finding exists beyond the supplied baseline |
| 2 | A positive control or safe counterexample failed |
| 4 | The scanner encountered a read, parse, enumeration, rule, registry, or baseline error |

Bits combine. For example, `5` means there is a new finding and a checker error. Check the JSON report at `-ReportPath` for details.

The default baseline and report paths are under `tools`. For reproducible CI, pass explicit paths in a writable build directory. Do not commit reports made against private source trees unless they have been reviewed for paths and snippets.

## Baselines

The baseline stores finding fingerprints derived from the rule ID, relative path, and normalized finding text. It does not store source contents. Generate a baseline only after reviewing findings:

```powershell
.\tools\sfg-lint.ps1 -Root . -BaselinePath .\out\baseline.json -WriteBaseline
```

Do not use `-WriteBaseline` to silence unreviewed findings. A malformed baseline is an error, not an empty baseline.

## Tests

Run the isolated regression suite:

```powershell
.\tests\Run-Tests.ps1
```

Tests create synthetic source files in a temporary directory, invoke the scanner as a separate PowerShell process, inspect JSON results and exit codes, then remove the temporary directory. They do not execute fixture code or touch a user's project files.

## Rules

The current package contains 19 rules covering selected issues such as lost checker errors, PowerShell array behavior, encoding assumptions, unsafe wildcard deletion filters, scheduler command patterns, and wrapper exit-code propagation. Rule names and messages describe the checked pattern, not a guaranteed defect.

Each rule is paired with a positive-control fixture. Three rules also include safe counterexamples. The fixtures are intentionally small and synthetic.

## Privacy

The package contains no production scan report, private baseline, user corpus, account identifier, API credential, or machine-specific path. Runtime reports can contain paths and short source excerpts from whatever tree the operator scans. Review reports before sharing them.

## License

MIT. See [LICENSE](LICENSE).
