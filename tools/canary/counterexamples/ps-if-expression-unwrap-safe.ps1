# Safe counterexample: these arrays are nested arguments or hashtable values,
# not arrays emitted as the top-level output of the if expression.
function Resolve-Brain {
  @{ Engine = ''; Exe = ''; Args = @(); Invalid = $true }
}
$brain = if ($true) { Resolve-Brain -ExtraArgs @('--verbose') } else { @{ Engine = ''; Args = @() } }
