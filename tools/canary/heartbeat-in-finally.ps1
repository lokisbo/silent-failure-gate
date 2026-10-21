$ErrorActionPreference = 'Stop'

function Beat($id, $result) { Add-Content 'runs.log' "$id result=$result;" }

Invoke-Round -Round 1
Invoke-Round -Round 2
Beat -id 'CANARY' -result 'OK'
