$x = if ($true) { @('glm') } else { @() }
Write-Output $x.GetType().Name
