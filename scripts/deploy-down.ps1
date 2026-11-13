<#
.SYNOPSIS
  Stops and removes the containers of the project casevault-rebuild. Data volumes (cvr_pgdata, cvr_evidence, cvr_keys,
  cvr_firstrun) are KEPT unless -RemoveData is given. Never touches any other compose project.
#>
param([switch]$RemoveData)

. "$PSScriptRoot\deploy-common.ps1"
Assert-Project

if ($RemoveData) {
    Write-Host 'Removing containers AND the data volumes of project casevault-rebuild (cvr_pgdata, cvr_evidence, cvr_keys, cvr_firstrun).'
    # The first-run override is included so that its volume (cvr_firstrun) is part of the project and is removed too.
    Invoke-Compose -WithFirstRun -ComposeArgs @('down', '--volumes', '--remove-orphans')
} else {
    Invoke-Compose -ComposeArgs @('down', '--remove-orphans')
    Write-Host 'Containers removed; data volumes kept.'
}
