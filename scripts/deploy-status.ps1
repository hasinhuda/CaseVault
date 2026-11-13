<#
.SYNOPSIS
  Shows the state of the project casevault-rebuild: containers, health, published ports and the hardening settings
  reported by docker inspect (read-only root, dropped capabilities, security options, memory limit, user).
#>
. "$PSScriptRoot\deploy-common.ps1"
Assert-Project

Invoke-Compose -ComposeArgs @('ps', '--all')
Write-Host ''
foreach ($name in @('cvr-db', 'cvr-app', 'cvr-nginx')) {
    & docker container inspect $name *> $null
    if ($LASTEXITCODE -ne 0) { Write-Host "$name : not present"; continue }
    $format = '{{.Name}} user={{.Config.User}} readonly={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} security={{.HostConfig.SecurityOpt}} memory={{.HostConfig.Memory}} pids={{.HostConfig.PidsLimit}} ports={{.NetworkSettings.Ports}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}'
    & docker container inspect --format $format $name
}
