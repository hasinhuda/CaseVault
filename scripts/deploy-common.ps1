# Shared helpers for the deployment scripts (Phase 12B). Dot-source this file; do not run it.
# Every docker command built here is scoped to the compose project "casevault-rebuild". Any other project name is refused.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:ProjectName = 'casevault-rebuild'
$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:ComposeFile = Join-Path $script:RepoRoot 'deploy\compose.yaml'
$script:FirstRunFile = Join-Path $script:RepoRoot 'deploy\compose.first-run.yaml'
$script:DeployDataDir = Join-Path $script:RepoRoot '.local-data\deploy'

function Assert-Project {
    param([string]$Name = $script:ProjectName)
    if ($Name -ne 'casevault-rebuild') {
        throw "Refusing to run: the only allowed compose project is 'casevault-rebuild' (got '$Name')."
    }
    if ($env:COMPOSE_PROJECT_NAME -and $env:COMPOSE_PROJECT_NAME -ne 'casevault-rebuild') {
        throw "Refusing to run: COMPOSE_PROJECT_NAME is '$($env:COMPOSE_PROJECT_NAME)'. Unset it; this script only works on 'casevault-rebuild'."
    }
    if ($script:ProjectName -ne 'casevault-rebuild') {
        throw 'Refusing to run: the project name was changed.'
    }
}

function Invoke-Compose {
    param(
        [Parameter(Mandatory = $true)][string[]]$ComposeArgs,
        [switch]$WithFirstRun
    )
    Assert-Project
    $argList = @('compose', '-p', $script:ProjectName, '-f', $script:ComposeFile)
    if ($WithFirstRun) {
        $argList += @('-f', $script:FirstRunFile)
    }
    $argList += $ComposeArgs
    & docker @argList
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE"
    }
}

function Assert-SecretFilesExist {
    $needed = @(
        (Join-Path $script:DeployDataDir 'secrets\db_password.txt'),
        (Join-Path $script:DeployDataDir 'tls\tls.crt'),
        (Join-Path $script:DeployDataDir 'tls\tls.key')
    )
    foreach ($file in $needed) {
        if (-not (Test-Path -LiteralPath $file)) {
            throw "Missing $file. Run scripts\deploy-init.ps1 first."
        }
    }
}
