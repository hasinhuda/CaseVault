<#
.SYNOPSIS
  Starts the hardened stack (project casevault-rebuild: cvr-db, cvr-app, cvr-nginx; host port 127.0.0.1:8443).
.PARAMETER Build
  Builds the image cvr-app:dev from the Dockerfile first (also done if the image does not exist).
.PARAMETER FirstRun
  Adds deploy\compose.first-run.yaml: creates the four standard accounts once (credentials only in the volume cvr_firstrun).
.PARAMETER FinishFirstRun
  Restarts the application WITHOUT the first-run override and deletes the credentials file from the volume.
#>
param([switch]$Build, [switch]$FirstRun, [switch]$FinishFirstRun)

. "$PSScriptRoot\deploy-common.ps1"
Assert-Project
if ($FirstRun -and $FinishFirstRun) { throw 'Use either -FirstRun or -FinishFirstRun, not both.' }
Assert-SecretFilesExist

& docker image inspect cvr-app:dev *> $null
$imageMissing = ($LASTEXITCODE -ne 0)
if ($Build -or $imageMissing) {
    & docker build -t cvr-app:dev $script:RepoRoot
    if ($LASTEXITCODE -ne 0) { throw 'docker build failed' }
}

if ($FinishFirstRun) {
    # Recreate the application from the base file only (no first-run flag, no credentials volume mounted).
    Invoke-Compose -ComposeArgs @('up', '-d', '--wait', '--wait-timeout', '240', '--force-recreate', 'cvr-app')
    # Delete the one-time credentials file from the volume that this project created.
    & docker run --rm --name cvr-firstrun-clean --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true `
        -v cvr_firstrun:/d --entrypoint rm cvr-app:dev -f /d/initial-credentials.txt
    if ($LASTEXITCODE -ne 0) { throw 'could not delete the credentials file' }
    Write-Host 'First run finished: the application runs without the override and the credentials file was deleted.'
    return
}

if ($FirstRun) {
    Invoke-Compose -WithFirstRun -ComposeArgs @('up', '-d', '--wait', '--wait-timeout', '300')
    Write-Host 'Started with the first-run override. Read the credentials from the volume (never into a log), log in, then run scripts\deploy-up.ps1 -FinishFirstRun.'
} else {
    Invoke-Compose -ComposeArgs @('up', '-d', '--wait', '--wait-timeout', '300')
}
Write-Host 'Open https://localhost:8443/login (self-signed certificate: the browser will warn).'
