param(
    [Parameter(Mandatory=$true)][string]$Profile,
    [Parameter(Mandatory=$true)][string]$PlayerName,
    [string]$Python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
)
$ErrorActionPreference = 'Stop'
# The persistent account directory is loaded at startup. Stop its single owner
# before provisioning, then load the new account/key before writing the package.
& (Join-Path $PSScriptRoot 'stop-server.ps1')
try {
    & $Python -B (Join-Path $PSScriptRoot 'tools\provision-test-player.py') $Profile $PlayerName
    if ($LASTEXITCODE) { throw 'Guest provisioning failed.' }
} finally {
    & (Join-Path $PSScriptRoot 'start-server.ps1')
}
& $Python -B (Join-Path $PSScriptRoot 'tools\package-remote-guest.py') --profile $Profile
if ($LASTEXITCODE) { throw 'Guest packaging failed.' }
