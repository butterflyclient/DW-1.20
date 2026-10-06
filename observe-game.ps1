param([int]$ProcessId = 0)
$ErrorActionPreference = 'Stop'
$deployment = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\deployment.json') -Raw | ConvertFrom-Json
if (-not $ProcessId) {
    $matches = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq 'game_dx12_ship_replay_dw.exe' -and $_.ExecutablePath -eq $deployment.executable
    })
    if ($matches.Count -ne 1) { throw 'Start one verified root-folder DW game, or pass its explicit -ProcessId.' }
    $ProcessId = $matches[0].ProcessId
}
$python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$launchPath = Join-Path $PSScriptRoot 'data\current-runtime-launch.json'
$useReceipt = $false
if (Test-Path -LiteralPath $launchPath) {
    $launch = Get-Content -LiteralPath $launchPath -Raw | ConvertFrom-Json
    $useReceipt = $launch.pid -eq $ProcessId -and $launch.sha256 -eq $deployment.sha256
}
$deploymentPath = Join-Path $PSScriptRoot 'data\deployment.json'
if ($useReceipt -and $launch.deployment_receipt) {
    $deploymentPath = $launch.deployment_receipt.path
    if ((Get-FileHash -LiteralPath $deploymentPath).Hash.ToLowerInvariant() -ne $launch.deployment_receipt.sha256) {
        throw 'The runtime deployment receipt changed after launch.'
    }
} elseif (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'data\current-runtime-deployment.json')) {
    $deploymentPath = Join-Path $PSScriptRoot 'data\current-runtime-deployment.json'
}
if ($useReceipt) { & $python -B (Join-Path $PSScriptRoot 'tools\observe-game.py') --deployment $deploymentPath }
else { & $python -B (Join-Path $PSScriptRoot 'tools\observe-game.py') --deployment $deploymentPath --pid $ProcessId }
if ($LASTEXITCODE) { throw 'The read-only DW observation failed; no game state was changed.' }
