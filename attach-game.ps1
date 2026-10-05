$ErrorActionPreference = 'Stop'
$record = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\deployment.json') -Raw | ConvertFrom-Json
$games = @(Get-CimInstance Win32_Process -Filter "Name='game_dx12_ship_replay_dw.exe'" |
    Where-Object { $_.ExecutablePath -eq $record.executable })
if ($games.Count -ne 1) { throw 'Expected exactly one deployed DW game process.' }
if ((Get-FileHash -LiteralPath $record.executable).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'The running DW image differs from the deployment.'
}
$status = Invoke-RestMethod -Uri 'http://127.0.0.1:8085/health' -TimeoutSec 3
if ($status.server -ne 'iw8-dw') { throw 'Start the DW server first.' }
$folder = Split-Path -Parent $record.executable
if (-not (Test-Path -LiteralPath (Join-Path $folder 'replay-dw-test.enabled'))) {
    throw 'The native command bridge is not opted in.'
}
$log = Join-Path $folder 'replay-dw-client.log'
$serverLog = Join-Path $PSScriptRoot 'data\server.log'
$offset = if (Test-Path -LiteralPath $log) { (Get-Item -LiteralPath $log).Length } else { 0 }
$serverOffset = if (Test-Path -LiteralPath $serverLog) { (Get-Item -LiteralPath $serverLog).Length } else { 0 }
@{ pid=$games[0].ProcessId; executable=$record.executable; sha256=$record.sha256;
   launched_utc=$games[0].CreationDate.ToUniversalTime().ToString('o');
   attached_utc=[DateTime]::UtcNow.ToString('o'); manually_attached=$true;
   client_log_offset=$offset; server_log_offset=$serverOffset; server_baseline=$status } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'data\current-runtime-launch.json') -Encoding utf8
Write-Host ('Attached to verified root-folder DW process ' + $games[0].ProcessId + '; evidence starts at this attachment.')
