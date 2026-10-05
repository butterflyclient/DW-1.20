$ErrorActionPreference = 'Stop'
$data = Join-Path $PSScriptRoot 'data'
$deployment = Get-Content -LiteralPath (Join-Path $data 'deployment.json') -Raw | ConvertFrom-Json
$launch = Get-Content -LiteralPath (Join-Path $data 'current-runtime-launch.json') -Raw | ConvertFrom-Json
$server = Get-Content -LiteralPath (Join-Path $data 'server-process.json') -Raw | ConvertFrom-Json
$process = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$server.pid)
if (-not $process -or $process.ExecutablePath -ne $server.executable -or
    $server.sha256 -ne $deployment.server_sha256 -or
    (Get-FileHash -LiteralPath $server.executable).Hash.ToLowerInvariant() -ne $server.sha256) {
    throw 'Start the verified server before refreshing the native connection.'
}
$clientLog = Join-Path (Split-Path -Parent $deployment.executable) 'replay-dw-client.log'
$serverLog = Join-Path $data 'server.log'
$record = @{ schema=1; pid=$launch.pid; sha256=$deployment.sha256;
    requested_utc=[DateTime]::UtcNow.ToString('o'); command='dw_restart';
    client_log_offset=(Get-Item -LiteralPath $clientLog).Length;
    server_log_offset=(Get-Item -LiteralPath $serverLog).Length;
    server_baseline=(Invoke-RestMethod -Uri 'http://127.0.0.1:8085/health' -TimeoutSec 3);
    server_process=$server; native_completion_verified=$false }
& (Join-Path $PSScriptRoot 'invoke-game-command.ps1') -Command 'dw_restart'
$record.dispatched_utc = [DateTime]::UtcNow.ToString('o')
$pending = Join-Path $data 'current-runtime-connection.pending'
$record | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $pending -Encoding utf8
Move-Item -LiteralPath $pending -Destination (Join-Path $data 'current-runtime-connection.json') -Force
Write-Host 'Connection refresh dispatched; observe-game.ps1 establishes native completion separately.'
