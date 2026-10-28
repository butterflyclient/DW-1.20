<#
.SYNOPSIS
Host a full-featured Replay DW server on this PC and launch the local client.

.DESCRIPTION
One command for local play:
  1. builds the backend if it is missing (or with -Rebuild),
  2. starts it on loopback with the content pack (Store, Battle Pass, playlists,
     leaderboards, publisher content, QoS/relay) and the local map inventory,
  3. creates or refreshes the local client when the production EXE was updated
     or the server key changed (your INI is kept),
  4. launches the game from its own folder.

It never touches the remote primary server or its keys. Server data lives in
-Data (default data\local-play) and persists between sessions.

.EXAMPLE
.\Host-Local-Server.ps1 -GameDirectory 'C:\Games\Replay'

.EXAMPLE
.\Host-Local-Server.ps1            # reuses the game folder remembered from last time
.\Host-Local-Server.ps1 -Stop      # stops the local server this script started
#>
param(
    [string]$GameDirectory,
    [string]$Data = (Join-Path $PSScriptRoot 'data\local-play'),
    [switch]$Rebuild,
    [switch]$NoLaunch,
    [switch]$Stop,
    [switch]$StopWhenGameExits
)
$ErrorActionPreference = 'Stop'
$server = Join-Path $PSScriptRoot 'build\Release\iw8-dw-server.exe'
$health = 'http://127.0.0.1:8085/health'
$Data = [IO.Path]::GetFullPath($Data)
$processRecord = Join-Path $Data 'local-server-process.json'

function Write-Step([string]$message) { Write-Host "==> $message" -ForegroundColor Cyan }

function Get-Health {
    try { return Invoke-RestMethod -Uri $health -TimeoutSec 2 } catch { return $null }
}

function Get-OwnedServer {
    if (-not (Test-Path -LiteralPath $processRecord)) { return $null }
    $record = Get-Content -LiteralPath $processRecord -Raw | ConvertFrom-Json
    $process = Get-Process -Id $record.pid -ErrorAction SilentlyContinue
    if ($process -and $process.Path -and ([IO.Path]::GetFullPath($process.Path) -eq [IO.Path]::GetFullPath($record.executable))) {
        return $process
    }
    return $null
}

function Find-Python {
    foreach ($candidate in @(@('py', '-3'), @('python'), @('python3'))) {
        $command = Get-Command $candidate[0] -ErrorAction SilentlyContinue
        if (-not $command) { continue }
        $arguments = @($candidate | Select-Object -Skip 1) + @('-c', 'import sys; print(sys.version_info >= (3, 10))')
        $ok = & $command.Source @arguments 2>$null
        if ($LASTEXITCODE -eq 0 -and "$ok".Trim() -eq 'True') {
            $found = @($command.Source) + @($candidate | Select-Object -Skip 1)
            return , $found
        }
    }
    throw 'Python 3.10 or newer is required for local-client setup (install it from python.org, then open a new window).'
}

if ($Stop) {
    $owned = Get-OwnedServer
    if (-not $owned) { Write-Host 'No local server started by this script is running.'; return }
    Write-Step "Stopping local server (PID $($owned.Id))"
    Stop-Process -Id $owned.Id
    $owned.WaitForExit(10000) | Out-Null
    Remove-Item -LiteralPath $processRecord -ErrorAction SilentlyContinue
    return
}

New-Item -ItemType Directory -Force -Path $Data | Out-Null
$configPath = Join-Path $Data 'local-play.json'
$config = if (Test-Path -LiteralPath $configPath) { Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json } else { $null }
if (-not $GameDirectory -and $config -and $config.game_directory) { $GameDirectory = $config.game_directory }
if (-not $GameDirectory) {
    $GameDirectory = Read-Host 'Game folder (the one containing game_dx12_ship_replay_dw.exe)'
}
$GameDirectory = [IO.Path]::GetFullPath($GameDirectory.Trim('"'))
$original = Join-Path $GameDirectory 'game_dx12_ship_replay_dw.exe'
if (-not (Test-Path -LiteralPath $original -PathType Leaf)) {
    throw "game_dx12_ship_replay_dw.exe was not found in $GameDirectory"
}
# The server reads this at startup to inventory installed maps for matchmaking.
@{ schema = 1; game_directory = $GameDirectory } | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding utf8

if ($Rebuild -or -not (Test-Path -LiteralPath $server -PathType Leaf)) {
    Write-Step 'Building the backend server (first run takes a few minutes)'
    & (Join-Path $PSScriptRoot 'build-server.ps1') | Out-Host
}

$running = Get-Health
$owned = Get-OwnedServer
if ($running -and -not $owned) {
    if ($running.server -ne 'iw8-dw') { throw 'Port 8085 is used by another program. Close it and run again.' }
    Write-Warning 'A Replay DW server is already running on this PC (not started by this script); reusing it.'
} elseif (-not $running) {
    foreach ($port in 8085, 8443, 3075) {
        if (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) {
            throw "Port $port is already in use. Close the program using it, or run .\Host-Local-Server.ps1 -Stop."
        }
    }
    Write-Step "Starting local server (data: $Data)"
    $process = Start-Process -FilePath $server -ArgumentList @("`"$Data`"") -WorkingDirectory $PSScriptRoot `
        -WindowStyle Minimized -PassThru
    @{ pid = $process.Id; executable = $server; data = $Data; started = (Get-Date).ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $processRecord -Encoding utf8
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) { throw "The server exited; see $(Join-Path $Data 'server.log')" }
        $running = Get-Health
        if ($running.server -eq 'iw8-dw') { break }
        Start-Sleep -Milliseconds 250
    }
    if ($running.server -ne 'iw8-dw') { throw "The server did not become ready; see $(Join-Path $Data 'server.log')" }
}
$log = Join-Path $Data 'server.log'
if (Test-Path -LiteralPath $log) {
    Get-Content -LiteralPath $log -Tail 40 | Where-Object { $_ -match ' (CONTENT|LOCAL|OPERATOR) ' } |
        Select-Object -Last 4 | ForEach-Object { Write-Host "    $_" }
}
Write-Host ("    QoS: {0}  relay: {1}" -f $running.local_qos_enabled, $running.relay.enabled)

Write-Step 'Checking the local client'
$python = Find-Python
$setup = Join-Path $PSScriptRoot 'tools\setup-local-client.py'
$pythonArgs = @($python | Select-Object -Skip 1) + @('-B', $setup, '--client', $original, '--server-data', $Data, '--refresh')
$result = & $python[0] @pythonArgs
if ($LASTEXITCODE) { throw 'Local client setup failed (see the message above).' }
$report = ($result | Out-String) | ConvertFrom-Json
if ($report.refreshed) {
    $why = if ($report.previous) { ($report.previous.reasons -join '; ') } else { 'first setup' }
    Write-Host "    Local client created ($why)."
} else {
    Write-Host '    Local client is current.'
}

$keyPath = Join-Path $Data 'operator-access.key'
Write-Host ''
Write-Host 'Dashboard:     http://127.0.0.1:8085/stats'
if (Test-Path -LiteralPath $keyPath) { Write-Host "Operator key:  $((Get-Content -LiteralPath $keyPath -TotalCount 1).Trim())  (start match / fill bots)" }
Write-Host "Server log:    $log"
Write-Host ''

if ($NoLaunch) { return }
$localExe = Join-Path $GameDirectory 'game_dx12_ship_replay_local_dw.exe'
Write-Step 'Launching the game'
$game = Start-Process -FilePath $localExe -WorkingDirectory $GameDirectory -PassThru
if ($StopWhenGameExits) {
    Write-Host 'Waiting for the game to close...'
    $game.WaitForExit()
    $owned = Get-OwnedServer
    if ($owned) { Stop-Process -Id $owned.Id; Remove-Item -LiteralPath $processRecord -ErrorAction SilentlyContinue }
    Write-Host 'Local server stopped.'
}
