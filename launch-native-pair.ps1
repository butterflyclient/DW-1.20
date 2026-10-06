param(
    [Parameter(Mandatory=$true)][ValidateSet('alpha','bravo')][string]$Instance,
    [ValidateSet('Start','Stop')][string]$Action = 'Start'
)
$ErrorActionPreference = 'Stop'
$state = Join-Path $PSScriptRoot ('data\native-pair-20261006\' + $Instance)
$deploymentPath = Join-Path $state 'deployment.json'
$launchPath = Join-Path $state 'launch.json'
$record = Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json
if (-not $record.private_test_build -or
    (Get-FileHash -LiteralPath $record.executable).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'Prepare the verified private native-pair build first.'
}
$running = Get-CimInstance Win32_Process -Filter "Name LIKE 'game_dx12_ship_replay%.exe'"
if ($Action -eq 'Stop') {
    $launch = Get-Content -LiteralPath $launchPath -Raw | ConvertFrom-Json
    $owned = $running | Where-Object { $_.ProcessId -eq $launch.pid }
    if (-not $owned) { Write-Host ($Instance + ' is already stopped.'); return }
    if ($owned.ExecutablePath -ne $record.executable -or
        $owned.CreationDate.ToUniversalTime().Ticks -ne ([datetime]$launch.process_created_utc).ToUniversalTime().Ticks) {
        throw 'Process identity differs from the owned launch receipt.'
    }
    $process = Get-Process -Id $launch.pid
    [void]$process.CloseMainWindow()
    if (-not $process.WaitForExit(10000)) { Stop-Process -Id $launch.pid }
    Write-Host ('Stopped owned native ' + $Instance + ' client.')
    return
}
foreach ($process in $running) {
    $verified = $false
    foreach ($peer in @('alpha','bravo')) {
        $peerState = Join-Path $PSScriptRoot ('data\native-pair-20261006\' + $peer)
        $peerLaunch = Join-Path $peerState 'launch.json'
        if (Test-Path -LiteralPath $peerLaunch) {
            $previous = Get-Content -LiteralPath $peerLaunch -Raw | ConvertFrom-Json
            if ($process.ProcessId -eq $previous.pid -and $process.ExecutablePath -eq $previous.executable -and
                $process.CreationDate.ToUniversalTime().Ticks -eq ([datetime]$previous.process_created_utc).ToUniversalTime().Ticks -and
                (Get-FileHash -LiteralPath $process.ExecutablePath).Hash.ToLowerInvariant() -eq $previous.sha256) {
                if ($peer -eq $Instance) { throw 'This native client is already running.' }
                $verified = $true
            }
        }
    }
    if (-not $verified) { throw 'An unrelated Replay game is running; leave it intact.' }
}
$status = Invoke-RestMethod -Uri 'http://127.0.0.1:8085/health' -TimeoutSec 3
$server = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\server-process.json') -Raw | ConvertFrom-Json
if ($status.server -ne 'iw8-dw' -or $server.sha256 -ne $record.server_sha256) {
    throw 'Start the hash-matching backend first.'
}
$folder = Split-Path -Parent $record.executable
if ($record.test_command_file -ne ('replay-dw-test-' + $Instance + '.command') -or
    $record.test_enabled_file -ne ('replay-dw-test-' + $Instance + '.enabled')) {
    throw 'Private control filenames differ from the selected instance.'
}
$enabled = Join-Path $folder $record.test_enabled_file
if (-not (Test-Path -LiteralPath $enabled)) { throw 'Private native test opt-in is missing.' }
# A previous process's valid command must not replay into a new engine session.
$commandFile = Join-Path $folder $record.test_command_file
Remove-Item -LiteralPath $commandFile,($commandFile + '.pending') -ErrorAction SilentlyContinue
$environment = [Environment]::GetEnvironmentVariables()
$environment['LOCALAPPDATA'] = [string]$record.localappdata
$environment['REPLAY_DW_TEST_HOME'] = [string]$record.home
$variables = @($environment.GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value })
$startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{
    ShowWindow=[uint16]1; EnvironmentVariables=[string[]]$variables
}
$clientLog = Join-Path $folder 'replay-dw-client.log'
$offset = if (Test-Path $clientLog) { (Get-Item $clientLog).Length } else { 0 }
$serverLog = Join-Path $PSScriptRoot 'data\server.log'
$serverOffset = (Get-Item $serverLog).Length
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine=('"' + $record.executable + '" +set LKOTRPTMKO ' + $record.game_port)
    CurrentDirectory=$folder; ProcessStartupInformation=$startup
}
if ($created.ReturnValue -ne 0) { throw 'Native game creation failed.' }
$native = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $created.ProcessId)
@{
    pid=[int]$created.ProcessId; executable=$record.executable; sha256=$record.sha256;
    process_created_utc=$native.CreationDate.ToUniversalTime().ToString('o');
    launched_utc=[DateTime]::UtcNow.ToString('o'); client_log_offset=$offset;
    server_log_offset=$serverOffset; server_baseline=$status; server_process=$server;
    test_command_file=$record.test_command_file; test_enabled_file=$record.test_enabled_file;
    isolated_profile=$true; isolated_cache=$true
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $launchPath -Encoding utf8
Write-Host ('Started root-folder native ' + $Instance + ' PID ' + $created.ProcessId)
