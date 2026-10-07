param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$remoteMode = Test-Path -LiteralPath (Join-Path $PSScriptRoot 'data\primary-backend.json')
$resolver = if ($remoteMode) { 'tools\resolve-remote-deployment.py' } else { 'tools\resolve-runtime-deployment.py' }
$deploymentPath = & $python -B (Join-Path $PSScriptRoot $resolver)
if ($LASTEXITCODE) { throw 'The current backend/game pair has no matching validation evidence.' }
$record = Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json
if (-not $record.startup_compatibility) {
    throw 'Rebuild and deploy the DW image with its compiled Windows startup fix before launching.'
}
if (-not $record.platform_auth -or -not $record.native_auth -or -not $record.native_tasks -or -not $record.disconnect_lifecycle -or
    -not $record.profile_storage.native_user_objects -or -not $record.native_account_metadata.compiled_layout_verified) {
    throw 'Deploy the new signed-platform/auth DW build before testing this milestone.'
}
if ((Get-FileHash -LiteralPath $record.executable).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'DW executable changed after deployment; rebuild and deploy it again.'
}
$backendHost = if ($record.remote_backend) { $record.remote_backend.host } else { '127.0.0.1' }
$status = Invoke-RestMethod -Uri ('http://' + $backendHost + ':8085/health') -TimeoutSec 10
if ($status.server -ne 'iw8-dw') { throw 'Start the IW8 DW server first.' }
if (-not $status.platform_auth -or -not $status.native_auth -or -not $status.native_tasks -or
    $status.capability_stage -ne $record.stage) { throw 'Restart the newly compiled DW server before launching.' }
if ($record.remote_backend) {
    $serverRecord = $record.remote_backend
} else {
    $serverRecord = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\server-process.json') -Raw | ConvertFrom-Json
    $serverProcess = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$serverRecord.pid)
    if ($serverRecord.sha256 -ne $record.server_sha256 -or -not $serverProcess -or
        $serverProcess.ExecutablePath -ne $serverRecord.executable -or
        (Get-FileHash -LiteralPath $serverRecord.executable).Hash.ToLowerInvariant() -ne $serverRecord.sha256) {
        throw 'The running server differs from the verified deployment. Stop it, then start the current server.'
    }
}
if ($ValidateOnly) {
    Write-Host 'Validated the unchanged shipping game and current live backend. No game launched.'
    return
}
if (Get-CimInstance Win32_Process -Filter "Name LIKE 'game_dx12_ship_replay%.exe'") {
    throw 'A Replay instance is already running. Close it before starting the DW test.'
}
Write-Host ('DW test: signed authentication and encrypted lobby at ' + $backendHost + '; unchanged compiled game.')
$log = Join-Path (Split-Path -Parent $record.executable) 'replay-dw-client.log'
$offset = if (Test-Path -LiteralPath $log) { (Get-Item -LiteralPath $log).Length } else { 0 }
$serverLog = Join-Path $PSScriptRoot 'data\server.log'
$serverOffset = if ($record.remote_backend) { $record.remote_log_offset } elseif (Test-Path -LiteralPath $serverLog) { (Get-Item -LiteralPath $serverLog).Length } else { 0 }
# The WMI provider starts the game with the current user's normal desktop token,
# outside packaged editors' AppData virtualization. Keep the native save identity
# identical to an Explorer launch and explicitly retain the root game directory.
$startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]1}
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine=('"' + $record.executable + '"')
    CurrentDirectory=(Split-Path -Parent $record.executable)
    ProcessStartupInformation=$startup
}
if ($created.ReturnValue -ne 0) { throw "DW game creation failed with WMI result $($created.ReturnValue)." }
$process = [pscustomobject]@{ Id=[int]$created.ProcessId }
@{ pid=$process.Id; executable=$record.executable; sha256=$record.sha256;
   deployment_receipt=@{path=$deploymentPath; sha256=(Get-FileHash -LiteralPath $deploymentPath).Hash.ToLowerInvariant()};
   launched_utc=[DateTime]::UtcNow.ToString('o'); client_log_offset=$offset; server_log_offset=$serverOffset;
   server_baseline=$status; server_process=$serverRecord } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'data\current-runtime-launch.json') -Encoding utf8
Write-Host ('Started root-folder DW test PID ' + $process.Id)
