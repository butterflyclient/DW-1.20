param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$deploymentPath = & $python -B (Join-Path $PSScriptRoot 'tools\resolve-runtime-deployment.py')
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
$status = Invoke-RestMethod -Uri 'http://127.0.0.1:8085/health' -TimeoutSec 3
if ($status.server -ne 'iw8-dw') { throw 'Start the IW8 DW server first.' }
if (-not $status.platform_auth -or -not $status.native_auth -or -not $status.native_tasks -or
    $status.capability_stage -ne $record.stage) { throw 'Restart the newly compiled DW server before launching.' }
$serverRecord = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\server-process.json') -Raw | ConvertFrom-Json
$serverProcess = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$serverRecord.pid)
if ($serverRecord.sha256 -ne $record.server_sha256 -or -not $serverProcess -or
    $serverProcess.ExecutablePath -ne $serverRecord.executable -or
    (Get-FileHash -LiteralPath $serverRecord.executable).Hash.ToLowerInvariant() -ne $serverRecord.sha256) {
    throw 'The running server differs from the verified deployment. Stop it, then start the current server.'
}
if ($ValidateOnly) {
    Write-Host 'Validated the unchanged shipping game and current live backend. No game launched.'
    return
}
if (Get-CimInstance Win32_Process -Filter "Name LIKE 'game_dx12_ship_replay%.exe'") {
    throw 'A Replay instance is already running. Close it before starting the DW test.'
}
Write-Host 'DW test: signed local auth, encrypted lobby, native startup services and compiled provider disconnect fix.'
$log = Join-Path (Split-Path -Parent $record.executable) 'replay-dw-client.log'
$offset = if (Test-Path -LiteralPath $log) { (Get-Item -LiteralPath $log).Length } else { 0 }
$serverLog = Join-Path $PSScriptRoot 'data\server.log'
$serverOffset = if (Test-Path -LiteralPath $serverLog) { (Get-Item -LiteralPath $serverLog).Length } else { 0 }
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
