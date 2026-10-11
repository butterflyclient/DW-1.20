param([switch]$ValidateOnly)
$ErrorActionPreference = 'Stop'
$recordPath = Join-Path $PSScriptRoot 'data\current-remote-deployment.json'
$record = Get-Content -LiteralPath $recordPath -Raw | ConvertFrom-Json
$config = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'dw-client.json') -Raw | ConvertFrom-Json
$gameRoot = (Resolve-Path -LiteralPath 'E:\IW8\Builds\1.20-replay').Path
$image = Join-Path $gameRoot $config.target
if ($config.target -ne 'game_dx12_ship_replay_dw.exe' -or $record.executable -ne $image -or
    (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'The production DW executable differs from its deployment receipt.'
}
$ini = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($image, '.ini')) -Raw
$hostMatch = [regex]::Match($ini, '(?m)^host=([^\r\n]+)')
if (-not $hostMatch.Success) { throw 'The DW INI has no backend host.' }
$backendAddress = $hostMatch.Groups[1].Value.Trim()
$parsed = $null
if (-not [Net.IPAddress]::TryParse($backendAddress, [ref]$parsed) -or
    $parsed.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'The DW INI host must be an IPv4 address.'
}
$health = Invoke-RestMethod -Uri ('http://' + $backendAddress + ':8085/health') -TimeoutSec 10
if ($health.server -ne 'iw8-dw' -or -not $health.native_auth -or -not $health.platform_auth -or -not $health.native_tasks) {
    throw 'The configured DW backend is not ready.'
}
if ($ValidateOnly) {
    Write-Host 'PASS: one verified production DW executable and configured backend. No game launched.'
    return
}
if (Get-CimInstance Win32_Process -Filter "Name='game_dx12_ship_replay_dw.exe'") {
    throw 'The production DW game is already running.'
}
# Retain the normal desktop token and the root game directory for native saves.
$startup = New-CimInstance -ClassName Win32_ProcessStartup -ClientOnly -Property @{ShowWindow=[uint16]1}
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine=('"' + $image + '"'); CurrentDirectory=$gameRoot; ProcessStartupInformation=$startup
}
if ($created.ReturnValue -ne 0) { throw ('DW game creation failed: ' + $created.ReturnValue) }
Write-Host ('Started production DW PID ' + $created.ProcessId)
