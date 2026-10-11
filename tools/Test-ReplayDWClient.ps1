param(
    [string]$GameDirectory = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'
$gameRoot = (Resolve-Path -LiteralPath $GameDirectory).Path
$image = Join-Path $gameRoot 'game_dx12_ship_replay_dw.exe'
$iniPath = Join-Path $gameRoot 'game_dx12_ship_replay_dw.ini'
$deploymentPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'data\current-remote-deployment.json'
$expectedHash = if (Test-Path -LiteralPath $deploymentPath) {
    (Get-Content -LiteralPath $deploymentPath -Raw | ConvertFrom-Json).sha256
} else { $null }

Write-Output 'Replay DW client diagnostics (read-only; no identity keys are read)'
Write-Output "Game folder: $gameRoot"
if (Test-Path -LiteralPath $image) {
    $imageHash = (Get-FileHash -LiteralPath $image -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output "EXE SHA256: $imageHash"
    if ($expectedHash) { Write-Output "Matches current production DW deployment: $($imageHash -eq $expectedHash)" }
    else { Write-Output 'No local deployment receipt; compare the EXE hash with the published client release.' }
} else {
    Write-Output 'ERROR: game_dx12_ship_replay_dw.exe is missing.'
}

$backendAddress = '127.0.0.1'
if (Test-Path -LiteralPath $iniPath) {
    $iniBytes = [System.IO.File]::ReadAllBytes($iniPath)
    $iniText = [System.Text.Encoding]::UTF8.GetString($iniBytes).TrimStart([char]0xFEFF)
    $configured = [regex]::Match($iniText, '(?m)^host=([^\r\n]*)')
    if ($configured.Success) { $backendAddress = $configured.Groups[1].Value }
    Write-Output "INI host: $backendAddress"
    Write-Output "INI size: $($iniBytes.Length) bytes"
    Write-Output "INI contains exact host= line: $($configured.Success)"
    Write-Output "INI begins with UTF-8 BOM: $($iniBytes.Length -ge 3 -and $iniBytes[0] -eq 239 -and $iniBytes[1] -eq 187 -and $iniBytes[2] -eq 191)"
    $nameField = [regex]::Match($iniText, '(?m)^player_name=([^\r\n]*)')
    $playerName = $nameField.Groups[1].Value
    $nameValid = $playerName.Length -le 35 -and $playerName -notmatch '[^\x20-\x7e]|[#%]|^ | $'
    Write-Output "INI player_name format valid: $nameValid"
    if (!$nameValid) { Write-Output 'Use at most 35 printable ASCII characters, no # or %, and no edge spaces.' }
} else {
    Write-Output 'ERROR: executable-specific INI missing; fallback or loopback default may be used.'
}
if ($backendAddress -eq '127.0.0.1') {
    Write-Output 'Loopback host: correct only when this PC runs the DW backend.'
}
$parsedAddress = $null
if (![System.Net.IPAddress]::TryParse($backendAddress, [ref]$parsedAddress) -or
    $parsedAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    Write-Output 'ERROR: host must be an IPv4 address without a protocol or port.'
    exit 1
}

foreach ($port in @(8085, 3075)) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.ConnectAsync($backendAddress, $port)
        if (!$pending.Wait(5000)) { throw 'Connection timed out.' }
        Write-Output "TCP ${backendAddress}:${port}: connected"
    } catch {
        Write-Output "TCP ${backendAddress}:${port}: FAILED - $($_.Exception.GetBaseException().Message)"
    } finally {
        $client.Dispose()
    }
}
try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri "http://${backendAddress}:8085/health" -TimeoutSec 10
    Write-Output "Backend health HTTP: $($response.StatusCode)"
} catch {
    Write-Output "Backend health HTTP: FAILED - $($_.Exception.GetBaseException().Message)"
}

Write-Output "Local proxy present: $(Test-Path -LiteralPath (Join-Path $gameRoot 'XInput9_1_0.dll'))"
$identityPath = Join-Path $env:LOCALAPPDATA 'ReplayDW\player-identity.bin'
Write-Output "Local player identity exists: $(Test-Path -LiteralPath $identityPath)"
Write-Output "Windows local profile directory exists: $(Test-Path -LiteralPath $env:LOCALAPPDATA)"
foreach ($name in @('player-identity.bin', 'player-identity.creating', 'player-identity.lock')) {
    $identityFile = Join-Path $env:LOCALAPPDATA ('ReplayDW\' + $name)
    if (Test-Path -LiteralPath $identityFile) {
        Write-Output "$name : $((Get-Item -LiteralPath $identityFile).Length) bytes"
    }
}
Write-Output 'Preserve that identity file; do not share its contents.'
$logPath = Join-Path $gameRoot 'replay-dw-client.log'
if (Test-Path -LiteralPath $logPath) {
    Write-Output 'Recent provider diagnostics:'
    Get-Content -LiteralPath $logPath -Tail 150 |
        Where-Object { $_ -match 'DW_LOCAL_PLATFORM|DW_LOCAL_PROFILE|DW_LOCAL_RESOURCE|server-identity|local-identity|windows-identity' } |
        Select-Object -Last 20
} else {
    Write-Output 'No replay-dw-client.log: confirm the correct EXE was launched and the game folder is writable.'
}
