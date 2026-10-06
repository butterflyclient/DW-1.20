param([Parameter(Mandatory=$true)][string]$Command,
      [ValidateRange(1,30)][int]$TimeoutSeconds = 5,
      [string]$DeploymentReceipt = (Join-Path $PSScriptRoot 'data\deployment.json'),
      [string]$LaunchReceipt = (Join-Path $PSScriptRoot 'data\current-runtime-launch.json'))
$ErrorActionPreference = 'Stop'
$record = Get-Content -LiteralPath $DeploymentReceipt -Raw | ConvertFrom-Json
$launch = Get-Content -LiteralPath $LaunchReceipt -Raw | ConvertFrom-Json
$game = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$launch.pid)
if (-not $game -or $game.ExecutablePath -ne $record.executable -or $launch.sha256 -ne $record.sha256 -or
    (Get-FileHash -LiteralPath $record.executable).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'The recorded verified DW game is not running.'
}
if ($launch.process_created_utc -and
    $game.CreationDate.ToUniversalTime().Ticks -ne ([datetime]$launch.process_created_utc).ToUniversalTime().Ticks) {
    throw 'The current process differs from the owned launch receipt.'
}
$folder = Split-Path -Parent $record.executable
$commandFile = if ($launch.test_command_file) { [string]$launch.test_command_file } else { 'replay-dw-test.command' }
$enabledFile = if ($launch.test_enabled_file) { [string]$launch.test_enabled_file } else { 'replay-dw-test.enabled' }
foreach ($name in @($commandFile, $enabledFile)) {
    if ($name -notmatch '^replay-dw-test(?:-[a-z0-9.-]+)?\.(command|enabled)$' -or $name.Contains('..')) {
        throw 'Invalid development control filename in launch receipt.'
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $folder $enabledFile))) {
    throw 'Opt in with replay-dw-test.enabled before launching this development game.'
}
if ($Command.Length -eq 0 -or $Command.Length -gt 460 -or $Command -match '[^\x20-\x7e]|;') {
    throw 'Supply one printable engine command, without separators or newlines.'
}
$destination = Join-Path $folder $commandFile
$pending = $destination + '.pending'
$clientLog = Join-Path $folder 'replay-dw-client.log'
$logOffset = if (Test-Path -LiteralPath $clientLog) { (Get-Item -LiteralPath $clientLog).Length } else { 0 }
$request = [DateTime]::UtcNow.Ticks.ToString() + ' ' + $Command
[IO.File]::WriteAllText($pending, $request, [Text.Encoding]::ASCII)
Move-Item -LiteralPath $pending -Destination $destination -Force
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
while ([DateTime]::UtcNow -lt $deadline) {
    if ([IO.File]::ReadAllText($destination) -ne $request) {
        throw 'Another command replaced this request before its dispatch was confirmed.'
    }
    if (Test-Path -LiteralPath $clientLog) {
        $stream = [IO.File]::Open($clientLog, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            [void]$stream.Seek($logOffset, [IO.SeekOrigin]::Begin)
            $reader = [IO.StreamReader]::new($stream)
            $tail = $reader.ReadToEnd()
        } finally { $stream.Dispose() }
        $marker = if ($launch.test_command_file) { 'DW_LOCAL_TEST_CHANNEL ' + $commandFile } else { 'DW_LOCAL_TEST_COMMAND native main-thread command dispatched' }
        if ($tail.Contains($marker)) {
            # Native test keys release after 100 ms. Let that engine-thread
            # release finish before the next key or screenshot is submitted.
            Start-Sleep -Milliseconds 250
            Write-Host ('Native engine dispatched: ' + $Command)
            return
        }
    }
    Start-Sleep -Milliseconds 100
}
throw 'The native game did not dispatch this command within the timeout; inspect its loading/error state.'
