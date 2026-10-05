param([Parameter(Mandatory=$true)][string]$Command,
      [ValidateRange(1,30)][int]$TimeoutSeconds = 5)
$ErrorActionPreference = 'Stop'
$record = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\deployment.json') -Raw | ConvertFrom-Json
$launch = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'data\current-runtime-launch.json') -Raw | ConvertFrom-Json
$game = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$launch.pid)
if (-not $game -or $game.ExecutablePath -ne $record.executable -or $launch.sha256 -ne $record.sha256 -or
    (Get-FileHash -LiteralPath $record.executable).Hash.ToLowerInvariant() -ne $record.sha256) {
    throw 'The recorded verified DW game is not running.'
}
$folder = Split-Path -Parent $record.executable
if (-not (Test-Path -LiteralPath (Join-Path $folder 'replay-dw-test.enabled'))) {
    throw 'Opt in with replay-dw-test.enabled before launching this development game.'
}
if ($Command.Length -eq 0 -or $Command.Length -gt 460 -or $Command -match '[^\x20-\x7e]|;') {
    throw 'Supply one printable engine command, without separators or newlines.'
}
$destination = Join-Path $folder 'replay-dw-test.command'
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
        if ($tail.Contains('DW_LOCAL_TEST_COMMAND native main-thread command dispatched')) {
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
