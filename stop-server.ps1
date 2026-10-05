$ErrorActionPreference = 'Stop'
$receipt = Join-Path $PSScriptRoot 'data\server-process.json'
if (-not (Test-Path -LiteralPath $receipt)) { Write-Host 'No DW server receipt.'; return }
$record = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
$process = Get-CimInstance Win32_Process -Filter "ProcessId=$($record.pid)"
if (-not $process) { Write-Host 'DW server is already stopped.'; return }
$expected = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'build\Release\iw8-dw-server.exe'))
if ($process.ExecutablePath -ne $expected -or $record.executable -ne $expected) { throw 'The recorded PID belongs to another program; it was left running.' }
Stop-Process -Id $record.pid -ErrorAction Stop
Write-Host "Stopped IW8 DW server ($($record.pid))."
