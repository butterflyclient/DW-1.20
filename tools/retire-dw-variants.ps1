param([switch]$Execute)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$gameRoot = (Resolve-Path -LiteralPath 'E:\IW8\Builds\1.20-replay').Path
$stateRoot = (Resolve-Path -LiteralPath (Join-Path $projectRoot 'data\dw-client')).Path
$archive = [IO.Path]::GetFullPath((Join-Path $stateRoot ('retired-artifacts\' + (Get-Date -Format 'yyyyMMdd-HHmmss'))))
if (-not $archive.StartsWith($stateRoot + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Retirement archive escaped the DW build state.'
}
$files = @(Get-ChildItem -LiteralPath $gameRoot -File | Where-Object {
    $_.Name -match '^game_dx12_ship_replay_(audit|hostscale_r\d+|pair_alpha|pair_bravo)_dw\.(exe|ini)$' -or
    $_.Name -in @('replay-dw-test-alpha.enabled', 'replay-dw-test-bravo.enabled',
                  'replay-dw-test.command', 'replay-dw-test.enabled')
})
$candidate = Join-Path $projectRoot 'tools\prepare-host-scale-candidate.py'
if (Test-Path -LiteralPath $candidate) { $files += Get-Item -LiteralPath $candidate }
$records = @($files | ForEach-Object {
    $source = [IO.Path]::GetFullPath($_.FullName)
    $isGameFile = [string]::Equals($_.DirectoryName, $gameRoot, [StringComparison]::OrdinalIgnoreCase)
    if (-not $isGameFile -and $source -ne $candidate) { throw 'Unexpected retirement source.' }
    $folder = if ($isGameFile) { 'game' } else { 'tools' }
    $destination = [IO.Path]::GetFullPath((Join-Path (Join-Path $archive $folder) $_.Name))
    if (-not $destination.StartsWith($archive + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Retirement target escaped the reviewed archive.'
    }
    [ordered]@{ source = $source; destination = $destination; bytes = $_.Length;
        sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() }
})
if (-not $Execute) { $records | ConvertTo-Json -Depth 4; return }
$running = @(Get-CimInstance Win32_Process | Where-Object {
    $_.Name -in @($files | Where-Object Extension -eq '.exe' | ForEach-Object Name)
})
if ($running.Count) { throw 'A retired variant is running. No processes were stopped or files moved.' }
if (-not $records.Count) { Write-Host 'No alternate DW targets remain.'; return }
New-Item -ItemType Directory -Path $archive | Out-Null
$manifest = Join-Path $archive 'manifest.json'
[ordered]@{ archived = $false; records = $records; primaryExePreserved = $true;
    playerProfilesTouched = $false; gameProcessesStopped = $false } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding utf8
foreach ($record in $records) {
    if ((Get-FileHash -LiteralPath $record.source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) {
        throw ('Retirement source changed: ' + $record.source)
    }
    $parent = Split-Path -Parent $record.destination
    if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent | Out-Null }
    Move-Item -LiteralPath $record.source -Destination $record.destination
    if ((Get-FileHash -LiteralPath $record.destination -Algorithm SHA256).Hash.ToLowerInvariant() -ne $record.sha256) {
        throw ('Archived bytes differ: ' + $record.destination)
    }
}
[ordered]@{ archived = $true; records = $records; primaryExePreserved = $true;
    playerProfilesTouched = $false; gameProcessesStopped = $false } |
    ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest -Encoding utf8
Write-Host ('Archived obsolete DW launch targets: ' + $records.Count)
Write-Host ('Recovery manifest: ' + $manifest)
