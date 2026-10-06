param([Parameter(Mandatory=$true)][string]$Output,
      [string]$ScreenshotDirectory,
      [string]$DeploymentReceipt = (Join-Path $PSScriptRoot 'data\deployment.json'),
      [string]$LaunchReceipt = (Join-Path $PSScriptRoot 'data\current-runtime-launch.json'))
$ErrorActionPreference='Stop'
$target=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Output))
$dataRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'data'))+[IO.Path]::DirectorySeparatorChar
if(-not $target.StartsWith($dataRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($target) -ne '.jpg') {
    throw 'Save native screenshot evidence to a JPG inside the backend data directory.'
}
$documents=[Environment]::GetFolderPath('MyDocuments')
$screens=if($ScreenshotDirectory) { @([IO.Path]::GetFullPath($ScreenshotDirectory)) } else {
    @((Join-Path $documents 'Call of Duty Modern Warfare Replay\players\screenshots'),
      (Join-Path $documents 'Call of Duty Modern Warfare\players\screenshots'))
}
$before=@{}
Get-ChildItem -LiteralPath $screens -Filter '*.jpg' -ErrorAction SilentlyContinue | ForEach-Object { $before[$_.FullName]=$_.LastWriteTimeUtc.Ticks }
& (Join-Path $PSScriptRoot 'invoke-game-command.ps1') -Command 'screenshotJpeg' -DeploymentReceipt $DeploymentReceipt -LaunchReceipt $LaunchReceipt
$deadline=[DateTime]::UtcNow.AddSeconds(15)
while([DateTime]::UtcNow -lt $deadline) {
    $changed=@(Get-ChildItem -LiteralPath $screens -Filter '*.jpg' -ErrorAction SilentlyContinue | Where-Object {
        -not $before.ContainsKey($_.FullName) -or $before[$_.FullName] -ne $_.LastWriteTimeUtc.Ticks
    })
    if($changed.Count -gt 1){throw 'More than one screenshot changed; evidence capture is ambiguous.'}
    if($changed.Count -eq 1) {
        Copy-Item -LiteralPath $changed[0].FullName -Destination $target -Force
        @{schema=1;source=$changed[0].FullName;output=$target;captured_utc=$changed[0].LastWriteTimeUtc.ToString('o')} |
            ConvertTo-Json | Set-Content -LiteralPath ($target+'.json') -Encoding utf8
        Write-Host $target;return
    }
    Start-Sleep -Milliseconds 250
}
throw 'Native screenshot command dispatched, but no new screenshot was saved.'
