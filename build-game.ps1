param(
    [string]$Python = 'C:\Users\achar\AppData\Local\Programs\Python\Python314\python.exe',
    [switch]$PrepareOnly
)
$ErrorActionPreference = 'Stop'
# One production source selection. Optimizations and the active updater are
# always compiled in; com_optimized controls behavior at runtime.
$arguments = @('-B', (Join-Path $PSScriptRoot 'tools\build-dw-client.py'))
if ($PrepareOnly) { $arguments += '--prepare-only' }
& $Python @arguments
if ($LASTEXITCODE) { throw 'Production DW build failed; deployment was not changed.' }
if ($PrepareOnly) { Write-Host 'Production DW inputs prepared.' }
else { Write-Host 'Production DW executable verified. Run deploy-game.ps1 to install it.' }
