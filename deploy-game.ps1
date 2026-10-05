param([string]$Python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe')
$ErrorActionPreference = 'Stop'
$previous = $env:PYTHONPATH
try {
    $config = Get-Content -LiteralPath 'E:\replay-compiler\replay-project.local.json' -Raw | ConvertFrom-Json
    $env:PYTHONPATH = $config.python_dependency_root
    & $Python -B (Join-Path $PSScriptRoot 'tools\deploy-game.py')
    if ($LASTEXITCODE) { throw 'DW executable deployment verification failed.' }
} finally { $env:PYTHONPATH = $previous }
