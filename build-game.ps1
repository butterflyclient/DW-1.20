param(
    [string]$Python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe',
    [switch]$SharedCompiler
)
$ErrorActionPreference = 'Stop'
# This compiles the revisions currently saved in Replay Workstation. It does not
# reimport the template sources or discard subsequent edits made in the editor.
if ($SharedCompiler) {
    & $Python -B (Join-Path $PSScriptRoot 'tools\workstation-client.py') --build
    if ($LASTEXITCODE) { throw 'Workstation did not accept the compiler job.' }
    Write-Host 'Inspect the compiler job in Replay Workstation. Deploy only after it succeeds.'
} else {
    $previous = $env:PYTHONPATH
    try {
        $config = Get-Content -LiteralPath 'E:\replay-compiler\replay-project.local.json' -Raw | ConvertFrom-Json
        $env:PYTHONPATH = $config.python_dependency_root
        & $Python -B (Join-Path $PSScriptRoot 'tools\build-frozen-workstation.py')
        if ($LASTEXITCODE) { throw 'Frozen workstation compiler job failed; deployment was not changed.' }
        Write-Host 'Workstation engine job verified. Run deploy-game.ps1 to install its DW variant.'
    } finally { $env:PYTHONPATH = $previous }
}
