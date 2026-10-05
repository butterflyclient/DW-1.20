param([int]$Port = 8126)
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot 'replay-workstation'
$config = Get-Content -LiteralPath (Join-Path $root 'replay-project.local.json') -Raw | ConvertFrom-Json
$credentials = Join-Path $PSScriptRoot 'data\workstation-http-credentials.json'
if (-not (Test-Path -LiteralPath $credentials)) { throw "Workstation HTTP credentials are missing at $credentials." }
if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
    throw "Port $Port is occupied. Use restart-workstation.ps1 to restart the workstation."
}
$env:PYTHONPATH = $config.python_dependency_root
$env:PYTHONUTF8 = '1'
& $config.workstation_python -B -u (Join-Path $PSScriptRoot 'tools\workstation-server.py') --root $root --cache $config.cache --port $Port --host 0.0.0.0 --credentials $credentials
if ($LASTEXITCODE) { throw 'DW workstation stopped with an error.' }
