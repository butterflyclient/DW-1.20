param([int]$Port = 8126)
$ErrorActionPreference = 'Stop'
$credentials = Join-Path $PSScriptRoot 'data\workstation-http-credentials.json'
if (-not (Test-Path -LiteralPath $credentials)) { throw "Workstation HTTP credentials are missing at $credentials." }
$owners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)
foreach ($ownerId in $owners) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $ownerId"
    if ($process.Name -notmatch '^python(w)?\.exe$' -or
        ($process.CommandLine -notlike '*E:\replay-compiler\workstation\server.py*' -and
         $process.CommandLine -notlike '*E:\DW\IW8\tools\workstation-server.py*')) {
        throw "Port $Port belongs to another application; it was left running."
    }
}
foreach ($ownerId in $owners) {
    Stop-Process -Id $ownerId
    Wait-Process -Id $ownerId -Timeout 15 -ErrorAction SilentlyContinue
}
& (Join-Path $PSScriptRoot 'start-workstation.ps1') -Port $Port
