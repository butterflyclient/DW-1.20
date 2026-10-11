param([string]$Python = 'C:\Users\achar\AppData\Local\Programs\Python\Python314\python.exe')
$ErrorActionPreference = 'Stop'
& $Python -B (Join-Path $PSScriptRoot 'tools\deploy-dw-client.py')
if ($LASTEXITCODE) { throw 'DW executable deployment verification failed.' }
