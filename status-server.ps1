$ErrorActionPreference = 'Stop'
Invoke-RestMethod -Uri 'http://127.0.0.1:8085/status' -TimeoutSec 3 | Format-List
