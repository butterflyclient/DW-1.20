param([switch]$Launch)
$ErrorActionPreference = 'Stop'
if ($Launch -and (Get-CimInstance Win32_Process -Filter "Name LIKE 'game_dx12_ship_replay%.exe'")) {
    throw 'Close the running Replay instance before issuing new test credentials and launching the DW test.'
}
$deploymentPath = Join-Path $PSScriptRoot 'data\deployment.json'
if (-not (Test-Path -LiteralPath $deploymentPath -PathType Leaf)) {
    throw 'No verified DW executable is deployed yet. Finish build-game/deploy-game first.'
}
$deployment = Get-Content -Raw -LiteralPath $deploymentPath | ConvertFrom-Json
if (-not $deployment.startup_compatibility -or -not $deployment.native_tasks -or -not $deployment.disconnect_lifecycle -or
    -not $deployment.profile_storage.native_user_objects -or
    -not $deployment.native_account_metadata.compiled_layout_verified -or
    -not $deployment.native_account_metadata.original_platform_id_getter_executed -or
    -not $deployment.startup_domains.Replay_publisher_defaults -or
    $deployment.stage -ne 'encrypted-lobby-profiles') {
    throw 'This DW deployment predates the native account-getter and startup-service corrections. Build and deploy before launching.'
}
$expected = 'E:\IW8\Builds\1.20-replay\game_dx12_ship_replay_dw.exe'
if ($deployment.executable -ne $expected -or
    (Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash.ToLowerInvariant() -ne $deployment.sha256) {
    throw 'DW executable identity differs from the verified deployment.'
}
$runningGame = Get-CimInstance Win32_Process -Filter "Name='game_dx12_ship_replay_dw.exe'"
if ($runningGame) {
    throw 'The DW game is already running. Close it before login checks; use observe-game.ps1 for read-only diagnostics. These checks would otherwise replace its live session.'
}
$serverPath = Join-Path $PSScriptRoot 'build\Release\iw8-dw-server.exe'
if ((Get-FileHash -LiteralPath $serverPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $deployment.server_sha256) {
    throw 'The DW server differs from the verified deployment. Re-run the protocol checks and deploy-game.ps1 before launching.'
}
if (-not (Get-NetTCPConnection -LocalPort 8085 -State Listen -ErrorAction SilentlyContinue)) {
    & (Join-Path $PSScriptRoot 'start-server.ps1') | Out-Null
}
$python = 'C:\Users\achar\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $python -B (Join-Path $PSScriptRoot 'tools\test-server.py')
if ($LASTEXITCODE -ne 0) { throw 'Basic DW server checks failed.' }
& $python -B (Join-Path $PSScriptRoot 'tools\test-platform.py')
if ($LASTEXITCODE -ne 0) { throw 'Signed local platform checks failed.' }
& $python -B (Join-Path $PSScriptRoot 'tools\test-auth.py')
if ($LASTEXITCODE -ne 0) { throw 'Native auth ticket/signature checks failed.' }
Write-Host "PASS: verified freshly compiled DW executable: $expected"
Write-Host 'Game check: DW_LOCAL_PLATFORM_VERIFIED, DW_LOCAL_PLATFORM_SIGNED_IN, then DW_LOCAL_PLATFORM_TOKENS in replay-dw-client.log.'
Write-Host 'Account check: DW_LOCAL_ACCOUNT_PROFILE; platform ID and license initialized before tokens. Timed client markers identify any startup pause.'
Write-Host 'Server check: native AUTH, legacy Umbrella login, encrypted LOBBY authentication, then native TASK requests. Startup services include DML 27/2 and event filtering 67/6; request order may vary.'
Write-Host 'Profile check: TASK 193/6 user-objects-read, 193/7 user-objects-uploaded. Publisher metadata is 193/16. Retain the task entries if startup still waits.'
Write-Host 'Startup checks: publisher 95/1, user state 125/9, mail 29/10, clan info 197/21, stats 4/1 and Friends REST 255/10 now have native domain handlers.'
Write-Host 'The launch receipt saves counter baselines so offline auth checks are distinguishable from game requests.'
Write-Host 'Profiles and stats persist in E:\DW\IW8\data. Publisher content and other online services remain incomplete.'
if ($Launch) { & (Join-Path $PSScriptRoot 'launch-game.ps1') }
