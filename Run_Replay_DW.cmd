@echo off
cd /d "%~dp0"
if not exist "%~dp0game_dx12_ship_replay_dw.exe" (
    echo Put this launcher beside game_dx12_ship_replay_dw.exe and its INI.
    pause
    exit /b 1
)
start "" "%~dp0game_dx12_ship_replay_dw.exe"
