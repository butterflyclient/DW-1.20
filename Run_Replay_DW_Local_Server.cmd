@echo off
rem One-click local play: starts the full local Replay DW server and the local client.
rem The game folder is asked for once and remembered in data\local-play\local-play.json.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Host-Local-Server.ps1" -StopWhenGameExits %*
if errorlevel 1 pause
