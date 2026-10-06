"""Package a portable, non-destructive tester diagnostic without game credentials."""

import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
checker = ROOT / "build/Release/iw8-dw-identity-check.exe"
script = ROOT / "tools/Test-ReplayDWClient.ps1"
launcher = b"""@echo off\r
cd /d "%~dp0"\r
echo Replay DW diagnostics - existing identity is preserved.\r
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Test-ReplayDWClient.ps1" -GameDirectory "%~dp0."\r
echo.\r
"%~dp0iw8-dw-identity-check.exe"\r
echo.\r
pause\r
"""
readme = b"""REPLAY DW DIAGNOSTICS

Extract these files into the same root folder as game_dx12_ship_replay_dw.exe.
Run Run_Replay_DW_Diagnostics.cmd under the same Windows user as the game.
The PowerShell check reports the image, INI, network reachability and recent log.
The EXE checks the existing local identity record, Windows DPAPI decryption and
P-256 key import. It does not sign in, create a player, delete or replace keys.
No key bytes or encrypted identity contents are printed. Keep the identity file.
The checker needs no proxy DLL, Python or Visual C++ runtime installation.
Share the console's stage/error text if sign-in fails. Do not share identity files.
"""
archive = ROOT / "data/Replay-DW-Diagnostics.zip"
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as package:
    package.write(checker, checker.name)
    package.write(script, script.name)
    package.writestr("Run_Replay_DW_Diagnostics.cmd", launcher)
    package.writestr("READ_ME.txt", readme)
receipt = {
    "archive": str(archive),
    "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "checker_sha256": hashlib.sha256(checker.read_bytes()).hexdigest(),
    "identity_source_sha256": hashlib.sha256(
        (ROOT / "integration/replay/DW_LocalIdentity.cpp").read_bytes()
    ).hexdigest(),
    "private_identity_or_credentials_included": False,
}
(ROOT / "data/client-diagnostics-package.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print("Portable diagnostics:", archive)
