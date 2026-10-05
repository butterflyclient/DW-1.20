"""Package the verified private DW image and one guest's configuration.

Does not copy game assets, backend signing keys or proxy DLLs. Each guest must
already have the compatible Replay game folder and its normal dependencies.
"""

import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
deployment = json.loads((ROOT / "data/deployment.json").read_text())
image = Path(deployment["executable"])
digest = hashlib.sha256(image.read_bytes()).hexdigest()
if digest != deployment["sha256"]:
    raise RuntimeError("Deployed game image changed")
network = json.loads((ROOT / "data/network.json").read_text())
router = json.loads((ROOT / "data/host-network-receipt.json").read_text())
if network["advertised_address"] != router["public_address"]:
    raise RuntimeError("Backend and verified router address differ")
profile = "remote-test-1"
if not (ROOT / f"data/platform-profiles/{profile}.bin").exists():
    raise RuntimeError("Guest identity is not provisioned")
host_ini = image.with_suffix(".ini")
text = (
    "# Replay DW host. Endpoints are loaded at process startup.\n"
    "host=127.0.0.1\n"
    f"public_address={router['public_address']}\n"
    f"local_address={router['lan_address']}\n"
    "game_port=3074\n"
)
if host_ini.exists() and host_ini.read_text() != text:
    retained = ROOT / "data/retained-host-config"
    retained.mkdir(exist_ok=True)
    old = host_ini.read_bytes()
    (retained / (hashlib.sha256(old).hexdigest() + ".ini")).write_bytes(old)
host_ini.write_text(text, encoding="ascii")

folder = ROOT / "data/remote-test-guest"
folder.mkdir(exist_ok=True)
guest_ini = (
    f"host={router['public_address']}\nprofile={profile}\n"
    f"access_key={network['clients'][profile]}\n"
)
launcher = (
    '@echo off\r\ncd /d "%~dp0"\r\nstart "" "%~dp0game_dx12_ship_replay_dw.exe"\r\n'
)
readme = (
    "REPLAY DW GUEST TEST\n\n"
    "Extract all four files into your compatible 1.20 Replay root game folder.\n"
    "The EXE and INI must be together. Do not use a local XInput9_1_0.dll proxy.\n"
    "Keep the game's normal assets and dependency DLLs installed.\n"
    "Run Run_Replay_DW_Guest.cmd, choose Multiplayer, then Social.\n"
    "Your identity is ReplayGuest; DWPlayer is your host and is already a friend.\n"
    "Join the host's private party and test Shipment. Both clients use this EXE.\n"
    "Use controlled full game restarts instead of dw_leave.\n"
    "Only one player may use this guest configuration at a time.\n"
    "Keep this package private; its INI selects your provisioned test account.\n\n"
    f"Game SHA256: {digest}\n"
)
guest_ini_name = image.with_suffix(".ini").name
legacy_ini = folder / "replay-dw.ini"
if legacy_ini.exists():
    legacy_ini.unlink()
(folder / guest_ini_name).write_text(guest_ini, encoding="ascii")
(folder / "Run_Replay_DW_Guest.cmd").write_bytes(launcher.encode())
(folder / "READ_ME.txt").write_text(readme, encoding="ascii")
archive = ROOT / "data/Replay-DW-Guest-Test.zip"
with zipfile.ZipFile(
    archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1
) as package:
    package.write(image, image.name)
    for path in sorted(folder.iterdir()):
        if path.name not in (guest_ini_name, "Run_Replay_DW_Guest.cmd", "READ_ME.txt"):
            raise RuntimeError("Unexpected guest package file")
        package.write(path, path.name)
receipt = {
    "schema": 1,
    "archive": str(archive),
    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "game_sha256": digest,
    "profile": profile,
    "host_ini": str(host_ini),
    "public_address": router["public_address"],
    "proxy_dll_included": False,
    "private_signing_keys_included": False,
    "second_network_gameplay_verified": False,
}
(ROOT / "data/remote-package-receipt.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print("Guest package:", archive)
print("Game SHA256:", digest)
