"""Package the verified private DW image and one guest's configuration.

Does not copy game assets, backend signing keys or proxy DLLs. Each guest must
already have the compatible Replay game folder and its normal dependencies.
"""

import hashlib
import argparse
import json
from pathlib import Path
import re
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--profile", default="remote-test-1")
args = parser.parse_args()
profile = args.profile
if not re.fullmatch(r"[a-z0-9-]{1,32}", profile):
    raise ValueError("Profile must be 1..32 lowercase letters, numbers or hyphens")
deployment = json.loads((ROOT / "data/deployment.json").read_text())
image = Path(deployment["executable"])
digest = hashlib.sha256(image.read_bytes()).hexdigest()
if digest != deployment["sha256"]:
    raise RuntimeError("Deployed game image changed")
network = json.loads((ROOT / "data/network.json").read_text())
router = json.loads((ROOT / "data/host-network-receipt.json").read_text())
if network["advertised_address"] != router["public_address"]:
    raise RuntimeError("Backend and verified router address differ")
identity_path = ROOT / f"data/platform-profiles/{profile}.bin"
if not identity_path.exists() or profile not in network["clients"]:
    raise RuntimeError("Guest identity is not provisioned")
identity = identity_path.read_bytes()
if len(identity) != 56:
    raise RuntimeError("Guest identity layout mismatch")
player_name = identity[20:56].split(b"\0", 1)[0].decode("ascii")
host_ini = image.with_suffix(".ini")
text = (
    "# Replay DW host. Endpoints are loaded at process startup.\n"
    "host=127.0.0.1\n"
    f"public_address={router['public_address']}\n"
    f"local_address={router['lan_address']}\n"
    "game_port=3074\n"
)
if not host_ini.exists():
    host_ini.write_text(text + "player_name=DWPlayer\n", encoding="ascii")

folder = ROOT / "data" / ("remote-test-guest" if profile == "remote-test-1" else profile)
folder.mkdir(exist_ok=True)
guest_ini = (
    f"host={router['public_address']}\nprofile={profile}\n"
    f"access_key={network['clients'][profile]}\n"
    f"player_name={player_name}\n"
)
launcher = (
    '@echo off\r\ncd /d "%~dp0"\r\nstart "" "%~dp0game_dx12_ship_replay_dw.exe"\r\n'
)
readme = (
    "REPLAY DW GUEST TEST\n\n"
    "Extract all four files into your compatible 1.20 Replay root game folder.\n"
    "The EXE and INI must be together. Do not use a local XInput9_1_0.dll proxy.\n"
    "Keep the game's normal assets and dependency DLLs installed.\n"
    "Close the old game first; replace both its EXE and INI with this package.\n"
    "Run Run_Replay_DW_Guest.cmd, choose Multiplayer, then Social.\n"
    f"Your initial name is {player_name}. Change player_name in the INI, then\n"
    "fully restart the game. Use a unique name of 1..35 printable ASCII characters,\n"
    "without #, %, or spaces at either end. This preserves your account and saves.\n"
    "No friends are pre-added. Social > Add Friends > Activision Account accepts\n"
    "the other player's name or name#0. They accept it in Friend Requests.\n"
    "Join the host's private party and test Shipment. Both clients use this EXE.\n"
    "Use controlled full game restarts instead of dw_leave.\n"
    "Online/Away/Busy/Offline selections use the local platform session.\n"
    "Player settings save on your own PC under Documents/Call of Duty Modern\n"
    "Warfare/players (config.cfg and settings.<platformId>.iw8). Native cloud\n"
    "settings sync is disabled for this DW process. No profile file is supplied.\n"
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
archive = ROOT / "data" / ("Replay-DW-Guest-Test.zip" if profile == "remote-test-1"
                           else f"Replay-DW-{profile}.zip")
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
    "player_name": player_name,
    "user_id": struct.unpack_from("<Q", identity, 8)[0],
    "host_ini": str(host_ini),
    "public_address": router["public_address"],
    "proxy_dll_included": False,
    "private_signing_keys_included": False,
    "second_network_gameplay_verified": False,
}
receipt_path = ROOT / "data" / ("remote-package-receipt.json" if profile == "remote-test-1"
                                else f"{profile}-package-receipt.json")
receipt_path.write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print("Guest package:", archive)
print("Game SHA256:", digest)
