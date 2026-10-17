"""Package one universal Replay DW client; identity is created on the player's PC."""

import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
deployment = json.loads((ROOT / "data/dw-client/deployment.json").read_text())
readiness = json.loads(Path(deployment["readiness"]).read_bytes())
report = json.loads(Path(readiness["build_report"]).read_bytes())
if (not readiness["passed"] or report["unresolved_symbols"]
        or readiness["sha256"] != deployment["sha256"]):
    raise RuntimeError("The sole DW production target is not ready for distribution")
image = Path(deployment["executable"])
digest = hashlib.sha256(image.read_bytes()).hexdigest()
if digest != deployment["sha256"]:
    raise RuntimeError("Deployed game image changed")
if not any(
    Path(item["source"]).name == "DW_LocalIdentity.cpp"
    for item in report["cpp"]
):
    raise RuntimeError(
        "Deployed image does not contain automatic local identity support"
    )
primary_path = ROOT / "data/primary-backend.json"
primary = json.loads(primary_path.read_bytes()) if primary_path.exists() else {}
if primary.get("kind") == "linux-systemd":
    from remote_backend import verify

    remote = verify()
    endpoint = remote["host"]
else:
    network = json.loads((ROOT / "data/network.json").read_text())
    router = json.loads((ROOT / "data/host-network-receipt.json").read_text())
    if network["advertised_address"] != router["public_address"]:
        raise RuntimeError("Backend and verified router address differ")
    endpoint = router["public_address"]

ini = f"host={endpoint}\nplayer_name=\nunlock_all=0\nrank=0\nbypass_update_restart=0\n"
launcher = (
    '@echo off\r\ncd /d "%~dp0"\r\nstart "" "%~dp0game_dx12_ship_replay_dw.exe"\r\n'
)
readme = rf"""REPLAY DW CLIENT TEST

New players: extract the package into the compatible 1.20 Replay root folder.
Existing players: close the game and replace only the EXE, keeping your own INI.
The EXE embeds its owned FF/FP files and stages them in the native folders.
The updater also repairs missing owned files. No manual fastfile copy is needed.
On launch it also checks the server's explicitly published custom map package.
Missing Nuketown files download compressed and decompress into
mods\mw120r\maps\mp_nuketown. Allow free space for the compressed download,
decompressed map files, temporary staging and backups.
The native update screen requests a restart before installing missing files.
Existing files are backed up in game_dx12_ship_replay_dw.exe.update\asset-backups.
Maps are downloaded separately; this ZIP does not contain the map data.
This client supports the English game data. Regional companions remain native.
The included zone entries add only the named DW script overlay;
they do not replace shipped game fastfiles.
The EXE and INI must stay together. Keep normal game assets/dependencies.
Remove the optional XInput9_1_0.dll Replay proxy; this EXE needs no proxy.
Close any old game instance before replacing the EXE and INI.
Run Run_Replay_DW_Client.cmd, choose Multiplayer, then Social.

The same package works for every player. No host provisioning is necessary.
On first launch, your Windows user creates a unique identity at:
%LOCALAPPDATA%\ReplayDW\player-identity.bin
Windows protects this file for your user on this machine. Keep it: deleting it
creates a new player. Never share it or include it in a client distribution.
The backend registers the identity automatically when you connect. Restarting
or replacing the EXE/INI preserves your account and native local settings.

Set player_name in the INI, then restart the game to change your name.
Leave it blank for an automatically generated unique ReplayPlayer name.
Names are 1..35 printable ASCII characters, without #, %, or edge spaces.
Names must be unique on the backend. No friendships are pre-added.
Social > Add Friends > Activision Account accepts the other player's name
or name#0. The other player accepts the request in Friend Requests.
Join the host's private party and test Shipment. Use full controlled restarts
instead of dw_leave. Online/Away/Busy/Offline use the local platform session.

Settings save locally under Documents\Call of Duty Modern Warfare Replay\players:
config.cfg and settings.<platformId>.iw8. Native cloud sync is disabled for DW.
Earned player XP saves locally in %LOCALAPPDATA%\ReplayDW\player-progression.bin.
Keep it with the local identity when preserving progress. The server restores
your signed local total when you reconnect.
INI unlock_all=1 selects Replay's native unlock controls; 0 uses normal unlocks.
INI rank=0 restores saved progress. Values 1..55 select that career rank once
when the value changes, then earned XP continues normally. Restart after edits.
Earned item ownership persists. Lowering rank or disabling unlock_all does not
erase inventory items already granted by the backend.
com_optimized defaults to 1 for optimizations preserving the 3D scene's look.
Set it to 0 to disable them, or 2 for the aggressive visual/CPU experiment.
bypass_update_restart=0 enables normal verified full-EXE and owned-file updates.
Set it to 1 to bypass the updater completely: it performs no update check,
download or repair. Set it back to 0 to receive EXE and map updates again.
No backend signing keys, access keys or player identities are in this package.
This is the current multiplayer test build, not a completed DW replacement.

Game SHA256: {digest}
"""
files = {
    image.with_suffix(".ini").name: ini.encode("ascii"),
    "Run_Replay_DW_Client.cmd": launcher.encode("ascii"),
    "READ_ME.txt": readme.encode("ascii"),
}
archive = ROOT / "data/Replay-DW-Client-Test.zip"
source = Path(readiness["source_root"])
assets = json.loads((source / "generated/update-assets.json").read_bytes())
maps = json.loads((source / "generated/update-maps.json").read_bytes())
from dw_update_assets import extract, decode_groups, sha
owned_manifest = extract(image.read_bytes())
if sha(owned_manifest) != assets["manifest_sha256"]:
    raise RuntimeError("Client image does not bind its owned asset inventory")
owned_groups = decode_groups(owned_manifest)
if assets['entries'] != [entry for group in owned_groups for entry in group['entries']]:
    raise RuntimeError('Owned asset inventory differs from the client image')
owned_packages = [source / ('generated/bot-style-scripts' if group['owner'] == 1
                            else 'generated/weapon-inspect-assets') for group in owned_groups]
from dw_update_maps import extract as extract_maps, verify_record
if maps is None or extract_maps(image.read_bytes()) != verify_record(maps):
    raise RuntimeError("Client image does not bind its explicitly published custom maps")
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as package:
    package.write(image, image.name)
    for name, data in files.items():
        package.writestr(name, data)
    for entry in assets["entries"]:
        relative = Path(assets["relative_paths"][entry["name"]])
        if (relative.is_absolute() or ".." in relative.parts or len(relative.parts) > 2
                or relative.name != entry['name']):
            raise RuntimeError("Owned asset escaped its native zone folders")
        payload = Path(assets["payloads"][entry["sha256"]]["source"]).resolve()
        if not any(payload.is_relative_to(package) for package in owned_packages):
            raise RuntimeError("Owned package input escaped its frozen source")
        data = payload.read_bytes()
        if sha(data) != entry["sha256"] or len(data) != entry["size"]:
            raise RuntimeError("Owned package payload changed")
        package.writestr("zone/" + relative.as_posix(), data)
receipt = {
    "schema": 2,
    "archive": str(archive),
    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
    "game_sha256": digest,
    "release": deployment["public_updater"]["release"],
    "owned_native_assets": len(assets["entries"]),
    "owned_manifest_sha256": assets["manifest_sha256"],
    "custom_map_package_sha256": maps["package_hash"],
    "custom_maps_downloaded_separately": True,
    "custom_map_compressed_bytes": maps["transport_bytes"],
    "custom_map_installed_bytes": maps["uncompressed_bytes"],
    "public_address": endpoint,
    "universal_client": True,
    "player_provisioning_required": False,
    "proxy_dll_included": False,
    "private_signing_keys_included": False,
    "player_identity_included": False,
    "second_network_gameplay_verified": False,
}
(ROOT / "data/remote-package-receipt.json").write_text(
    json.dumps(receipt, indent=2) + "\n"
)
print("Universal client package:", archive)
print("Game SHA256:", digest)
