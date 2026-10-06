"""Package one universal Replay DW client; identity is created on the player's PC."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
deployment = json.loads((ROOT / 'data/deployment.json').read_text())
image = Path(deployment['executable'])
digest = hashlib.sha256(image.read_bytes()).hexdigest()
if digest != deployment['sha256']:
    raise RuntimeError('Deployed game image changed')
if not any(Path(item['source']).name == 'DW_LocalIdentity.cpp'
           for item in deployment['platform_sources']):
    raise RuntimeError('Deployed image does not contain automatic local identity support')
network = json.loads((ROOT / 'data/network.json').read_text())
router = json.loads((ROOT / 'data/host-network-receipt.json').read_text())
if network['advertised_address'] != router['public_address']:
    raise RuntimeError('Backend and verified router address differ')

ini = f"host={router['public_address']}\nplayer_name=\n"
launcher = '@echo off\r\ncd /d "%~dp0"\r\nstart "" "%~dp0game_dx12_ship_replay_dw.exe"\r\n'
readme = rf'''REPLAY DW CLIENT TEST

Extract all four files into your compatible 1.20 Replay root game folder.
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

Settings save locally under Documents\Call of Duty Modern Warfare\players:
config.cfg and settings.<platformId>.iw8. Native cloud sync is disabled for DW.
No backend signing keys, access keys or player identities are in this package.
This is the current multiplayer test build, not a completed DW replacement.

Game SHA256: {digest}
'''
files = {image.with_suffix('.ini').name: ini.encode('ascii'),
         'Run_Replay_DW_Client.cmd': launcher.encode('ascii'),
         'READ_ME.txt': readme.encode('ascii')}
archive = ROOT / 'data/Replay-DW-Client-Test.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=1) as package:
    package.write(image, image.name)
    for name, data in files.items():
        package.writestr(name, data)
receipt = {'schema': 2, 'archive': str(archive), 'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
           'game_sha256': digest, 'public_address': router['public_address'],
           'universal_client': True, 'player_provisioning_required': False,
           'proxy_dll_included': False, 'private_signing_keys_included': False,
           'player_identity_included': False, 'second_network_gameplay_verified': False}
(ROOT / 'data/remote-package-receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
print('Universal client package:', archive)
print('Game SHA256:', digest)
