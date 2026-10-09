"""Exercise every owner playlist through an isolated encrypted DW backend.

Reads the installed package headers but never launches or edits the game.
One disposable account is sufficient for backend document/capacity checks;
this does not establish native map loading or multiplayer gameplay.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import runpy
import shutil
import socket
import struct
import subprocess
import time
import urllib.request

from native_wire_client import NativeClient, u32, u64

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--game-directory", type=Path)
parser.add_argument(
    "--publication",
    type=Path,
    help="Previously verified native catalog/package directory for Linux fixtures",
)
parser.add_argument("--server", type=Path, default=ROOT / "build/Release/iw8-dw-server.exe")
parser.add_argument("--output", type=Path, default=ROOT / "data/playlist-wire-verification.json")
args = parser.parse_args()
if bool(args.game_directory) == bool(args.publication):
    parser.error("Choose exactly one of --game-directory and --publication")
EXE = args.server.resolve(strict=True)
creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
fixture = ROOT / "data" / f"playlist-wire-fixture-{time.time_ns()}"
data = fixture / "data"
data.mkdir(parents=True)
shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data / "replay-traffic-kdf.bin")
prepare = runpy.run_path(str(ROOT / "tools/prepare-playlist-catalog.py"))["prepare"]
policy = data / "playlists/5800/policy.json"
if args.publication:
    shutil.copytree(args.publication, policy.parent)
else:
    policy.parent.mkdir(parents=True)
    policy.write_text(
        json.dumps(
            {
                "minimum_players": 2,
                "minimum_lobby_seconds": 60,
                "split_parties_for_team_balance": True,
            }
        )
    )
    prepare(data, game_directory=args.game_directory)
catalog = json.loads((policy.parent / "catalog.json").read_bytes())
packages = json.loads((policy.parent / "packages.json").read_bytes())
available = {row["name"] for row in packages["maps"] if row["available"]}
modes = {row["gametype"]: row for row in catalog["gametypes"]}


def spare_offset():
    for offset in range(10400, 10600):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                channel = socket.socket()
                sockets.append(channel)
                channel.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            continue
        finally:
            for channel in sockets:
                channel.close()
    raise RuntimeError("No isolated playlist fixture ports available")


def text(value):
    return b"\x10" + value.encode() + b"\0"


def documents(raw):
    result = []
    while raw:
        assert raw[0] == 16
        end = raw.index(0, 1)
        assert end < 16384
        result.append(json.loads(raw[1:end]))
        raw = raw[end + 1 :]
    return result


def receive(client):
    return (2, client.pushes.pop(0)) if client.pushes else client.receive()


offset = spare_offset()
output = (fixture / "stdout.log").open("wb")
process = subprocess.Popen(
    [str(EXE), str(data), "--port-offset", str(offset)],
    stdout=output,
    stderr=subprocess.STDOUT,
    creationflags=creation_flags,
)
results = []
try:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Isolated playlist backend exited")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=0.3):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("Isolated playlist backend did not become ready")

    with NativeClient(fixture, port_offset=offset) as client:
        info = {
            "dedicated_server": {"build_name": "replay-playlist-wire-fixture"},
            "listen_server": {
                "local_address": base64.b64encode(bytes(84)).decode(),
                "security_id": base64.b64encode(os.urandom(8)).decode(),
                "security_key": base64.b64encode(os.urandom(16)).decode(),
            },
            "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]},
            "hardware": "pc",
        }
        assert client.task(145, 2, text(json.dumps(info)), structured=False) == b""
        token = struct.unpack_from("<Q", client.task(145, 3, b"", structured=False), 1)[0]
        for playlist in catalog["playlists"]:
            entries = [
                row
                for row in playlist["maps"][:20]
                if row["map"] in available and row["weight"] > 0
            ]
            team_count = modes[entries[0]["gametype"]].get("teamCount", 0) if entries else 0
            query = {
                "members": [client.user],
                "tokens": [token],
                "lobby_slots": {"min": 2, "max": 200},
                "team_balance": {"num_teams": team_count},
                "ruleset_payload": {
                    "filter": {
                        "playlist_id": playlist["playlist"],
                        "playlist_version": catalog["system"]["version"],
                        "netcode_version": 66514,
                    }
                },
            }
            packet = text(json.dumps(query))
            if not entries:
                try:
                    client.task(145, 18, packet, structured=False)
                    raise AssertionError("An unavailable playlist formed a lobby")
                except RuntimeError as error:
                    assert "returned 108" in str(error)
                results.append({"playlist": playlist["playlist"], "eligible": False})
                continue
            reply = client.task(145, 18, packet, structured=False)
            search = documents(reply)[0]["mm_id"]
            kind, created = receive(client)
            assert kind == 2 and created.startswith(u32(2005) + u64(search))
            lobby = struct.unpack_from("<Q", created, 15)[0]
            host, backend = documents(created[32:])
            assert backend["ruleset_payload"]["filter"]["playlist_id"] == playlist["playlist"]
            assert len(backend["ruleset_payload"]["dvar_overrides"]) <= 128
            weights = backend["ruleset_payload"]["map_weights"]
            assert {name for name, weight in weights.items() if weight > 0} == {
                row["map"] for row in entries
            }
            assert len(weights) <= 20
            path = data / "matchmaking/5800/lobbies" / f"{lobby}.json"
            stored = json.loads(path.read_bytes())["match_selection"]
            assert stored["eligible_entries"] == entries
            assert stored["playlist_dvars"] == playlist.get("dvars", {})
            assert stored["map_package_revision"] == packages["revision"]
            if "maximum_members" in stored:
                state = json.loads(path.read_bytes())
                assert state["maximum_members"] == stored["maximum_members"]
            assert client.task(145, 13, u64(lobby), structured=False) == (
                text(json.dumps(host, separators=(",", ":"), sort_keys=True))
                + text(json.dumps(backend, separators=(",", ":"), sort_keys=True))
            )
            assert client.task(145, 10, u64(lobby), structured=False) == b""
            assert receive(client) == (2, u32(2002) + u64(lobby) + u64(0))
            results.append(
                {
                    "playlist": playlist["playlist"],
                    "eligible": True,
                    "entry_count": len(entries),
                    "team_count": team_count,
                    "backend_bytes": len(json.dumps(backend, separators=(",", ":"))),
                    "native_playlist_dvars": len(stored["playlist_dvars"]),
                    "maximum_members": stored.get("maximum_members"),
                }
            )
    proof = {
        "schema": 1,
        "passed": True,
        "server_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
        "package_revision": packages["revision"],
        "fixture_directory": str(fixture),
        "results": results,
        "game_runs_performed": False,
        "native_map_load_verified": False,
    }
    destination = args.output
    destination.write_text(json.dumps(proof, indent=2) + "\n")
    print(
        f"PASS: {len(results)} owner playlists through encrypted native matchmaking; no game runs"
    )
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    output.close()
