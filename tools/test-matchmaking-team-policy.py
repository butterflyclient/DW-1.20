"""Focused encrypted-wire team policy and host-readiness regression checks.

Creates an isolated backend and disposable fixture profiles on spare local
ports. Never authenticates as, provisions, or changes a real game player.
"""

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
EXE = ROOT / "build/Release/iw8-dw-server.exe"
fixture = ROOT / "data" / ("team-policy-fixture-" + str(time.time_ns()))
data = fixture / "data"
data.mkdir(parents=True)
shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data / "replay-traffic-kdf.bin")
prepare = runpy.run_path(str(ROOT / "tools/prepare-playlist-catalog.py"))["prepare"]
catalog = prepare(data, ["mp_shipment"], 1)
policy_path = data / "playlists/5800/policy.json"


def policy(split):
    value = {"available_maps": ["mp_shipment"], "minimum_players": 1}
    value["split_parties_for_team_balance"] = split
    policy_path.write_text(json.dumps(value) + "\n")


def spare_offset():
    for offset in range(10000, 10200):
        sockets = []
        try:
            for port in (8085, 8443, 3075):
                s = socket.socket()
                sockets.append(s)
                s.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            continue
        finally:
            for s in sockets:
                s.close()
    raise RuntimeError("No isolated fixture ports available")


def text(value):
    return b"\x10" + value.encode() + b"\0"


def documents(raw):
    result = []
    while raw:
        assert raw[0] == 16
        end = raw.index(0, 1)
        result.append(json.loads(raw[1:end]))
        raw = raw[end + 1 :]
    return result


def receive(client):
    return (2, client.pushes.pop(0)) if client.pushes else client.receive()


def ordinary(client, task, params=b""):
    return client.task(145, task, params, structured=False)


subprocess.run(
    [str(EXE), str(data), "--provision-profile", "peer", "Team Fixture 2"],
    check=True, stdout=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
)
offset = spare_offset()
output = (fixture / "stdout.log").open("wb")
process = subprocess.Popen(
    [str(EXE), str(data), "--port-offset", str(offset)], stdout=output,
    stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW,
)
checks = []
try:
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Isolated team-policy backend exited")
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=0.3):
                break
        except OSError:
            time.sleep(0.05)
    else:
        raise RuntimeError("Isolated backend did not become ready")
    with NativeClient(fixture, port_offset=offset) as host, NativeClient(
        fixture, profile="peer", port_offset=offset
    ) as peer:
        for client in (host, peer):
            info = {
                "listen_server": {
                    "local_address": base64.b64encode(bytes(84)).decode(),
                    "security_id": base64.b64encode(os.urandom(8)).decode(),
                    "security_key": base64.b64encode(os.urandom(16)).decode(),
                },
                "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]}, "hardware": "pc",
            }
            assert ordinary(client, 2, text(json.dumps(info))) == b""
        tokens = [struct.unpack_from("<Q", ordinary(c, 3), 1)[0] for c in (host, peer)]
        query = {
            "members": [host.user, peer.user], "tokens": tokens,
            "lobby_slots": {"min": 1, "max": 4}, "team_balance": {"num_teams": 2},
            "ruleset_payload": {"filter": {
                "playlist_id": 1, "netcode_version": 66514,
                "playlist_version": catalog["version"],
            }},
        }
        for split in (False, True):
            policy(split)
            mm = documents(ordinary(host, 18, text(json.dumps(query))))[0]["mm_id"]
            kind, created = receive(host)
            assert kind == 2 and created.startswith(u32(2005) + u64(mm))
            lobby = struct.unpack_from("<Q", created, 15)[0]
            docs = documents(created[32:])
            expected = {"0": [host.user], "1": [peer.user]} if split else {
                "0": [host.user, peer.user], "1": [],
            }
            assert docs[1]["team_balance"]["teams"] == expected
            assert docs[1]["ruleset_payload"]["map_weights"]["mp_shipment"] > 0
            assert all(
                weight == 0 for name, weight in docs[1]["ruleset_payload"]["map_weights"].items()
                if name != "mp_shipment"
            )
            assert ordinary(host, 15, u64(lobby) + u64(docs[1]["update_id"])
                            + text(json.dumps(docs[0]))) == b"\x01\x01"
            kind, update = receive(host)
            assert kind == 2 and update.startswith(u32(2006) + u64(lobby))
            assert receive(peer) == (2, u32(2001) + u64(mm) + u64(lobby) + update[23:])
            current = documents(update[23:])
            assert current[1]["team_balance"]["teams"] == expected
            assert documents(ordinary(peer, 13, u64(lobby))) == current
            assert ordinary(host, 10, u64(lobby)) == b""
            ended = (2, u32(2002) + u64(lobby) + u64(0))
            assert receive(host) == ended and receive(peer) == ended
            checks.append("player-balanced 1v1" if split else "normal party grouping preserved")
        policy(1)
        try:
            ordinary(host, 18, text(json.dumps(query)))
            raise AssertionError("Non-boolean team policy accepted")
        except RuntimeError as error:
            assert "returned 106" in str(error)
        checks.extend(["Shipment-only native weights", "host-ready peer join and shared documents",
                       "invalid policy rejected", "normal disband delivery"])
    receipt = {
        "schema": 1, "passed": True, "native_game_verified": False,
        "scope": "focused team allocation, native lobby wire and playlist policy regression",
        "server_sha256": hashlib.sha256(EXE.read_bytes()).hexdigest(),
        "fixture_directory": str(fixture), "checks": checks,
    }
    (ROOT / "data/team-policy-verification.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"PASS: {len(checks)} focused encrypted team-policy checks; no game launched")
finally:
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)
    output.close()
