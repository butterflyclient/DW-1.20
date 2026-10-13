"""Isolated encrypted-wire regression for manual bot fill during a pending ballot.

Uses only disposable profiles/data and spare loopback ports; never contacts the
game or deployed backend. Baseline mode proves the former 145/15 error106.
"""

import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import runpy
import secrets
import shutil
import socket
import struct
import subprocess
import time
import urllib.request

from native_wire_client import u32, u64
from operator_match_start_fixtures import request as operator_request

ROOT = Path(__file__).resolve().parents[1]
adapter_spec = importlib.util.spec_from_file_location(
    "manual_fill_adapter", ROOT / "tools/test-auto-fill-wire.py"
)
adapter_module = importlib.util.module_from_spec(adapter_spec)
adapter_spec.loader.exec_module(adapter_module)
Adapter = adapter_module.Adapter


def text(value):
    return b"\x10" + value.encode() + b"\0"


def documents(raw):
    result = []
    while raw:
        assert raw[0] == 16
        end = raw.index(0, 1)
        result.append(json.loads(raw[1:end]))
        raw = raw[end + 1:]
    return result


def spare_offset():
    for offset in range(23500, 23700):
        probes = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                probes.append(probe)
                probe.bind(("127.0.0.1", port + offset))
            return offset
        except OSError:
            pass
        finally:
            for probe in probes:
                probe.close()
    raise RuntimeError("No spare loopback fixture ports")


def exercise(clients, data, catalog, offset, baseline, checks):
    host, peer = clients
    root = data / "matchmaking/5800"
    info = {
        "dedicated_server": {},
        "listen_server": {
            "local_address": base64.b64encode(bytes(84)).decode(),
            "security_id": base64.b64encode(bytes(8)).decode(),
            "security_key": base64.b64encode(bytes(16)).decode(),
        },
        "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]},
        "hardware": "pc",
    }
    tokens = []
    for client in clients:
        client.task(145, 2, text(json.dumps(info)))
        tokens.append(struct.unpack_from("<Q", client.task(145, 3), 1)[0])
    key = secrets.token_hex(32)
    (data / "operator-access.key").write_text(key + "\n")
    base = f"http://127.0.0.1:{8085 + offset}"

    for humans in (1, 2):
        members = clients[:humans]
        query = {
            "members": [client.user for client in members],
            "tokens": tokens[:humans],
            "player_id_to_slots": {str(client.user): 0 for client in members},
            "ruleset_payload": {
                "only_join_existing_lobbies": False,
                "filter": {"playlist_id": 1, "netcode_version": 1,
                           "playlist_version": catalog["version"]},
            },
        }
        mm = documents(host.task(145, 18, text(json.dumps(query))))[0]["mm_id"]
        kind, packet = host.receive()
        assert kind == 2 and packet.startswith(u32(2005) + u64(mm))
        lobby = struct.unpack_from("<Q", packet, 15)[0]
        docs = documents(packet[32:])
        path = root / "lobbies" / f"{lobby}.json"

        def durable():
            return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*.json")}

        def received():
            nonlocal docs
            kind, packet = host.receive()
            assert kind == 2 and packet.startswith(u32(2006) + u64(lobby))
            for observer in members[1:]:
                assert observer.receive() == (kind, packet)
            docs = documents(packet[23:])

        def publish(payload, error=0, revision=None):
            before = durable()
            result = host.task(145, 15, u64(lobby)
                               + u64(docs[1]["update_id"] if revision is None else revision)
                               + text(json.dumps(payload)), error=error)
            if error:
                assert durable() == before
                return
            if revision is not None:
                assert result == b"\x01\x00" and durable() == before
                return
            assert result == b"\x01\x01"
            received()

        # Establish readiness before arming; first acknowledgement sends2001
        # to the retained party peer rather than a normal2006 notification.
        assert host.task(145, 15, u64(lobby) + u64(docs[1]["update_id"])
                         + text(json.dumps(docs[0]))) == b"\x01\x01"
        _, packet = host.receive()
        assert packet.startswith(u32(2006) + u64(lobby))
        for observer in members[1:]:
            assert observer.receive() == (2, u32(2001) + u64(mm) + u64(lobby) + packet[23:])
        docs = documents(packet[23:])
        arm = copy.deepcopy(docs[0])
        arm["dw_map_vote"] = {"version": 1, "entry": 0, "votes": {str(host.user): 2}}
        publish(arm)
        state = json.loads(path.read_bytes())
        ballot = copy.deepcopy(state["map_vote"])
        assert not ballot["complete"] and len(ballot["choices"]) == 3
        last_remaining = ballot["remaining_ms"]

        def assert_ballot():
            nonlocal last_remaining
            current = json.loads(path.read_bytes())["map_vote"]
            assert 0 < current["remaining_ms"] <= last_remaining
            last_remaining = current["remaining_ms"]
            assert {key: value for key, value in current.items() if key != "remaining_ms"} == {
                key: value for key, value in ballot.items() if key != "remaining_ms"}

        retained = {key: copy.deepcopy(state[key]) for key in
                    ("id", "owner", "owner_session", "members", "maximum_members")}
        retained_backend = {key: copy.deepcopy(state["backend_doc"][key]) for key in
                            ("players", "player_id_to_mm_id", "player_id_to_slots", "team_balance")}
        index = (root / "current-lobbies.json").read_bytes()
        searches = {p.name: p.read_bytes() for p in (root / "searches").glob("*.json")}
        capacity = state["maximum_members"] - humans
        token = hashlib.sha256(
            f"5800:{lobby}:{state['owner_session']}:{state.get('operator_start_cycle', 0)}".encode()
        ).hexdigest()
        auto = copy.deepcopy(docs[0])
        auto.update(dw_auto_fill_request=1, dw_auto_fill_bots=True,
                    dw_auto_fill_complete=False, dw_bot_count=0)
        publish(auto)
        manual = copy.deepcopy(docs[0]); manual["dw_bot_count"] = 1
        publish(manual, error=106)
        saved = durable()
        assert operator_request(base, token, key, fill_bots=True, bot_count=1)[0] == 409
        assert durable() == saved
        off = copy.deepcopy(docs[0])
        off.update(dw_auto_fill_request=2, dw_auto_fill_bots=False,
                   dw_auto_fill_complete=False, dw_bot_count=0)
        publish(off)
        assert_ballot()
        before = durable()
        assert operator_request(base, token, key)[0] == 409
        assert durable() == before
        fill = operator_request(base, token, key, fill_bots=True, bot_count=1)
        assert fill[0] == (409 if baseline else 202), fill
        if baseline:
            assert durable() == before
        else:
            received()
            saved = durable()
            assert operator_request(base, token, key, fill_bots=True, bot_count=1)[0] == 200
            assert durable() == saved
            received()

        for count in sorted({1, 2, 5, capacity}):
            assert count <= capacity
            payload = copy.deepcopy(docs[0])
            payload["dw_bot_count"] = count
            payload["dw_map_vote"] = arm["dw_map_vote"]
            publish(payload, error=106 if baseline else 0)
            state = json.loads(path.read_bytes())
            assert_ballot()
            assert not state.get("disbanded", False) and state["host_ready"]
            assert {key: state[key] for key in retained} == retained
            assert {key: state["backend_doc"][key] for key in retained_backend} == retained_backend
            assert (root / "current-lobbies.json").read_bytes() == index
            assert {p.name: p.read_bytes() for p in (root / "searches").glob("*.json")} == searches
            if not baseline:
                assert state["operator_bot_count"] == count
                assert "dw_bot_count" not in docs[0]
                rules = docs[1]["ruleset_payload"]["dvar_overrides"]
                assert rules["replay_dw_botCount"] == count
                assert rules["replay_dw_fillBots"] == 0 and rules["replay_dw_forceStart"] == 0
                assert rules["replay_dw_mapVoteActive"] == 1 and rules["replay_dw_mapVoteComplete"] == 0
                # Native heartbeat remains usable: no fresh search or disband,
                # no deadline restart, and every party member gets2006.
                publish(copy.deepcopy(docs[0]))
                assert_ballot()
                publish(payload, revision=docs[1]["update_id"] - 1)
            checks.append({"humans": humans, "bots": count,
                           "expected_error": 106 if baseline else 0,
                           "ballot_and_membership_preserved": True})

        for count in (0, capacity + 1, 200):
            payload = copy.deepcopy(docs[0]); payload["dw_bot_count"] = count
            publish(payload, error=106)
        premature = copy.deepcopy(docs[0]); premature["game_state"] = {"state": "countdown"}
        publish(premature, error=106)
        saved = durable()
        assert operator_request(base, token, key)[0] == 409 and durable() == saved
        # Test backend authorization/automatic ownership separately from ballot.
        payload = copy.deepcopy(docs[0]); payload["dw_bot_count"] = 1
        saved = durable()
        peer.task(145, 15, u64(lobby) + u64(docs[1]["update_id"])
                  + text(json.dumps(payload)), error=101)
        assert durable() == saved
        auto = copy.deepcopy(docs[0])
        auto.update(dw_auto_fill_request=3, dw_auto_fill_bots=True,
                    dw_auto_fill_complete=False, dw_bot_count=0)
        # Once a manual count owns the round, automatic fill cannot take over.
        publish(auto, error=0 if baseline else 106)
        host.task(145, 10, u64(lobby))
        for member in members:
            assert member.receive() == (2, u32(2002) + u64(lobby) + u64(0))
        host.task(145, 9, u64(mm))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expect-baseline-rejection", action="store_true")
    args = parser.parse_args()
    image = args.server.resolve(strict=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    fixture = args.output.parent / f"manual-fill-wire-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    catalog = runpy.run_path(str(ROOT / "tools/prepare-playlist-catalog.py"))["prepare"](
        data, ["mp_backlot2", "mp_cave_am", "mp_crash2"], 1)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for profile in ("manual-host", "manual-peer"):
        subprocess.run([str(image), str(data), "--provision-profile", profile, profile],
                       check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    offset = spare_offset()
    log = (fixture / "stdout.log").open("wb")
    process = subprocess.Popen([str(image), str(data), "--port-offset", str(offset)],
                               stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
    clients = []
    try:
        for _ in range(100):
            assert process.poll() is None
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=0.2):
                    break
            except OSError:
                time.sleep(0.03)
        clients = [Adapter(fixture, profile=profile, port_offset=offset)
                   for profile in ("manual-host", "manual-peer")]
        checks = []
        exercise(clients, data, catalog, offset, args.expect_baseline_rejection, checks)
        args.output.write_text(json.dumps({"passed": True,
            "baseline_rejection": args.expect_baseline_rejection,
            "server_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "checks": checks, "fixture": str(fixture),
            "native_game_verified": False, "production_changed": False}, indent=2) + "\n")
        print(f"PASS manual fill/ballot encrypted-wire regression: {len(checks)} counts")
    finally:
        for client in clients:
            client.close()
        process.terminate()
        process.wait(timeout=5)
        log.close()


if __name__ == "__main__":
    main()
