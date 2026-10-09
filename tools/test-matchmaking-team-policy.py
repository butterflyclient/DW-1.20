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
import sys
import subprocess
import time
import urllib.request

from native_wire_client import NativeClient, u32, u64

ROOT = Path(__file__).resolve().parents[1]
EXE = Path(os.environ.get("IW8_DW_TEST_SERVER", str(ROOT / "build/Release/iw8-dw-server.exe")))
WINDOW_FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
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


for profile, name in (("peer", "Team Fixture 2"), ("third", "Team Fixture 3"),
                      ("fourth", "Team Fixture 4")):
    subprocess.run(
        [str(EXE), str(data), "--provision-profile", profile, name],
        check=True, stdout=subprocess.DEVNULL, creationflags=WINDOW_FLAGS,
    )
offset = spare_offset()
output = (fixture / "stdout.log").open("wb")
process = subprocess.Popen(
    [str(EXE), str(data), "--port-offset", str(offset)], stdout=output,
    stderr=subprocess.STDOUT, creationflags=WINDOW_FLAGS,
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
    ) as peer, NativeClient(fixture, profile="third", port_offset=offset) as third, NativeClient(
        fixture, profile="fourth", port_offset=offset
    ) as fourth:
        clients = (host, peer, third, fourth)
        for client in clients:
            info = {
                "dedicated_server": {"build_name": "replay-team-fixture"},
                "listen_server": {
                    "local_address": base64.b64encode(bytes(84)).decode(),
                    "security_id": base64.b64encode(os.urandom(8)).decode(),
                    "security_key": base64.b64encode(os.urandom(16)).decode(),
                },
                "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]}, "hardware": "pc",
            }
            assert ordinary(client, 2, text(json.dumps(info))) == b""
        tokens = [struct.unpack_from("<Q", ordinary(c, 3), 1)[0] for c in clients]
        query = {
            "members": [host.user, peer.user], "tokens": tokens[:2],
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
            names = json.loads((data / "playlists/5800/native-dvar-names.json").read_text())
            guard = names["online_matchmaking_ignore_partition_value"]
            overrides = docs[1]["ruleset_payload"]["dvar_overrides"]
            assert overrides.get(guard) == 1 if split else guard not in overrides
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
            if split:
                joining = {
                    **query, "members": [third.user, fourth.user], "tokens": tokens[2:],
                    "ruleset_payload": {**query["ruleset_payload"],
                                        "only_join_existing_lobbies": True},
                }
                joined_mm = documents(ordinary(third, 18, text(json.dumps(joining))))[0]["mm_id"]
                kind, joined = receive(third)
                assert kind == 2 and joined.startswith(u32(2001) + u64(joined_mm) + u64(lobby))
                assert receive(fourth) == (kind, joined)
                joined_docs = documents(joined[23:])
                teams = joined_docs[1]["team_balance"]["teams"]
                assert len(teams["0"]) == len(teams["1"]) == 2
                assert teams["0"][0] == host.user and teams["1"][0] == peer.user
                assert {teams["0"][1], teams["1"][1]} == {third.user, fourth.user}
                for observer in (host, peer):
                    kind, changed = receive(observer)
                    assert kind == 2 and changed.startswith(u32(2006) + u64(lobby))
                    assert documents(changed[23:]) == joined_docs
                checks.append("joining party balances each primary and retains existing team assignments")
            assert ordinary(host, 10, u64(lobby)) == b""
            ended = (2, u32(2002) + u64(lobby) + u64(0))
            assert receive(host) == ended and receive(peer) == ended
            if split:
                assert receive(third) == ended and receive(fourth) == ended
            checks.append("player-balanced 1v1" if split else "normal party grouping preserved")
        policy_path.write_text(json.dumps({"available_maps": ["mp_donetsk"],
            "minimum_players": 1, "split_parties_for_team_balance": True}) + "\n")
        br = {**query, "team_balance": {"num_teams": 1, "lock_squad": True},
              "lobby_slots": {"min": 1, "max": 150},
              "ruleset_payload": {**query["ruleset_payload"], "filter": {
                  "playlist_id": 25, "playlist_version": catalog["version"]}}}
        mm = documents(ordinary(host, 18, text(json.dumps(br))))[0]["mm_id"]
        kind, created = receive(host)
        assert kind == 2 and created.startswith(u32(2005) + u64(mm))
        lobby = struct.unpack_from("<Q", created, 15)[0]
        docs = documents(created[32:])
        assert docs[1]["team_balance"]["squad_size"] == 3
        assert docs[1]["team_balance"]["squads"] == {"0": [host.user, peer.user]}
        assert len(docs[1]["team_balance"]["teams"]) == 50
        assert docs[1]["team_balance"]["teams"]["0"] == [host.user, peer.user]
        assert docs[1]["ruleset_payload"]["dvar_overrides"][names["party_teamCount"]] == 50
        assert docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_squadSize"] == 3
        assert int(docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_reservedSquads"], 16) == 1
        assert docs[1]["ruleset_payload"]["dvar_overrides"][guard] == 0
        assert ordinary(host, 15, u64(lobby) + u64(docs[1]["update_id"])
                        + text(json.dumps(docs[0]))) == b"\x01\x01"
        _, update = receive(host)
        receive(peer)
        joining = {**br, "members": [third.user, fourth.user], "tokens": tokens[2:],
                   "team_balance": {"num_teams": 50, "lock_squad": True},
                   "ruleset_payload": {**br["ruleset_payload"], "only_join_existing_lobbies": True}}
        joined_mm = documents(ordinary(third, 18, text(json.dumps(joining))))[0]["mm_id"]
        kind, joined = receive(third)
        assert kind == 2 and joined.startswith(u32(2001) + u64(joined_mm) + u64(lobby))
        assert receive(fourth) == (kind, joined)
        joined_docs = documents(joined[23:])
        assert {k: set(v) for k, v in joined_docs[1]["team_balance"]["squads"].items()} == {
            "0": {host.user, peer.user}, "1": {third.user, fourth.user}}
        assert joined_docs[1]["team_balance"]["teams"]["1"] == [third.user, fourth.user]
        assert int(joined_docs[1]["ruleset_payload"]["dvar_overrides"]["replay_dw_reservedSquads"], 16) == 3
        for observer in (host, peer):
            _, changed = receive(observer)
            assert documents(changed[23:]) == joined_docs
        assert ordinary(host, 10, u64(lobby)) == b""
        for client in clients:
            assert receive(client) == (2, u32(2002) + u64(lobby) + u64(0))
        checks.append("Verdansk BR uses its published squad size, preserves each party in one squad, and disables MP partition splitting")
        checks.append("BR publishes all fifty combat groups, preserves capacity and native bindings, carries No Fill bot reservations, and matches clients with stale MP team counts")
        squad_binding = names["online_matchmaking_update_party_team_squad_assignments"]
        assert docs[1]["ruleset_payload"]["dvar_overrides"][squad_binding] == 1
        for host_locked, joining_locked in ((True, False), (False, True), (False, False)):
            initial = {**br, "team_balance": {"num_teams": 1, "lock_squad": host_locked},
                       "ruleset_payload": {**br["ruleset_payload"], "filter": {
                           "playlist_id": 89, "playlist_version": catalog["version"]}}}
            mm = documents(ordinary(host, 18, text(json.dumps(initial))))[0]["mm_id"]
            _, created = receive(host)
            lobby = struct.unpack_from("<Q", created, 15)[0]
            docs = documents(created[32:])
            assert docs[1]["team_balance"]["squad_size"] == 4
            ordinary(host, 15, u64(lobby) + u64(docs[1]["update_id"]) + text(json.dumps(docs[0])))
            receive(host); receive(peer)
            joining = {**initial, "members": [third.user, fourth.user], "tokens": tokens[2:],
                       "team_balance": {"num_teams": 1, "lock_squad": joining_locked},
                       "ruleset_payload": {**initial["ruleset_payload"], "only_join_existing_lobbies": True}}
            joined_mm = documents(ordinary(third, 18, text(json.dumps(joining))))[0]["mm_id"]
            _, joined = receive(third); receive(fourth)
            assert joined.startswith(u32(2001) + u64(joined_mm) + u64(lobby))
            squads = documents(joined[23:])[1]["team_balance"]["squads"]
            assert squads["0"] == [host.user, peer.user] if host_locked or joining_locked else squads["0"] == [host.user, peer.user, third.user, fourth.user]
            if host_locked or joining_locked:
                assert squads["1"] == [third.user, fourth.user]
            receive(host); receive(peer)
            ordinary(host, 10, u64(lobby))
            for client in clients:
                assert receive(client) == (2, u32(2002) + u64(lobby) + u64(0))
        checks.append("Fill Off parties reserve separate squads; Fill On fills only consenting squads, mixed fill modes share lobbies and DW-to-native squad updates are enabled")
        policy(True)
        # This is a document-only fixture. The native S&D publication excludes
        # Shipment, so use an eligible installed map without launching any map.
        policy_path.write_text(json.dumps({"available_maps": ["mp_backlot2"],
            "minimum_players": 1, "split_parties_for_team_balance": True}) + "\n")
        quick = {**query, "playlist_config": [{"playlist_ids": [4]}]}
        mm = documents(ordinary(host, 18, text(json.dumps(quick))))[0]["mm_id"]
        _, created = receive(host)
        lobby = struct.unpack_from("<Q", created, 15)[0]
        quick_docs = documents(created[32:])
        assert quick_docs[1]["ruleset_payload"]["filter"]["playlist_id"] == 4
        assert quick_docs[1]["ruleset_payload"]["map_weights"]["mp_backlot2"] > 0
        ordinary(host, 15, u64(lobby) + u64(quick_docs[1]["update_id"]) + text(json.dumps(quick_docs[0])))
        receive(host); receive(peer)
        ordinary(host, 10, u64(lobby))
        assert receive(host) == receive(peer) == (2, u32(2002) + u64(lobby) + u64(0))
        checks.append("Quick Play category anchor 1 with authoritative selected IDs [4] produces Search and Destroy rather than excluded TDM")
        policy(1)
        try:
            ordinary(host, 18, text(json.dumps(query)))
            raise AssertionError("Non-boolean team policy accepted")
        except RuntimeError as error:
            assert "returned 106" in str(error)
        checks.extend(["Shipment-only native weights", "host-ready peer join and shared documents",
                       "invalid policy rejected", "normal disband delivery"])
        invitation = b"INV:\0\x02Team Sender\0" + struct.pack("<IQ", int(time.time()), host.user)
        for body, kind in ((b"INV:\0\x00", "join_info_request"),
                           (b"INV:\0\x01\x01", "join_info_response"),
                           (invitation, "invitation")):
            blob = b"\x13" + u32(len(body)) + body
            assert host.task(6, 14, u64(peer.user) + blob, structured=False) == b""
            push_kind, pushed = receive(peer)
            assert push_kind == 2 and pushed.startswith(u32(21) + u64(host.user))
            assert pushed[14] == 16
            name_end = pushed.index(0, 15)
            assert pushed[name_end + 1:] == blob
            log = (data / "server.log").read_text(errors="replace")
            assert "message_kind=" + kind in log
        assert "invitation_layout=valid inviter_matches_sender=1" in log
        checks.append("exact native invitation/request/response bytes preserved with typed routing diagnostics")
        if "--lobby-only" in sys.argv:
            receipt = dict(schema=1, passed=True, native_game_verified=False,
                           scope="focused lobby team/squad/filter wire regression",
                           server_sha256=hashlib.sha256(EXE.read_bytes()).hexdigest(),
                           fixture_directory=str(fixture), checks=checks)
            (ROOT / "data/team-policy-verification.json").write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"PASS: {len(checks)} focused encrypted lobby/team-policy checks; no game launched")
            raise SystemExit(0)
        from multiplayer_progression_fixtures import exercise
        exercise(host, peer, third, data, query, tokens, policy, ordinary,
                 receive, documents, text, checks)
    # Machine-identity fixtures use fresh keys on this isolated backend only.
    from local_progression_fixtures import exercise as exercise_local_progression
    exercise_local_progression(fixture, data, offset, checks)
    from progression_restart_fixtures import exercise as exercise_progression_restart

    def restart_fixture_backend():
        global process
        previous = process.pid
        process.terminate()
        process.wait(timeout=5)
        process = subprocess.Popen(
            [str(EXE), str(data), "--port-offset", str(offset)],
            stdout=output, stderr=subprocess.STDOUT,
            creationflags=WINDOW_FLAGS,
        )
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("Restarted progression fixture exited")
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{8085 + offset}/health", timeout=0.3
                ):
                    return previous, process.pid
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Restarted progression fixture did not become ready")

    exercise_progression_restart(fixture, data, offset, restart_fixture_backend, checks)
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
