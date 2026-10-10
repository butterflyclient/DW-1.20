"""Exercise real encrypted tasks using outputs from Replay's original kill parser.

Uses disposable profiles, loopback ports and backend snapshots. No game launch,
live-account login, production-state edit or packed-field reimplementation.
"""
import argparse
import base64
import copy
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

from native_wire_client import NativeClient, binary, fields, integer, structure, text, u32, u64
from progression_delivery_fixtures import decode_event67

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--parser-proof", type=Path, required=True)
    parser.add_argument("--battlepass-publication", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    original = json.loads(args.parser_proof.read_bytes())
    assert original["target_image_sha256"] == "68fb1cbcb2924182724004039de55a4c50152bb6561803c4898b7930b38132f0"
    cases = {row["fixture_label"]: row for row in original["cases"] if "fixture_label" in row}
    assert all(row["accepted"] for row in cases.values())
    assert all(row["parameter_count"] == 7 for row in cases.values() if row["name"] == "kill")
    metadata = json.loads((ROOT / "validation/20261008-replay-quest-rewards-assets.json").read_bytes())
    quests = {row["id"]: row for row in metadata["quests"]}
    fixtures = {1501: "pistol", 1503: "frag", 1505: "assault", 1506: "smg",
                1507: "shotgun", 1508: "lmg", 1509: "sniper", 1510: "pistol",
                1513: "finishing_move", 1553: "frag", 1555: "molotov",
                1556: "proximity_mine", 1557: "semtex", 1559: "throwing_knife",
                1560: "thermite", 1569: "pistol", 1571: "tactical",
                1594: "one_attachment", 1596: "lmg_five", 1597: "fr556",
                1600: "sniper_head_five", 10007: "throwing_knife", 10044: "pistol",
                10046: "magnum_three", 1514: "ghost_first", 1563: "ghost_third",
                1562: "shrapnel_frag", 1595: "reflex_head", 1598: "sks_five",
                1624: "reflex_pistol", 10000: "smg_head", 10003: "tracker_smg",
                10040: "zoom_head", 10131: "ak47_head"}
    fixture = ROOT / "data" / f"quest-earning-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    catalog = runpy.run_path(str(ROOT / "tools/prepare-playlist-catalog.py"))["prepare"](data, ["mp_shipment", "mp_donetsk"], 1)
    runpy.run_path(str(ROOT / "tools/publish-replay-battlepass.py"))["publish"](args.battlepass_publication, data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for profile in ("quest-host", "quest-peer"):
        subprocess.run([str(args.server), str(data), "--provision-profile", profile, profile],
                       check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    offset = None
    for candidate in range(15400, 15500):
        probes = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                probes.append(probe)
                probe.bind(("127.0.0.1", port + candidate))
            offset = candidate
            break
        except OSError:
            continue
        finally:
            for probe in probes:
                probe.close()
    assert offset is not None
    log = (fixture / "stdout.log").open("wb")
    process, checks = None, []
    retired_lobbies = set()
    reward_history = []

    def start():
        nonlocal process
        process = subprocess.Popen([str(args.server), str(data), "--port-offset", str(offset)],
                                   stdout=log, stderr=log, creationflags=flags)
        for _ in range(100):
            assert process.poll() is None
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=0.3).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("Quest earning fixture did not start")

    def stop():
        nonlocal process
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        process = None

    def states_path(client):
        return data / "achievements/5800/5800" / str(client.user) / "states.json"

    def snapshot(client):
        client.task(125, 3, structure(text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0)))
        folder = states_path(client).parent
        inventory = data / "marketplace/5800" / str(client.user) / "inventory.json"
        return [path.read_bytes() if path.exists() else None for path in
                (folder / "states.json", folder / "events.json", inventory)]

    def select(client, identity, activate=True):
        payload = text(1, "5800") + text(2, "")
        payload += integer(3, 123) + integer(4, identity) if activate else integer(3, identity)
        assert client.task(125, 5 if activate else 6, structure(payload)) == b""

    def seed(client, identity, near_completion=True):
        select(client, identity)
        path = states_path(client)
        stored = json.loads(path.read_bytes())
        for row in stored:
            if row["id"] != identity and row.get("status") == 1 and quests.get(row["id"], {}).get("category") == quests[identity]["category"]:
                row["status"] = 2
        stage = next(row for row in stored if row["id"] == identity)
        stage.update(status=1, progress=quests[identity]["target"] - 1 if near_completion else 0)
        stage.pop("completionTimestamp", None)
        stage.pop("completionCount", None)
        path.write_text(json.dumps(stored) + "\n")

    def event(label, timestamp=1000, mode=2, name="kill", extra=None):
        values = {f"Param{i}": value for i, value in enumerate(cases[label]["values"])}
        if name == "kill":
            name = cases[label]["name"]
        values.update(version=1, gamemode=mode)
        values.update(extra or {})
        raw = text(1, name) + integer(2, timestamp) + integer(4, 0)
        for key, value in values.items():
            raw += binary(3, text(1, key) + integer(2, value))
        return raw

    def send(client, request, events):
        packet = structure(text(1, "5800") + b"".join(binary(2, row) for row in events) + text(3, request))
        assert client.task(125, 1, packet) == b""
        return packet

    def ordinary_text(value):
        return b"\x10" + value.encode() + b"\0"

    def documents(raw):
        out = []
        while raw:
            assert raw[0] == 16
            end = raw.index(0, 1)
            out.append(json.loads(raw[1:end]))
            raw = raw[end + 1:]
        return out

    def receive(client):
        # The native lobby lifecycle may reannounce a retired assignment when
        # subsequent player-info/token tasks run. Drain only the exact retired
        # disband envelope; retain every reward and unknown notification.
        while True:
            kind, packet = (2, client.pushes.pop(0)) if client.pushes else client.receive()
            if kind == 2 and packet.startswith(u32(2002)):
                old = struct.unpack_from("<Q", packet, 6)[0]
                if old in retired_lobbies:
                    assert packet == u32(2002) + u64(old) + u64(0)
                    continue
            return kind, packet

    def rewards(client, count):
        # NativeClient.task queues unsolicited pushes received before its task
        # result. lobby.cpp sends that result before the task's own deliveries.
        # Separate only validated absolute-XP catch-up from this pre-reply
        # queue; do not suppress any completion, rank-up or mission packet.
        pending = []
        for packet in client.pushes:
            if packet.startswith(u32(67)):
                update = decode_event67(packet, client.user)[2]
                if update["kind"] == 0 and update["reason"] == "inProgress":
                    assert update["id_"] == 1000000 and "xp" in update["multiProgress"]
                    reward_history.append({"user": client.user, "pre_reply_xp_refresh": update})
                    continue
            pending.append(packet)
        client.pushes[:] = pending
        out = []
        while len(out) < count:
            kind, packet = receive(client)
            assert kind == 2
            if packet.startswith(u32(67)):
                update = decode_event67(packet, client.user)[2]
                reward_history.append({"user": client.user, "update": update})
                out.append(update)
        return out

    def receive_lobby(client, expected):
        while True:
            kind, packet = receive(client)
            if packet.startswith(u32(67)):
                update = decode_event67(packet, client.user)[2]
                # The earlier unqualified kill created the native absolute-zero
                # XP journal. Its one idle catch-up is independent of lobby
                # creation and must not be mistaken for the create response.
                assert update["kind"] == 0 and update["reason"] == "inProgress"
                assert update["multiProgress"]["xp"]["value"] == 0
                continue
            assert kind == 2 and packet.startswith(u32(expected)), packet[:32].hex()
            return packet

    def create_match(host, peer, private=False, phase="in_game", br=False):
        tokens = []
        for client in (host, peer):
            info = {"dedicated_server": {"build_name": "replay-quest-fixture"},
                    "listen_server": {"local_address": base64.b64encode(bytes(84)).decode(),
                                      "security_id": base64.b64encode(os.urandom(8)).decode(),
                                      "security_key": base64.b64encode(os.urandom(16)).decode()},
                    "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]}, "hardware": "pc"}
            assert client.task(145, 2, ordinary_text(json.dumps(info)), structured=False) == b""
            tokens.append(struct.unpack_from("<Q", client.task(145, 3, b"", structured=False), 1)[0])
        query = {"members": [host.user, peer.user], "tokens": tokens,
                 "lobby_slots": {"min": 1, "max": 4}, "team_balance": {"num_teams": 2},
                 "ruleset_payload": {"filter": {"playlist_id": 1, "netcode_version": 66514,
                                                  "playlist_version": catalog["version"]}}}
        if private:
            query["private_lobby"] = {"initial_party_id": 61}
        if br:
            query["ruleset_payload"]["filter"]["playlist_id"] = 25
            query["lobby_slots"] = {"min": 1, "max": 150}
            query["team_balance"] = {"num_teams": 1, "lock_squad": True}
        client_result = documents(host.task(145, 18, ordinary_text(json.dumps(query)), structured=False))
        created = receive_lobby(host, 2005)
        assert created.startswith(u32(2005) + u64(client_result[0]["mm_id"])), (created[:32].hex(), client_result)
        lobby = struct.unpack_from("<Q", created, 15)[0]
        docs = documents(created[32:])
        docs[0]["game_state"]["state"] = phase
        assert host.task(145, 15, u64(lobby) + u64(docs[1]["update_id"])
                         + ordinary_text(json.dumps(docs[0])), structured=False) == b"\x01\x01"
        receive_lobby(host, 2006)
        receive_lobby(peer, 2001)
        return data / "matchmaking/5800/lobbies" / f"{lobby}.json"

    try:
        start()
        with NativeClient(fixture, profile="quest-host", port_offset=offset) as host, \
             NativeClient(fixture, profile="quest-peer", port_offset=offset) as peer:
            seed(host, 1503, False)
            before = states_path(host).read_bytes()
            send(host, "no-public-match", [event("frag")])
            assert states_path(host).read_bytes() == before
            private = create_match(host, peer, private=True)
            send(host, "private-match", [event("frag")])
            assert states_path(host).read_bytes() == before
            host.task(145, 10, u64(int(private.stem)), structured=False)
            receive_lobby(host, 2002)
            receive_lobby(peer, 2002)
            retired_lobbies.add(int(private.stem))
            lobby = create_match(host, peer)
            for label, modifications in (("tactical", {}), ("frag", {"mode": 8}),
                                          ("frag", {"timestamp": 122}), ("frag", {"extra": {"version": 0}}),
                                          ("frag", {"name": "death"})):
                send(host, f"negative-{len(checks)}-{label}-{len(modifications)}", [event(label, **modifications)])
                assert states_path(host).read_bytes() == before
                checks.append("Unqualified mission action rejected: " + label + str(modifications))
            select(host, 1503, False)
            before = states_path(host).read_bytes()
            send(host, "inactive", [event("frag")])
            assert states_path(host).read_bytes() == before
            checks.append("No active public match, wrong game mode/version/event, stale time, tactical equipment and deactivated stages cannot earn mission credit")
            seed(host, 1501, False)
            before = states_path(host).read_bytes()
            for label in ("equipment_target", "vehicle_target", "killstreak_target", "unknown_target"):
                send(host, label, [event(label)])
                assert states_path(host).read_bytes() == before
            checks.append("The shared kill event cannot credit player kills for equipment, vehicles, streaks or unknown target types")
            seed(host, 1501, False)
            partial = send(host, "partial-kills", [event("pistol"), event("pistol")])
            update = rewards(host, 1)[0]
            assert update["kind"] == 15 and update["progress"] == 2 and update["reason"] == "inProgress"
            stored = {row["id"]: row for row in json.loads(states_path(host).read_bytes())}
            assert stored[1501]["progress"] == 2 and stored[1501]["status"] == 1
            saved = snapshot(host)
            assert host.task(125, 1, partial) == b""
            assert rewards(host, 1)[0]["progress"] == 2 and snapshot(host) == saved
            send(host, "remaining-kills", [event("pistol")] * 3)
            update = next(row for row in rewards(host, 2) if row["kind"] == 15)
            assert update["progress"] == 5 and update["reason"] == "completed"
            checks.append("Separate batches accumulate individual kills from zero to the exact target; partial retries neither skip stages nor re-add progress")
            negative_kill_contexts = {
                1514: ("pistol", "br_ghost"),
                1563: ("pistol", "br_ghost"),
                1562: ("frag", "shrapnel_pistol"),
                1595: ("reflex_pistol", "acog_head"),
                1598: ("sniper_head_five", "marksman_four", "unknown_attachments"),
                1624: ("pistol", "reflex_assault"),
                10000: ("smg", "reflex_head"),
                10003: ("smg", "tracker_pistol", "br_tracker_smg"),
                10040: ("zoom_body", "acog_head"),
                10131: ("ak47_body", "smg_head"),
            }
            for identity, labels in negative_kill_contexts.items():
                seed(host, identity, False)
                before = states_path(host).read_bytes()
                for index, label in enumerate(labels):
                    send(host, f"wrong-{identity}-{index}", [event(label)])
                    assert states_path(host).read_bytes() == before, (identity, label)
                checks.append(f"Stage {identity} rejects wrong perk, class, optic, death cause or attachment context")
            seed(host, 1514, False)
            send(host, "all-native-ghost-slots", [event("ghost_first"), event("ghost_second"), event("ghost_third")])
            update = rewards(host, 1)[0]
            assert update["id_"] == 1514 and update["progress"] == 3 and update["reason"] == "inProgress"
            before = states_path(host).read_bytes()
            send(host, "upper-super-is-not-perk", [event("pistol", extra={"Param4": 52 << 48})])
            assert states_path(host).read_bytes() == before
            checks.append("Ghost is recognized in all three native loadout slots; the super-ID field cannot masquerade as a perk")
            seed(host, 1598, False)
            send(host, "shipped-marksman-family", [event("marksman_head_five"), event("sks_five"), event("crossbow_five")])
            update = rewards(host, 1)[0]
            assert update["id_"] == 1598 and update["progress"] == 3 and update["reason"] == "inProgress"
            checks.append("The shipped marksman family includes classic DMR, SKS and crossbow; native shared sniper mask does not merge the families")
            for identity, label in fixtures.items():
                seed(host, identity)
                journal = states_path(host).with_name("events.json")
                previous_xp = json.loads(journal.read_bytes()).get("player_xp", 0)
                packet = send(host, f"stage-{identity}", [event(label)])
                updates = rewards(host, 2)
                mission = next(row for row in updates if row["kind"] == 15)
                assert mission["id_"] == identity and mission["reason"] == "completed"
                assert mission["progress"] == quests[identity]["target"]
                stored = {row["id"]: row for row in json.loads(states_path(host).read_bytes())}
                assert stored[identity]["status"] == 3 and stored[identity]["completionCount"] == 1
                assert json.loads(journal.read_bytes())["player_xp"] == previous_xp + quests[identity]["xp_reward"]
                item = quests[identity]["item_reward"]
                inventory = json.loads((data / "marketplace/5800" / str(host.user) / "inventory.json").read_bytes())
                assert next(row["2"] for row in inventory["items"] if row["1"] == item) >= 1
                next_id = quests[identity]["next_id"]
                if next_id and stored[next_id]["status"] == 1:
                    assert any(t["type"] == "ACTIVATE_ACHIEVEMENT" and t["name"] == quests[next_id]["name"] for t in mission["triggers"])
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                retry = rewards(host, 2)
                assert all(row["reason"] == "inProgress" for row in retry)
                assert snapshot(host) == saved
                assert not any(t["type"] == "ACTIVATE_ACHIEVEMENT" for row in retry for t in row.get("triggers", []))
                checks.append(f"Stage {identity}: original {label} parser result completes exact target, grants shipped XP/item, activates successor and refreshes retry once")
            for identity, label in ((1509, "marksman"), (1600, "marksman_head_five"),
                                    (1596, "lmg"), (10046, "pistol"), (1500, "pistol")):
                seed(host, identity)
                before = states_path(host).read_bytes()
                send(host, f"excluded-{identity}", [event(label)])
                assert states_path(host).read_bytes() == before
            checks.append("Marksman/sniper distinction, missing attachments, wrong weapon and unbound completion criteria remain correct")
            seed(host, 1503)
            # Mixed mission, normal player XP and Battle Pass credit in one native
            # batch must produce one states write and one merged inventory write.
            xp_event = text(1, "mp_addxp") + integer(2, 1000) + integer(4, 0)
            for key, value in {"Param0": 7, "Param4": 100}.items():
                xp_event += binary(3, text(1, key) + integer(2, value))
            journal = states_path(host).with_name("events.json")
            previous_xp = json.loads(journal.read_bytes())["player_xp"]
            send(host, "mixed-bp-mission", [event("frag"), xp_event])
            updates = rewards(host, 3)
            assert {row["kind"] for row in updates} == {0, 15, 20}
            rows = {row["id"]: row for row in json.loads(states_path(host).read_bytes())}
            assert rows[1503]["status"] == 3 and rows[1504]["status"] == 1
            assert rows[3002000]["multiProgress"][0]["current"] == 100
            assert json.loads(journal.read_bytes())["player_xp"] == previous_xp + 7 + quests[1503]["xp_reward"]
            checks.append("One mixed batch commits mission stage/reward/successor, normal XP and Battle Pass state without duplicate destinations or lost items")
            seed(host, 1503)
            seed(peer, 1503)
            entries = b""
            for client in (host, peer):
                first = integer(1, client.user) + text(2, "uno")
                platform = integer(1, client.platform_account_id) + text(2, "bnet")
                entry = binary(1, first) + binary(2, event("frag")) + binary(3, platform) + integer(4, 113)
                entries += binary(2, entry)
            batch = structure(text(1, "5800") + entries + text(3, base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("=")))
            blocker = states_path(peer).with_name("states.json.pending")
            blocker.mkdir()
            intent = data / "achievements/5800/event-transaction.json"
            try:
                try:
                    host.task(125, 2, batch)
                except RuntimeError as failure:
                    assert str(failure) == "Native task 125/2 returned 102", failure
                else:
                    raise AssertionError("Blocked remote mission write succeeded")
                assert intent.exists()
                try:
                    snapshot(peer)
                except RuntimeError as failure:
                    assert str(failure) == "Native task 125/3 returned 102", failure
                else:
                    raise AssertionError("Incomplete remote mission reward became visible")
            finally:
                blocker.rmdir()
            snapshot(peer)
            assert not intent.exists()
            saved_peer = snapshot(peer)
            assert host.task(125, 2, batch) == b""
            assert rewards(peer, 2)[0]["reason"] == "inProgress"
            assert all(row["reason"] == "inProgress" for row in rewards(host, 2))
            assert snapshot(peer) == saved_peer
            checks.append("Authenticated listen-host remote mission report recovers a real interrupted mixed commit and its retry without duplicating rewards")
            host.task(145, 10, u64(int(lobby.stem)), structured=False)
            receive(host)
            receive(peer)
            retired_lobbies.add(int(lobby.stem))
            # Wire-only BR allocation; no map is loaded or game launched.
            lobby = create_match(host, peer, br=True)
            br_pickups = {50005: "Param0", 50007: "Param1", 50042: "Param1", 50066: "Param1",
                          50069: "Param1", 50010: "Param2", 50031: "Param2", 50084: "Param2"}
            for identity, key in br_pickups.items():
                seed(host, identity)
                before = snapshot(host)
                send(host, f"wrong-br-mode-{identity}", [event("pickup_totals", mode=2)])
                assert states_path(host).read_bytes() == before[0]
                label = {"Param0": "pickup_weapons", "Param1": "pickup_cash", "Param2": "pickup_caches"}[key]
                wrong = "pickup_cash" if key == "Param0" else "pickup_weapons"
                send(host, f"wrong-counter-{identity}", [event(wrong, mode=8)])
                assert states_path(host).read_bytes() == before[0]
                packet = send(host, f"br-pickup-{identity}", [event(label, mode=24)])
                updates = rewards(host, 2)
                mission = next(row for row in updates if row["kind"] == 15)
                assert mission["id_"] == identity and mission["reason"] == "completed"
                assert mission["progress"] == quests[identity]["target"]
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                retry_updates = rewards(host, 2)
                assert all(row["reason"] == "inProgress" for row in retry_updates), (identity, retry_updates)
                assert snapshot(host) == saved
            checks.append("All eight BR weapon/cash/cache pickup stages consume original aggregated fields, clamp targets and preserve retries without MP-mode cross-credit")
            for identity in (50008, 50063, 50009, 50021, 50059):
                seed(host, identity)
                label = "gas_partial_ms" if identity in (50008, 50063) else "driving_ms"
                if identity == 50059:
                    label = "not_downed_partial_ms"
                packet = send(host, f"timer-partial-{identity}", [event(label, mode=8)])
                update = rewards(host, 1)[0]
                assert update["kind"] == 15 and update["reason"] == "inProgress"
                row = next(row for row in json.loads(states_path(host).read_bytes()) if row["id"] == identity)
                assert row["progress"] == quests[identity]["target"] - 1
                assert row["timerRemainderMs"] == (250 if identity in (50008, 50063) else 45000)
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert rewards(host, 1)[0]["reason"] == "inProgress" and snapshot(host) == saved
                finish_label = "gas_remaining_ms" if identity in (50008, 50063) else "driving_remaining_ms"
                if identity == 50059:
                    finish_label = "not_downed_remaining_ms"
                send(host, f"timer-finish-{identity}", [event(finish_label, mode=24)])
                update = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert update["progress"] == quests[identity]["target"] and update["reason"] == "completed"
            checks.append("Five BR gas/driving/non-downed timers preserve fractional units and retries; seconds/minutes do not round up from milliseconds")
            actions = {50014: "self_revive", 50077: "self_revive", 50049: "teammate_revive",
                       50048: "gulag_win", 50076: "gulag_win"}
            for identity, label in actions.items():
                seed(host, identity)
                before = snapshot(host)
                wrong = ("teammate_revive" if label == "self_revive" else "self_revive")
                negatives = ("gulag_loss",) if label == "gulag_win" else (
                    wrong, "being_revived", "invalid_revive_flags")
                for negative in negatives:
                    send(host, f"an{identity}-{negative[:8]}", [event(negative, mode=8)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                send(host, f"wm{identity}", [event(label, mode=2)])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
                packet = send(host, f"br-action-{identity}", [event(label, mode=24)])
                mission = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert mission["id_"] == identity and mission["reason"] == "completed"
                assert mission["progress"] == quests[identity]["target"]
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2))
                assert snapshot(host) == saved
            checks.append("Five BR revive/Gulag stages distinguish the actor, self-revival and win/loss; malformed flags, MP mode and retries cannot duplicate credit")
            pings = {50000: "ping_enemy", 50001: "ping_object", 50003: "ping_danger"}
            select(peer, 50000)
            for identity, label, successor in (
                (50000, "ping_enemy", 50001), (50001, "ping_object", 50003),
                (50003, "ping_danger", 50005), (50005, "pickup_weapons", 50006),
                (50006, "loadout_preset", 50007),
            ):
                # Only the first stage is activated explicitly. Every following
                # head comes from the shipped successor transaction, without
                # seeding progress or overriding a selected state in between.
                send(peer, f"bc{identity}", [event(label, mode=8)])
                update = next(row for row in rewards(peer, 2) if row["kind"] == 15)
                assert update["id_"] == identity and update["reason"] == "completed"
                states = json.loads(states_path(peer).read_bytes())
                following = next(row for row in states if row["id"] == successor)
                assert following["status"] == 1 and following["progress"] == 0
            saved_peer = snapshot(peer)
            checks.append("Native activation of BR Boot Camp advances its first five stages, including preset loadout collection, through actual event/reward/successor transactions without seeding subsequent heads")
            for identity, label in pings.items():
                seed(host, identity)
                before = snapshot(host)
                for negative in ("ping_unknown", *[value for value in pings.values() if value != label]):
                    send(host, f"pn{identity}-{negative[-6:]}", [event(negative, mode=8)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                packet = send(host, f"py{identity}", [event(label, mode=24)])
                update = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert update["id_"] == identity and update["reason"] == "completed"
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2))
                assert snapshot(host) == saved
                checks.append(f"Stage {identity}: native UI reference-table ping ID excludes other ping kinds and unknown names; completion and retry preserve shipped rewards")
            contracts = {50012: 4, 50015: 33, 50019: 15, 50022: 32, 50026: 6,
                         50029: 31, 50033: 11, 50036: 2, 50040: 10, 50043: 5,
                         50047: 7, 50050: 8, 50054: 1, 50057: 20, 50061: 21,
                         50064: 16, 50068: 15, 50071: 1, 50075: 32, 50078: 6,
                         50082: 33, 50085: 7}
            for identity, locale in contracts.items():
                seed(host, identity)
                before = snapshot(host)
                for label in (f"contract_player_{locale}", "contract_no_locale",
                              f"contract_card_{locale % 33 + 1}"):
                    send(host, f"cn{identity}-{label[-3:]}", [event(label, mode=8)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                label = f"contract_card_{locale}"
                send(host, f"cm{identity}", [event(label, mode=2)])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
                packet = send(host, f"cy{identity}", [event(label, mode=24)])
                update = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert update["id_"] == identity and update["reason"] == "completed"
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2))
                assert snapshot(host) == saved
                checks.append(f"Stage {identity}: original contract-card locale {locale} excludes player-only/wrong/unknown locations and MP mode; rewards and retry remain atomic")
            context_actions = {
                50006: ("loadout", ("loadout_invalid",)),
                50034: ("loadout_preset", ("loadout_invalid",)),
                50011: ("use_armor", ("use_respawn_token", "use_unknown", "collect_armor")),
                50024: ("use_armor", ("use_respawn_token", "use_unknown", "collect_armor")),
                50070: ("use_armor", ("use_respawn_token", "use_unknown", "collect_armor")),
            }
            for identity in (50016, 50023, 50030, 50037, 50044, 50051,
                             50058, 50065, 50072, 50079, 50086):
                context_actions[identity] = (
                    "contract_success_dead" if identity % 2 else "contract_success_alive",
                    ("contract_failed", "contract_target_survived", "contract_invalid_alive",
                     "contract_invalid_role", "contract_unknown_result", "contract_unknown_category"),
                )
            for identity, (label, negatives) in context_actions.items():
                seed(host, identity)
                before = snapshot(host)
                for index, negative in enumerate(negatives):
                    send(host, f"bn{identity}-{index}", [event(negative, mode=8)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                send(host, f"bm{identity}", [event(label, mode=2)])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
                packet = send(host, f"by{identity}", [event(label, mode=24)])
                update = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert update["id_"] == identity and update["reason"] == "completed"
                assert update["progress"] == quests[identity]["target"]
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2))
                assert snapshot(host) == saved
                checks.append(f"Stage {identity}: shipped item/loadout/contract actor fields exclude wrong actions and MP mode; completion/rewards/retry remain atomic")
            seed(host, 50009)
            packet = send(host, "timer-restart", [event("driving_ms", mode=8)])
            rewards(host, 1)
            saved_host = snapshot(host)
        stop()
        start()
        with NativeClient(fixture, profile="quest-host", port_offset=offset) as host, \
             NativeClient(fixture, profile="quest-peer", port_offset=offset) as peer:
            assert snapshot(host) == saved_host and snapshot(peer) == saved_peer
            assert next(row for row in json.loads(states_path(host).read_bytes()) if row["id"] == 50009)["timerRemainderMs"] == 45000
        checks.append("Both accounts retain mission XP, items, completion and successor selections across a real backend restart")
    finally:
        stop()
        log.close()
        (fixture / "reward-history.json").write_text(json.dumps(reward_history, indent=2) + "\n")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(dict(passed=True, server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                                         parser_proof_sha256=hashlib.sha256(args.parser_proof.read_bytes()).hexdigest(),
                                         tool_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                         supported_stage_count=len(fixtures) + 59, checks=checks,
                                         fixture_directory=str(fixture), game_runs_performed=False,
                                         native_game_callback_verified=False), indent=2) + "\n")
    print(f"PASS: {len(checks)} quest earning groups; {len(fixtures) + 59} stages; {args.output}")


if __name__ == "__main__":
    main()
