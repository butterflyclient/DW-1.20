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
import uuid

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
                10040: "zoom_head", 10131: "ak47_head", 10006: "double_time_smg",
                10012: "vehicle_target", 10013: "killstreak_target",
                1570: "tdm_headshot", 1589: "tdm_pistol", 1592: "hq_pistol",
                10004: "arena_smg", 10047: "dom_m19",
                1512: "capture_dom", 1588: "capture_dom", 1517: "capture_hq",
                1590: "defuse_sd",
                1573: "modifier_pointblank", 1576: "modifier_secondary_weapon",
                1577: "modifier_longshot", 1586: "modifier_quadfeed",
                1565: "secondary_specialty_munitions_2",
                10001: "secondary_smg_specialty_munitions_2",
                10038: "ads_reflex", 10039: "longshot_thermal",
                10130: "oden_longshot", 10134: "fal_ads", 10135: "m13_kingslayer"}
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
    reward_ranks = {}

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

    def event(label, timestamp=1000, mode=2, name="kill", extra=None, omit=()):
        values = {f"Param{i}": value for i, value in enumerate(cases[label]["values"])}
        if name == "kill":
            name = cases[label]["name"]
        values.update(version=1, gamemode=mode)
        values.update(extra or {})
        for key in omit:
            values.pop(key)
        raw = text(1, name) + integer(2, timestamp) + integer(4, 0)
        for key, value in values.items():
            raw += binary(3, text(1, key) + integer(2, value))
        return raw

    def send(client, request, events):
        packet = structure(text(1, "5800") + b"".join(binary(2, row) for row in events) + text(3, request))
        assert client.task(125, 1, packet) == b""
        return packet

    def send_remote(client, recipient, request, events, error=0, rest=False, first_party=None):
        identity = integer(1, recipient.user) + text(2, "uno")
        platform_user = recipient.platform_account_id if first_party is None else first_party
        platform = integer(1, platform_user) + text(2, "bnet")
        token_bytes = hashlib.sha256(request.encode()).digest()[:16]
        token = base64.urlsafe_b64encode(token_bytes).decode().rstrip("=")
        entry = binary(1, identity) + b"".join(binary(2, e) for e in events)
        entry += binary(3, platform) + integer(4, 113)
        # Context may follow the owner batch. Authorization waits until the
        # complete request is parsed rather than depending on protobuf order.
        packet = structure(binary(2, entry) + text(1, "5800") + text(3, token))
        service, task, structured = 125, 2, True
        if rest:
            rows = []
            for raw in events:
                parsed = fields(raw)
                values = {}
                for pair in parsed.get(3, []):
                    pair_fields = fields(pair)
                    values[pair_fields[1][0].decode()] = pair_fields[2][0]
                rows.append(dict(name=parsed[1][0].decode(), timestamp=parsed[2][0], values=values))
            body = dict(titleID=5800, idempotentRequestID=str(uuid.UUID(bytes=token_bytes[::-1])),
                        userEvents=[dict(userID=recipient.user, accountType="uno", events=rows,
                                         firstPartyUserID=platform_user, firstPartyAccountType="bnet", platform="bnet")])
            params = integer(1, 1) + integer(2, 0) + integer(3, 1) + integer(100, 10000)
            params += binary(200, bytes(256)) + text(300, "user_events") + text(301, "report_user_events_batch")
            message = binary(1, params) + integer(2, 1) + integer(10, 0x504F5354)
            message += text(11, "/v2/user-events/$batch/?context=5800&client=replaylocal&titleID=5800")
            message += text(101, "ae.demonware.net") + integer(102, 1) + integer(302, 1)
            payload = json.dumps(body).encode()
            blob = lambda raw: b"\x13" + u32(len(raw)) + raw
            packet = u32(713) + blob(message) + b"\x01\x01" + blob(payload)
            service, task, structured = 255, 10, False
        try:
            result = client.task(service, task, packet, structured=structured)
        except RuntimeError as failure:
            assert error and str(failure) == f"Native task {service}/{task} returned {error}", failure
            return
        assert not error
        if rest:
            assert result[:7] == u32(713) + b"\x13\x08"
            size = struct.unpack_from("<I", result, 7)[0]
            # The common REST metadata includes fixed64 clock fields. The
            # achievement-field decoder handles varints and strings only;
            # status is the verified first varint in this ordinary envelope.
            assert result[11:11 + size].startswith(integer(1, 200))
            position = 11 + size
            assert result[position:position + 4] == b"\x01\x01\x13\x08"
            length = struct.unpack_from("<I", result, position + 4)[0]
            assert len(result) == position + 8 + length
            assert json.loads(result[position + 8:]) == {"allSucceeded": True}
        else:
            assert result == b""

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

    def rewards(client, count, refresh=False):
        # Match the task's semantic results, not a fixed number of intervening
        # asynchronous packets. Keep every packet in the diagnostic history.
        # A stale absolute XP snapshot cannot stand in for the current award,
        # and a new-rank snapshot cannot stand in for its completed notification.
        expected = {1: {15}, 2: {0, 15}, 3: {0, 15, 20}}[count]
        expected_xp = json.loads(states_path(client).with_name("events.json").read_bytes())["player_xp"]
        previous_rank = reward_ranks.get(client.user, 0)

        def xp_snapshot(update):
            if update["kind"] != 0:
                return None
            assert update["id_"] == 1000000 and update["name"] == "player_xp"
            assert update["type"] == "ACHIEVEMENT"
            progress = update["multiProgress"]
            assert set(progress) == {"xp", "rank"}
            for value in progress.values():
                assert set(value) == {"value"}
                assert type(value["value"]) is int and value["value"] >= 0
            return progress["xp"]["value"], progress["rank"]["value"]

        out = []
        received = set()
        while received != expected:
            kind, packet = receive(client)
            assert kind == 2
            if packet.startswith(u32(67)):
                update = decode_event67(packet, client.user)[2]
                reward_history.append({"user": client.user, "update": update})
                xp = xp_snapshot(update)
                if xp is not None and update["reason"] == "inProgress" and xp[0] == expected_xp and \
                        (0 not in expected or 0 in received or (xp[1] > previous_rank and not refresh)):
                    inventory_path = data / "marketplace/5800" / str(client.user) / "inventory.json"
                    persisted = json.loads(inventory_path.read_bytes()) if inventory_path.exists() else {"items": []}
                    owned = {row["1"]: row["2"] for row in persisted["items"]}
                    for trigger in update.get("triggers", []):
                        assert trigger["type"] == "GRANT_PRODUCT" and set(trigger) == {"type", "inventory"}
                        assert set(trigger["inventory"]) == {"granted_items"}
                        seen_items = set()
                        for item in trigger["inventory"]["granted_items"]:
                            assert set(item) == {"id", "quantity"} and item["id"] not in seen_items
                            assert 0 < item["quantity"] <= owned.get(item["id"], 0)
                            seen_items.add(item["id"])
                    reward_history[-1]["asynchronous_existing_inventory_snapshot"] = True
                    continue
                plain = xp is not None and update["reason"] == "inProgress" and "triggers" not in update
                if plain and (xp[0] != expected_xp or (xp[1] > previous_rank and not refresh) or
                              0 not in expected or 0 in received):
                    reward_history[-1]["asynchronous_absolute_snapshot"] = True
                    continue
                assert update["kind"] in expected and update["kind"] not in received, update
                if xp is not None:
                    assert xp[0] == expected_xp
                    assert update["reason"] == ("completed" if xp[1] > previous_rank and not refresh else "inProgress")
                    reward_ranks[client.user] = xp[1]
                received.add(update["kind"])
                out.append(update)
        return out

    def receive_lobby(client, expected):
        while True:
            kind, packet = receive(client)
            if packet.startswith(u32(67)):
                update = decode_event67(packet, client.user)[2]
                # An idle absolute XP catch-up is independent of lobby creation.
                # Check it against persisted XP, including after a reconnect.
                assert update["kind"] == 0 and update["reason"] == "inProgress"
                journal = states_path(client).with_name("events.json")
                expected_xp = json.loads(journal.read_bytes()).get("player_xp", 0)
                assert update["multiProgress"]["xp"]["value"] == expected_xp
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
            send(host, "history-private-start", [event("start_tdm", extra={
                "dw_match_id": 987654321, "dw_lobby_id": int(private.stem)})])
            assert not json.loads(states_path(host).with_name("events.json").read_bytes()).get("matches")
            send(host, "private-match", [event("frag")])
            assert states_path(host).read_bytes() == before
            host.task(145, 10, u64(int(private.stem)), structured=False)
            receive_lobby(host, 2002)
            receive_lobby(peer, 2002)
            retired_lobbies.add(int(private.stem))
            lobby = create_match(host, peer)
            seed(host, 1501, False)
            native_match = cases["start_tdm"]["values"][0]
            tag = {"dw_match_id": native_match}
            start_tag = {**tag, "dw_lobby_id": int(lobby.stem)}
            before = states_path(host).read_bytes()
            send(host, "history-unregistered", [event("tdm_pistol", extra=tag)])
            assert states_path(host).read_bytes() == before
            send(host, "history-no-allocation", [event("start_tdm", extra=tag)])
            send(host, "history-wrong-allocation", [event("start_tdm", extra={**start_tag, "dw_lobby_id": int(lobby.stem) + 1})])
            assert not json.loads(states_path(host).with_name("events.json").read_bytes()).get("matches")
            send(host, "history-start", [event("start_tdm", extra=start_tag)])
            send(peer, "history-peer-start", [event("start_tdm", extra=start_tag)])
            journal_path = states_path(host).with_name("events.json")
            captured = json.loads(journal_path.read_bytes())["matches"][str(native_match)]
            assert captured["lobby"] == int(lobby.stem) and captured["sessions"] == [host.session_fingerprint]
            assert captured["mode"] == 6 and captured["category"] == 0
            assert captured["reporters"] == [{"user": host.user, "session": host.session_fingerprint}]
            send(host, "history-start-repeat", [event("start_tdm", timestamp=1001, extra=start_tag)])
            assert json.loads(journal_path.read_bytes())["matches"][str(native_match)] == captured
            send(host, "history-live-kill", [event("tdm_pistol", timestamp=1001, extra=tag)])
            assert rewards(host, 1)[0]["progress"] == 1
            checks.append("Native start captures the exact public allocation/session; private and unregistered tags cannot earn and new-UUID starts cannot replace that snapshot")
            host.task(145, 10, u64(int(lobby.stem)), structured=False)
            receive_lobby(host, 2002)
            receive_lobby(peer, 2002)
            retired_lobbies.add(int(lobby.stem))
            send(host, "history-after-departure", [event("tdm_pistol", timestamp=1002, extra=tag)])
            assert rewards(host, 1)[0]["progress"] == 2
            seed(peer, 1501, False)
            delayed = [event("tdm_pistol", timestamp=1002, extra=tag)]
            send_remote(host, peer, "history-remote", delayed)
            assert rewards(peer, 1)[0]["progress"] == 1
            saved_peer = snapshot(peer)
            send_remote(host, peer, "history-remote", delayed, rest=True)
            assert rewards(peer, 1, refresh=True)[0]["progress"] == 1
            assert snapshot(peer) == saved_peer
            checks.append("The captured listen-host session can report for its exact online recipient after departure; binary/REST retries retain one award and journal")
            later_host = create_match(peer, host)
            before_host, before_peer = snapshot(host), snapshot(peer)
            send_remote(peer, host, "history-future-host", delayed, error=101)
            assert snapshot(host) == before_host and snapshot(peer) == before_peer
            checks.append("A future lobby host cannot report against a member's earlier native match, even when current membership would authorize ordinary host reports")
            peer.task(145, 10, u64(int(later_host.stem)), structured=False)
            receive_lobby(peer, 2002)
            receive_lobby(host, 2002)
            retired_lobbies.add(int(later_host.stem))
            private_later = create_match(host, peer, private=True)
            before_peer = snapshot(peer)
            send_remote(host, peer, "history-family-denied", [event("tdm_pistol", mode=8, timestamp=1003, extra=tag)], error=101)
            send_remote(host, peer, "history-alias-denied", delayed, error=101, first_party=peer.platform_account_id + 1)
            send_remote(host, peer, "history-unknown-owner", [event("tdm_pistol", timestamp=1003, extra={"dw_match_id": native_match + 1})], error=101)
            assert snapshot(peer) == before_peer
            checks.append("Historical reporting rejects wrong families, first-party aliases and unknown match IDs without any recipient state or receipt write")
            peer_journal = states_path(peer).with_name("events.json")
            complete_journal = peer_journal.read_bytes()
            try:
                legacy = json.loads(complete_journal)
                del legacy["matches"][str(native_match)]["reporters"]
                peer_journal.write_text(json.dumps(legacy) + "\n")
                before_peer = snapshot(peer)
                send_remote(host, peer, "history-unbound-host", delayed, error=101, rest=True)
                assert snapshot(peer) == before_peer
            finally:
                peer_journal.write_bytes(complete_journal)
            checks.append("Older nine-field match records remain readable, but do not invent retained listen-host authority")
            send(host, "history-different-lobby", [event("tdm_pistol", timestamp=1003, extra=tag)])
            assert rewards(host, 1)[0]["progress"] == 3
            before = states_path(host).read_bytes()
            send(host, "history-unknown-tag", [event("tdm_pistol", timestamp=1004, extra={"dw_match_id": native_match + 1})])
            assert states_path(host).read_bytes() == before
            checks.append("Tagged events retain their original public allocation after departure and during a later private lobby; an unknown ID never inherits the latest lobby")
            saved_journal = journal_path.read_bytes()
            valid_journal = json.loads(saved_journal)
            broken = copy.deepcopy(valid_journal)
            broken["matches"][str(native_match)]["sessions"].append(host.session_fingerprint)
            row_text = json.dumps(valid_journal["matches"][str(native_match)])
            duplicate = "{" + ",".join(json.dumps(key) + ":" +
                ("{" + json.dumps(str(native_match)) + ":" + row_text + "," +
                 json.dumps(str(native_match)) + ":" + row_text + "}" if key == "matches" else json.dumps(value))
                for key, value in valid_journal.items()) + "}"
            raw_paths = [states_path(host), journal_path,
                         data / "marketplace/5800" / str(host.user) / "inventory.json"]
            for index, damaged in enumerate((json.dumps(broken), duplicate)):
                try:
                    journal_path.write_text(damaged + "\n")
                    before = [path.read_bytes() if path.exists() else None for path in raw_paths]
                    try:
                        send(host, f"history-corrupt-ledger-{index}", [event("tdm_pistol", timestamp=1004, extra=tag)])
                    except RuntimeError as failure:
                        assert "Native task 125/1 returned" in str(failure)
                    else:
                        raise AssertionError("Corrupt match ledger was accepted")
                    assert [path.read_bytes() if path.exists() else None for path in raw_paths] == before
                finally:
                    journal_path.write_bytes(saved_journal)
            checks.append("Malformed retained ownership and duplicate persisted IDs are rejected before any mission, XP, inventory or receipt write")
            send(host, "history-incomplete-end", [event("end_match_mode_operators", timestamp=1004, extra=tag, omit=("Param4",))])
            assert json.loads(journal_path.read_bytes())["matches"][str(native_match)]["end"] == 0
            send(host, "history-wrong-family-end", [event("end_match_mode_operators", timestamp=1004, mode=8, extra=tag)])
            assert json.loads(journal_path.read_bytes())["matches"][str(native_match)]["end"] == 0
            send(host, "history-end", [event("end_match_mode_operators", timestamp=1004, extra=tag)])
            closed = json.loads(journal_path.read_bytes())["matches"][str(native_match)]
            assert closed["end"] == 1004 and closed["outcome"] == 1
            send(host, "history-end-repeat", [event("end_match_mode_operators", timestamp=1005, extra=tag)])
            assert json.loads(journal_path.read_bytes())["matches"][str(native_match)] == closed
            before = states_path(host).read_bytes()
            send(host, "history-post-end-kill", [event("tdm_pistol", timestamp=1005, extra=tag)])
            assert states_path(host).read_bytes() == before
            checks.append("Wrong-family ends cannot close a match; the first valid outcome is immutable and new-UUID repeats cannot reopen it or credit post-end immediate actions")
            host.task(145, 10, u64(int(private_later.stem)), structured=False)
            receive_lobby(host, 2002)
            receive_lobby(peer, 2002)
            retired_lobbies.add(int(private_later.stem))
            lobby = create_match(host, peer)
            # A named native host handoff within the same allocation does not
            # emit another GSC start. The successor must acquire only this match.
            migrated_match = native_match + 101
            send(host, "migration-start-host", [event("start_tdm", timestamp=1100,
                 extra={"Param0": migrated_match, "dw_lobby_id": int(lobby.stem)})])
            send(peer, "migration-start-peer", [event("start_tdm", timestamp=1100,
                 extra={"Param0": migrated_match, "dw_lobby_id": int(lobby.stem)})])
            docs = documents(host.task(145, 13, u64(int(lobby.stem)), structured=False))
            handoff = copy.deepcopy(docs[0])
            handoff["dw_migration_target"] = peer.user
            handoff["player_state"] = {str(host.user): 2, str(peer.user): 2}
            assert host.task(145, 15, u64(int(lobby.stem)) + u64(docs[1]["update_id"])
                             + ordinary_text(json.dumps(handoff)), structured=False) == b"\x01\x01"
            current = documents(receive_lobby(host, 2006)[23:])
            receive_lobby(peer, 2006)
            successor = copy.deepcopy(current[0])
            address = json.loads((data / "matchmaking/5800/players" / f"{peer.user}.json").read_bytes())["info"]["listen_server"]["local_address"]
            successor["listen_server"] = {"host_player_id": peer.user, "host_address": address}
            assert peer.task(145, 15, u64(int(lobby.stem)) + u64(current[1]["update_id"])
                             + ordinary_text(json.dumps(successor)), structured=False) == b"\x01\x01"
            receive_lobby(host, 2006)
            receive_lobby(peer, 2006)
            send_remote(peer, host, "migrated-same-allocation-report", [event("driving_ms", timestamp=1101,
                        extra={"dw_match_id": migrated_match})])
            reporters = json.loads(journal_path.read_bytes())["matches"][str(migrated_match)]["reporters"]
            assert {r["user"] for r in reporters} == {host.user, peer.user}
            peer.task(145, 10, u64(int(lobby.stem)), structured=False)
            receive_lobby(host, 2002)
            receive_lobby(peer, 2002)
            retired_lobbies.add(int(lobby.stem))
            send_remote(peer, host, "migrated-captured-report-after-departure", [event("driving_ms", timestamp=1102,
                        extra={"dw_match_id": migrated_match})], rest=True)
            checks.append("Same-allocation authenticated host migration retains the successor without a second native start, and its exact session can report after departure")
            lobby = create_match(host, peer)
            seed(host, 1503, False)
            before = states_path(host).read_bytes()
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
            assert rewards(host, 1, refresh=True)[0]["progress"] == 2 and snapshot(host) == saved
            send(host, "remaining-kills", [event("pistol")] * 3)
            update = next(row for row in rewards(host, 2) if row["kind"] == 15)
            assert update["progress"] == 5 and update["reason"] == "completed"
            checks.append("Separate batches accumulate individual kills from zero to the exact target; partial retries neither skip stages nor re-add progress")
            negative_kill_contexts = {
                1570: ("tdm_pistol", "reflex_head", "hq_pistol"),
                1589: ("hq_pistol", "unknown_mode_pistol"),
                1592: ("tdm_pistol", "unknown_mode_pistol"),
                10004: ("arena_pistol", "gungame_smg", "tdm_smg"),
                10047: ("dom_pistol", "tdm_m19"),
                10012: ("pistol", "equipment_target", "killstreak_target", "air_streak_target",
                        "ground_streak_target", "agent_soldier_target", "agent_juggernaut_target",
                        "agent_shield_target", "agent_suicide_target", "unknown_target_bit"),
                10013: ("pistol", "equipment_target", "vehicle_target", "ground_vehicle_target",
                        "agent_soldier_target", "agent_juggernaut_target", "agent_shield_target",
                        "agent_suicide_target", "unknown_target_bit"),
                10006: ("smg", "double_time_assault"),
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
            for identity, labels in ((1512, ("capture_tdm", "capture_hq", "defuse_sd")),
                                     (1588, ("capture_tdm", "capture_hq", "plant_sd")),
                                     (1517, ("capture_dom", "capture_tdm", "defuse_sd")),
                                     (1590, ("defuse_dom", "plant_dom", "capture_sd"))):
                seed(host, identity, False)
                before = states_path(host).read_bytes()
                for index, label in enumerate(labels):
                    send(host, f"obj-neg-{identity}-{index}", [event(label)])
                    assert states_path(host).read_bytes() == before
                checks.append(f"Stage {identity} rejects the wrong objective action or specific game type")
            seed(host, 1512, False)
            packet = send(host, "capture-no-modifiers", [event("capture_dom")] * 2)
            assert rewards(host, 1)[0]["progress"] == 2
            saved = snapshot(host)
            assert host.task(125, 1, packet) == b""
            assert rewards(host, 1, refresh=True)[0]["progress"] == 2 and snapshot(host) == saved
            checks.append("Repeated zero-modifier capture packets represent separate objective actions; request retries preserve partial progress")
            seed(host, 1590, False)
            packet = send(host, "bomb-actions-both-modes", [event(label) for label in
                          ("defuse_sd", "plant_sd", "defuse_cyber", "plant_cyber")])
            assert rewards(host, 1)[0]["progress"] == 4
            saved = snapshot(host)
            assert host.task(125, 1, packet) == b""
            assert rewards(host, 1, refresh=True)[0]["progress"] == 4 and snapshot(host) == saved
            checks.append("Combined bomb criterion accepts native plant/defuse in Search and Destroy and Cyber Attack exactly once per action")
            seed(host, 1570, False)
            send(host, "mode-with-operator-ids", [event("kill_mode_operators")])
            assert rewards(host, 1)[0]["progress"] == 1
            checks.append("Specific kill game type is independent of the two packed operator IDs")
            for identity, labels in ((10012, ("ground_vehicle_target", "streak_vehicle_target")),
                                     (10013, ("air_streak_target", "ground_streak_target",
                                              "support_streak_target", "streak_vehicle_target"))):
                seed(host, identity, False)
                packet = send(host, f"target-masks-{identity}", [event(label) for label in labels])
                update = rewards(host, 1)[0]
                assert update["id_"] == identity and update["progress"] == len(labels)
                assert update["reason"] == "inProgress"
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert rewards(host, 1, refresh=True)[0]["progress"] == len(labels)
                assert snapshot(host) == saved
                checks.append(f"Stage {identity} accumulates native overlapping target subtypes and retries without duplicate destruction credit")
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
                retry = rewards(host, 2, refresh=True)
                assert all(row["reason"] == "inProgress" for row in retry)
                assert snapshot(host) == saved
                assert not any(t["type"] == "ACTIVATE_ACHIEVEMENT" for row in retry for t in row.get("triggers", []))
                checks.append(f"Stage {identity}: original {label} parser result completes exact target, grants shipped XP/item, activates successor and refreshes retry once")
            modifier_negatives = {
                1573: ("modifier_none", "modifier_longshot"),
                1576: ("modifier_none", "modifier_secondary_wrong_word"),
                1577: ("modifier_none", "modifier_pointblank"),
                1586: ("modifier_none", "modifier_firstblood"),
                1565: ("modifier_secondary_weapon", "secondary_specialty_ghost", "secondary_perkpackage_munitions"),
                10001: ("modifier_secondary_weapon", "secondary_specialty_munitions_2",
                        "secondary_smg_specialty_ghost", "secondary_smg_perkpackage_munitions"),
                10038: ("modifier_ads", "ads_acog", "modifier_none"),
                10039: ("modifier_longshot", "longshot_reflex", "ads_thermal"),
                10130: ("oden_longshot_no_flag", "modifier_longshot"),
                10134: ("fal_ads_no_flag", "modifier_ads"),
                10135: ("m13_kingslayer_no_flag", "modifier_kingslayer", "modifier_king_wrong_word"),
            }
            for identity, labels in modifier_negatives.items():
                seed(host, identity, False)
                before = snapshot(host)
                for index, label in enumerate(labels):
                    send(host, f"mn{identity}-{index}", [event(label)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                # A present bit in the wrong mask word or a missing packet field
                # must not substitute for the exact producer flag.
                send(host, f"mi{identity}", [event(fixtures[identity], omit=("Param1",))])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
                checks.append(f"Stage {identity}: exact native modifier/weapon/perk/optic qualifiers exclude wrong-word and incomplete packets")
            for identity in (1565, 10001):
                prefix = "secondary_smg_" if identity == 10001 else "secondary_"
                for index, ref in enumerate(("specialty_twoprimaries", "specialty_munitions", "specialty_munitions_2")):
                    seed(host, identity, False)
                    send(host, f"oa{identity}-{index}", [event(prefix + ref)])
                    update = rewards(host, 1)[0]
                    assert update["id_"] == identity and update["progress"] == 1
                seed(host, identity, False)
                before = snapshot(host)
                source = cases[prefix + "specialty_munitions_2"]["values"][4]
                send(host, f"os{identity}", [event(prefix + "specialty_munitions_2", extra={"Param4": source << 48})])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
            checks.append("Both Overkill-secondary stages recognize all three native UI aliases; an unresolved package or super-ID field cannot become a perk")
            seed(host, 10039, False)
            send(host, "thermal-hybrid", [event("longshot_hybrid3")])
            assert rewards(host, 1)[0]["progress"] == 1
            checks.append("Thermal longshots recognize both thermal and thermal-hybrid native optic groups")
            for identity, label in ((1509, "marksman"), (1600, "marksman_head_five"),
                                    (1596, "lmg"), (10046, "pistol"), (1500, "pistol")):
                seed(host, identity)
                before = states_path(host).read_bytes()
                send(host, f"excluded-{identity}", [event(label)])
                assert states_path(host).read_bytes() == before
            checks.append("Marksman/sniper distinction, missing attachments, wrong weapon and unbound completion criteria remain correct")
            for label in ("double_time_second", "double_time_third"):
                seed(host, 10006)
                packet = send(host, label, [event(label)])
                update = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert update["id_"] == 10006 and update["reason"] == "completed"
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
                assert snapshot(host) == saved
            checks.append("Double Time qualifies in each of the three original perk slots; wrong weapon/missing perk and completion retries remain excluded")

            # Earlier kill tests completed the successor. Put this disposable
            # stage back into its fresh inactive state before testing activation.
            seed(host, 1559, False)
            seed(host, 1558, False)
            before = snapshot(host)
            def no_stim_credit(after):
                assert after[0] == before[0] and after[2] == before[2]
                old_journal, new_journal = json.loads(before[1]), json.loads(after[1])
                for key in ("player_xp", "weapon_xp"):
                    assert old_journal.get(key) == new_journal.get(key)

            for label in ("stim_zero", "stim_fraction"):
                send(host, label, [event(label)])
                no_stim_credit(snapshot(host))
            send(host, "stim-wrong-mode", [event("stim_health", mode=8)])
            no_stim_credit(snapshot(host))
            send(host, "stim-first-health", [event("stim_health")])
            update = rewards(host, 1)[0]
            assert update["id_"] == 1558 and update["progress"] == 17
            assert update["reason"] == "inProgress"
            partial = snapshot(host)
            packet = send(host, "stim-finish-health", [event("stim_remaining_health")])
            update = next(row for row in rewards(host, 2) if row["kind"] == 15)
            assert update["id_"] == 1558 and update["progress"] == 2500
            assert update["reason"] == "completed"
            saved = snapshot(host)
            assert saved[0] != partial[0] and saved[2] != partial[2]
            assert host.task(125, 1, packet) == b""
            assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
            assert snapshot(host) == saved
            stored = {row["id"]: row for row in json.loads(states_path(host).read_bytes())}
            assert stored[1558]["status"] == 3 and stored[1559]["status"] == 1
            checks.append("Stim counts native integer health rather than uses; fractional/zero/wrong-mode reports, exact target, XP/item/successor and retry are correct")
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
            assert rewards(peer, 2, refresh=True)[0]["reason"] == "inProgress"
            assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
            assert snapshot(peer) == saved_peer
            checks.append("Authenticated listen-host remote mission report recovers a real interrupted mixed commit and its retry without duplicating rewards")
            host.task(145, 10, u64(int(lobby.stem)), structured=False)
            receive(host)
            receive(peer)
            retired_lobbies.add(int(lobby.stem))
            # Wire-only BR allocation; no map is loaded or game launched.
            lobby = create_match(host, peer, br=True)
            original_states = states_path(host).read_bytes()
            native_br_match = native_match + 1
            br_tag = {"dw_match_id": native_br_match}
            # This changes only the fixture's scalar match-ID boundary, not
            # the original parser's mode/operator packing or counter fields.
            send(host, "history-br-start", [event("start_br", mode=8,
                extra={**br_tag, "Param0": native_br_match, "dw_lobby_id": int(lobby.stem)})])
            send(host, "history-br-end", [event("end_br", timestamp=1100, mode=8, extra=br_tag)])
            seed(host, 50009, False)
            send(host, "history-late-timer", [event("driving_ms", timestamp=1101, mode=8, extra=br_tag)])
            assert rewards(host, 1)[0]["progress"] == 0
            selected = json.loads(states_path(host).read_bytes())
            timer = next(row for row in selected if row["id"] == 50009)
            assert timer["timerRemainderMs"] == 45000
            timer["activationTimestamp"] = 1102
            states_path(host).write_text(json.dumps(selected) + "\n")
            before = states_path(host).read_bytes()
            send(host, "history-later-mission", [event("driving_ms", timestamp=1103, mode=8, extra=br_tag)])
            assert states_path(host).read_bytes() == before
            states_path(host).write_bytes(original_states)
            checks.append("A native cached timer can arrive after match closure, but cannot credit a mission activated after that match ended")
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
                retry_updates = rewards(host, 2, refresh=True)
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
                assert rewards(host, 1, refresh=True)[0]["reason"] == "inProgress" and snapshot(host) == saved
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
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
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
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
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
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
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
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
                assert snapshot(host) == saved
                checks.append(f"Stage {identity}: shipped item/loadout/contract actor fields exclude wrong actions and MP mode; completion/rewards/retry remain atomic")
            kiosk_purchases = {
                50035: ("buy_uav", "buy_toma_strike", "buy_manual_turret", "buy_precision_airstrike", "buy_uav_operators"),
                50052: ("buy_teamrevive",),
                50055: ("buy_supply_drop",),
                50062: ("buy_super_ammo_drop", "buy_field_upgrade_case"),
            }
            native_purchase_labels = {label for label in cases if label.startswith("buy_")}
            for identity, positives in kiosk_purchases.items():
                seed(host, identity, False)
                before = snapshot(host)
                # All ten purchase rows, unknown names and cross-category
                # combinations come from original ProcessParams execution.
                for index, negative in enumerate(sorted(native_purchase_labels - set(positives))):
                    send(host, f"kn{identity}-{index}", [event(negative, mode=8)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                for index in range(3):
                    send(host, f"ki{identity}-{index}", [event(positives[0], mode=8, omit=(f"Param{index}",))])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                for index in range(2):
                    raw = cases[positives[0]]["values"][index] + (1 << 32)
                    send(host, f"kw{identity}-{index}", [event(positives[0], mode=8, extra={f"Param{index}": raw})])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                send(host, f"km{identity}", [event(positives[0], mode=2)])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
                for index in range(quests[identity]["target"]):
                    label = positives[index % len(positives)]
                    packet = send(host, f"ky{identity}-{index}", [event(label, mode=24)])
                    finished = index + 1 == quests[identity]["target"]
                    updates = rewards(host, 2 if finished else 1)
                    update = next(row for row in updates if row["kind"] == 15)
                    assert update["id_"] == identity and update["progress"] == index + 1
                    assert update["reason"] == ("completed" if finished else "inProgress")
                    saved = snapshot(host)
                    assert host.task(125, 1, packet) == b""
                    assert all(row["reason"] == "inProgress" for row in rewards(host, 2 if finished else 1, refresh=True))
                    assert snapshot(host) == saved
                checks.append(f"Stage {identity}: each native kiosk report credits one purchase; wrong/unknown pairs, incomplete/oversized fields and MP mode earn nothing; exact rewards and retry remain atomic")
            # Exercise the other valid streaks and nonzero operator mask too,
            # rather than testing only the two purchases needed for completion.
            for index, label in enumerate(("buy_manual_turret", "buy_precision_airstrike", "buy_uav_operators")):
                seed(host, 50035, False)
                send(host, f"ko{index}", [event(label, mode=8)])
                update = rewards(host, 1)[0]
                assert update["id_"] == 50035 and update["progress"] == 1
            checks.append("All four shipped killstreak purchases and operator-masked packets earn one action, not their item ID")
            seed(peer, 50052)
            before = snapshot(host)
            send_remote(host, peer, "kiosk-listen-host-rest", [event("buy_teamrevive", mode=8)], rest=True)
            update = next(row for row in rewards(peer, 2) if row["kind"] == 15)
            assert update["id_"] == 50052 and update["reason"] == "completed"
            assert snapshot(host) == before
            checks.append("Signed listen-host REST purchase reporting credits only the authorized remote buyer and grants its exact reward")
            br_kill_stages = {50027: "br_rarity_3", 50028: "br_rarity_4", 50038: "br_rarity_0",
                              50083: "br_rarity_0", 50041: "br_circle_0", 50073: "br_victim_downed"}
            for identity, label in br_kill_stages.items():
                if identity == 50041:
                    negatives = [f"br_circle_{value}" for value in (1, 2, 256, 65535)]
                elif identity == 50073:
                    negatives = ["br_attacker_downed", "br_equipment_downed", "modifier_victim_down_wrong_word"]
                else:
                    rarity = {50027: 3, 50028: 4, 50038: 0, 50083: 0}[identity]
                    negatives = [f"br_rarity_{value}" for value in (0, 1, 2, 3, 4, 5, 6, 7, 65535) if value != rarity]
                    negatives.append("br_rarity_equipment_" + str(rarity))
                seed(host, identity, False)
                before = snapshot(host)
                for index, negative in enumerate(negatives):
                    send(host, f"bkn{identity}-{index}", [event(negative, mode=8)])
                    after = snapshot(host)
                    assert after[0] == before[0] and after[2] == before[2]
                # BR family alone does not turn a packed MP kill into BR.
                wrong_type = cases["modifier_none"]["values"][2]
                send(host, f"bkt{identity}", [event(label, mode=8, extra={"Param2": wrong_type})])
                send(host, f"bkm{identity}", [event(label, mode=2)])
                send(host, f"bki{identity}", [event(label, mode=8, omit=("Param6",))])
                after = snapshot(host)
                assert after[0] == before[0] and after[2] == before[2]
                send(host, f"bkp{identity}", [event(label, mode=24)])
                update = rewards(host, 2 if quests[identity]["target"] == 1 else 1)
                assert next(row for row in update if row["kind"] == 15)["progress"] == 1
                seed(host, identity)
                packet = send(host, f"bkf{identity}", [event(label, mode=8)])
                update = next(row for row in rewards(host, 2) if row["kind"] == 15)
                assert update["id_"] == identity and update["progress"] == quests[identity]["target"]
                assert update["reason"] == "completed"
                saved = snapshot(host)
                assert host.task(125, 1, packet) == b""
                assert all(row["reason"] == "inProgress" for row in rewards(host, 2, refresh=True))
                assert snapshot(host) == saved
                checks.append(f"Stage {identity}: exact original BR rarity/circle/victim flags credit one player kill, exclude unknown and wrong fields, and preserve completion/retry rewards")
            seed(host, 50009)
            packet = send(host, "timer-restart", [event("driving_ms", mode=8)])
            rewards(host, 1)
            host.task(145, 10, u64(int(lobby.stem)), structured=False)
            receive_lobby(host, 2002)
            receive_lobby(peer, 2002)
            lobby = create_match(host, peer)
            allocation = json.loads(lobby.read_bytes())
            search_id = allocation["backend_doc"]["player_id_to_mm_id"][str(peer.user)]
            search_path = data / "matchmaking/5800/searches" / f"{search_id}.json"
            search = json.loads(search_path.read_bytes())
            assert search["owner_session"] == host.session_fingerprint
            assert search["member_sessions"] == {
                str(host.user): host.session_fingerprint,
                str(peer.user): peer.session_fingerprint,
            }
            checks.append("Ordinary allocations persist the exact authenticated session for every party member")
            seed(peer, 1501, False)
            resumed_identity = peer.fixture_auth_identity
            peer.close()
            with NativeClient(fixture, profile="quest-peer", port_offset=offset,
                              auth_identity=resumed_identity) as resumed:
                send(resumed, "same-ticket-resume", [event("pistol")])
                stage = next(row for row in json.loads(states_path(resumed).read_bytes()) if row["id"] == 1501)
                assert stage["progress"] == 1
                checks.append("A transport reconnect with the same signed session retains its allocation and earns mission credit")
            with NativeClient(fixture, profile="quest-peer", port_offset=offset) as rotated:
                assert rotated.user == peer.user and rotated.session_fingerprint != peer.session_fingerprint
                before = snapshot(rotated)
                rejected_request = send(rotated, "rotated-old-allocation", [event("pistol")])
                assert states_path(rotated).read_bytes() == before[0]
                checks.append("A new login for the same account cannot earn mission credit against its old allocation")
                before = states_path(rotated).read_bytes()
                send(rotated, "history-new-login-denied", [event("tdm_pistol", timestamp=1006, extra=tag)])
                assert states_path(rotated).read_bytes() == before
                checks.append("Retained native-match ownership remains bound to its authorized sessions; a later login cannot inherit it")

                def remote_report(request, error):
                    owner = integer(1, rotated.user) + text(2, "uno")
                    platform = integer(1, rotated.platform_account_id) + text(2, "bnet")
                    entry = binary(1, owner) + binary(2, event("pistol")) + binary(3, platform) + integer(4, 113)
                    token = base64.urlsafe_b64encode(hashlib.sha256(request.encode()).digest()[:16]).decode().rstrip("=")
                    raw = structure(text(1, "5800") + binary(2, entry) + text(3, token))
                    try:
                        result = host.task(125, 2, raw)
                    except RuntimeError as failure:
                        assert error and str(failure) == f"Native task 125/2 returned {error}", failure
                        return
                    assert error == 0 and result == b""

                before = snapshot(rotated)
                remote_report("rotated-host-denied", 101)
                assert snapshot(rotated) == before
                checks.append("Listen-host reports cannot adopt a remote member's newer login; denial writes no rewards or receipts")
                with NativeClient(fixture, profile="quest-peer", port_offset=offset,
                                  auth_identity=resumed_identity) as old_session:
                    assert old_session.task(12, 6, b"", structured=False).startswith(b"\x08")
                    lobby = create_match(host, rotated)
                    renewed = json.loads(lobby.read_bytes())
                    search_id = renewed["backend_doc"]["player_id_to_mm_id"][str(rotated.user)]
                    renewed_path = data / "matchmaking/5800/searches" / f"{search_id}.json"
                    bound = renewed_path.read_bytes()
                    legacy = json.loads(bound)
                    del legacy["owner_session"], legacy["member_sessions"]
                    try:
                        renewed_path.write_text(json.dumps(legacy) + "\n")
                        before = snapshot(rotated)
                        send(rotated, "legacy-unbound-direct", [event("pistol")])
                        assert states_path(rotated).read_bytes() == before[0]
                        before = snapshot(rotated)
                        remote_report("legacy-unbound-host", 101)
                        assert snapshot(rotated) == before
                    finally:
                        renewed_path.write_bytes(bound)
                    checks.append("Historical unbound searches remain readable but cannot authorize self or host mission attribution")
                    before = states_path(rotated).read_bytes()
                    assert rotated.task(125, 1, rejected_request) == b""
                    assert states_path(rotated).read_bytes() == before
                    send(rotated, "renewed-session-direct", [event("pistol")])
                    remote_report("renewed-session-host", 0)
                    stage = next(row for row in json.loads(states_path(rotated).read_bytes()) if row["id"] == 1501)
                    assert stage["progress"] == 3
                    saved_peer = snapshot(rotated)
                    checks.append("Fresh authorized matchmaking binds the token's exact session even with two live logins; direct and host credit resume without re-crediting an old request")
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
                                         supported_stage_count=len(fixtures) + 70, checks=checks,
                                         fixture_directory=str(fixture), game_runs_performed=False,
                                         native_game_callback_verified=False), indent=2) + "\n")
    print(f"PASS: {len(checks)} quest earning groups; {len(fixtures) + 70} stages; {args.output}")


if __name__ == "__main__":
    main()
