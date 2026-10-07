"""Exercise native weapon XP wire tasks against an isolated compiled backend."""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

from native_wire_client import NativeClient, binary, fields, integer, structure, text
from progression_delivery_fixtures import decode_reward

ROOT = Path(__file__).resolve().parents[1]


def packet(events, request, context="5800"):
    token = base64.urlsafe_b64encode(bytes.fromhex(request.replace("-", ""))[::-1])
    body = text(1, context) + text(3, token.decode().rstrip("="))
    for values in events:
        event = text(1, "mp_addxp") + integer(2, 123) + integer(4, 0)
        for key, value in values.items():
            event += binary(3, text(1, key) + integer(2, value))
        body += binary(2, event)
    return structure(body)


def updates(client, expected):
    actual = {}
    for _ in expected:
        kind, raw = (2, client.pushes.pop(0)) if client.pushes else client.receive()
        assert kind == 2
        owner, context, event = decode_reward(raw, client.user)
        assert owner == client.user and context == "5800"
        key = event["id_"]
        assert key not in actual
        actual[key] = (event["multiProgress"]["xp"]["value"],
                       event["multiProgress"]["rank"]["value"], event["reason"])
    assert actual == expected, (actual, expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = ROOT / "data" / f"weapon-progression-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.run([str(args.server), str(data), "--provision-profile", "weapon", "Weapon Fixture"],
                   check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    offset = None
    for candidate in range(11600, 11800):
        probes = []
        try:
            for port in (8085, 8443, 3075):
                probe = socket.socket()
                probes.append(probe)
                probe.bind(("127.0.0.1", port + candidate))
            offset = candidate
            break
        except OSError:
            pass
        finally:
            for probe in probes:
                probe.close()
    assert offset is not None
    log = (fixture / "stdout.log").open("wb")
    process = None
    checks = []

    def start():
        nonlocal process
        process = subprocess.Popen([str(args.server), str(data), "--port-offset", str(offset)],
                                   stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        for _ in range(100):
            assert process.poll() is None
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=0.5).close()
                return
            except urllib.error.URLError:
                time.sleep(0.05)
        raise RuntimeError("Weapon progression backend failed to start")

    def quiet(client):
        time.sleep(1.2)
        assert not client.pushes and not select.select([client.socket], [], [], 0.1)[0]

    def reject(client, events, request):
        before = journal.read_bytes()
        try:
            client.task(125, 1, packet(events, request))
        except RuntimeError as failure:
            assert str(failure) == "Native task 125/1 returned 106"
        else:
            raise AssertionError("Invalid weapon event accepted")
        assert journal.read_bytes() == before

    def query(client, maximum=100, page="", kind=5):
        result = fields(client.task(125, 3, structure(text(1, "5800") + integer(2, kind) +
            integer(3, maximum) + text(4, page) + integer(8, 0))))
        rows = {}
        for raw in result.get(1, []):
            row = fields(raw)
            assert row[2] == [kind]
            progress = {fields(p)[1][0].decode(): fields(p)[2][0] for p in row.get(10, [])}
            rows[row[11][0]] = progress
        return rows, result.get(2, [b""])[0].decode()

    spec = importlib.util.spec_from_file_location("retry_helpers", ROOT / "tools/test-progression-retry.py")
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    try:
        start()
        with NativeClient(fixture, profile="weapon", port_offset=offset) as client:
            journal = data / "achievements/5800/5800" / str(client.user) / "events.json"
            request = "00000000-0000-0000-0000-000000000041"
            first = packet([dict(Param0=100, Param2=1, Param3=750)], request)
            assert client.task(125, 1, first) == b""
            updates(client, {1000000: (100, 0, "inProgress"), 2000001: (750, 1, "completed")})
            saved = json.loads(journal.read_bytes())
            assert saved["player_xp"] == saved["player_xp_pending"] == 100
            assert saved["weapon_xp"] == {"1": 750}
            checks.append("player and weapon deltas commit with one receipt and distinct native notifications")
            before = journal.read_bytes()
            assert client.task(125, 1, first) == b""
            updates(client, {1000000: (100, 0, "inProgress"), 2000001: (750, 1, "inProgress")})
            assert journal.read_bytes() == before
            checks.append("accepted retry refreshes both absolute snapshots without duplicate XP or rank-up actions")
            assert client.task(125, 1, packet([dict(Param2=15, Param3=750)],
                "00000000-0000-0000-0000-000000000042")) == b""
            updates(client, {2000015: (750, 1, "completed")})
            assert client.task(125, 1, packet([dict(Param2=43, Param3=250)],
                "00000000-0000-0000-0000-000000000043")) == b""
            updates(client, {2000015: (1000, 2, "completed")})
            assert json.loads(journal.read_bytes())["weapon_xp"] == {"1": 750, "15": 1000}
            checks.append("shipped variant 43 and base 15 share one weapon record and native rank thresholds")
            quiet(client)
            checks.append("identical XP values on separate weapons are not coalesced together; idle duplicates stop")
            for number, weapon in ((44, 12), (45, 0), (46, 999999)):
                reject(client, [dict(Param0=99, Param2=weapon, Param3=1)],
                       f"00000000-0000-0000-0000-0000000000{number}")
            reject(client, [dict(Param0=99, Param2=1, Param3=2**32)],
                   "00000000-0000-0000-0000-000000000047")
            checks.append("unknown weapon IDs and native UInt32 overflow reject the complete player/weapon batch")
            # Preserve non-weapon kind-5 data while replacing only weapon states.
            (journal.parent / "states.json").write_text(json.dumps([dict(
                id=77, name="fixture_camo", kind=5, status=1, multiProgress=[])]))
            rows, page = query(client)
            assert not page and rows == {77: {}, 2000001: {"xp": 750, "rank": 1},
                                          2000015: {"xp": 1000, "rank": 2}}
            rows, page = query(client, maximum=1)
            visited = dict(rows)
            while page:
                rows, page = query(client, maximum=1, page=page)
                assert not set(visited) & set(rows)
                visited.update(rows)
            assert len(visited) == 3
            checks.append("kind filters and pagination include native weapon snapshots without removing camo states")
            raw = helpers.rest_packet(client.user, 0, "00000000-0000-0000-0000-000000000048")
            old = json.dumps(dict(Param0=0)).encode()
            new = json.dumps(dict(Param0=0, Param2=1, Param3=250)).encode()
            position = raw.rfind(old)
            assert position >= 0
            size_position = raw.rfind(b"\x01\x01\x13\x08") + 4
            length = int.from_bytes(raw[size_position:size_position+4], "little") + len(new) - len(old)
            raw = raw[:position] + new + raw[position+len(old):]
            raw = raw[:size_position] + length.to_bytes(4, "little") + raw[size_position+4:]
            assert helpers.rest_response(client.task(255, 10, raw, structured=False)) == (200, {"allSucceeded": True})
            updates(client, {2000001: (1000, 2, "completed")})
            checks.append("REST native report envelope preserves the weapon notification")
            assets = json.loads((ROOT / "validation/20261007-weapon-progression-assets.json").read_bytes())
            all_weapons = assets["canonical_weapons"]
            events = [dict(Param2=row["id"], Param3=1) for row in all_weapons]
            assert client.task(125, 1, packet(events,
                "00000000-0000-0000-0000-000000000049")) == b""
            expected = {2000000+row["id"]: ((1001 if row["id"] in (1, 15) else 1),
                (2 if row["id"] in (1, 15) else 0), "inProgress") for row in all_weapons}
            updates(client, expected)
            rows, _ = query(client)
            assert len(rows) == 52 and rows[2000626]["rank"] == rows[2000631]["rank"] == 0
            checks.append("all 51 shipped base weapons fit native 64-slot capacity; empty developer tables cap at rank zero")
            assert client.task(125, 1, packet([dict(Param2=1, Param3=2**32-1-1001)],
                "00000000-0000-0000-0000-000000000050")) == b""
            updates(client, {2000001: (2**32-1, 34, "completed")})
            reject(client, [dict(Param0=50, Param2=1, Param3=1)],
                   "00000000-0000-0000-0000-000000000051")
            checks.append("high UInt32 XP bits are retained, per-weapon rank is capped and overflow cannot wrap the profile")
            totals = json.loads(journal.read_bytes())["weapon_xp"]
            quiet(client)
        with NativeClient(fixture, profile="weapon", port_offset=offset) as client:
            expected = {1000000: (100, 0, "inProgress")}
            for row in all_weapons:
                xp = totals[str(row["id"])]
                expected[2000000+row["id"]] = (xp, 34 if row["id"] == 1 else
                    (2 if row["id"] == 15 else 0), "inProgress")
            updates(client, expected)
            quiet(client)
            checks.append("reconnect independently catches up the player and every weapon without task retries")
        process.terminate()
        process.wait(timeout=10)
        start()
        with NativeClient(fixture, profile="weapon", port_offset=offset) as client:
            updates(client, expected)
            assert json.loads(journal.read_bytes())["weapon_xp"] == totals
            checks.append("backend restart retains all weapon records and republishes them to the new authenticated writer")
        args.output.write_text(json.dumps(dict(schema=1, passed=True, checks=checks,
            server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
            fixture_directory=str(fixture), native_game_verified=False), indent=2)+"\n")
        print(f"PASS: {len(checks)} weapon progression groups, no game launched")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
