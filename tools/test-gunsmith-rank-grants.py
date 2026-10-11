"""Verify rank grants, native notifications and interrupted XP/inventory commits."""

import argparse
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

from achievement_transaction_fixtures import assert_applied
from native_wire_client import NativeClient, fields, integer, structure, text
from progression_delivery_fixtures import decode_reward

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = ROOT / "data" / f"rank-grants-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.run([str(args.server), str(data), "--provision-profile", "ranks", "Rank Fixture"],
                   check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    spec = importlib.util.spec_from_file_location("weapon_helpers", ROOT / "tools/test-weapon-progression.py")
    helpers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helpers)
    offset = None
    for candidate in range(11800, 12000):
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
        raise RuntimeError("Rank grants backend failed to start")
    def event(client):
        kind, raw = (2, client.pushes.pop(0)) if client.pushes else client.receive()
        assert kind == 2
        owner, context, body = decode_reward(raw, client.user)
        assert owner == client.user and context == "5800"
        return body
    def grants(body):
        result = {}
        for trigger in body.get("triggers", []):
            assert trigger["type"] == "GRANT_PRODUCT"
            for row in trigger["inventory"]["granted_items"]:
                assert row["id"] not in result and 0 < row["quantity"] <= 2**31-1
                result[row["id"]] = row["quantity"]
        return result
    def quiet(client):
        time.sleep(1.2)
        assert not client.pushes and not select.select([client.socket], [], [], 0.1)[0]
    def inventory(client):
        response = fields(client.task(80, 69, structure(text(1, "5800") + text(2, "") + integer(3, 1000))))
        return {fields(raw)[1][0]: fields(raw)[2][0] for raw in response.get(4, [])}
    def weapon_inventory(client):
        owned = inventory(client)
        return {item: count for item, count in owned.items()
                if item in (1001124, 2001000, 1015124, 2015000, 1001048, 2001001)}
    def send(client, values, number):
        return client.task(125, 1, helpers.packet([values],
            f"00000000-0000-0000-0000-{number:012d}"))
    def rejected(client, service, task, params):
        try:
            client.task(service, task, params)
        except RuntimeError as failure:
            assert str(failure) == f"Native task {service}/{task} returned 102"
        else:
            raise AssertionError("Blocked cross-domain publication accepted")
    try:
        start()
        with NativeClient(fixture, profile="ranks", port_offset=offset) as client:
            journal = data / "achievements/5800/5800" / str(client.user) / "events.json"
            store = data / "marketplace/5800" / str(client.user) / "inventory.json"
            store.parent.mkdir(parents=True, exist_ok=True)
            retained = dict(items=[{"1": 1001124, "2": 5, "4": [1, 2], "5": True, "13": "retain", "19": 7}],
                            balances=[dict(currency=11, amount=900)], fixture_metadata="retain")
            store.write_text(json.dumps(retained))
            assert send(client, dict(Param0=1500, Param2=1, Param3=500), 61) == b""
            player, weapon = event(client), event(client)
            assert player["id_"] == 1000000 and weapon["id_"] == 2000001
            assert weapon["reason"] == "completed" and grants(weapon) == {2001000: 1}
            owned = json.loads(store.read_bytes())
            assert owned["items"][0] == retained["items"][0]
            assert owned["balances"] == retained["balances"] and owned["fixture_metadata"] == "retain"
            assert weapon_inventory(client) == {1001124: 5, 2001000: 1}
            assert inventory(client)[350000] == 1
            assert json.loads(journal.read_bytes())["weapon_xp"] == {"1": 500}
            checks.append("native rank-one group grants missing ownership while retaining existing stack, metadata and balances")
            before = store.read_bytes()
            assert send(client, dict(Param2=1, Param3=250), 62) == b""
            weapon = event(client)
            assert weapon["id_"] == 2000001 and not grants(weapon) and store.read_bytes() == before
            quiet(client)
            checks.append("ordinary earned XP does not republish ownership or repeat idle reward notifications")
            assert send(client, dict(Param0=1500, Param2=1, Param3=500), 61) == b""
            event(client)
            weapon = event(client)
            assert grants(weapon) == {1001124: 5, 2001000: 1} and weapon["reason"] == "inProgress"
            assert store.read_bytes() == before
            checks.append("accepted retry refreshes absolute owned quantities without duplicate grants or XP")
            updated = json.loads(store.read_bytes())
            updated["items"][0]["2"] = 7
            store.write_text(json.dumps(updated))
            weapon = event(client)
            assert weapon["id_"] == 2000001 and weapon["multiProgress"]["xp"]["value"] == 750
            assert grants(weapon) == {1001124: 7, 2001000: 1}
            quiet(client)
            checks.append("changed ownership refreshes its native snapshot even when weapon XP is unchanged")
            assert not {1001048, 2001001} & set(inventory(client))
            checks.append("negative-gate ammo and challenge-dependent camo tier items are not rank grants")
            blocker = store.with_name(store.name + ".pending")
            blocker.mkdir()
            blocked = helpers.packet([dict(Param0=99, Param2=15, Param3=500)],
                "00000000-0000-0000-0000-000000000063")
            before = store.read_bytes()
            try:
                rejected(client, 125, 1, blocked)
                intent = data / "achievements/5800/event-transaction.json"
                window = json.loads(intent.read_bytes())
                assert any(row.get("kind") == "inventory" for row in window["writes"])
                assert store.read_bytes() == before
                rejected(client, 80, 69, structure(text(1, "5800") + text(2, "") + integer(3, 1000)))
                rejected(client, 125, 3, structure(text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0)))
                quiet(client)
            finally:
                blocker.rmdir()
            received = {body["id_"]: body for body in (event(client), event(client))}
            assert received[1000000]["multiProgress"]["xp"]["value"] == 1599
            assert grants(received[2000015]) == {1015124: 1, 2015000: 1}
            assert_applied(intent)
            owned = weapon_inventory(client)
            assert owned == {1001124: 7, 2001000: 1, 1015124: 1, 2015000: 1}
            checks.append("XP and inventory share a flushed intent; blocked writes fence both reads and idle recovery completes the whole window")
            before_journal, before_store = journal.read_bytes(), store.read_bytes()
            assert client.task(125, 1, blocked) == b""
            received = {body["id_"]: body for body in (event(client), event(client))}
            assert received[1000000]["multiProgress"]["xp"]["value"] == 1599
            assert grants(received[2000015]) == {1015124: 1, 2015000: 1}
            assert journal.read_bytes() == before_journal and store.read_bytes() == before_store
            checks.append("retry after interrupted cross-domain recovery cannot add XP or increase item quantities again")
        process.terminate()
        process.wait(timeout=10)
        start()
        with NativeClient(fixture, profile="ranks", port_offset=offset) as client:
            received = {body["id_"]: body for body in (event(client), event(client), event(client))}
            assert grants(received[2000001]) == {1001124: 7, 2001000: 1}
            assert grants(received[2000015]) == {1015124: 1, 2015000: 1}
            assert weapon_inventory(client) == owned
            quiet(client)
            checks.append("restart/reconnect preserves ownership and synchronizes each weapon exactly once")
        args.output.write_text(json.dumps(dict(schema=1, passed=True, checks=checks,
            server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
            fixture_directory=str(fixture), native_game_verified=False), indent=2) + "\n")
        print(f"PASS: {len(checks)} rank grant/recovery groups, no game launched")
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
