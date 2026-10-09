"""Exercise native-wire mission activation, mode switching and persistence."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request

from native_wire_client import NativeClient, fields, integer, structure, text
from progression_transaction_fixtures import exercise_mission_window, mission_snapshot

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = ROOT / "data" / f"quest-management-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for profile in ("quests", "quest-peer"):
        subprocess.run(
            [str(args.server), str(data), "--provision-profile", profile, profile],
            check=True,
            stdout=subprocess.DEVNULL,
            creationflags=flags,
        )
    asset_receipt = json.loads(
        (ROOT / "validation/20261008-replay-quest-assets.json").read_bytes()
    )
    assert (
        asset_receipt["all_native_rows_match"]
        and asset_receipt["supported_mission_stages"] == 232
    )
    expected = {row["id"]: row for row in asset_receipt["quests"]}
    offset = None
    for candidate in range(12400, 12600):
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
    process, checks = None, []

    def start():
        nonlocal process
        process = subprocess.Popen(
            [str(args.server), str(data), "--port-offset", str(offset)],
            stdout=log,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        for _ in range(100):
            assert process.poll() is None
            try:
                urllib.request.urlopen(
                    f"http://127.0.0.1:{8085 + offset}/health", timeout=0.5
                ).close()
                return
            except urllib.error.URLError:
                time.sleep(0.05)
        raise RuntimeError("Quest fixture backend did not start")

    def stop():
        nonlocal process
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        process = None

    def query(client, page="", definitions=False):
        params = text(1, "5800") + integer(2, 15) + integer(3, 100) + text(4, page)
        if not definitions:
            params += integer(8, 0)
        return fields(client.task(125, 4 if definitions else 3, structure(params)))

    def states(client):
        page, rows = "", {}
        while True:
            result = query(client, page)
            for raw in result.get(1, []):
                row = fields(raw)
                assert row[11][0] not in rows
                rows[row[11][0]] = row
            page = result[2][0].decode()
            if not page:
                return rows

    def select(
        client, identity, name="", timestamp=123, activate=True, extra=b"", error=0
    ):
        params = text(1, "5800") + text(2, name)
        if activate:
            params += integer(3, timestamp) + integer(4, identity)
        else:
            params += integer(3, identity)
        try:
            result = client.task(125, 5 if activate else 6, structure(params) + extra)
        except RuntimeError as failure:
            assert (
                error
                and str(failure)
                == f"Native task 125/{5 if activate else 6} returned {error}"
            )
        else:
            assert not error and result == b""

    try:
        start()
        with NativeClient(fixture, profile="quests", port_offset=offset) as client:
            path = data / "achievements/5800/5800" / str(client.user) / "states.json"
            publication = path.parent.parent / "definitions.json"
            page, seen = "", {}
            while True:
                result = query(client, page, definitions=True)
                for raw in result.get(1, []):
                    row = fields(raw)
                    identity = row[14][0]
                    assert identity not in seen
                    seen[identity] = row
                page = result[2][0].decode()
                if not page:
                    break
            assert seen.keys() == expected.keys() and len(seen) == 232
            for identity, row in seen.items():
                source = expected[identity]
                assert row[1] == [source["name"].encode()] and row[2] == [
                    source["description"].encode()
                ]
                assert row[3] == [15] and row[7] == [source["target"]] and row[9] == [1]
            assert not publication.exists()
            checks.append(
                "all 232 native MP/BR/CP stage definitions paginate with exact asset IDs, names, descriptions and targets"
            )
            select(client, 1500)
            row = states(client)[1500]
            assert row[3] == [0] and row[4] == [1] and row[5] == [1] and row[7] == [123]
            before = path.read_bytes()
            select(client, 1500, timestamp=999)
            assert path.read_bytes() == before
            checks.append(
                "native Boot Camp activation creates a real inactive-stage snapshot and idempotently preserves activation time and progress"
            )
            select(client, 0, expected[1501]["name"], timestamp=124)
            select(client, 50000)
            select(client, 10057)
            rows = states(client)
            assert rows[1500][5] == [2]
            assert {identity for identity, row in rows.items() if row[5] == [1]} == {
                1501,
                50000,
                10057,
            }
            select(client, 50001)
            rows = states(client)
            assert rows[50000][5] == [2] and rows[50001][5] == [1]
            assert rows[1501][5] == rows[10057][5] == [1]
            checks.append(
                "name and ID selectors switch one mission per mode while MP, BR and co-op activation remain independent"
            )
            select(client, 1501, activate=False)
            before = path.read_bytes()
            select(client, 1501, activate=False)
            assert path.read_bytes() == before
            checks.append(
                "deactivation is durable and retry-safe without resetting mission progress"
            )
            for identity, name, extra, error in (
                (1502, "wrong_name", b"", 106),
                (1502, "", b"\x03\x01", 106),
                (999999, "", b"", 108),
                (1603, "", b"", 108),
                (20000, "", b"", 108),
            ):
                select(client, identity, name, extra=extra, error=error)
                assert path.read_bytes() == before
            checks.append(
                "unknown, excluded-platform, mismatched-name and trailing-parameter requests cannot create or replace mission state"
            )
            with NativeClient(
                fixture, profile="quest-peer", port_offset=offset
            ) as peer:
                assert states(peer) == {} and path.read_bytes() == before
                select(peer, 1500)
                assert set(states(peer)) == {1500} and path.read_bytes() == before
            checks.append(
                "signed accounts retain separate mission selections and stored progress"
            )
            records = json.loads(before)
            records[0]["progress"], records[0]["status"] = 1, 3
            path.write_text(json.dumps(records))
            select(client, 1500)
            select(client, 1500, activate=False)
            assert states(client)[1500][3] == [1] and states(client)[1500][5] == [3]
            checks.append(
                "completed missions cannot be reactivated or reset by activation/deactivation retries"
            )
            blocker = path.with_name(path.name + ".pending")
            blocker.mkdir()
            before = path.read_bytes()
            intent = data / "achievements/5800/event-transaction.json"
            try:
                select(client, 1502, error=102)
                prepared = intent.read_bytes()
                assert path.read_bytes() == before
                try:
                    states(client)
                except RuntimeError as failure:
                    assert str(failure) == "Native task 125/3 returned 102"
                else:
                    raise AssertionError("Partially committed mission state was exposed")
                assert intent.read_bytes() == prepared
            finally:
                blocker.rmdir()
            row = states(client)[1502]
            assert row[3] == [0] and row[5] == [1] and row[7] == [123]
            assert not intent.exists()
            before = path.read_bytes()
            select(client, 1502, timestamp=999)
            assert path.read_bytes() == before
            checks.append(
                "a real failed mission write blocks partial reads, recovers its durable selection and preserves the first activation timestamp on retry"
            )
            override = {
                "1": expected[1503]["name"],
                "3": 15,
                "14": 1503,
                "initialState": {
                    "id": 1503,
                    "name": expected[1503]["name"],
                    "kind": 15,
                    "status": 2,
                    "progress": 8,
                    "target": 999,
                },
            }
            publication.write_text(json.dumps([override]))
            select(client, 1503)
            assert states(client)[1503][3] == [8] and states(client)[1503][4] == [999]
            assert len(query(client, definitions=True)[1]) == 1
            publication.write_text(
                json.dumps([{"1": expected[1504]["name"], "3": 15, "14": 1504}])
            )
            select(client, 1504, error=108)
            assert 1504 not in states(client)
            publication.unlink()
            checks.append(
                "explicit domain publications preserve their own initial state and may deliberately withhold activation"
            )
            saved = states(client)
            before = path.read_bytes()
            assert not (path.parent / "events.json").exists()
            assert not (
                data / "marketplace/5800" / str(client.user) / "inventory.json"
            ).exists()
        stop()
        start()
        with NativeClient(fixture, profile="quests", port_offset=offset) as client:
            assert states(client) == saved and path.read_bytes() == before
            with NativeClient(fixture, profile="quest-peer", port_offset=offset) as peer:
                snapshots = exercise_mission_window(client, peer, data, checks)
        checks.append(
            "mode selections and completed progress survive server restart without awarding XP, items or fabricated mission completion"
        )
        stop()
        start()
        with NativeClient(fixture, profile="quests", port_offset=offset) as client:
            with NativeClient(fixture, profile="quest-peer", port_offset=offset) as peer:
                assert [mission_snapshot(c) for c in (client, peer)] == snapshots
        checks.append("both signed accounts retain the recovered mixed mission, XP and inventory results after process restart")
    finally:
        stop()
        log.close()
    receipt = dict(
        schema=1,
        passed=True,
        server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
        checks=checks,
        fixture_directory=str(fixture),
        game_runs_performed=False,
        native_remote_task_completion_verified=False,
    )
    args.output.write_text(json.dumps(receipt, indent=2) + "\n", newline="\n")
    print(f"PASS: {len(checks)} native-wire quest management groups; {args.output}")


if __name__ == "__main__":
    main()
