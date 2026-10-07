"""Exercise shipped column selections over an isolated authenticated DW lobby."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

from native_wire_client import NativeClient, u32, u64, binary, integer, structure, text as proto_text


ROOT = Path(__file__).resolve().parents[1]


def text(value):
    return b"\x10" + value.encode() + b"\0"


def write_row(board, owner, rating, values, mode=0):
    score = b"\x14" if rating is None else b"\x09" + struct.pack("<q", rating)
    columns = b"".join(b"\x14" if value is None else b"\x07" + struct.pack("<i", value)
                       for value in values)
    return u32(board) + u64(owner) + b"\x03" + bytes([mode]) + score + columns


def columns(raw, count, metadata=False):
    offset = 0

    def read(tag, fmt):
        nonlocal offset
        assert raw[offset] == tag
        offset += 1
        value = struct.unpack_from(fmt, raw, offset)[0]
        offset += struct.calcsize(fmt)
        return value

    owner = read(10, "<Q")
    rating = read(9, "<q")
    rank = read(10, "<Q")
    assert raw[offset] == 16
    end = raw.index(0, offset + 1)
    name = raw[offset + 1:end].decode()
    offset = end + 1
    read(8, "<I")  # age
    result = [read(7, "<i") for _ in range(count)]
    assert offset == len(raw)
    return {"owner": owner, "rating": rating, "rank": rank, "name": name, "columns": result} \
        if metadata else result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--publication", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalog_path = args.publication / "catalog.json"
    catalog = json.loads(catalog_path.read_bytes())
    fixture = ROOT / "data" / f"leaderboard-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    shutil.copytree(args.publication / "leaderboard-definitions", data / "leaderboard-definitions")
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.run([str(args.server), str(data), "--provision-profile", "leaderboard",
                    "Leaderboard Fixture"], check=True, stdout=subprocess.DEVNULL,
                   creationflags=flags)
    offset = None
    for candidate in range(10800, 11000):
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
    checks = []
    with (fixture / "stdout.log").open("wb") as log:
        process = subprocess.Popen([str(args.server), str(data), "--port-offset", str(offset)],
                                   stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
        try:
            for _ in range(100):
                assert process.poll() is None
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health",
                                           timeout=0.5).close()
                    break
                except urllib.error.URLError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Fixture server failed to become ready")
            with NativeClient(fixture, profile="leaderboard", port_offset=offset) as client:
                path = data / "leaderboard-stats/5800" / f"{client.user}.json"
                path.parent.mkdir(parents=True)
                stats = {}
                for case in catalog["native_column_builder"]["cases"]:
                    board = 150000 + case["id"]
                    width = len(catalog["definitions"][str(board)]["columns"])
                    storage_board = catalog["definitions"][str(board)]["storage_board"]
                    stats[str(storage_board)] = {"rating": 42, "name": "Column Fixture",
                                         "columns": [1000 + i for i in range(width)]}
                stats["7000"] = {"rating": 1, "columns": list(range(10))}
                path.write_text(json.dumps(stats))
                before = path.read_bytes()

                def request(board, names, entity=False):
                    prefix = u32(board) + (u32(1) + u64(client.user) if entity else u64(1) + u32(1))
                    return prefix + u32(len(names)) + b"".join(text(name) for name in names)

                for case in catalog["native_column_builder"]["cases"]:
                    board, names = 150000 + case["id"], case["columns"]
                    expected = [1000 + int(name[4:]) for name in names]
                    for task, entity in ((17, False), (16, True)):
                        result = client.task(4, task, request(board, names, entity), structured=False)
                        assert columns(result, len(names)) == expected, (case["name"], task)
                checks.append("all 40 original virtual requests retain exact column order on entity and rank reads")
                definition = data / "leaderboard-definitions/5800/7000.json"
                definition.write_text(json.dumps({"columns": [f"col_{i}" for i in range(10)]}))
                result = client.task(4, 17, request(7000, ["col_8", "col_2"]), structured=False)
                assert columns(result, 2) == [8, 2]
                result = client.task(4, 4, request(7000, ["col_8", "col_2"]), structured=False)
                assert columns(result, 8) == [0, 1, 3, 4, 5, 6, 7, 9]
                result = client.task(4, 17, request(7000, []), structured=False)
                assert columns(result, 10) == list(range(10))
                checks.append("included request order, excluded schema order and ordinary ten-column layout")

                # The native packet updates only its ten-column window. The
                # wider row and the base/read-namespace relation must survive.
                prior = json.loads(path.read_bytes())["17"]
                client.task(4, 1, write_row(17, client.user, 73, [11, 22] + [None] * 8),
                            structured=False)
                saved = json.loads(path.read_bytes())
                assert saved["17"]["rating"] == 73
                assert saved["17"]["columns"][:2] == [11, 22]
                assert saved["17"]["columns"][2:] == prior["columns"][2:]
                client.task(4, 1, write_row(17, client.user, 2, [3, None, 4] + [None] * 7, mode=1),
                            structured=False)
                client.task(4, 1, write_row(17, client.user, 72, [-10] + [None] * 9, mode=2),
                            structured=False)
                saved = json.loads(path.read_bytes())
                assert saved["17"]["rating"] == 75
                assert saved["17"]["columns"][:3] == [14, 22, 1006]
                assert saved["17"]["columns"][3:] == prior["columns"][3:]
                for board in (140017, 150017):
                    result = client.task(4, 17, request(board, ["col_16", "col_0", "col_13"]),
                                         structured=False)
                    assert columns(result, 3) == [1016, 14, 1013]
                checks.append("native partial write preserves the wide tail and resolves both published read namespaces")
                checks.append("replace/add/max and NAN preserve untouched columns throughout wide rows")
                client.task(4, 1, write_row(1003, client.user, 91, list(range(10))), structured=False)
                for board in (141003, 151003):
                    result = client.task(4, 17, request(board, []), structured=False)
                    assert columns(result, 10) == list(range(10))
                client.task(4, 1, write_row(7010, client.user, 2, list(range(10))), structured=False)
                assert client.task(4, 17, request(1507010, []), structured=False) == b""
                checks.append("actual regular write IDs feed namespaced reads; unpublished prefixes never alias automatically")
                saved = json.loads(path.read_bytes())
                saved["7001"] = {"rating": 1, "columns": list(range(240))}
                path.write_text(json.dumps(saved))
                alias = data / "leaderboard-definitions/5800/7002.json"
                alias.write_text(json.dumps({"schema": 2, "storage_board": 7001,
                                             "columns": [f"col_{i}" for i in range(240)]}))
                client.task(4, 1, write_row(7001, client.user, None, [7] + [None] * 9),
                            structured=False)
                result = client.task(4, 17, request(7002, ["col_239", "col_0"]), structured=False)
                assert columns(result, 2) == [239, 7]
                checks.append("full 240-column stored boundary supports partial writes and last-column projection")
                before = path.read_bytes()

                def rejected(task, params, error):
                    try:
                        client.task(4, task, params, structured=False)
                    except RuntimeError as failure:
                        assert str(failure) == f"Native task 4/{task} returned {error}"
                    else:
                        raise AssertionError("Invalid leaderboard request accepted")
                    assert path.read_bytes() == before

                rejected(17, request(7000, ["col_8", "col_8"]), 106)
                rejected(17, request(7000, ["unknown"]), 108)
                rejected(17, request(7000, [f"col_{i}" for i in range(11)]), 106)
                rejected(4, request(150017, ["col_0"]), 106)
                checks.append("duplicate/unknown columns, oversized response requests and wide excluded reads rejected atomically")
                definition.write_text(json.dumps({"columns": ["col_0", "col_0"]}))
                rejected(17, request(7000, ["col_0"]), 106)
                definition.write_text(json.dumps({"columns": [7]}))
                rejected(17, request(7000, ["col_0"]), 106)
                checks.append("duplicate and non-string schema publications rejected before serializing rows")
                for invalid in (-1, 2**32 - 1, True, "7000"):
                    definition.write_text(json.dumps({"schema": 2, "storage_board": invalid,
                                                     "columns": ["col_0"]}))
                    rejected(17, request(7000, []), 106)
                definition.write_text(json.dumps({"schema": 3, "storage_board": 7000,
                                                 "columns": ["col_0"]}))
                rejected(17, request(7000, []), 106)
                checks.append("invalid alias IDs and unknown publication schemas rejected even on ordinary reads")
                definition.write_text(json.dumps({"columns": [f"col_{i}" for i in range(10)]}))
                stats = json.loads(path.read_bytes())
                stats["17"]["columns"][20] = 2**31
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(1, write_row(17, client.user, 80, list(range(10))), 106)
                stats["17"]["columns"][20] = 1020
                stats["7001"]["columns"].append(240)
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(1, write_row(7001, client.user, None, [8] + [None] * 9), 106)
                rejected(17, request(7002, ["col_239"]), 106)
                stats["7001"]["columns"].pop()
                stats["17"]["rating"] = 2**63 - 1
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(1, write_row(1004, client.user, 3, list(range(10))) +
                         write_row(17, client.user, 1, [None] * 10, mode=1), 106)
                rejected(1, write_row(1004, client.user, 3, list(range(10))) +
                         write_row(17, client.user + 1, 1, [None] * 10), 101)
                checks.append("partial writes reject malformed tail, late overflow and foreign-owner batches without partial commit")
                stats["7000"]["columns"] = [2**31]
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(17, request(7000, ["col_0"]), 106)
                stats["7000"]["columns"] = [-(2**31) - 1]
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(17, request(7000, ["col_0"]), 106)
                checks.append("out-of-range signed native column values rejected without integer wrapping")
                stats["7000"]["columns"] = list(range(10))
                path.write_text(json.dumps(stats))
                before = path.read_bytes()

                def xp_event(delta, request_id):
                    event = proto_text(1, "mp_addxp") + integer(2, int(time.time()))
                    event += binary(3, proto_text(1, "Param0") + integer(2, delta)) + integer(4, 0)
                    return structure(proto_text(1, "5800") + binary(2, event) +
                                     proto_text(3, request_id))

                packet = xp_event(1500, "xp-board-earned")
                assert client.task(125, 1, packet) == b""
                journal = data / "achievements/5800/5800" / str(client.user) / "events.json"
                journal_before = journal.read_bytes()
                for board in (3, 140003, 150003):
                    result = client.task(4, 17, request(board, ["col_1", "col_2"]), structured=False)
                    row = columns(result, 2, metadata=True)
                    assert row["rating"] == 1500 and row["rank"] == 1
                    assert row["columns"] == [1500, 1002] and row["owner"] == client.user
                    assert row["name"] == "Leaderboard Fixture"
                assert path.read_bytes() == before and journal.read_bytes() == journal_before
                assert client.task(125, 1, packet) == b""
                assert journal.read_bytes() == journal_before
                checks.append("earned XP feeds all Total XP namespaces with current account name, preserves other columns and does not double-award retries")
                assert client.task(125, 1, xp_event(2**31, "xp-board-unsigned")) == b""
                result = client.task(4, 17, request(150003, ["col_1"]), structured=False)
                row = columns(result, 1, metadata=True)
                assert row["rating"] == 2**31 + 1500
                assert row["columns"] == [-(2**31) + 1500]
                assert row["columns"][0] & 0xFFFFFFFF == row["rating"]
                checks.append("unsigned native XP column preserves its 32-bit transport representation with an exact Int64 ranking value")
                pending = journal.with_name("events.json.pending")
                pending.mkdir()
                try:
                    blocked = xp_event(25, "xp-board-recovery")
                    try:
                        client.task(125, 1, blocked)
                    except RuntimeError as failure:
                        assert str(failure) == "Native task 125/1 returned 102"
                    else:
                        raise AssertionError("Blocked event publication accepted")
                    rejected(17, request(150003, ["col_1"]), 102)
                finally:
                    pending.rmdir()
                result = client.task(4, 17, request(150003, ["col_1"]), structured=False)
                row = columns(result, 1, metadata=True)
                assert row["rating"] == 2**31 + 1525
                assert row["columns"] == [-(2**31) + 1525]
                recovered = journal.read_bytes()
                assert client.task(125, 1, blocked) == b""
                assert journal.read_bytes() == recovered and path.read_bytes() == before
                checks.append("XP ranking blocks partial event transactions, then recovers the accepted snapshot and retains retry identity without another award")
                saved_journal = journal.read_bytes()
                states = journal.with_name("states.json")
                prior_states = states.read_bytes() if states.exists() else None
                try:
                    journal.unlink()
                    legacy = [{"id": 1000000, "name": "player_xp", "kind": 0,
                               "status": 1, "progress": 0, "target": 0,
                               "multiProgress": [{"name": "xp", "current": 77, "target": 0},
                                                 {"name": "rank", "current": 0, "target": 0}]}]
                    states.write_text(json.dumps(legacy))
                    result = client.task(4, 17, request(150003, ["col_1"]), structured=False)
                    row = columns(result, 1, metadata=True)
                    assert row["rating"] == 77 and row["columns"] == [77]
                    states.write_text("[]")
                    result = client.task(4, 17, request(150003, ["col_1"]), structured=False)
                    row = columns(result, 1, metadata=True)
                    assert row["rating"] == 42 and row["columns"] == [1001]
                finally:
                    journal.write_bytes(saved_journal)
                    if prior_states is None:
                        states.unlink()
                    else:
                        states.write_bytes(prior_states)
                assert path.read_bytes() == before
                checks.append("explicit legacy XP states remain readable and absent XP preserves the ordinary stored row without provisioning")
            process.terminate()
            process.wait(timeout=10)
            process = subprocess.Popen([str(args.server), str(data), "--port-offset", str(offset)],
                                       stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
            for _ in range(100):
                assert process.poll() is None
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health",
                                           timeout=0.5).close()
                    break
                except urllib.error.URLError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Fixture restart failed to become ready")
            with NativeClient(fixture, profile="leaderboard", port_offset=offset) as client:
                result = client.task(4, 17, request(150017, ["col_16", "col_0", "col_13"]),
                                     structured=False)
                assert columns(result, 3) == [1016, 14, 1013]
                assert path.read_bytes() == before
                result = client.task(4, 17, request(140003, ["col_1"]), structured=False)
                row = columns(result, 1, metadata=True)
                assert row["rating"] == 2**31 + 1525 and row["columns"] == [-(2**31) + 1525]
            checks.append("fresh backend/session retains canonical rows, wide tails and published namespace resolution")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
    result = {"schema": 1, "passed": True, "checks": checks,
              "native_virtual_cases": 40, "encrypted_projected_reads": 80,
              "server_sha256": hashlib.sha256(args.server.read_bytes()).hexdigest(),
              "catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest(),
              "native_game_verified": False, "fixture": str(fixture)}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: 80 shipped virtual projections and {len(checks)} contract groups")


if __name__ == "__main__":
    main()
