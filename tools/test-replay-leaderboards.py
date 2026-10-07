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

from native_wire_client import NativeClient, u32, u64


ROOT = Path(__file__).resolve().parents[1]


def text(value):
    return b"\x10" + value.encode() + b"\0"


def columns(raw, count):
    offset = 0

    def read(tag, fmt):
        nonlocal offset
        assert raw[offset] == tag
        offset += 1
        value = struct.unpack_from(fmt, raw, offset)[0]
        offset += struct.calcsize(fmt)
        return value

    read(10, "<Q")  # owner
    read(9, "<q")  # rating
    read(10, "<Q")  # rank
    assert raw[offset] == 16
    offset = raw.index(0, offset + 1) + 1
    read(8, "<I")  # age
    result = [read(7, "<i") for _ in range(count)]
    assert offset == len(raw)
    return result


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
                    stats[str(board)] = {"rating": 42, "name": "Column Fixture",
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
                definition.write_text(json.dumps({"columns": [f"col_{i}" for i in range(10)]}))
                stats["7000"]["columns"] = [2**31]
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(17, request(7000, ["col_0"]), 106)
                stats["7000"]["columns"] = [-(2**31) - 1]
                path.write_text(json.dumps(stats))
                before = path.read_bytes()
                rejected(17, request(7000, ["col_0"]), 106)
                checks.append("out-of-range signed native column values rejected without integer wrapping")
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
