"""Run native tournament round/recovery contracts against an isolated backend.

The explicit fixture tree must match the server's frozen source cohort. No game
or real player account is used, and the public backend is never contacted.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

from native_wire_client import NativeClient, u64


ROOT = Path(__file__).resolve().parents[1]


class TournamentClient(NativeClient):
    fixture_root = None
    fixture_offset = 0

    def __init__(self, root=None, **kwargs):
        self.reading_task = False
        kwargs.setdefault("port_offset", self.fixture_offset)
        super().__init__(root or self.fixture_root, **kwargs)
        self.s = self.socket

    def receive(self):
        if not self.reading_task and self.pushes:
            return 2, self.pushes.pop(0)
        return super().receive()

    def task(self, service, task, params=b"", error=0, structured=False):
        self.reading_task = True
        try:
            result = super().task(service, task, params, structured)
        except RuntimeError as failure:
            if not error or str(failure) != f"Native task {service}/{task} returned {error}":
                raise
            return []
        finally:
            self.reading_task = False
        assert not error, f"Expected task {service}/{task} error {error}, received success"
        return [] if result == b"" else result


def ordinary_text(value):
    return b"\x10" + value.encode() + b"\0"


def boolean(value):
    return b"\x01" + bytes([bool(value)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = args.fixtures.resolve()
    assert source == ROOT or source.is_relative_to(ROOT / "data")
    sys.path.insert(0, str(source / "tools"))
    import tournament_round_fixtures

    fixture = ROOT / "data" / f"tournament-round-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    spec = importlib.util.spec_from_file_location("playlist_prepare", source / "tools/prepare-playlist-catalog.py")
    prepare = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prepare)
    catalog = prepare.prepare(data, ["mp_shipment"], 1)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for index in range(32):
        subprocess.run([str(args.server), str(data), "--provision-profile",
                        f"round-{index}", f"Round Fixture {index}"], check=True,
                       stdout=subprocess.DEVNULL, creationflags=flags)
    offset = None
    for candidate in range(12300, 12400):
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
    if offset is None:
        raise RuntimeError("No isolated fixture ports available")
    checks = []
    TournamentClient.fixture_root, TournamentClient.fixture_offset = fixture, offset
    with (fixture / "stdout.log").open("wb") as output:
        process = subprocess.Popen([str(args.server), str(data), "--port-offset", str(offset)],
                                   stdout=output, stderr=subprocess.STDOUT, creationflags=flags)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("Isolated backend exited during startup")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{8085 + offset}/health", timeout=0.3):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("Isolated backend startup timed out")

            def new_client(index, **kwargs):
                connection = TournamentClient(fixture, profile=f"round-{index}", port_offset=offset)
                return connection.user, connection

            info = {
                "dedicated_server": {"build_name": "replay-round-fixture"},
                "listen_server": {
                    "local_address": base64.b64encode(bytes(84)).decode(),
                    "security_id": base64.b64encode(os.urandom(8)).decode(),
                    "security_key": base64.b64encode(os.urandom(16)).decode(),
                },
                "game_state": {"map_packs": ["MP_ORIGINAL_MAPS"]}, "hardware": "pc",
            }
            query = {"ruleset_payload": {"filter": {
                "playlist_id": 1, "netcode_version": 1, "playlist_version": catalog["version"],
            }}}
            tournament_round_fixtures.exercise(data, 5800, info, query, new_client,
                                               (u64, ordinary_text, boolean), checks)
            receipt = dict(schema=1, passed=True, native_game_verified=False,
                           server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                           fixture_directory=str(fixture), checks=checks,
                           fixture_tree=str(source), fixture_sha256=hashlib.sha256(
                               (source / "tools/tournament_round_fixtures.py").read_bytes()).hexdigest())
            args.output.write_text(json.dumps(receipt, indent=2) + "\n")
            print(f"PASS: {len(checks)} focused tournament round/recovery groups; no game launched")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
