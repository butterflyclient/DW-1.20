"""Run automatic lobby fill fixture over genuine encrypted SDK transport, on private loopback profiles."""

import argparse, base64, hashlib, json, os, runpy, shutil, socket, subprocess, time, urllib.request
from pathlib import Path
from native_wire_client import NativeClient, u32, u64
from auto_fill_bot_fixtures import exercise

ROOT = Path(__file__).resolve().parents[1]


class Adapter(NativeClient):
    inside_task = False

    @property
    def s(self):
        return self.socket

    def receive(self):
        if not self.inside_task and self.pushes:
            return 2, self.pushes.pop(0)
        return super().receive()

    def task(self, service, task, params=b"", error=0):
        self.inside_task = True
        try:
            try:
                result = super().task(service, task, params, structured=False)
            except RuntimeError as failure:
                assert (
                    error
                    and str(failure) == f"Native task {service}/{task} returned {error}"
                )
                return None
            assert not error
            return result
        finally:
            self.inside_task = False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    image = args.server.resolve(strict=True)
    fixture = ROOT / "data" / f"auto-fill-wire-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    catalog = runpy.run_path(str(ROOT / "tools/prepare-playlist-catalog.py"))[
        "prepare"
    ](data, ["mp_shipment"], 1)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for profile in ("auto-host", "auto-peer"):
        subprocess.run(
            [str(image), str(data), "--provision-profile", profile, profile],
            check=True,
            stdout=subprocess.DEVNULL,
            creationflags=flags,
        )
    offset = None
    for candidate in range(22700, 22900):
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
    process = subprocess.Popen(
        [str(image), str(data), "--port-offset", str(offset)],
        stdout=log,
        stderr=subprocess.STDOUT,
        creationflags=flags,
    )
    clients = []
    try:
        for _ in range(100):
            assert process.poll() is None
            try:
                with urllib.request.urlopen(
                    f"http://127.0.0.1:{8085+offset}/health", timeout=0.2
                ):
                    break
            except OSError:
                time.sleep(0.03)
        clients = [
            Adapter(fixture, profile=profile, port_offset=offset)
            for profile in ("auto-host", "auto-peer")
        ]
        host, peer = clients
        ordinary = lambda v: b"\x10" + v.encode() + b"\0"
        boolean = lambda v: b"\x01" + bytes([v])
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
        host.task(145, 2, ordinary(json.dumps(info)))
        query = {
            "members": [host.user],
            "tokens": [],
            "player_id_to_slots": {str(host.user): 0},
            "ruleset_payload": {
                "filter": {
                    "playlist_id": 1,
                    "netcode_version": 1,
                    "playlist_version": catalog["version"],
                }
            },
        }
        checks = []
        exercise(
            host,
            peer,
            data,
            5800,
            host.user,
            query,
            (u32, u64, ordinary, boolean),
            checks,
        )
        args.output.write_text(
            json.dumps(
                dict(
                    passed=True,
                    server_sha256=hashlib.sha256(image.read_bytes()).hexdigest(),
                    checks=checks,
                    fixture=str(fixture),
                    native_game_verified=False,
                    production_changed=False,
                ),
                indent=2,
            )
            + "\n"
        )
        print(
            "PASS encrypted automatic fill, human replacement and native/operator start gates"
        )
    finally:
        for client in clients:
            client.close()
        process.terminate()
        process.wait(timeout=5)
        log.close()


if __name__ == "__main__":
    main()
