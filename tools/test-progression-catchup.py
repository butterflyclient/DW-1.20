"""Verify idle XP catch-up and signed confirmation of player-local persistence."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from native_wire_client import NativeClient, binary, fields, integer, structure, text
from progression_delivery_fixtures import reward

ROOT = Path(__file__).resolve().parents[1]


def xp_event(delta, number):
    request = bytes([number]) * 16
    event = text(1, "mp_addxp") + integer(2, 123) + integer(4, 0)
    event += binary(3, text(1, "Param0") + integer(2, delta))
    return structure(text(1, "5800") + binary(2, event) +
                     text(3, base64.urlsafe_b64encode(request).decode().rstrip("=")))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reproduce-stale-restore", action="store_true")
    args = parser.parse_args()
    fixture = ROOT / "data" / f"progression-catchup-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.run([str(args.server), str(data), "--provision-profile", "unused", "Issuer Fixture"],
                   check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    offset = None
    for candidate in range(11400, 11600):
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
    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key().public_numbers()
    blob = struct.pack("<II", 0x31534345, 32)
    blob += public.x.to_bytes(32, "big") + public.y.to_bytes(32, "big")
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
        raise RuntimeError("Catch-up backend did not start")
    def post(path, body):
        request = urllib.request.Request(f"http://127.0.0.1:{8085 + offset}" + path, body)
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.read()
    def login(user=0, xp=0, restore=False, rank=0):
        nonce = os.urandom(32)
        challenge = post("/platform/client/challenge", blob + nonce)
        prefix = struct.pack("<II", 0x31494452, 2) + nonce + challenge + blob
        prefix += b"XP Catchup Fixture".ljust(36, b"\0")
        prefix += struct.pack("<IQQII", int(restore), user, xp, rank, 0)
        r, s = utils.decode_dss_signature(key.sign(prefix, ec.ECDSA(hashes.SHA256())))
        return post("/platform/client/login", prefix + r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    def quiet(client):
        # Observe across more than one idle publication tick. No task is sent.
        time.sleep(1.25)
        assert not client.pushes and not select.select([client.socket], [], [], 0.1)[0]
    try:
        start()
        if args.reproduce_stale_restore:
            with NativeClient(fixture, port_offset=offset, platform_reply=login(rank=5)) as client:
                user = client.user
                assert client.task(125, 1, xp_event(750, 31)) == b""
                reward(client, 15750)
            with NativeClient(fixture, port_offset=offset,
                              platform_reply=login(user, 15000, restore=True)) as client:
                result = fields(client.task(125, 3, structure(
                    text(1, "5800") + integer(3, 100) + text(4, "") + integer(8, 0))))
                row = next(fields(v) for v in result[1] if fields(v)[11] == [1000000])
                values = {fields(p)[1][0].decode(): fields(p)[2][0] for p in row[10]}
                assert values["xp"] == 15000
            args.output.write_text(json.dumps(dict(schema=1, confirmed_gap=True,
                accepted_xp=15750, stale_local_xp=15000, overwritten_backend_xp=15000,
                server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
                native_game_verified=False), indent=2) + "\n")
            print("CONFIRMED: stale signed local restoration erases accepted XP on the baseline backend")
            return
        with NativeClient(fixture, port_offset=offset, platform_reply=login(rank=5)) as client:
            user = client.user
            journal = data / "achievements/5800/5800" / str(user) / "events.json"
            reward(client, 15000)
            quiet(client)
            checks.append("signed local rank restoration is published once on the authenticated idle writer without any achievement query")
            assert client.task(125, 1, xp_event(750, 31)) == b""
            reward(client, 15750)
            saved = json.loads(journal.read_bytes())
            assert saved["player_xp"] == saved["player_xp_pending"] == 15750
            quiet(client)
            checks.append("accepted earned XP and its pending local-save snapshot share the durable event journal; successful immediate delivery coalesces idle repeats")
        with NativeClient(fixture, port_offset=offset,
                          platform_reply=login(user, 15000, restore=True)) as client:
            reward(client, 15750)
            saved = json.loads(journal.read_bytes())
            assert saved["player_xp"] == saved["player_xp_pending"] == 15750
            quiet(client)
            checks.append("an older signed local snapshot cannot erase pending XP; reconnect receives the accepted total without retrying its event")
        with NativeClient(fixture, port_offset=offset,
                          platform_reply=login(user, 15750, restore=True)) as client:
            reward(client, 15750)
            saved = json.loads(journal.read_bytes())
            assert saved["player_xp"] == 15750 and "player_xp_pending" not in saved
            assert client.task(125, 1, xp_event(500, 32)) == b""
            reward(client, 16250)
            checks.append("nonce-bound local persistence confirmation retires the pending snapshot; later awards create a new one")
        with NativeClient(fixture, port_offset=offset,
                          platform_reply=login(user, 15750, restore=True, rank=2)) as client:
            reward(client, 3000)
            saved = json.loads(journal.read_bytes())
            assert saved["player_xp"] == 3000 and "player_xp_pending" not in saved
            assert client.task(125, 1, xp_event(500, 32)) == b""
            reward(client, 3000)
            assert journal.read_bytes() == json.dumps(saved, separators=(",", ":"), sort_keys=True).encode()
            checks.append("explicit INI rank changes override pending XP while preserving accepted-event retry identity")
            pending = journal.with_name("events.json.pending")
            pending.mkdir()
            try:
                try:
                    client.task(125, 1, xp_event(1000, 33))
                    raise AssertionError("Blocked XP publication accepted")
                except RuntimeError as error:
                    assert "returned 102" in str(error)
                before = journal.read_bytes()
                quiet(client)
                assert journal.read_bytes() == before
            finally:
                pending.rmdir()
            # Recovery and notification must happen from the idle publisher,
            # without another client task or request.
            reward(client, 4000)
            assert not (data / "achievements/5800/event-transaction.json").exists()
            assert json.loads(journal.read_bytes())["player_xp_pending"] == 4000
            checks.append("a blocked accepted event cannot notify partial state; idle maintenance recovers and delivers it after the write blocker is removed")
        old = process.pid
        process.terminate()
        process.wait(timeout=10)
        start()
        assert process.pid != old
        with NativeClient(fixture, port_offset=offset,
                          platform_reply=login(user, 3000, restore=True)) as client:
            reward(client, 4000)
            quiet(client)
            saved = json.loads(journal.read_bytes())
            assert saved["player_xp"] == saved["player_xp_pending"] == 4000
            checks.append("pending progression survives backend process restart and stale player-local restoration without an event retry")
        with NativeClient(fixture, port_offset=offset,
                          platform_reply=login(user, 4000, restore=True)) as client:
            reward(client, 4000)
            assert "player_xp_pending" not in json.loads(journal.read_bytes())
        with NativeClient(fixture, port_offset=offset,
                          platform_reply=login(user, 3900, restore=True)) as client:
            reward(client, 3900)
            assert json.loads(journal.read_bytes())["player_xp"] == 3900
            checks.append("after pending delivery is confirmed, the existing signed local-profile authority remains intact")
        args.output.write_text(json.dumps(dict(schema=1, passed=True, checks=checks,
            server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
            native_game_verified=False, fixture=str(fixture)), indent=2) + "\n")
        print(f"PASS: {len(checks)} idle catch-up/local confirmation wire groups")
    finally:
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
