"""Verify recovered and cross-transport XP retries refresh the native client."""

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

from native_wire_client import NativeClient, binary, fields, integer, structure, text, u32, u64
from progression_delivery_fixtures import reward

ROOT = Path(__file__).resolve().parents[1]


def packet(delta, request, context="5800", name="mp_addxp"):
    # The native binary writer encodes its reversed 16-byte UUID; the REST
    # writer uses the canonical UUID text for the same retry identity.
    encoded = base64.urlsafe_b64encode(bytes.fromhex(request.replace("-", ""))[::-1])
    event = text(1, name) + integer(2, 123) + integer(4, 0)
    event += binary(3, text(1, "Param0") + integer(2, delta))
    return structure(text(1, context) + binary(2, event) + text(3, encoded.decode().rstrip("=")))


def rest_packet(user, delta, request):
    params = integer(1, 1) + integer(2, 0) + integer(3, 1) + integer(100, 10000)
    params += binary(200, bytes(256)) + text(300, "user_events") + text(301, "report_user_events_batch")
    message = binary(1, params) + integer(2, 1) + integer(10, 0x504F5354)
    message += text(11, "/v2/user-events/$batch/?context=5800&client=replaylocal&titleID=5800")
    message += text(101, "ae.demonware.net") + integer(102, 1) + integer(302, 1)
    body = dict(titleID=5800, idempotentRequestID=request,
                userEvents=[dict(accountType="uno", userID=user,
                                 events=[dict(name="mp_addxp", timestamp=123,
                                              values=dict(Param0=delta))])])
    blob = lambda raw: b"\x13" + u32(len(raw)) + raw
    return u32(713) + blob(message) + b"\x01\x01" + blob(json.dumps(body).encode())


def rejected(client, service, task, params, error):
    try:
        client.task(service, task, params)
    except RuntimeError as failure:
        assert str(failure) == f"Native task {service}/{task} returned {error}"
    else:
        raise AssertionError("Rejected XP fixture was accepted")


def rest_response(raw):
    assert raw[:7] == u32(713) + b"\x13\x08"
    length = struct.unpack_from("<I", raw, 7)[0]
    metadata = raw[11:11 + length]
    assert metadata[0] == 8  # First native metadata field is HTTP status.
    status = 0
    for i, byte in enumerate(metadata[1:11]):
        status |= (byte & 127) << (7 * i)
        if not byte & 128:
            break
    else:
        raise AssertionError("Invalid REST status varint")
    position = 11 + length
    assert raw[position:position + 4] == b"\x01\x01\x13\x08"
    size = struct.unpack_from("<I", raw, position + 4)[0]
    assert len(raw) == position + 8 + size
    return status, json.loads(raw[position + 8:])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = ROOT / "data" / f"progression-retry-fixture-{time.time_ns()}"
    data = fixture / "data"
    data.mkdir(parents=True)
    shutil.copy2(ROOT / "data/replay-traffic-kdf.bin", data)
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    subprocess.run([str(args.server), str(data), "--provision-profile", "retry", "XP Retry Fixture"],
                   check=True, stdout=subprocess.DEVNULL, creationflags=flags)
    offset = None
    for candidate in range(11200, 11400):
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
        raise RuntimeError("XP fixture backend failed to become ready")
    try:
        start()
        with NativeClient(fixture, profile="retry", port_offset=offset) as client:
            first_id = "00000000-0000-0000-0000-000000000021"
            first = packet(3500, first_id)
            assert client.task(125, 1, first) == b""
            reward(client, 3500, reason="completed")
            journal = data / "achievements/5800/5800" / str(client.user) / "events.json"
            before = journal.read_bytes()
            assert client.task(125, 1, first) == b""
            reward(client, 3500)
            assert journal.read_bytes() == before
            checks.append("matching retry refreshes absolute XP without another award or rank-up toast")
            newer = packet(750, "00000000-0000-0000-0000-000000000022")
            assert client.task(125, 1, newer) == b""
            reward(client, 4250)
            before = journal.read_bytes()
            assert client.task(125, 1, first) == b""
            reward(client, 4250)
            assert journal.read_bytes() == before
            checks.append("old accepted request refreshes the current total rather than rolling the client back")
            rejected(client, 125, 1, packet(3501, first_id), 106)
            assert journal.read_bytes() == before
            assert not client.pushes and not select.select([client.socket], [], [], 0.1)[0]
            checks.append("altered retry cannot change progression or emit a reward notification")
            raw = client.task(255, 10, rest_packet(client.user, 3500, first_id), structured=False)
            assert rest_response(raw) == (200, {"allSucceeded": True})
            reward(client, 4250)
            assert journal.read_bytes() == before
            checks.append("REST retry of a binary accepted UUID refreshes the same snapshot without a second event")
            fresh_rest = rest_packet(client.user, 13250, "00000000-0000-0000-0000-000000000026")
            assert rest_response(client.task(255, 10, fresh_rest, structured=False)) == (
                200, {"allSucceeded": True})
            reward(client, 17500, reason="completed")
            before = journal.read_bytes()
            assert rest_response(client.task(255, 10, fresh_rest, structured=False)) == (
                200, {"allSucceeded": True})
            reward(client, 17500)
            assert journal.read_bytes() == before
            checks.append("new REST-earned XP reaches the native rank-up notification and its retry retains the full domain delivery without another award")
            # Move an accepted receipt to the existing durable archive layout.
            # This only changes the disposable fixture, and keeps the XP source.
            saved = json.loads(journal.read_bytes())
            receipt = next(r for r in saved["requests"] if r["id"] == first_id)
            saved["requests"].remove(receipt)
            archive = journal.parent / "receipts" / (hashlib.sha256(first_id.encode()).hexdigest() + ".json")
            archive.parent.mkdir(exist_ok=True)
            checksum = hashlib.sha256(json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]
            archive.write_text(json.dumps(dict(schema=1, title=5800, owner=client.user, context="5800",
                                               receipt=receipt, checksum=checksum)))
            journal.write_text(json.dumps(saved))
            archived = archive.read_bytes()
            assert client.task(125, 1, first) == b""
            reward(client, 17500)
            assert archive.read_bytes() == archived
            checks.append("evicted hot receipt remains retryable and refreshes current XP through the validated archive")
            blocked = packet(275, "00000000-0000-0000-0000-000000000023")
            pending = journal.with_name("events.json.pending")
            pending.mkdir()
            try:
                rejected(client, 125, 1, blocked, 102)
                assert not client.pushes and not select.select([client.socket], [], [], 0.1)[0]
            finally:
                pending.rmdir()
        previous = process.pid
        process.terminate()
        process.wait(timeout=10)
        start()
        assert process.pid != previous
        with NativeClient(fixture, profile="retry", port_offset=offset) as client:
            assert client.task(125, 1, blocked) == b""
            reward(client, 17775)
            assert not (data / "achievements/5800/event-transaction.json").exists()
            before = journal.read_bytes()
            assert client.task(125, 1, blocked) == b""
            reward(client, 17775)
            assert journal.read_bytes() == before
            checks.append("interrupted commit survives process/session restart and its retry restores the missing absolute update once XP is recovered")
            for context, delta in (("5800", 0), ("iw8", 40)):
                request = "00000000-0000-0000-0000-0000000000" + ("24" if delta == 0 else "25")
                value = packet(delta, request, context, name="frontend_login" if delta == 0 else "mp_addxp")
                assert client.task(125, 1, value) == b""
                if delta:
                    reward(client, delta, context)
                assert client.task(125, 1, value) == b""
                if delta:
                    reward(client, delta, context)
                else:
                    assert not client.pushes and not select.select([client.socket], [], [], 0.1)[0]
            checks.append("ordinary event retries do not manufacture progression, and iw8 updates retain their original context")
        args.output.write_text(json.dumps(dict(schema=1, passed=True, checks=checks,
            server_sha256=hashlib.sha256(args.server.read_bytes()).hexdigest(),
            native_game_verified=False, fixture=str(fixture)), indent=2) + "\n")
        print(f"PASS: {len(checks)} XP replay/recovery wire groups")
    finally:
        if process and process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
        log.close()


if __name__ == "__main__":
    main()
