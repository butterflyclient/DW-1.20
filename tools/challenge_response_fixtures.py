"""Exact same-Replay 38/2 request and durable receipt checks; isolated data only."""

import base64
import hashlib
import json
import struct


def exercise(client, directory, title, user, blob, checks):
    def request(rows, log=b""):
        encoded = b"\x06" + struct.pack("<H", len(rows))
        for challenge, response in rows:
            encoded += b"\x0a" + struct.pack("<Q", challenge)
            encoded += (
                b"\x14" if response is None else b"\x09" + struct.pack("<q", response)
            )
        return encoded + blob(log)

    parent = directory / "anti-cheat" / str(title) / str(user)
    empty = request([])
    assert client.task(38, 2, empty) == []
    payload = request(
        [(0, -(2**63)), (2**64 - 2, 2**63 - 2), (37, None)], bytes(range(64))
    )
    assert client.task(38, 2, payload) == []
    digest = hashlib.sha256(payload + b"\0").hexdigest()
    path = parent / (digest + ".json")
    before = path.read_bytes()
    receipt = json.loads(before)
    assert (
        receipt["owner"] == user
        and receipt["title"] == title
        and receipt["request_sha256"] == digest
    )
    assert receipt["responses"] == [
        {"challenge": 0, "response": -(2**63)},
        {"challenge": 2**64 - 2, "response": 2**63 - 2},
        {"challenge": 37, "response": None},
    ]
    assert base64.b64decode(receipt["log"]) == bytes(range(64))
    assert client.task(38, 2, payload) == [] and path.read_bytes() == before
    snapshot = {entry.name: entry.read_bytes() for entry in parent.glob("*.json")}
    for invalid in [
        b"",
        b"\x06\x01\0",
        request([(1, 4), (1, 5)]),
        request([(1, 2**63 - 1)]),
        request([(2**64 - 1, 0)]),
        request([], bytes(65)),
        request([]) + b"\x08\0\0\0\0",
        b"\x06\x01\0\x08"
        + struct.pack("<I", 1)
        + b"\x09"
        + struct.pack("<q", 2)
        + blob(b""),
        b"\x06\xff\xff" + blob(b""),
        request([(7, 2)])[:-1],
    ]:
        client.task(38, 2, invalid, error=106)
        assert {
            entry.name: entry.read_bytes() for entry in parent.glob("*.json")
        } == snapshot
    for change in [
        lambda r: r.update(owner=user + 1),
        lambda r: r["responses"][0].update(response=2**63),
        lambda r: r.update(log="AA=A"),
        lambda r: r.update(recorded=-1),
        lambda r: r["responses"][0].update(challenge=38),
    ]:
        corrupt = json.loads(before)
        change(corrupt)
        path.write_text(json.dumps(corrupt))
        client.task(38, 2, payload, error=102)
    path.write_bytes(before)
    checks.append(
        "complete native challenge-response reports: signed/NAN values, 64-byte log, durable retries and whole-request validation"
    )
    checks.append(
        "challenge-response receipt owner/hash integrity and corrupt-store rejection without overwriting data"
    )
    return {"request": payload, "path": path, "bytes": before, "digest": digest}


def check_peer(peer, directory, title, user, fixture, checks):
    assert peer.task(38, 2, fixture["request"]) == []
    peer_path = (
        directory
        / "anti-cheat"
        / str(title)
        / str(user)
        / (fixture["digest"] + ".json")
    )
    assert json.loads(peer_path.read_bytes())["owner"] == user
    assert fixture["path"].read_bytes() == fixture["bytes"]
    checks.append(
        "challenge-response reports are isolated to the signed account and title"
    )
