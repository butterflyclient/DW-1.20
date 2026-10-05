"""Independent whole-user-file wire, HTTP staging, ownership and restart checks.

The post writer and full metadata/task readers are recovered from Replay.
The preparation writer is a source-oracle contract, not a target/native proof.
"""

import base64
import copy
import hashlib
import json
import struct
import urllib.error
import urllib.request


def exercise(client, peer, directory, title, user, peer_user, base, helpers, checks):
    u32, u64, text, blob = helpers
    u16 = lambda value: b"\x06" + struct.pack("<H", value)
    root = directory / "content-streaming" / str(title)
    path, pending_path = root / "files.json", root / "user-uploads.json"
    body = b"whole user-file content\x00" * 211

    def tags(pairs):
        return (
            b"\x6e\x08"
            + struct.pack("<II", len(pairs) * 16, len(pairs) * 2)
            + b"".join(struct.pack("<QQ", *pair) for pair in pairs)
        )

    def prepare(
        name="user-content.bin",
        slot=701,
        size=len(body),
        category=13,
        connection=client,
    ):
        raw = connection.task(
            50,
            5,
            text(name) + u16(slot) + u32(size) + u16(category) + blob(b"") + text(""),
        )
        assert raw[0] == 16
        end = raw.index(0, 1)
        url = raw[1:end].decode()
        assert raw[end + 1 : end + 4] == u16(0) and raw[end + 4] == 16
        stop = raw.index(0, end + 5)
        token = raw[end + 5 : stop].decode()
        assert raw[stop + 1] == 10 and len(raw) == stop + 10
        file = struct.unpack_from("<Q", raw, stop + 2)[0]
        assert len(token) == 32 and int(token, 16) >= 0 and file not in (0, 2**64 - 1)
        assert url == f"{base}/content-streaming/upload/user/{title}/{token}"
        return dict(
            url=url,
            token=token,
            id=file,
            name=name,
            slot=slot,
            size=size,
            category=category,
        )

    def post(stage, **changes):
        values = dict(
            stage, location=0, metadata=b"user metadata", tags=[[7, 97], [5, 41]]
        )
        values.update(changes)
        return (
            text(values["name"])
            + u16(values["slot"])
            + u16(values["location"])
            + text(values["token"])
            + u32(values["size"])
            + u16(values["category"])
            + blob(values["metadata"])
            + tags(values["tags"])
            + text("")
        )

    def put(stage, data=body, status=200, url=None, headers=None):
        request = urllib.request.Request(
            url or stage["url"], data, method="PUT", headers=headers or {}
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                assert response.status == status and response.read() == b""
        except urllib.error.HTTPError as error:
            assert error.code == status

    def expected(row):
        return (
            u64(row["id"])
            + u32(row["created"])
            + u32(row["modified"])
            + u32(row["size"])
            + u64(row["owner"])
            + text(row["owner_name"])
            + u16(row["slot"])
            + text(row["name"])
            + text(f"{base}/content-streaming/download/{title}/{row['content']}")
            + u16(row["category"])
            + blob(base64.b64decode(row["metadata"]))
            + u32(0)
            + tags(row["tags"])
            + u32(row["copies"])
            + u64(0)
        )

    def store():
        return json.loads(path.read_bytes())

    def row(file):
        return next(item for item in store()["files"] if item["id"] == file)

    first = prepare()
    params = post(first)
    catalog_before = path.read_bytes()
    pending_before = pending_path.read_bytes()
    client.task(50, 6, params, error=106)
    peer.task(50, 6, params, error=101)
    put(first, body[:-1], status=400)
    put(first, status=400, headers={"Range": "bytes=0-9"})
    put(
        first,
        status=404,
        url=first["url"].replace(f"/user/{title}/", f"/user/{title+1}/"),
    )
    put(
        first,
        status=404,
        url=first["url"].replace(f"/user/{title}/", f"/user/0{title}/"),
    )
    assert (
        pending_path.read_bytes() == pending_before
        and path.read_bytes() == catalog_before
    )
    put(first)
    pending_before = pending_path.read_bytes()
    put(first)
    put(first, bytes(len(body)), status=409)
    assert pending_path.read_bytes() == pending_before
    content_path = root / "blobs" / (hashlib.sha256(body).hexdigest() + ".bin")
    content_path.write_bytes(bytes(len(body)))
    put(first, status=500)
    client.task(50, 6, params, error=102)
    assert (
        pending_path.read_bytes() == pending_before
        and path.read_bytes() == catalog_before
    )
    content_path.write_bytes(body)
    checks.append(
        "Whole-user preparation DTO, exact-size persistent HTTP staging, idempotent bytes, scoped URLs, range rejection and corrupt blob rollback"
    )

    for changes in (
        {"name": "wrong.bin"},
        {"name": "x" * 128},
        {"slot": 702},
        {"location": 1},
        {"size": len(body) + 1},
        {"category": 14},
        {"metadata": bytes(2049)},
        {"tags": [[1, 2**64 - 1]]},
    ):
        client.task(50, 6, post(first, **changes), error=106)
        assert path.read_bytes() == catalog_before
    for bad in (params + b"\x01", params[:-2], params[:-2] + text("nonempty")):
        client.task(50, 6, bad, error=106)
        assert path.read_bytes() == catalog_before
    raw = client.task(50, 6, params)
    uploaded = row(first["id"])
    assert raw == expected(uploaded) and raw[:9] == u64(first["id"])
    assert uploaded["kind"] == "user" and uploaded["owner"] == user
    assert (
        uploaded["slot"] == first["slot"]
        and uploaded["content"] == hashlib.sha256(body).hexdigest()
    )
    assert uploaded["metadata"] == base64.b64encode(b"user metadata").decode()
    assert uploaded["tags"] == [[7, 97], [5, 41]] and uploaded["summary"] == ""
    committed = path.read_bytes()
    assert client.task(50, 6, params) == raw and path.read_bytes() == committed
    peer.task(50, 6, params, error=101)
    client.task(50, 6, post(first, metadata=b"changed"), error=106)
    assert path.read_bytes() == committed
    assert client.task(50, 9, u64(first["id"]) + u32(0)) == raw
    with urllib.request.urlopen(
        f"{base}/content-streaming/download/{title}/{uploaded['content']}", timeout=5
    ) as response:
        assert response.read() == body
    checks.append(
        "Complete Replay post-upload contract and metadata/FileID prefix, metadata/tags persistence, signed ownership, download, strict malformed rollback and retry fingerprint"
    )

    second = prepare(name="replacement.bin")
    put(second)
    second_params = post(second, metadata=b"replacement metadata")
    second_raw = client.task(50, 6, second_params)
    assert second_raw == expected(row(second["id"]))
    committed = path.read_bytes()
    assert client.task(50, 6, params) == raw and path.read_bytes() == committed
    assert [
        item["id"]
        for item in store()["files"]
        if item["kind"] == "user" and item["owner"] == user and item["slot"] == 701
    ] == [second["id"]]
    peer_stage = prepare(connection=peer)
    put(peer_stage)
    peer.task(50, 6, post(peer_stage))
    assert row(peer_stage["id"])["owner"] == peer_user
    assert row(second["id"])["owner"] == user
    # Use the uploaded user file as a copy source. Mutable copy counters must
    # not corrupt the immutable upload receipt, and old retries do not reset them.
    copied = client.task(50, 20, u64(second["id"]) + u16(708))
    split = copied.index(0, 1)
    source_url = copied[1:split].decode()
    token_start = split + 5
    token_stop = copied.index(0, token_start)
    copy_token = copied[token_start:token_stop].decode()
    destination_start = token_stop + 11
    destination_stop = copied.index(0, destination_start)
    destination = copied[destination_start:destination_stop].decode()
    request = urllib.request.Request(
        source_url, b"", method="COPY", headers={"Destination": destination}
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        assert response.status == 201
    copy_post = (
        text("upload-copy.bin")
        + u16(708)
        + u16(0)
        + text(copy_token)
        + u32(len(body))
        + u16(13)
        + u32(0)
        + blob(b"")
        + tags([])
        + b"\x01\x00"
        + u64(second["id"])
    )
    client.task(50, 16, copy_post)
    assert row(second["id"])["copies"] == 1
    committed = path.read_bytes()
    assert (
        client.task(50, 6, second_params) == second_raw
        and path.read_bytes() == committed
    )
    checks.append(
        "Atomic user-slot replacement, immutable historical metadata receipts, same-slot peer isolation and copy-source counters preserve old-upload retry semantics"
    )

    expired = prepare(slot=704)
    pending = json.loads(pending_path.read_bytes())
    stage = next(
        item for item in pending["sessions"] if item["token"] == expired["token"]
    )
    stage["created"], stage["expires"] = 0, 1
    pending_path.write_text(json.dumps(pending))
    put(expired, status=404)
    client.task(50, 6, post(expired), error=108)
    pending_before = pending_path.read_bytes()
    for checksum, error in ((b"x", 106), (bytes(32), 108), (bytes(33), 106)):
        client.task(
            50,
            5,
            text("checksum.bin") + u16(1) + u32(4) + u16(1) + blob(checksum) + text(""),
            error=error,
        )
        assert pending_path.read_bytes() == pending_before
    original = path.read_bytes()
    broken = copy.deepcopy(store())
    broken["upload_receipts"][first["token"]]["row"]["size"] = 2**32
    path.write_text(json.dumps(broken))
    client.task(50, 6, params, error=102)
    assert store() == broken
    path.write_bytes(original)
    checks.append(
        "Whole-user capability expiry, unknown optional checksum variant rejection and corrupt durable receipt rejection leave storage unchanged"
    )

    active = prepare(slot=705)
    put(active)
    incomplete = prepare(slot=706)
    empty = prepare(name="empty.bin", slot=707, size=0)
    put(empty, b"")
    return dict(
        path=path,
        first=params,
        first_raw=raw,
        second=second_params,
        second_raw=second_raw,
        active=post(active),
        active_id=active["id"],
        incomplete=post(incomplete),
        empty=post(empty),
        empty_id=empty["id"],
    )


def check_restart(client, fixture, checks):
    path = fixture["path"]
    before = path.read_bytes()
    assert client.task(50, 6, fixture["first"]) == fixture["first_raw"]
    assert client.task(50, 6, fixture["second"]) == fixture["second_raw"]
    assert path.read_bytes() == before
    client.task(50, 6, fixture["incomplete"], error=106)
    assert path.read_bytes() == before
    active = client.task(50, 6, fixture["active"])
    empty = client.task(50, 6, fixture["empty"])
    assert active[:9] == b"\x0a" + struct.pack("<Q", fixture["active_id"])
    assert empty[:9] == b"\x0a" + struct.pack("<Q", fixture["empty_id"])
    committed = path.read_bytes()
    assert client.task(50, 6, fixture["active"]) == active
    assert client.task(50, 6, fixture["empty"]) == empty
    assert path.read_bytes() == committed
    checks.append(
        "Whole-user completed/incomplete HTTP staging, historical result receipts and zero-byte uploads survive a real backend process restart"
    )
