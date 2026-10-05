"""Independent content-copy wire, HTTP, ownership and restart checks.

Replay exports the post-copy writer and pre-copy result/HTTP consumers.
Preparation IDs 50/15 and 50/20 come from the source oracle; this fixture
does not establish that a native Replay caller uses either preparation ID.
"""

import base64
import copy
import hashlib
from http.client import HTTPConnection
import json
import struct
import urllib.parse
import urllib.request


def exercise(client, peer, directory, title, user, peer_user, base, helpers, checks):
    u32, u64, text, blob, boolean = helpers
    u16 = lambda value: b"\x06" + struct.pack("<H", value)
    root = directory / "content-streaming" / str(title)
    path, staging_path = root / "files.json", root / "copies.json"
    body = b"independent copied content\x00" * 73
    summary = b"distinct summary\x00" * 19

    def tags(pairs):
        return (
            bytes([110, 8])
            + struct.pack("<II", len(pairs) * 16, len(pairs) * 2)
            + b"".join(struct.pack("<QQ", *pair) for pair in pairs)
        )

    def store():
        return json.loads(path.read_bytes())

    def save(value):
        path.write_text(json.dumps(value), encoding="utf-8")

    def publish_bytes(value):
        digest = hashlib.sha256(value).hexdigest()
        blob_path = root / "blobs" / (digest + ".bin")
        blob_path.parent.mkdir(parents=True, exist_ok=True)
        blob_path.write_bytes(value)
        return digest, blob_path

    content_hash, body_path = publish_bytes(body)
    summary_hash, _ = publish_bytes(summary)
    catalog = store()
    source = copy.deepcopy(catalog["files"][0])
    source.update(
        id=(1 << 62) + 18001,
        name="copy-source.bin",
        size=len(body),
        content=content_hash,
        summary_size=len(summary),
        summary=summary_hash,
        metadata=base64.b64encode(b"source metadata").decode(),
        tags=[[5, 29], [31, 43]],
        copies=0,
    )
    catalog["files"].append(source)
    save(catalog)

    def prepare(file=source["id"], slot=611, pooled=True, connection=client):
        raw = connection.task(50, 15 if pooled else 20, u64(file) + u16(slot))
        cursor = 0

        def string():
            nonlocal cursor
            assert raw[cursor] == 16
            end = raw.index(0, cursor + 1)
            value = raw[cursor + 1 : end].decode()
            cursor = end + 1
            return value

        def integer(tag, fmt):
            nonlocal cursor
            assert raw[cursor] == tag
            value = struct.unpack_from(fmt, raw, cursor + 1)[0]
            cursor += 1 + struct.calcsize(fmt)
            return value

        parts = []
        while cursor < len(raw):
            source_url = string()
            assert integer(6, "<H") == 0
            token, file_id, destination = string(), integer(10, "<Q"), string()
            size = integer(8, "<I")
            assert len(token) == 32 and int(token, 16) >= 0 and file_id > 0
            assert (
                source_url
                == f"{base}/content-streaming/copy/{title}/{token}/source/{len(parts)}"
            )
            assert (
                destination
                == f"{base}/content-streaming/copy/{title}/{token}/destination/{len(parts)}"
            )
            parts.append((source_url, destination, size))
        assert parts and all(token in part[0] for part in parts)
        return {
            "parts": parts,
            "token": token,
            "id": file_id,
            "slot": slot,
            "source": file,
            "pooled": pooled,
        }

    def post(
        value, name="copied.bin", metadata=b"custom metadata", pair_tags=None, **changes
    ):
        fields = dict(
            name=name,
            slot=value["slot"],
            token=value["token"],
            size=value["parts"][0][2],
            category=11,
            summary_size=value["parts"][1][2] if len(value["parts"]) == 2 else 0,
            metadata=metadata,
            tags=pair_tags or [[7, 83]],
            pooled=value["pooled"],
            source=value["source"],
            location=0,
        )
        fields.update(changes)
        return (
            text(fields["name"])
            + u16(fields["slot"])
            + u16(fields["location"])
            + text(fields["token"])
            + u32(fields["size"])
            + u16(fields["category"])
            + u32(fields["summary_size"])
            + blob(fields["metadata"])
            + tags(fields["tags"])
            + boolean(fields["pooled"])
            + u64(fields["source"])
        )

    def http(
        value,
        part=0,
        expected=201,
        destination=None,
        extra=None,
        body=b"",
        duplicate=False,
    ):
        source_url, target, _ = value["parts"][part]
        parsed = urllib.parse.urlsplit(source_url)
        connection = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
        connection.putrequest("COPY", parsed.path)
        if destination is not False:
            connection.putheader(
                "Destination", target if destination is None else destination
            )
            if duplicate:
                connection.putheader("Destination", target)
        for name, data in (extra or {}).items():
            connection.putheader(name, data)
        connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body)
        response = connection.getresponse()
        data = response.read()
        assert response.status == expected, (response.status, data)
        if expected in (200, 201):
            assert not data
        connection.close()

    def row(file):
        return next(entry for entry in store()["files"] if entry["id"] == file)

    first = prepare()
    assert [part[2] for part in first["parts"]] == [len(body), len(summary)]
    params = post(first)
    before = path.read_bytes()
    client.task(50, 16, params, error=108)
    peer.task(50, 16, params, error=101)
    assert path.read_bytes() == before
    staged_before = staging_path.read_bytes()
    for kwargs in (
        {"destination": False},
        {"duplicate": True},
        {"destination": first["parts"][0][1].replace("127.0.0.1", "localhost")},
        {"destination": first["parts"][1][1]},
        {"extra": {"Range": "bytes=0-3"}},
        {"body": b"unwanted body"},
    ):
        http(first, expected=400, **kwargs)
        assert staging_path.read_bytes() == staged_before
    body_path.write_bytes(bytes(len(body)))
    http(first, expected=500)
    assert staging_path.read_bytes() == staged_before
    body_path.write_bytes(body)
    http(first)
    http(first, expected=200)
    client.task(50, 16, params, error=108)
    http(first, part=1)
    checks.append(
        "Full native bdURL/pre-copy destination/size DTO, two-part COPY, retry, exact Destination, header/body/range and corrupt-blob rejection without advancing staging"
    )

    for changes in (
        {"name": "x" * 128},
        {"slot": first["slot"] + 1},
        {"location": 1},
        {"pooled": False},
        {"source": source["id"] + 1},
        {"size": len(body) + 1},
        {"summary_size": len(summary) + 1},
        {"metadata": bytes(2049)},
    ):
        client.task(50, 16, post(first, **changes), error=106)
        assert path.read_bytes() == before
    client.task(50, 16, params[:-9] + b"\x0a\x01", error=106)
    assert path.read_bytes() == before
    assert client.task(50, 16, params) == u64(first["id"])
    committed = path.read_bytes()
    assert client.task(50, 16, params) == u64(first["id"])
    assert path.read_bytes() == committed and row(source["id"])["copies"] == 1
    peer.task(50, 16, params, error=101)
    client.task(50, 16, post(first, name="conflict.bin"), error=106)
    assert path.read_bytes() == committed
    clone = row(first["id"])
    assert clone["owner"] == user and clone["kind"] == "user" and "parts" not in clone
    assert clone["origin"] == source["id"] and clone["content"] == content_hash
    assert (
        clone["summary"] == summary_hash
        and clone["metadata"] == base64.b64encode(b"custom metadata").decode()
    )
    assert (
        clone["tags"] == [[7, 83]] and clone["category"] == 11 and clone["copies"] == 0
    )
    expected = (
        u64(clone["id"])
        + u32(clone["created"])
        + u32(clone["modified"])
        + u32(len(body))
        + u64(user)
        + text(clone["owner_name"])
        + u16(clone["slot"])
        + text(clone["name"])
        + text(f"{base}/content-streaming/download/{title}/{content_hash}")
        + u16(11)
        + blob(b"custom metadata")
        + u32(len(summary))
        + tags([[7, 83]])
        + u32(0)
        + u64(source["id"])
    )
    assert client.task(50, 9, u64(first["id"]) + u32(0)) == expected
    for digest, value in ((content_hash, body), (summary_hash, summary)):
        with urllib.request.urlopen(
            f"{base}/content-streaming/download/{title}/{digest}", timeout=5
        ) as response:
            assert response.read() == value
    assert client.task(50, 18, u64(first["id"]) + u32(0)) == text(
        f"{base}/content-streaming/download/{title}/{summary_hash}"
    ) + u32(len(summary))
    checks.append(
        "Replay full post-copy request, atomic signed ownership/metadata/tags/origin/source counter, whole-file and summary preservation, owner denial, malformed rollback and idempotent conflict checking"
    )

    second = prepare(slot=first["slot"])
    for part in range(2):
        http(second, part)
    second_params = post(second, name="replacement.bin")
    assert client.task(50, 16, second_params) == u64(second["id"])
    committed = path.read_bytes()
    assert client.task(50, 16, params) == u64(first["id"])
    assert path.read_bytes() == committed
    assert row(source["id"])["copies"] == 2
    assert [
        entry["id"]
        for entry in store()["files"]
        if entry["owner"] == user
        and entry["kind"] == "user"
        and entry["slot"] == first["slot"]
    ] == [second["id"]]
    client.task(50, 20, u64(source["id"]) + u16(614), error=108)
    client.task(50, 15, u64(second["id"]) + u16(614), error=108)
    user_copy = prepare(file=second["id"], slot=615, pooled=False, connection=peer)
    for part in range(2):
        http(user_copy, part)
    assert peer.task(50, 16, post(user_copy)) == u64(user_copy["id"])
    assert row(user_copy["id"])["owner"] == peer_user
    assert row(second["id"])["owner"] == user and row(second["id"])["copies"] == 1
    checks.append(
        "Durable copy receipts survive newer same-slot replacement without rollback/double-counting; public user copy selects task20 and creates only the signed target owner's file"
    )

    expired = prepare(slot=616)
    staged = json.loads(staging_path.read_bytes())
    next(entry for entry in staged["sessions"] if entry["token"] == expired["token"])[
        "expires"
    ] = 1
    staging_path.write_text(json.dumps(staged))
    http(expired, expected=404)
    client.task(50, 16, post(expired), error=108)
    before_corruption = path.read_bytes()
    bad_catalog = copy.deepcopy(store())
    bad_catalog["copy_receipts"][first["token"]]["file"] = 1 << 64
    save(bad_catalog)
    client.task(50, 16, params, error=102)
    assert store() == bad_catalog
    path.write_bytes(before_corruption)
    active = prepare(slot=617)
    http(active)
    overflow = copy.deepcopy(store())
    next(entry for entry in overflow["files"] if entry["id"] == source["id"])[
        "copies"
    ] = 0xFFFFFFFF
    save(overflow)
    http(active, part=1)
    client.task(50, 16, post(active), error=102)
    assert store() == overflow
    next(entry for entry in overflow["files"] if entry["id"] == source["id"])[
        "copies"
    ] = 2
    save(overflow)
    checks.append(
        "Expiring COPY capabilities, corrupt receipt/storage rejection, UInt32 source counter overflow and failed-commit rollback"
    )

    # Leave an actual completed HTTP stage and an incomplete stage for the
    # parent suite's process restart. No synthetic in-memory restoration.
    pending = prepare(slot=618)
    http(pending)
    one = copy.deepcopy(source)
    one.update(
        id=source["id"] + 2,
        name="single-part.bin",
        summary="",
        summary_size=0,
        copies=0,
    )
    catalog = store()
    catalog["files"].append(one)
    save(catalog)
    single = prepare(file=one["id"], slot=619)
    assert len(single["parts"]) == 1 and single["parts"][0][2] == len(body)
    http(single)
    return {
        "path": path,
        "title": title,
        "first": params,
        "first_id": first["id"],
        "second": second_params,
        "second_id": second["id"],
        "pending": post(pending),
        "active": post(active),
        "active_id": active["id"],
        "single": post(single),
        "single_id": single["id"],
        "source": source["id"],
        "user": user,
        "slot": first["slot"],
    }


def check_restart(client, fixture, checks):
    u64 = lambda value: b"\x0a" + struct.pack("<Q", value)
    path = fixture["path"]
    before = path.read_bytes()
    assert client.task(50, 16, fixture["first"]) == u64(fixture["first_id"])
    assert client.task(50, 16, fixture["second"]) == u64(fixture["second_id"])
    assert path.read_bytes() == before
    client.task(50, 16, fixture["pending"], error=108)
    assert path.read_bytes() == before
    assert client.task(50, 16, fixture["active"]) == u64(fixture["active_id"])
    assert client.task(50, 16, fixture["single"]) == u64(fixture["single_id"])
    catalog = json.loads(path.read_bytes())
    catalog["files"] = [
        row for row in catalog["files"] if row["id"] != fixture["source"]
    ]
    path.write_text(json.dumps(catalog))
    before = path.read_bytes()
    assert client.task(50, 16, fixture["first"]) == u64(fixture["first_id"])
    assert path.read_bytes() == before
    checks.append(
        "Content-copy completed/incomplete HTTP staging and receipts survive process restart; single-part commit and retry after source removal preserve newer slots"
    )
