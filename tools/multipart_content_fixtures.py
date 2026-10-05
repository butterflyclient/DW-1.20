"""Independent Replay 58/20-21 wire, real HTTP and restart checks."""

import hashlib
import json
import struct
import urllib.error
import urllib.request


def exercise(client, directory, title, user, base, helpers, checks):
    u32, u64, text = helpers
    u16 = lambda value: b"\x06" + struct.pack("<H", value)
    i16 = lambda value: b"\x05" + struct.pack("<h", value)
    i32 = lambda value: b"\x07" + struct.pack("<i", value)
    tags = b"\x6e\x08" + struct.pack("<IIQQ", 16, 2, 17, 81)

    def prepare(file=0, offset=0, maximum=10, name="native-parts.bin"):
        return text(name) + u16(31) + tags + i16(offset) + i16(maximum) + u64(file)

    def commit(file, count, size, error=0):
        return u64(file) + u16(count) + u32(size) + i32(error)

    def page(raw):
        assert raw[:1] == b"\x0a" and raw[9:11] == b"\x74\x08"
        file = struct.unpack_from("<Q", raw, 1)[0]
        size, count = struct.unpack_from("<II", raw, 11)
        assert file not in (0, 2**64 - 1) and count <= 10 and len(raw) == 19 + size
        values = [] if not count else raw[19:].split(b"\0")[:-1]
        assert len(values) == count and (not count or raw[-1] == 0)
        urls = [value.decode() for value in values]
        assert all(
            url.startswith(
                base + f"/content-streaming/upload/multipart/{title}/{file}/"
            )
            for url in urls
        )
        return file, urls

    def put(url, value, expected=200):
        request = urllib.request.Request(url, value, method="PUT")
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:
                assert reply.status == expected and reply.read() == b""
        except urllib.error.HTTPError as error:
            assert error.code == expected

    def get(url):
        with urllib.request.urlopen(url, timeout=5) as reply:
            return reply.read()

    pending_path = directory / "content-streaming" / str(title) / "multipart.json"
    catalog_path = directory / "content-streaming" / str(title) / "files.json"
    reserved, no_urls = page(client.task(58, 20, prepare(offset=-1, maximum=-1)))
    assert no_urls == []
    file, first_urls = page(client.task(58, 20, prepare(reserved)))
    assert file == reserved and len(first_urls) == 10
    assert page(client.task(58, 20, prepare(file)))[1] == first_urls
    second = page(client.task(58, 20, prepare(file, 10, 10)))[1]
    assert len(second) == 10 and set(first_urls).isdisjoint(second)
    for offset, maximum in [(-1, 10), (0, -1), (0, 0), (0, 11), (-2, -2), (1020, 10)]:
        before = pending_path.read_bytes()
        client.task(58, 20, prepare(file, offset, maximum), error=106)
        assert pending_path.read_bytes() == before
    client.task(58, 20, prepare(0, 1, 10), error=106)
    client.task(58, 20, prepare(file, name="changed.bin"), error=106)
    client.task(58, 20, prepare(file) + b"\x01", error=106)
    client.task(
        58,
        20,
        text("native-parts.bin") + u16(31) + tags + u16(0) + i16(10) + u64(file),
        error=106,
    )
    client.task(58, 20, prepare(2**64 - 1), error=106)
    checks.append(
        "Replay multipart file reservation, packed string-array DTO, stable ten-URL pages, signed offsets and strict pagination bounds"
    )

    bodies = [b"first-native-part" * 4096, b"", b"last-native-part" * 3072]
    urls = first_urls[:3]
    catalog_before = catalog_path.read_bytes()
    client.task(58, 21, commit(file, 3, sum(map(len, bodies))), error=106)
    put(urls[0], bodies[0])
    put(urls[0], bodies[0])
    put(urls[0], b"changed", 409)
    put(urls[1], bodies[1])
    put(urls[2][:-1] + ("a" if urls[2][-1] != "a" else "b"), b"forged", 404)
    put(
        urls[2].replace(f"/multipart/{title}/", f"/multipart/{title+1}/"),
        b"wrong title",
        404,
    )
    put(urls[2].replace("/2/", "/02/"), b"noncanonical index", 404)
    client.task(58, 21, commit(file, 3, sum(map(len, bodies))), error=106)
    put(urls[2], bodies[2])
    stage_before = pending_path.read_bytes()
    for count, size, error, expected in [
        (2, len(bodies[0]), 0, 106),
        (3, 1, 0, 106),
        (1025, 0, 0, 106),
        (3, sum(map(len, bodies)), -1, 108),
        (3, sum(map(len, bodies)), 404, 108),
    ]:
        client.task(58, 21, commit(file, count, size, error), error=expected)
        assert (
            catalog_path.read_bytes() == catalog_before
            and pending_path.read_bytes() == stage_before
        )
    client.task(
        58, 21, u64(file) + u16(3) + u32(sum(map(len, bodies))) + u32(0), error=106
    )
    checks.append(
        "multipart PUT transfers real immutable bytes, including an empty part; forged capabilities and incomplete/extra/incorrect/failed commits never publish"
    )

    saved = pending_path.read_bytes()
    damaged = json.loads(saved)
    damaged["sessions"][0]["parts"][0]["content"] = "g" * 64
    pending_path.write_text(json.dumps(damaged))
    broken = pending_path.read_bytes()
    client.task(58, 20, prepare(file), error=102)
    assert pending_path.read_bytes() == broken
    put(urls[0], bodies[0], 500)
    pending_path.write_bytes(saved)
    damaged = json.loads(saved)
    damaged["sessions"][0]["parts"][1]["token"] = damaged["sessions"][0]["parts"][0][
        "token"
    ]
    pending_path.write_text(json.dumps(damaged))
    client.task(58, 20, prepare(file), error=102)
    pending_path.write_bytes(saved)
    part_hash = hashlib.sha256(bodies[0]).hexdigest()
    blob_path = (
        directory / "content-streaming" / str(title) / "blobs" / (part_hash + ".bin")
    )
    blob_saved = blob_path.read_bytes()
    blob_path.write_bytes(b"corrupt")
    client.task(58, 21, commit(file, 3, sum(map(len, bodies))), error=102)
    put(urls[0], bodies[0], 500)
    assert (
        catalog_path.read_bytes() == catalog_before
        and blob_path.read_bytes() == b"corrupt"
    )
    blob_path.write_bytes(blob_saved)
    checks.append(
        "multipart staging schema/token uniqueness and actual part hashes fail closed without overwriting damaged state or acknowledging a false commit"
    )

    pre_commit = pending_path.read_bytes()
    post = commit(file, 3, sum(map(len, bodies)))
    assert client.task(58, 21, post) == u64(file)
    catalog = json.loads(catalog_path.read_bytes())
    row = next(row for row in catalog["files"] if row["id"] == file)
    assert (
        row["owner"] == user and row["kind"] == "pooled" and row["tags"] == [[17, 81]]
    )
    assert row["parts"] == [
        {"content": hashlib.sha256(body).hexdigest(), "size": len(body)}
        for body in bodies
    ]
    combined = b"".join(bodies)
    download = base + f"/content-streaming/download/{title}/" + row["content"]
    assert (
        row["content"] == hashlib.sha256(combined).hexdigest()
        and get(download) == combined
    )
    assert not any(
        session["id"] == file
        for session in json.loads(pending_path.read_bytes())["sessions"]
    )
    put(urls[0], bodies[0], 404)
    before = catalog_path.read_bytes()
    assert client.task(58, 21, post) == u64(file)
    assert catalog_path.read_bytes() == before
    # Simulate catalog publication preceding staging removal at interruption.
    pending_path.write_bytes(pre_commit)
    assert client.task(58, 21, post) == u64(file)
    assert catalog_path.read_bytes() == before
    assert not any(
        session["id"] == file
        for session in json.loads(pending_path.read_bytes())["sessions"]
    )
    pending_path.write_text(json.dumps({"schema": 1, "title": title, "sessions": []}))
    client.task(
        58, 6, u64(file) + u16(0) + text(str(file)) + u32(len(combined)), error=108
    )
    client.task(58, 21, commit(file, 2, len(combined)), error=106)
    checks.append(
        "one durable multipart manifest and assembled file, exact commit retries, interrupted staging cleanup and whole-file/multipart task separation"
    )

    resume_id, resume_urls = page(
        client.task(58, 20, prepare(name="resume-native-parts.bin", maximum=2))
    )
    put(resume_urls[0], b"persisted first part")
    resume_body = b"second part after process restart"
    expired_id, expired_urls = page(
        client.task(58, 20, prepare(name="expired-native-parts.bin", maximum=1))
    )
    stage = json.loads(pending_path.read_bytes())
    for session in stage["sessions"]:
        if session["id"] == expired_id:
            session.update(created=1, expires=2)
    pending_path.write_text(json.dumps(stage))
    put(expired_urls[0], b"late", 404)
    client.task(
        58,
        20,
        prepare(expired_id, maximum=1, name="expired-native-parts.bin"),
        error=108,
    )
    checks.append(
        "expired multipart capabilities do not accept data or regain validity through a known file ID"
    )
    return {
        "file": file,
        "post": post,
        "catalog_path": catalog_path,
        "row": row,
        "download": download,
        "combined": combined,
        "resume_id": resume_id,
        "resume_prepare": prepare(resume_id, maximum=2, name="resume-native-parts.bin"),
        "resume_urls": resume_urls,
        "resume_body": resume_body,
        "resume_post": commit(
            resume_id, 2, len(b"persisted first part") + len(resume_body)
        ),
        "peer_post": commit(resume_id, 1, len(b"persisted first part")),
        "page": page,
        "put": put,
        "get": get,
    }


def check_peer(peer, fixture, checks):
    before = fixture["catalog_path"].read_bytes()
    peer.task(58, 20, fixture["resume_prepare"], error=101)
    peer.task(58, 21, fixture["peer_post"], error=101)
    peer.task(58, 21, fixture["post"], error=101)
    assert fixture["catalog_path"].read_bytes() == before
    checks.append(
        "independently authenticated peer cannot request upload pages, commit staging or replay another owner multipart receipt"
    )


def check_restart(client, fixture, checks):
    assert client.task(58, 21, fixture["post"]) == b"\x0a" + struct.pack(
        "<Q", fixture["file"]
    )
    assert fixture["get"](fixture["download"]) == fixture["combined"]
    assert fixture["page"](client.task(58, 20, fixture["resume_prepare"])) == (
        fixture["resume_id"],
        fixture["resume_urls"],
    )
    fixture["put"](fixture["resume_urls"][1], fixture["resume_body"])
    assert client.task(58, 21, fixture["resume_post"]) == b"\x0a" + struct.pack(
        "<Q", fixture["resume_id"]
    )
    checks.append(
        "multipart committed receipt/bytes and unfinished stable-capability staging survive backend restart and resume through real HTTP"
    )
