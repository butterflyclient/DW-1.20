"""Independent wire/HTTP checks for the recovered utility/team/content layouts."""

import hashlib
import json
import os
import struct
import urllib.request
import urllib.error


def exercise(client, directory, title, user, base, helpers, checks):
    u32, u64, text, blob, structure, pb_text, pb_bytes = helpers
    u16 = lambda n: b"\x06" + struct.pack("<H", n)
    for original, expected in [
        ("Player 名", "Player 名"),
        ("a\t\r\nb\x7f\u0085c", "abc"),
        ("", ""),
    ]:
        assert client.task(
            12, 13, structure(pb_text(1, original)), structured=True
        ) == pb_text(1, expected)
    for payload in [
        b"",
        pb_text(1, "a") + pb_text(1, "b"),
        pb_bytes(1, b"\xc0\x80"),
        pb_bytes(1, b"\xed\xa0\x80"),
        pb_bytes(1, b"\xf4\x90\x80\x80"),
        pb_bytes(1, b"\xf0\x90"),
        pb_text(1, "a\0b"),
        pb_text(1, "x" * 1024),
    ]:
        client.task(12, 13, structure(payload), structured=True, error=106)
    checks.append(
        "Replay structured sanitizer: printable UTF-8, control removal, duplicate/missing fields and invalid Unicode rejection"
    )

    # Real 104/7 viewed-message telemetry, with its empty structured response.
    viewed_row = lambda number: (
        pb_text(4, "en") + b"\x08" + bytes([number]) + b"\x10\x02\x18\x03"
    )
    viewed_request = lambda rows: structure(
        pb_text(1, "iw8") + b"".join(pb_bytes(2, row) for row in rows)
    )
    row = viewed_row(71)
    assert client.task(104, 7, viewed_request([row]), structured=True) == b""
    views_path = directory / "marketing" / str(title) / "iw8" / f"{user}.views.json"
    views_before = views_path.read_bytes()
    assert client.task(104, 7, viewed_request([row, row]), structured=True) == b""
    assert views_path.read_bytes() == views_before
    for invalid in [
        row + b"\x08\x05",
        b"\x08\x01",
        pb_text(4, "x" * 21) + b"\x08\x01\x10\x02\x18\x03",
    ]:
        client.task(104, 7, viewed_request([viewed_row(72), invalid]), error=106)
        assert views_path.read_bytes() == views_before
    corrupt = json.loads(views_before)
    next(iter(corrupt["views"].values()))["view"]["2"] = -1
    views_path.write_text(json.dumps(corrupt))
    client.task(104, 7, viewed_request([row]), error=102)
    views_path.write_bytes(views_before)
    checks.append(
        "native viewed-message field layout, durable owner-scoped receipts, duplicate retries and atomic malformed-batch rejection"
    )

    team_path = directory / "teams" / str(title) / "iw8" / "teams.json"
    query = (
        lambda who=user, maximum=10, start=0: text("iw8")
        + u64(who)
        + text("uno")
        + u32(maximum)
        + u32(start)
    )
    assert client.task(3, 46, query()) == []
    team_path.parent.mkdir(parents=True)
    teams = {
        "schema": 1,
        "teams": [
            {
                "id": 31,
                "owner": user,
                "account": "uno",
                "name": "Native Legacy Team",
                "members": [{"user": user, "status": 2}],
            },
            {
                "id": 32,
                "owner": user,
                "account": "bnet",
                "name": "Second Team",
                "members": [{"user": user, "status": 4}],
            },
        ],
    }
    team_path.write_text(json.dumps(teams))
    team_row = (
        lambda n: u64(n["id"])
        + text(n["name"])
        + u64(n["owner"])
        + text(n["account"])
        + b"\x03"
        + bytes([n["members"][0]["status"]])
    )
    assert client.task(3, 46, query()) == b"".join(map(team_row, teams["teams"]))
    assert client.task(3, 46, query(0xFFFFFFFFFFFFFFFF, 1, 1)) == team_row(
        teams["teams"][1]
    )
    assert client.task(3, 46, query(user + 1)) == []
    client.task(3, 46, query(maximum=0), error=106)
    corrupt = json.loads(json.dumps(teams))
    corrupt["teams"][1]["members"][0]["user"] = -1
    team_path.write_text(json.dumps(corrupt))
    client.task(3, 46, query(), error=102)
    team_path.write_text(json.dumps(teams))
    checks.append(
        "complete native legacy team DTO, implicit owner, public lookup, paging and corrupt publication rejection"
    )

    path = directory / "content-streaming" / str(title) / "files.json"
    tags = (
        lambda pairs: bytes([110, 8])
        + struct.pack("<II", len(pairs) * 16, len(pairs) * 2)
        + b"".join(struct.pack("<QQ", *pair) for pair in pairs)
    )
    catalog_query = lambda owner=user: u64(owner) + u32(0) + u16(10) + u16(0) + u16(7)
    assert client.task(50, 2, catalog_query()) == []
    raw = client.task(
        58, 5, text("fixture.bin") + u16(7) + tags([(1, 9), (2, 8)]) + text("")
    )
    assert raw[0] == 16
    end = raw.index(0, 1)
    upload_url = raw[1:end].decode()
    offset = end + 1
    assert raw[offset : offset + 3] == u16(0)
    offset += 3
    assert raw[offset] == 16
    end = raw.index(0, offset + 1)
    server_name = raw[offset + 1 : end].decode()
    offset = end + 1
    assert raw[offset] == 10 and len(raw) == offset + 9
    file_id = struct.unpack_from("<Q", raw, offset + 1)[0]
    assert server_name == str(file_id) and upload_url.startswith(
        base + "/content-streaming/upload/"
    )
    post_params = u64(file_id) + u16(0) + text(server_name)
    client.task(58, 6, post_params + u32(8), error=106)
    body = os.urandom(300 * 1024)  # Exceeds ordinary auth/REST body limit.

    def put(url, value, expected=200):
        request = urllib.request.Request(url, value, method="PUT")
        try:
            with urllib.request.urlopen(request, timeout=5) as reply:
                assert reply.status == expected and reply.read() == b""
        except urllib.error.HTTPError as error:
            assert error.code == expected

    put(upload_url, body)
    put(upload_url, body)
    put(upload_url, b"changed", 409)
    assert client.task(58, 6, post_params + u32(len(body))) == u64(file_id)
    assert client.task(58, 6, post_params + u32(len(body))) == u64(file_id)
    client.task(58, 6, post_params + u32(len(body) + 1), error=106)
    put(upload_url, body, 404)
    store = json.loads(path.read_text())
    row = store["files"][0]
    assert (
        row["owner"] == user
        and row["kind"] == "pooled"
        and row["tags"] == [[1, 9], [2, 8]]
    )
    assert (
        row["size"] == len(body) and row["content"] == hashlib.sha256(body).hexdigest()
    )

    def expected_metadata(row):
        url = base + f"/content-streaming/download/{title}/" + row["content"]
        return (
            u64(row["id"])
            + u32(row["created"])
            + u32(row["modified"])
            + u32(row["size"])
            + u64(row["owner"])
            + text(row["owner_name"])
            + u16(row["slot"])
            + text(row["name"])
            + text(url)
            + u16(row["category"])
            + blob(__import__("base64").b64decode(row["metadata"]))
            + u32(row["summary_size"])
            + tags(row["tags"])
            + u32(row["copies"])
            + u64(row["origin"])
        )

    expected = expected_metadata(row)
    assert client.task(50, 2, catalog_query()) == expected
    assert client.task(50, 9, u64(file_id) + u32(0x40000000)) == expected
    client.task(50, 10, u64(file_id) + u32(0), error=108)
    client.task(50, 18, u64(file_id) + u32(0), error=108)
    download = base + f"/content-streaming/download/{title}/" + row["content"]
    with urllib.request.urlopen(download) as reply:
        assert reply.read() == body
    with urllib.request.urlopen(
        urllib.request.Request(download, headers={"Range": "bytes=91-117"})
    ) as reply:
        assert reply.status == 206 and reply.read() == body[91:118]
    checks.append(
        "pooled pre-upload/real HTTP PUT/commit/retry, signed owner, full file metadata/tag DTO, immutable hashed bytes and range downloads"
    )

    # Published user/publisher entries are explicit fixture data, not fabricated
    # production game files. Summary downloads use their own native DTO.
    published = dict(
        row,
        id=file_id + 1,
        kind="publisher",
        owner=0,
        owner_name="",
        name="publisher.bin",
        metadata="eA==",
        summary=row["content"],
        summary_size=len(body),
        copies=3,
        origin=file_id,
    )
    store["files"].append(published)
    path.write_text(json.dumps(store))
    publisher_query = u32(0) + u16(10) + u16(0) + u16(7)
    assert client.task(50, 3, publisher_query) == expected_metadata(published)
    assert client.task(50, 3, publisher_query + text("missing.bin")) == []
    assert client.task(50, 10, u64(published["id"]) + u32(0)) == expected_metadata(
        published
    )
    client.task(50, 9, u64(published["id"]) + u32(0), error=108)
    summary = text(download) + u32(len(body))
    assert client.task(50, 18, u64(published["id"]) + u32(0)) == summary
    assert client.task(58, 18, u64(published["id"]) + u32(0)) == summary
    assert client.task(50, 19, u64(published["id"])) == summary
    corrupted = dict(store)
    corrupted["files"] = [dict(row, size=-1)]
    path.write_text(json.dumps(corrupted))
    client.task(50, 2, catalog_query(), error=102)
    path.write_text(json.dumps(store))
    before = path.read_bytes()
    client.task(
        58, 5, text("bad.bin") + u16(7) + tags([(1, 9)])[:-1] + text(""), error=106
    )
    assert path.read_bytes() == before
    checks.append(
        "published frontend-independent file listing/filtering, complete native summary DTO and atomic malformed/corrupt-store rejection"
    )
    return {
        "id": file_id,
        "post": post_params + u32(len(body)),
        "download": download,
        "content_sha256": hashlib.sha256(body).hexdigest(),
        "metadata": expected,
        "team_query": query(),
        "team_result": b"".join(map(team_row, teams["teams"])),
    }
