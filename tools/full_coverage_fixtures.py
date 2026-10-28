"""Encrypted-wire checks for the routes that complete Replay's native task baseline.

193/9 and 193/10 (list publisher/user objects by category, with paging),
193/12 and 193/24 (large-object upload completion), 50/22 and 58/22 (part
windows for paged and multipart downloads). Every route in
validation/20261027-dw-task-baseline.json now has a handler; these cases
exercise the ones that previously returned 108.
"""

import base64
import hashlib
import json
import struct
import urllib.request


def exercise(client, directory, title, user, base, helpers, content, multipart, checks):
    u32, u64, text, structure, pb_text, pb_bytes, pb_fields = helpers
    u16 = lambda value: b"\x06" + struct.pack("<H", value)

    def http(method, url, body=None):
        raw = pb_text(1, method) + pb_text(2, url)
        if body is not None:
            raw += pb_text(3, json.dumps(body))
            raw += pb_bytes(4, pb_text(1, "Content-Type") + pb_text(2, "application/json"))
        return structure(raw)

    def reply(raw):
        fields = pb_fields(raw)
        status = next(v for t, k, v in fields if t == 2)
        return status, json.loads(next(v for t, k, v in fields if t == 3))

    # 193/9: three public publisher objects, two in one category, one expired.
    folder = directory / "objectstore" / "publisher" / str(title) / "iw8" / "coverage"
    folder.mkdir(parents=True, exist_ok=True)
    for name, category, expires in (("b.json", "cat-a", 0), ("a.json", "cat-a", 0),
                                    ("c.json", "cat-b", 0), ("old.json", "cat-a", 1)):
        payload = name.encode()
        (folder / (name + ".content.bin")).write_bytes(payload)
        (folder / (name + ".metadata.json")).write_text(json.dumps({
            "name": name, "owner": "coverage", "context": "iw8", "contentLength": len(payload),
            "checksum": base64.b64encode(hashlib.md5(payload).digest()).decode(),
            "objectVersion": "1", "acl": "public", "created": 1, "modified": 1,
            "expiresOn": expires, "category": category,
        }))
    query = "?client=replay&context=iw8&category=cat-a&limit=1"
    status, first = reply(client.task(
        193, 9, http("GET", "/v1/core/publishers/coverage/objects/" + query), structured=True))
    assert status == 200 and [o["metadata"]["name"] for o in first["objects"]] == ["a.json"]
    assert first["nextPageToken"] == "1"
    assert first["objects"][0]["metadata"]["contentURL"].startswith(base + "/objectstore/content/")
    status, second = reply(client.task(
        193, 9, http("GET", "/v1/core/publishers/coverage/objects/" + query + "&pageToken=1"),
        structured=True))
    assert [o["metadata"]["name"] for o in second["objects"]] == ["b.json"]
    assert "nextPageToken" not in second
    client.task(193, 9, http("GET", "/v1/core/publishers/coverage/objects/?client=replay&context=iw8&limit=1"),
                error=106)
    client.task(193, 9, http("GET", "/v1/core/publishers/../objects/" + query), error=106)
    checks.append("193/9 publisher category listing: public/unexpired only, name order, limit and pageToken paging")

    # 193/12 one-session completion, 193/24 $batch completion, then 193/10 listing.
    def entry(name, category, data):
        return {"metadata": {"owner": "me", "name": name, "category": category, "acl": "public"},
                "content": base64.b64encode(data).decode()}

    single = entry("large-one.bin", "loadouts", b"x" * 4000)
    status, done = reply(client.task(193, 12, http(
        "POST", "/v1/core/upload-sessions/large-one.bin/complete/?client=replay&context=iw8", single),
        structured=True))
    assert status == 200 and done["objects"][0]["metadata"]["name"] == "large-one.bin"
    client.task(193, 12, http(
        "POST", "/v1/core/upload-sessions/other.bin/complete/?client=replay&context=iw8", single), error=106)
    batch = {"objects": [entry("large-two.bin", "loadouts", b"y" * 3000),
                         entry("large-three.bin", "emblems", b"z" * 10)]}
    status, done = reply(client.task(193, 24, http(
        "POST", "/v2/core/upload-sessions/$batch/complete/?client=replay&context=iw8", batch),
        structured=True))
    assert status == 200 and len(done["objects"]) == 2
    client.task(193, 24, http(
        "POST", "/v2/core/upload-sessions/large-two.bin/complete/?client=replay&context=iw8", batch), error=106)
    status, listed = reply(client.task(193, 10, http(
        "GET", "/v2/core/users/me/objects/?client=replay&context=iw8&category=loadouts&limit=30"),
        structured=True))
    assert status == 200
    assert [o["metadata"]["name"] for o in listed["objects"]] == ["large-one.bin", "large-two.bin"]
    stored = directory / "objectstore" / "users" / str(title) / "iw8" / f"uno-{user}" / "large-one.bin.object.json"
    assert json.loads(stored.read_text())["metadata"]["contentLength"] == 4000
    checks.append("193/12 and 193/24 commit large objects through the journaled upload window; 193/10 lists them by category")

    # 50/22: the user file's complete metadata plus its one-part window.
    window = client.task(50, 22, u64(content["id"]) + u32(0) + u16(0) + u16(1))
    assert window.startswith(content["metadata"])
    tail = window[len(content["metadata"]):]
    assert tail[:3] == u16(0) and tail[3:5] == b"\x74\x08"
    size, count = struct.unpack_from("<II", tail, 5)
    urls = tail[13:13 + size].split(b"\0")[:-1]
    assert count == 1 and len(urls) == 1
    with urllib.request.urlopen(urls[0].decode()) as response:
        assert hashlib.sha256(response.read()).hexdigest() == content["content_sha256"]
    client.task(50, 22, u64(content["id"]) + u32(0) + u16(1) + u16(1), error=108)
    client.task(50, 22, u64(content["id"]) + u32(0) + u16(0) + u16(0), error=106)
    # 58/22: the pooled multipart file's stored parts, windowed.
    row = multipart["row"]
    window = client.task(58, 22, u64(multipart["file"]) + u16(1) + u16(5))
    parts = [part["content"] for part in row["parts"]]
    tail = window[window.rfind(u16(1) + b"t"):]
    assert tail[:3] == u16(1)
    size, count = struct.unpack_from("<II", tail, 5)
    urls = [u.decode() for u in tail[13:13 + size].split(b"\0")[:-1]]
    assert count == len(parts) - 1 and [u.rsplit("/", 1)[1] for u in urls] == parts[1:]
    for url, digest in zip(urls, parts[1:]):
        with urllib.request.urlopen(url) as response:
            assert hashlib.sha256(response.read()).hexdigest() == digest
    client.task(58, 22, u64(987654321987) + u16(0) + u16(1), error=108)
    checks.append("50/22 and 58/22 return complete file metadata plus a part window whose URLs serve each stored part")
