"""Recover complete Replay profile-object windows after real filesystem failures."""

import base64
import copy
import hashlib
import json


def exercise(client, directory, title, user, upload, read, reply, checks):
    root = directory / "objectstore" / "users" / str(title)
    journal_path = root / "_transactions" / f"{user}.json"
    owners = [f"uno-{user}", f"bnet-{user}"]
    names = ["transaction_first.bin", "transaction_second.bin"]
    items = [
        {
            "metadata": {"owner": owner, "name": name, "acl": "private"},
            "content": base64.b64encode(bytes([index + 1]) * 128).decode(),
            "tags": [{"key": "kind", "value": "transaction"}],
        }
        for index, (owner, name) in enumerate(zip(owners, names))
    ]
    ids = [item["metadata"] for item in items]
    paths = [
        root / "iw8" / owner / f"{name}.object.json"
        for owner, name in zip(owners, names)
    ]
    reply(7, upload(items))
    baseline = [path.read_bytes() for path in paths]
    block = paths[1].with_name(paths[1].name + ".pending")

    def interrupt():
        for index, item in enumerate(items):
            item["content"] = base64.b64encode(bytes([index + 31]) * 256).decode()
        block.mkdir()
        client.task(193, 7, upload(items), error=102)
        pending = journal_path.read_bytes()
        journal = json.loads(pending)
        assert journal["phase"] == "prepared" and len(journal["writes"]) == 2
        assert json.loads(paths[0].read_bytes()) == journal["writes"][0]["document"]
        assert paths[1].read_bytes() == baseline[1]
        client.task(193, 6, read(ids), error=102)
        assert journal_path.read_bytes() == pending
        return pending, journal

    pending, journal = interrupt()
    first_bytes = paths[0].read_bytes()
    checks.append(
        "object-store vector uploads retain a flushed complete intent after a real second-file failure; native reads reject partial profile windows"
    )

    for mode in (
        "foreign-user",
        "foreign-title",
        "foreign-owner",
        "escaping-context",
        "wrong-name",
        "bad-checksum",
        "bad-content",
        "bad-tags",
        "duplicate-destination",
        "case-alias-destination",
        "bad-phase",
        "too-many-objects",
        "duplicate-key",
    ):
        bad = copy.deepcopy(journal)
        # Alter the first valid snapshot, then poison a later entry. Recovery
        # must preflight the entire intent before replacing even the first file.
        first = bad["writes"][0]["document"]
        content = b"must-not-publish"
        first["content"] = base64.b64encode(content).decode()
        first["metadata"].update(
            contentLength=len(content), checksum=hashlib.md5(content).hexdigest()
        )
        last = bad["writes"][-1]
        if mode == "foreign-user":
            bad["user"] += 1
        elif mode == "foreign-title":
            bad["title"] += 1
        elif mode == "foreign-owner":
            last["owner"] = f"uno-{user + 1}"
        elif mode == "escaping-context":
            last["context"] = "../escape"
        elif mode == "wrong-name":
            last["name"] = "other.bin"
        elif mode == "bad-checksum":
            last["document"]["metadata"]["checksum"] = "0" * 32
        elif mode == "bad-content":
            last["document"]["content"] = "AA=A"
        elif mode == "bad-tags":
            last["document"]["tags"] = [{"value": "no-key"}]
        elif mode == "duplicate-destination":
            bad["writes"].append(copy.deepcopy(bad["writes"][0]))
        elif mode == "case-alias-destination":
            alias = copy.deepcopy(bad["writes"][0])
            alias["name"] = alias["name"].upper()
            alias["document"]["metadata"]["name"] = alias["name"]
            bad["writes"].append(alias)
        elif mode == "bad-phase":
            bad["phase"] = "applied"
        elif mode == "too-many-objects":
            bad["writes"] *= 26
        encoded = json.dumps(bad)
        if mode == "duplicate-key":
            encoded = '{"schema":1,' + encoded[1:]
        journal_path.write_text(encoded)
        client.task(193, 6, read(ids), error=102)
        assert paths[0].read_bytes() == first_bytes
        assert paths[1].read_bytes() == baseline[1]
    journal_path.write_bytes(pending)
    checks.append(
        "object-store recovery preflights full owner/title/context/name/content/checksum/tag layouts and rejects corrupt or duplicate intents before any replacement"
    )

    block.rmdir()
    recovered = reply(6, read(ids))
    assert not recovered["errors"]
    assert [path.read_bytes() for path in paths] != baseline
    for index, path in enumerate(paths):
        assert json.loads(path.read_bytes()) == journal["writes"][index]["document"]
        assert (
            recovered["objects"][index]["metadata"]
            == journal["writes"][index]["document"]["metadata"]
        )
    completed = journal_path.read_bytes()
    assert json.loads(completed) == {**journal, "phase": "applied", "writes": []}
    assert reply(6, read(ids)) == recovered
    assert journal_path.read_bytes() == completed
    checks.append(
        "object-store recovery publishes one complete mixed uno/bnet owner window, preserves exact metadata/versions/tags and remains idempotent"
    )

    # No publication is allowed before the task's outer typed buffer is consumed.
    before = [path.read_bytes() for path in paths] + [journal_path.read_bytes()]
    client.task(193, 7, upload(items) + b"\x01\x01", error=106)
    assert [path.read_bytes() for path in paths] + [journal_path.read_bytes()] == before
    checks.append(
        "object-store upload validates the complete native task boundary before preparing any durable object intent"
    )
    case_alias = copy.deepcopy(items[0])
    case_alias["metadata"]["name"] = case_alias["metadata"]["name"].upper()
    client.task(193, 7, upload([items[0], case_alias]), error=106)
    assert [path.read_bytes() for path in paths] + [journal_path.read_bytes()] == before
    checks.append(
        "object-store upload and recovery reject Windows case-alias destinations before preparing or publishing a duplicate file"
    )
    return {
        "directory": directory,
        "title": title,
        "user": user,
        "items": items,
        "ids": ids,
        "paths": paths,
        "block": block,
        "journal": journal_path,
        "upload": upload,
        "read": read,
    }


def prepare_restart(client, fixture):
    for index, item in enumerate(fixture["items"]):
        item["content"] = base64.b64encode(bytes([index + 61]) * 384).decode()
    fixture["block"].mkdir()
    client.task(193, 7, fixture["upload"](fixture["items"]), error=102)
    fixture["pending"] = json.loads(fixture["journal"].read_bytes())
    assert fixture["pending"]["phase"] == "prepared"


def before_restart(fixture):
    fixture["block"].rmdir()


def check_restart(client, fixture, pb_fields, checks):
    raw = client.task(193, 6, fixture["read"](fixture["ids"]), structured=True)
    fields = pb_fields(raw)
    assert next(v for t, k, v in fields if t == 2) == 200
    objects = json.loads(next(v for t, k, v in fields if t == 3))
    assert not objects["errors"] and len(objects["objects"]) == 2
    for index, path in enumerate(fixture["paths"]):
        expected = fixture["pending"]["writes"][index]["document"]
        assert json.loads(path.read_bytes()) == expected
        assert objects["objects"][index]["metadata"] == expected["metadata"]
    assert json.loads(fixture["journal"].read_bytes()) == {
        **fixture["pending"],
        "phase": "applied",
        "writes": [],
    }
    checks.append(
        "object-store prepared profile windows recover across process restart under the same authenticated account without losing snapshots or rotating versions"
    )
