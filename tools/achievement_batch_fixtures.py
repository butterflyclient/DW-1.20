"""Same-Replay 125/2 batch, identity and cross-transport retry tests."""

import base64
import hashlib
import json
import uuid


def exercise(
    client,
    directory,
    title,
    user,
    platform_id,
    pb_text,
    pb_integer,
    pb_bytes,
    structure,
    native_rest,
    checks,
):
    path = (
        directory / "achievements" / str(title) / str(title) / str(user) / "events.json"
    )
    event = pb_text(1, "batch_event") + pb_integer(2, 321) + pb_integer(4, 0)
    identity = lambda value, kind: pb_integer(1, value) + pb_text(2, kind)
    account = identity(user, "uno")
    first_party = identity(platform_id, "bnet")
    batch = lambda events, owner=account, first=first_party, platform=113: (
        pb_bytes(1, owner)
        + b"".join(pb_bytes(2, e) for e in events)
        + pb_bytes(3, first)
        + pb_integer(4, platform)
    )
    token = base64.urlsafe_b64encode(bytes(range(16))).rstrip(b"=").decode()
    request = lambda batches, token=token, context=str(title): structure(
        pb_text(1, context)
        + b"".join(pb_bytes(2, row) for row in batches)
        + pb_text(3, token)
    )
    payload = request([batch([event])])
    assert client.task(125, 2, payload, structured=True) == b""
    snapshot = path.read_bytes()
    saved = json.loads(snapshot)
    assert saved["events"][-1]["event"] == {
        "name": "batch_event",
        "timestamp": 321,
        "values": {},
    }
    canonical = str(uuid.UUID(bytes=bytes(range(16))[::-1]))
    receipt = next(row for row in saved["requests"] if row["id"] == canonical)
    assert receipt["users"] == [
        dict(
            userID=user,
            accountType="uno",
            firstPartyUserID=platform_id,
            firstPartyAccountType="bnet",
            platform="bnet",
            eventCount=1,
        )
    ]
    assert (
        client.task(125, 2, payload, structured=True) == b""
        and path.read_bytes() == snapshot
    )
    assert (
        client.task(
            125, 2, request([batch([event])], token=token + "=="), structured=True
        )
        == b""
    )
    body = dict(
        titleID=title,
        idempotentRequestID=canonical,
        userEvents=[
            dict(
                userID=user,
                accountType="bnet",
                firstPartyUserID=platform_id,
                firstPartyAccountType="bnet",
                platform="bnet",
                events=[dict(name="batch_event", timestamp=321, values={})],
            )
        ],
    )
    rest = lambda body: native_rest(
        "ae.demonware.net",
        "user_events",
        "report_user_events_batch",
        0x504F5354,
        body,
        uri=f"/v2/user-events/$batch/?context={title}&client=replaylocal&titleID={title}",
    )
    client.task(255, 10, rest(body))
    assert path.read_bytes() == snapshot
    changed = pb_text(1, "changed_event") + pb_integer(2, 321) + pb_integer(4, 0)
    client.task(125, 2, request([batch([changed])]), error=106)
    for bad in [
        request([]),
        request([batch([])]),
        request([batch([event], platform=256)]),
        request([batch([event], platform=114)]),
        request([batch([event])] * 17),
        request([batch([event] * 129)]),
        request([batch([event])], context="foreign"),
        request([batch([event])], token="bad"),
        request([batch([event])], token=token[:-1] + "B"),
        request([batch([event]) + pb_integer(4, 113)]),
        structure(pb_text(1, str(title)) + pb_bytes(2, batch([event]))),
        payload + b"\x08\0\0\0\0",
    ]:
        client.task(125, 2, bad, error=106)
        assert path.read_bytes() == snapshot
    for owner, first in [
        (identity(user + 1, "uno"), first_party),
        (account, identity(platform_id + 1, "bnet")),
        (account, identity(user + 1, "uno")),
    ]:
        client.task(
            125, 2, request([batch([event], owner=owner, first=first)]), error=101
        )
        assert path.read_bytes() == snapshot
    for change, code in [
        (dict(firstPartyUserID=platform_id + 1), 101),
        (dict(platform="steam"), 106),
        (dict(firstPartyAccountType="other"), 101),
    ]:
        rejected = json.loads(json.dumps(body))
        rejected["userEvents"][0].update(change)
        client.task(255, 10, rest(rejected), error=code)
        assert path.read_bytes() == snapshot
    # A full native batch commits once after every owner/event is checked.
    full_token = base64.urlsafe_b64encode(bytes(range(16, 32))).rstrip(b"=").decode()
    full = request([batch([event] * 8)] * 16, token=full_token)
    assert client.task(125, 2, full, structured=True) == b""
    assert len(json.loads(path.read_bytes())["events"]) == len(saved["events"]) + 128
    final = path.read_bytes()
    for mutate in [
        lambda store: store["requests"][0].update(digest="bad"),
        lambda store: store.update(next=0),
        lambda store: store["requests"].append(store["requests"][0]),
        lambda store: store["events"][0].update(id=store["next"]),
        lambda store: store["requests"][-1]["users"][0].update(
            firstPartyUserID=platform_id + 1
        ),
    ]:
        corrupt = json.loads(final)
        mutate(corrupt)
        path.write_text(json.dumps(corrupt))
        client.task(125, 2, full, error=102)
        assert json.loads(path.read_bytes()) == corrupt
    path.write_bytes(final)
    single_token = base64.urlsafe_b64encode(bytes(range(64, 80))).rstrip(b"=").decode()
    single_request = structure(
        pb_text(1, str(title)) + pb_bytes(2, event) + pb_text(3, single_token)
    )
    assert client.task(125, 1, single_request, structured=True) == b""
    single_saved = path.read_bytes()
    single_body = dict(
        titleID=title,
        idempotentRequestID=str(uuid.UUID(bytes=bytes(range(64, 80))[::-1])),
        userEvents=[
            dict(
                userID=user,
                accountType="bnet",
                events=[dict(name="batch_event", timestamp=321, values={})],
            )
        ],
    )
    client.task(255, 10, rest(single_body))
    assert path.read_bytes() == single_saved
    final = single_saved
    retained = json.loads(final)
    while len(retained["requests"]) < 256:
        retained["requests"].append(
            dict(id=f'older-{len(retained["requests"])}', digest="a" * 32)
        )
    path.write_text(json.dumps(retained))
    for start in (32, 48, 80):
        new_token = (
            base64.urlsafe_b64encode(bytes(range(start, start + 16)))
            .rstrip(b"=")
            .decode()
        )
        assert (
            client.task(
                125, 2, request([batch([event])], token=new_token), structured=True
            )
            == b""
        )
        assert len(json.loads(path.read_bytes())["requests"]) == 256
    archived = (
        path.parent
        / "receipts"
        / (hashlib.sha256(canonical.encode()).hexdigest() + ".json")
    )
    archived_bytes = archived.read_bytes()
    archive = json.loads(archived_bytes)
    assert (
        archive["owner"] == user
        and archive["title"] == title
        and archive["receipt"] == receipt
    )
    hot_bytes = path.read_bytes()
    assert client.task(125, 2, payload, structured=True) == b""
    client.task(255, 10, rest(body))
    assert path.read_bytes() == hot_bytes and archived.read_bytes() == archived_bytes
    client.task(125, 2, request([batch([changed])]), error=106)
    for mutate in [
        lambda archive: archive.update(owner=user + 1),
        lambda archive: archive.update(title=title + 1),
        lambda archive: archive.update(context="foreign"),
        lambda archive: archive["receipt"].update(id="misplaced"),
        lambda archive: archive["receipt"].update(digest="a" * 32),
        lambda archive: archive["receipt"]["users"][0].update(
            firstPartyUserID=platform_id + 1
        ),
    ]:
        corrupt = json.loads(archived_bytes)
        mutate(corrupt)
        archived.write_text(json.dumps(corrupt))
        client.task(125, 2, payload, error=102)
        assert (
            json.loads(archived.read_bytes()) == corrupt
            and path.read_bytes() == hot_bytes
        )
    archived.write_bytes(archived_bytes)
    # Crash after archive publication but before journal replacement: the hot
    # and archived receipt coexist. Retry must remain read-only and idempotent.
    duplicate = json.loads(hot_bytes)
    duplicate["requests"].insert(0, receipt)
    path.write_text(json.dumps(duplicate))
    duplicate_bytes = path.read_bytes()
    assert client.task(125, 2, payload, structured=True) == b""
    assert (
        path.read_bytes() == duplicate_bytes and archived.read_bytes() == archived_bytes
    )
    path.write_bytes(hot_bytes)
    # Previously deployed binary handlers saved the base64 token verbatim.
    # Upgrade lookup must work even when there is no canonical UUID archive.
    old_path = archived.parent / (hashlib.sha256(token.encode()).hexdigest() + ".json")
    old = json.loads(archived_bytes)
    old["receipt"]["id"] = token
    old["checksum"] = hashlib.sha256(
        json.dumps(old["receipt"], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:32]
    old_path.write_text(json.dumps(old))
    held = archived.with_suffix(".held")
    archived.rename(held)
    try:
        assert client.task(125, 2, payload, structured=True) == b""
        client.task(255, 10, rest(body))
        assert path.read_bytes() == hot_bytes
        old["receipt"]["digest"] = "a" * 32
        old["checksum"] = hashlib.sha256(
            json.dumps(old["receipt"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
        old_path.write_text(json.dumps(old))
        client.task(125, 2, payload, error=106)
    finally:
        old_path.unlink()
        held.rename(archived)
    checks.append(
        "native achievement 125/2 complete batch/account/event layouts, 16/128 bounds and atomic malformed-owner rejection"
    )
    checks.append(
        "signed first-party identity, binary/REST retry-ID normalization and changed-payload conflict protection"
    )
    checks.append(
        "achievement journal/archive integrity, durable late retries beyond the hot window and archive-before-commit crash recovery"
    )
    checks.append(
        "native single-owner 125/1 binary/REST fallback uses one canonical UUID receipt without changing legacy opaque IDs"
    )
    checks.append(
        "pre-upgrade binary-token archive lookup prevents duplicate ingestion and preserves changed-payload conflict checks"
    )
    return dict(
        request=full,
        single_request=single_request,
        cold_request=payload,
        path=path,
        bytes=path.read_bytes(),
        archive=archived,
        archive_bytes=archived_bytes,
    )


def check_restart(client, fixture, checks):
    assert client.task(125, 2, fixture["request"], structured=True) == b""
    assert client.task(125, 1, fixture["single_request"], structured=True) == b""
    assert client.task(125, 2, fixture["cold_request"], structured=True) == b""
    assert fixture["path"].read_bytes() == fixture["bytes"]
    assert fixture["archive"].read_bytes() == fixture["archive_bytes"]
    checks.append(
        "native achievement batch receipt and event attribution survive restart without duplicate recording"
    )
