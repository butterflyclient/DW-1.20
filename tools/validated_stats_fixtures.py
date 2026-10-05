"""Replay task 4/14 and trusted local stat authorization, with atomic retry checks."""

import base64
import copy
import hashlib
import json
import time


def exercise(client, directory, title, user, stat_row, blob, checks):
    path = directory / "validated-stats" / str(title) / "catalog.json"
    stats = directory / "leaderboard-stats" / str(title) / (str(user) + ".json")
    token = b"bounded local authoritative match token"
    request = blob(token)
    before = stats.read_bytes()
    client.task(4, 14, request, error=108)
    client.task(4, 14, blob(b""), error=106)
    client.task(4, 14, blob(b"x" * 10241), error=106)
    assert stats.read_bytes() == before
    row = dict(
        token_sha256=hashlib.sha256(token).hexdigest(),
        owner=user,
        enabled=True,
        starts=0,
        expires=0,
        stat_request_base64=base64.b64encode(
            stat_row(9907, 13, [7, None], mode=1) + b"\0"
        ).decode(),
    )
    catalog = dict(schema=1, title=title, authorizations=[row])
    path.parent.mkdir(parents=True)

    def publish(value):
        pending = path.with_suffix(".json.pending")
        pending.write_text(json.dumps(value))
        pending.replace(path)

    publish(catalog)
    assert client.task(4, 14, request) == []
    saved = stats.read_bytes()
    receipt = json.loads(saved)["_validated_tokens"][row["token_sha256"]]
    assert receipt["accepted"] > 0 and len(receipt["authorization_sha256"]) == 64
    assert client.task(4, 14, request) == []
    assert stats.read_bytes() == saved
    state = json.loads(saved)
    assert state["9907"]["rating"] == 13 and state["9907"]["columns"] == [7, None]
    # Ordinary stat writes must retain the authoritative receipt.
    assert client.task(4, 1, stat_row(9908, 3, [3])) == []
    saved = stats.read_bytes()
    assert json.loads(saved)["_validated_tokens"][row["token_sha256"]] == receipt
    assert client.task(4, 14, request) == []
    assert stats.read_bytes() == saved

    conflict = copy.deepcopy(catalog)
    conflict["authorizations"][0]["stat_request_base64"] = base64.b64encode(
        stat_row(9907, 100, [100], mode=1) + b"\0"
    ).decode()
    publish(conflict)
    client.task(4, 14, request, error=108)
    assert stats.read_bytes() == saved
    for field, value in (
        ("enabled", False),
        ("starts", int(time.time()) + 600),
        ("expires", 1),
    ):
        inactive = copy.deepcopy(catalog)
        inactive["authorizations"][0][field] = value
        publish(inactive)
        client.task(4, 14, request, error=108)
        assert stats.read_bytes() == saved
    foreign = copy.deepcopy(catalog)
    foreign["authorizations"][0].update(
        owner=user + 1,
        stat_request_base64=base64.b64encode(
            stat_row(9907, 13, [7], entity=user + 1) + b"\0"
        ).decode(),
    )
    publish(foreign)
    client.task(4, 14, request, error=101)
    assert stats.read_bytes() == saved
    corruptions = [
        [],
        {**catalog, "title": title + 1},
        {**catalog, "authorizations": [row, row]},
        {**catalog, "authorizations": [row, {**row, "token_sha256": "A" * 64}]},
        {**catalog, "authorizations": [{**row, "stat_request_base64": "AA=="}]},
        {**catalog, "authorizations": [{**row, "owner": user + 1}]},
    ]
    for corrupt in corruptions:
        publish(corrupt)
        client.task(4, 14, request, error=102)
        assert stats.read_bytes() == saved
    publish(catalog)
    path.write_bytes(b"x" * (4 * 1024 * 1024 + 1))
    client.task(4, 14, request, error=102)
    assert stats.read_bytes() == saved
    publish(catalog)
    bad_receipt = json.loads(saved)
    bad_receipt["_validated_tokens"][row["token_sha256"]][
        "authorization_sha256"
    ] = "bad"
    stats.write_text(json.dumps(bad_receipt))
    malformed = stats.read_bytes()
    client.task(4, 14, request, error=102)
    assert stats.read_bytes() == malformed
    stats.write_bytes(saved)
    overflow_token = b"validated batch must roll back all rows"
    overflow = {**row, "token_sha256": hashlib.sha256(overflow_token).hexdigest()}
    assert client.task(4, 1, stat_row(9909, 9223372036854775807, [])) == []
    saved = stats.read_bytes()
    overflow["stat_request_base64"] = base64.b64encode(
        stat_row(9907, 1, [1], mode=1) + stat_row(9909, 1, [], mode=1) + b"\0"
    ).decode()
    publish({**catalog, "authorizations": [row, overflow]})
    client.task(4, 14, blob(overflow_token), error=106)
    assert stats.read_bytes() == saved
    publish(catalog)
    assert client.task(4, 14, request) == []
    assert stats.read_bytes() == saved
    boundary_token = b"b" * 10240
    boundary = {
        **row,
        "token_sha256": hashlib.sha256(boundary_token).hexdigest(),
        "stat_request_base64": base64.b64encode(
            stat_row(9910, 4, [4]) + b"\0"
        ).decode(),
    }
    publish({**catalog, "authorizations": [row, boundary]})
    assert client.task(4, 14, blob(boundary_token)) == []
    saved = stats.read_bytes()
    assert json.loads(saved)["9910"]["rating"] == 4
    client.task(4, 14, request + b"extra", error=106)
    client.task(4, 14, blob(b"unpublished token"), error=108)
    assert stats.read_bytes() == saved
    capped = json.loads(saved)
    receipts = capped["_validated_tokens"]
    for index in range(1024 - len(receipts)):
        receipts[f"{index:064x}"] = dict(authorization_sha256="0" * 64, accepted=0)
    stats.write_text(json.dumps(capped))
    capacity_token = b"new token at capacity"
    capacity = {**boundary, "token_sha256": hashlib.sha256(capacity_token).hexdigest()}
    publish({**catalog, "authorizations": [row, capacity]})
    capped_bytes = stats.read_bytes()
    client.task(4, 14, blob(capacity_token), error=108)
    assert stats.read_bytes() == capped_bytes
    stats.write_bytes(saved)
    publish(catalog)
    checks.append(
        "native token-only server-validated stats, trusted owner/time authorization, full-batch atomic merge, receipt conflicts and retry isolation"
    )
    return dict(
        request=request,
        token_hash=row["token_sha256"],
        stats=stats.read_bytes(),
        path=stats,
    )


def check_restart(client, fixture, checks):
    assert client.task(4, 14, fixture["request"]) == []
    assert fixture["path"].read_bytes() == fixture["stats"]
    state = json.loads(fixture["path"].read_bytes())
    assert state["9907"]["rating"] == 13
    assert fixture["token_hash"] in state["_validated_tokens"]
    checks.append(
        "server-validated stat retry receipt and unchanged additive result survive process restart"
    )
