"""Native structured code/payload redemption and single-file grant transactions."""

import base64
import copy
import hashlib
import json


def exercise(client, directory, title, user, helpers, checks):
    structure, pb_text, pb_integer, pb_bytes, pb_map = helpers
    request = lambda transaction, value, signature=None: structure(
        pb_text(1, "iw8")
        + pb_text(2, transaction)
        + pb_text(3, value)
        + (b"" if signature is None else pb_text(4, signature))
    )
    inventory = directory / "marketplace" / str(title) / str(user) / "inventory.json"
    publication = directory / "redemptions" / str(title) / "iw8" / "codes.json"
    client.task(123, 1, request("missing", "LOCAL-CODE"), error=108)
    item = {
        "1": 9012,
        "2": 3,
        "3": 4,
        "4": [5, 6],
        "6": 0,
        "7": 0,
        "8": 321,
        "9": 2,
        "10": -1,
        "13": "Local fixture item",
        "14": "weapon",
        "15": "test",
        "16": False,
        "18": 100,
        "19": 0,
    }
    row = {
        "kind": "code",
        "hash": hashlib.sha256(b"LOCAL-CODE").hexdigest(),
        "enabled": True,
        "expires": 0,
        "users": [user],
        "items": [item],
        "currencies": [{"currency": 20, "amount": 50, "source": 2}],
    }
    payload = dict(
        row,
        kind="payload",
        hash=hashlib.sha256(b"Local signed payload").hexdigest(),
        signature_hash=hashlib.sha256(b"local-signature").hexdigest(),
        items=[dict(item, **{"2": 2})],
        currencies=[{"currency": 20, "amount": 10, "source": 2}],
    )
    expired = dict(row, hash=hashlib.sha256(b"EXPIRED").hexdigest(), expires=1)
    overflow = dict(
        row,
        hash=hashlib.sha256(b"OVERFLOW").hexdigest(),
        currencies=[{"currency": 20, "amount": 0xFFFFFFFF}],
    )
    catalog = {"schema": 1, "codes": [row, payload, expired, overflow]}
    publication.parent.mkdir(parents=True)
    publication.write_text(json.dumps(catalog))
    code_request = request("code-transaction", "LOCAL-CODE")
    result = client.task(123, 1, code_request, structured=True)
    grants = pb_map(result)
    grant = pb_map(grants[1][0])
    expected = {
        1: [9012],
        2: [b"Local fixture item"],
        3: [b"weapon"],
        4: [b"test"],
        5: [b"\x05\x06"],
        6: [3],
        7: [4],
        8: [2],
        9: [0],
        10: [1],
        11: [321],
        12: [0],
        13: [1],
        14: [0],
        15: [100],
        16: [0],
    }
    assert grant == expected and pb_map(grants[2][0]) == {1: [20], 2: [0], 3: [50]}
    before = inventory.read_bytes()
    assert (
        client.task(123, 1, code_request, structured=True) == result
        and inventory.read_bytes() == before
    )
    client.task(123, 1, request("code-transaction", "changed"), error=106)
    client.task(123, 1, request("new-transaction", "LOCAL-CODE"), error=108)
    client.task(123, 1, request("expired", "EXPIRED"), error=108)
    client.task(123, 1, request("overflow", "OVERFLOW"), error=102)
    assert inventory.read_bytes() == before
    client.task(
        123, 2, request("signed", "Local signed payload", "incorrect"), error=101
    )
    signed_request = request("signed", "Local signed payload", "local-signature")
    signed_result = client.task(123, 2, signed_request, structured=True)
    assert pb_map(pb_map(signed_result)[1][0])[6] == [2]
    assert pb_map(pb_map(signed_result)[2][0]) == {1: [20], 2: [50], 3: [10]}
    saved = inventory.read_bytes()
    state = json.loads(saved)
    assert state["items"][0]["2"] == 5 and state["balances"][0]["amount"] == 60
    assert len(state["redemptions"]) == len(state["redeemed_keys"]) == 2
    assert b"LOCAL-CODE" not in saved and b"local-signature" not in saved
    corrupt = json.loads(saved)
    next(iter(corrupt["redemptions"].values()))["request"] = "bad"
    inventory.write_text(json.dumps(corrupt))
    client.task(123, 1, code_request, error=102)
    inventory.write_bytes(saved)
    broken = copy.deepcopy(catalog)
    broken["codes"][1]["items"][0]["14"] = "x" * 10
    publication.write_text(json.dumps(broken))
    client.task(123, 1, request("unused", "UNKNOWN"), error=102)
    publication.write_text(json.dumps(catalog))
    checks.append(
        "native full redemption item/currency DTOs, atomic inventory and balance grants, issued payload signature binding, owner/expiry checks and durable exact retry receipts"
    )
    return {
        "request": code_request,
        "result": result,
        "signed_request": signed_request,
        "signed_result": signed_result,
        "path": inventory,
        "bytes": saved,
        "peer_request": request("peer-denied", "LOCAL-CODE"),
    }


def check_restart(client, fixture, checks):
    # Rank/progression fixtures legitimately share this inventory. Check the
    # complete redemption records and their grants, then require both retries
    # to preserve the entire current inventory, including those later awards.
    before = fixture["path"].read_bytes()
    current = json.loads(before)
    original = json.loads(fixture["bytes"])
    for field in ("redemptions", "redeemed_keys"):
        assert current[field] == original[field]
    by_item = lambda state: {row["1"]: row for row in state["items"]}
    by_currency = lambda state: {row["currency"]: row for row in state["balances"]}
    for item_id, item in by_item(original).items():
        assert by_item(current)[item_id] == item
    for currency, balance in by_currency(original).items():
        assert by_currency(current)[currency] == balance
    assert client.task(123, 1, fixture["request"], structured=True) == fixture["result"]
    assert client.task(123, 2, fixture["signed_request"], structured=True) == fixture["signed_result"]
    assert fixture["path"].read_bytes() == before
    checks.append(
        "single-file redemption receipts, grants and balances survive process restart; exact retries preserve later progression awards without duplicate grants"
    )
