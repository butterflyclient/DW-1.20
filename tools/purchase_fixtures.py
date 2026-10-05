"""Independent native 80/106 purchase layout and atomic owner-wallet checks."""

import base64
import copy
import hashlib
import json
import struct


def exercise(client, other, directory, title, user, helpers, checks):
    u32, u64, text, blob, boolean = helpers
    u8 = lambda value: b"\x03" + bytes([value])
    i32 = lambda value: b"\x07" + struct.pack("<i", value)

    def request(
        transaction="purchase-native",
        ids=(50011, 50012),
        quantities=(2, 3),
        maximum=1,
        discounts=(),
        recipients=(),
        metadata=(),
        source=0,
        ignore=False,
    ):
        return (
            text(str(title))
            + text(transaction)
            + u32(len(ids))
            + b"".join(map(u32, ids))
            + u32(len(quantities))
            + b"".join(map(u32, quantities))
            + u32(maximum)
            + u32(len(discounts))
            + b"".join(map(u32, discounts))
            + u32(len(recipients))
            + b"".join(u64(owner) + text(account) for owner, account in recipients)
            + u32(len(metadata))
            + b"".join(map(blob, metadata))
            + u8(source)
            + boolean(ignore)
        )

    inventory = directory / "marketplace" / str(title) / str(user) / "inventory.json"
    inventory.parent.mkdir(parents=True, exist_ok=True)
    inventory.write_text(
        json.dumps(
            {
                "items": [{"1": 850, "2": 5, "18": 100000}],
                "balances": [{"currency": 20, "amount": 10000, "source": 1}],
            }
        )
    )
    catalog_path = directory / "marketplace" / str(title) / "catalog.json"
    rules_path = catalog_path.with_name("purchase-rules.json")
    original_catalog = catalog_path.read_bytes()
    before = inventory.read_bytes()
    client.task(80, 106, request(), error=108)
    assert inventory.read_bytes() == before
    sku = {
        "id": 50011,
        "product": 52,
        "type": 1,
        "data": "",
        "ignore_entitlements": 0,
        "sale_start": 0,
        "sale_end": 0,
        "rental_duration": 0,
        "promotional": "",
        "original": 0,
        "collision": 0,
        "modified": 100,
        "coupon_enabled": 1,
        "prices": [{"currency": 20, "amount": 15}],
        "enabled": True,
    }
    second = dict(
        sku,
        id=50012,
        product=53,
        coupon_enabled=0,
        prices=[{"currency": 20, "amount": 10}],
    )
    catalog = {"schema": 1, "skus": [sku, second]}
    rule = {
        "sku": 50011,
        "enabled": True,
        "allow_ignore_entitlements": False,
        "sources": [0, 7],
        "maximum_quantity": 6,
        "items": [{"1": 850, "2": 2, "18": 100000}],
        "currencies": [{"currency": 30, "amount": 3}],
    }
    second_rule = dict(
        rule, sku=50012, maximum_quantity=8, items=[{"1": 851, "2": 1}], currencies=[]
    )
    rules = {"schema": 1, "rules": [rule, second_rule]}
    catalog_path.write_text(json.dumps(catalog))
    rules_path.write_text(json.dumps(rules))
    params = request(metadata=(b"native coupon data", b""))
    result = client.task(80, 106, params)
    coupon = (
        text(hashlib.sha256(b"purchase-native\n0").hexdigest()[:24])
        + u64(user)
        + text("uno")
        + boolean(True)
        + u32(52)
        + u64(user)
        + text("uno")
        + u32(50011)
        + u32(0)
        + u32(0)
        + i32(1)
    )
    assert result == text("purchase-native") + u32(1) + coupon
    state = json.loads(inventory.read_bytes())
    assert {item["1"]: item["2"] for item in state["items"]} == {850: 9, 851: 3}
    assert {
        balance["currency"]: balance["amount"] for balance in state["balances"]
    } == {20: 9940, 30: 6}
    receipt = next(iter(state["purchases"].values()))
    assert (
        receipt["orders"][0]["metadata"]
        == base64.b64encode(b"native coupon data").decode()
    )
    assert (
        receipt["owner"] == user
        and receipt["title"] == title
        and receipt["source"] == 0
    )
    saved = inventory.read_bytes()
    assert client.task(80, 106, params) == result and inventory.read_bytes() == saved
    for changed in [
        request(metadata=(b"changed", b"")),
        request(quantities=(1, 3), metadata=(b"native coupon data", b"")),
        request(maximum=2, metadata=(b"native coupon data", b"")),
        request(source=7, metadata=(b"native coupon data", b"")),
    ]:
        client.task(80, 106, changed, error=106)
        assert inventory.read_bytes() == saved
    checks.append(
        "Replay purchase request source-byte/boolean order, full bounded coupon result and atomic published-price debit/item/currency grants/metadata receipt"
    )

    for invalid in [
        request("bad", quantities=(0, 3)),
        request("bad", quantities=(2,)),
        request("bad", maximum=256),
        request("bad", discounts=(1,)),
        request("bad", recipients=((user, "uno"),)),
        request("bad", metadata=(b"a" * 65, b"")),
        request("bad", metadata=(b"x",)),
        request("bad", ids=()),
        request("bad", ids=(2**32 - 1, 50012)),
        request("bad")[:-4] + boolean(False) + u8(0),
        request("bad") + b"\x01",
        request("x" * 25),
        request("bad", recipients=((user, "psn"), (user, "uno"))),
    ]:
        client.task(80, 106, invalid, error=106)
        assert inventory.read_bytes() == saved
    for params_bad, expected in [
        (request("missing", ids=(999, 50012)), 108),
        (request("discount", discounts=(4, 0)), 108),
        (request("source", source=8), 108),
        (request("ignore", ignore=True), 101),
        (request("gift", recipients=((user + 1, "uno"), (user, "uno"))), 108),
        (request("quantity", ids=(50011, 50011), quantities=(2, 5)), 102),
    ]:
        client.task(80, 106, params_bad, error=expected)
        assert inventory.read_bytes() == saved
    # Explicit self recipients and metadata have their canonical owner meaning.
    foreign_params = request(
        "owned-explicit",
        ids=(50012,),
        quantities=(1,),
        maximum=0,
        recipients=((user, "uno"),),
    )
    owned = client.task(80, 106, foreign_params)
    assert owned == text("owned-explicit") + u32(0)
    other.task(80, 106, foreign_params, error=108)
    saved = inventory.read_bytes()
    checks.append(
        "purchase optional-array parity, capacities/tags/sentinels, duplicate-order aggregate limits and unpublished discount/source/gift/entitlement denial without side effects"
    )

    poor = json.loads(saved)
    poor["balances"][0]["amount"] = 0
    inventory.write_text(json.dumps(poor))
    poor_bytes = inventory.read_bytes()
    client.task(80, 106, request("no-money"), error=101)
    assert inventory.read_bytes() == poor_bytes
    inventory.write_bytes(saved)
    broken_rules = copy.deepcopy(rules)
    broken_rules["rules"][0]["items"][0]["2"] = 2**32 - 1
    rules_path.write_text(json.dumps(broken_rules))
    client.task(80, 106, request("overflow"), error=102)
    assert inventory.read_bytes() == saved
    rules_path.write_text(json.dumps(rules))
    for field, value in [
        ("sale_start", 2**32 - 1),
        ("sale_end", 1),
        ("enabled", False),
    ]:
        disabled = copy.deepcopy(catalog)
        disabled["skus"][0][field] = value
        catalog_path.write_text(json.dumps(disabled))
        client.task(80, 106, request("inactive"), error=108)
        assert inventory.read_bytes() == saved
    damaged = copy.deepcopy(catalog)
    damaged["skus"][0]["prices"][0]["amount"] = -1
    catalog_path.write_text(json.dumps(damaged))
    client.task(80, 106, request("corrupt-catalog"), error=102)
    assert inventory.read_bytes() == saved
    catalog_path.write_text(json.dumps(catalog))
    damaged = copy.deepcopy(rules)
    damaged["rules"][0]["sources"] = [0, 0]
    rules_path.write_text(json.dumps(damaged))
    client.task(80, 106, request("corrupt-rules"), error=102)
    assert inventory.read_bytes() == saved
    rules_path.write_text(json.dumps(rules))
    checks.append(
        "purchase funds/quantity/overflow/sale-window and entire publication validation complete before durable debit or grant"
    )

    for field, value in [
        ("checksum", "a" * 64),
        ("owner", user + 1),
        ("title", title + 1),
        ("request", "b" * 64),
        ("response", base64.b64encode(b"changed").decode()),
        ("recorded", -1),
    ]:
        corrupted = json.loads(saved)
        next(iter(corrupted["purchases"].values()))[field] = value
        inventory.write_text(json.dumps(corrupted))
        corrupted_bytes = inventory.read_bytes()
        client.task(80, 106, params, error=102)
        assert inventory.read_bytes() == corrupted_bytes
    inventory.write_bytes(saved)
    checks.append(
        "signed owner/title-bound checksum receipts and stored request/result integrity fail closed; changed retries never debit twice"
    )

    empty_request = request("", ids=(50012,), quantities=(1,), maximum=0)
    first = client.task(80, 106, empty_request)
    second = client.task(80, 106, empty_request)

    def transaction(raw):
        assert raw[0] == 16 and raw[25] == 0 and raw[26:] == u32(0)
        value = raw[1:25].decode()
        assert len(value) == 24 and all(char in "0123456789abcdef" for char in value)
        return value

    first_id, second_id = transaction(first), transaction(second)
    assert first_id != second_id
    state = json.loads(inventory.read_bytes())
    assert {item["1"]: item["2"] for item in state["items"]} == {850: 9, 851: 6}
    assert (
        next(
            balance["amount"]
            for balance in state["balances"]
            if balance["currency"] == 20
        )
        == 9910
    )
    server_id_retry = request(first_id, ids=(50012,), quantities=(1,), maximum=0)
    saved = inventory.read_bytes()
    assert (
        client.task(80, 106, server_id_retry) == first
        and inventory.read_bytes() == saved
    )
    checks.append(
        "Replay empty transaction IDs create separate legitimate purchases; generated IDs support exact later retry without conflating identical purchase intents"
    )
    import purchase_v4_fixtures

    v4 = purchase_v4_fixtures.exercise(
        client, other, directory, title, user, helpers, checks
    )
    # The general catalog fixture is used by other service checks. Accepted
    # purchase retries do not depend on changing or republishing offers.
    catalog_path.write_bytes(original_catalog)
    rules_path.unlink()
    assert client.task(80, 106, params) == result
    return {
        "user": user,
        "request": params,
        "result": result,
        "path": inventory,
        "bytes": inventory.read_bytes(),
        "server_id_retry": server_id_retry,
        "server_id_result": first,
        "v4": v4,
    }


def check_restart(client, fixture, checks):
    import purchase_v4_fixtures

    purchase_v4_fixtures.check_restart(client, fixture["v4"], checks)
    assert client.task(80, 106, fixture["request"]) == fixture["result"]
    assert (
        client.task(80, 106, fixture["server_id_retry"]) == fixture["server_id_result"]
    )
    assert fixture["path"].read_bytes() == fixture["bytes"]
    checks.append(
        "purchase debit/grants and both client/server transaction receipts survive process restart and unpublished catalog changes without duplication"
    )
