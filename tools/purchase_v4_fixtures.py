"""Independent Replay 80/125 request and full ResultV4/PlayerAssetsV3 contract."""

import base64
import copy
import hashlib
import json
import struct


def exercise(client, other, directory, title, user, helpers, checks):
    u32, u64, text, blob, boolean = helpers
    u8 = lambda value: b"\x03" + bytes([value])
    u16 = lambda value: b"\x06" + struct.pack("<H", value)
    i32 = lambda value: b"\x07" + struct.pack("<i", value)
    i64 = lambda value: b"\x09" + struct.pack("<q", value)
    inventory = directory / "marketplace" / str(title) / str(user) / "inventory.json"
    catalog_path = inventory.parent.parent / "catalog.json"
    rules_path = catalog_path.with_name("purchase-rules.json")
    catalog_before, rules_before = catalog_path.read_bytes(), rules_path.read_bytes()
    catalog, rules = json.loads(catalog_before), json.loads(rules_before)
    catalog["skus"][0].update(
        coupon_metadata=base64.b64encode(b"coupon v4 metadata").decode(),
        penalty_percentage=-7,
        rental_duration_unit=0,
        product_expires=77,
    )
    for rule in rules["rules"]:
        rule["sources"].append(1024)
    catalog_path.write_text(json.dumps(catalog))
    rules_path.write_text(json.dumps(rules))
    state = json.loads(inventory.read_bytes())
    state["entitlements"] = [{"id": 82, "level": 2}]
    state["items"][0].update(
        {
            "3": 19,
            "4": [11, 22, 33],
            "6": 901,
            "9": 123,
            "10": -12345,
            "8": 902,
            "11": 614,
        }
    )
    inventory.write_text(json.dumps(state))

    def request(
        transaction="purchase-native-v4",
        buyer=user,
        account="uno",
        orders=((50011, 1, 0, ((20, 15),)), (50012, 2, 0, ((20, 10),))),
        metadata=(("campaign", "local"),),
        source=1024,
        ignore=False,
        coupons=0,
    ):
        return (
            text(str(title))
            + text(transaction)
            + u64(buyer)
            + text(account)
            + u32(len(orders))
            + b"".join(
                u32(sku)
                + u32(quantity)
                + u32(discount)
                + u32(len(prices))
                + b"".join(u8(currency) + u32(amount) for currency, amount in prices)
                for sku, quantity, discount, prices in orders
            )
            + u32(coupons)
            + u32(len(metadata))
            + b"".join(text(key) + text(value) for key, value in metadata)
            + u32(source)
            + boolean(ignore)
        )

    params = request()
    before = inventory.read_bytes()
    result = client.task(80, 125, params)
    committed = json.loads(inventory.read_bytes())
    old_items = {row["1"]: row["2"] for row in state["items"]}
    old_balances = {row["currency"]: row["amount"] for row in state["balances"]}
    assert {row["1"]: row["2"] for row in committed["items"]} == {
        850: old_items[850] + 2,
        851: old_items[851] + 2,
    }
    assert {row["currency"]: row["amount"] for row in committed["balances"]} == {
        20: old_balances[20] - 35,
        30: old_balances[30] + 3,
    }
    key = hashlib.sha256((str(title) + "\npurchase-native-v4").encode()).hexdigest()
    receipt = committed["purchases"][key]
    assert (
        receipt["format"] == 125
        and receipt["source"] == 1024
        and receipt["maximum"] == 0
    )
    assert receipt["metadata"] == [{"key": "campaign", "value": "local"}]
    stamp = receipt["recorded"]
    # Explicit target grammar; no account is repeated inside inherited DTOs.
    expected = (
        text("purchase-native-v4")
        + u64(user)
        + text("uno")
        + u32(len(committed["balances"]))
    )
    expected += b"".join(
        u8(row["currency"]) + u32(row["amount"]) for row in committed["balances"]
    )
    expected += u32(len(committed["items"]))
    for item in committed["items"]:
        expected += (
            u32(item["1"])
            + u32(item["2"])
            + u32(item.get("3", 0))
            + blob(bytes(item.get("4", [])))
            + u32(item.get("6", 0))
            + i64(item.get("10", 0))
            + u16(item.get("9", 0))
            + u32(item.get("8", 0))
            + u32(item.get("11", 0))
        )
    expected += u32(1) + u32(82) + u32(2) + u32(0)
    coupon_id = hashlib.sha256(b"purchase-native-v4\n0").hexdigest()[:24]
    coupon = (
        text(coupon_id)
        + u64(user)
        + text("uno")
        + boolean(True)
        + u32(52)
        + u64(user)
        + text("uno")
        + u32(50011)
        + u32(0)
        + u8(0)
        + u32(0)
        + i32(-7)
        + u32(77)
        + blob(b"coupon v4 metadata")
        + u32(1024)
        + u32(stamp)
    )
    assert result == expected + u32(1) + coupon and inventory.read_bytes() != before
    saved = inventory.read_bytes()
    assert client.task(80, 125, params) == result and inventory.read_bytes() == saved
    checks.append(
        "Replay 80/125 buyer/SKU expected prices/metadata/UInt32 source and full ResultV4 account/currencies/InventoryV3/entitlements/CouponV4 grammar with atomic real debit/grant"
    )

    for invalid in [
        request("invalid", orders=((50011, 0, 0, ()),)),
        request("invalid", orders=((50011, 1, 0, ((20, 15), (20, 15))),)),
        request("invalid", orders=((50011, 1, 0, tuple((x, 1) for x in range(11))),)),
        request("invalid", metadata=(("same", "a"), ("same", "b"))),
        request("invalid", metadata=(("k" * 16, "a"),)),
        request("invalid", metadata=(("k", "a" * 256),)),
        request("invalid", source=2**32 - 1),
        request("invalid", account="psn"),
        request("invalid", orders=()),
        request("invalid")[:-7] + u8(0) + boolean(False),
    ]:
        client.task(80, 125, invalid, error=106)
        assert inventory.read_bytes() == saved
    for invalid, code in [
        (request("wrong-price", orders=((50011, 1, 0, ((20, 14),)),)), 101),
        (request("wrong-buyer", buyer=user + 1), 101),
        (request("bad-source", source=1025), 108),
        (request("discount", orders=((50011, 1, 5, ()),)), 108),
        (request("ignore", ignore=True), 101),
        (request("coupon", orders=(), coupons=1), 108),
    ]:
        client.task(80, 125, invalid, error=code)
        assert inventory.read_bytes() == saved
    other.task(80, 125, params, error=101)
    for changed in [
        request(metadata=(("campaign", "changed"),)),
        request(source=7),
        request(orders=((50011, 1, 0, ()), (50012, 2, 0, ()))),
    ]:
        client.task(80, 125, changed, error=106)
        assert inventory.read_bytes() == saved
    client.task(80, 125, request("purchase-native"), error=106)
    assert inventory.read_bytes() == saved
    checks.append(
        "purchase125 owner isolation, expected-price mismatch, metadata/source widths/counts, unsupported coupon/discount policies and cross-format transaction conflict without side effects"
    )

    for change in (
        "currency-width",
        "currency-count",
        "entitlement-count",
        "coupon-owner",
    ):
        bad = copy.deepcopy(committed)
        if change == "currency-width":
            bad["balances"][0]["amount"] = 2**32 + 10000
        elif change == "currency-count":
            bad["balances"] = [
                {"currency": i, "amount": 10000} for i in (20, 30, *range(9))
            ]
        elif change == "entitlement-count":
            bad["entitlements"] = [{"id": i, "level": 1} for i in range(1001)]
        else:
            bad["coupons"] = [{"owner": user + 1, "id": "bad"}]
        inventory.write_text(json.dumps(bad))
        bad_bytes = inventory.read_bytes()
        client.task(
            80, 125, request("cap-" + change, orders=((50012, 1, 0, ()),)), error=102
        )
        assert inventory.read_bytes() == bad_bytes
    inventory.write_bytes(saved)
    checks.append(
        "ResultV4 legacy currency/entitlement capacities and coupon ownership validated before commit; no truncated snapshot or overflow debit"
    )
    catalog_path.write_bytes(catalog_before)
    rules_path.write_bytes(rules_before)
    return {"request": params, "result": result}


def check_restart(client, fixture, checks):
    assert client.task(80, 125, fixture["request"]) == fixture["result"]
    checks.append(
        "durable purchase125 exact response survives backend restart after offer/rules removal without second debit or grant"
    )
